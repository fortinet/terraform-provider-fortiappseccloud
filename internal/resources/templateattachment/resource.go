package templateattachment

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                = (*attachmentResource)(nil)
	_ resource.ResourceWithConfigure   = (*attachmentResource)(nil)
	_ resource.ResourceWithImportState = (*attachmentResource)(nil)
)

const maxConflictAttempts = 3

type attachmentService interface {
	GetTemplate(context.Context, string) (client.Template, error)
	PutTemplateEndpoints(context.Context, string, []string) error
	FindApplicationByEPID(context.Context, string) (client.Application, error)
}

type attachmentResource struct {
	service attachmentService
	locks   *locking.Registry
}

type resourceModel struct {
	EPID       types.String `tfsdk:"ep_id"`
	TemplateID types.String `tfsdk:"template_id"`
}

// NewResource creates one application-to-template membership resource.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &attachmentResource{locks: locks}
}

func (r *attachmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_template_attachment"
}

func (r *attachmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Owns one application-to-template membership. Updates preserve every unrelated template member.",
		Attributes: map[string]schema.Attribute{
			"ep_id":       schema.StringAttribute{Required: true, PlanModifiers: replace},
			"template_id": schema.StringAttribute{Required: true, PlanModifiers: replace},
		},
	}
}

func (r *attachmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	apiClient, ok := req.ProviderData.(*client.Client)
	if !ok || apiClient == nil {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T.", req.ProviderData))
		return
	}
	r.service = apiClient
}

func (r *attachmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !r.ready(&resp.Diagnostics) {
		return
	}
	epID, templateID, ok := knownIDs(plan, &resp.Diagnostics)
	if !ok {
		return
	}
	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()
	application, err := r.service.FindApplicationByEPID(ctx, epID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to resolve application", err.Error())
		return
	}
	if application.TemplateID != "" && application.TemplateID != templateID {
		resp.Diagnostics.AddError("Application is attached to another template", fmt.Sprintf("Application %q is already attached to template %q.", epID, application.TemplateID))
		return
	}
	if !r.ensureMembership(ctx, epID, templateID, true, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *attachmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !r.ready(&resp.Diagnostics) {
		return
	}
	epID, templateID, ok := knownIDs(state, &resp.Diagnostics)
	if !ok {
		return
	}
	template, err := r.service.GetTemplate(ctx, templateID)
	if err != nil {
		if client.IsStatus(err, http.StatusBadRequest, http.StatusNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read template attachment", err.Error())
		return
	}
	if !templateContains(template, epID) {
		resp.State.RemoveResource(ctx)
	}
}

func (r *attachmentResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
	// Both attributes require replacement.
}

func (r *attachmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !r.ready(&resp.Diagnostics) {
		return
	}
	epID, templateID, ok := knownIDs(state, &resp.Diagnostics)
	if !ok {
		return
	}
	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()
	r.ensureMembership(ctx, epID, templateID, false, &resp.Diagnostics)
}

func (r *attachmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(strings.TrimSpace(req.ID), ":")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires template_id:ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("template_id"), strings.TrimSpace(parts[0]))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), strings.TrimSpace(parts[1]))...)
}

func (r *attachmentResource) ensureMembership(ctx context.Context, epID, templateID string, present bool, diagnostics *diag.Diagnostics) bool {
	for attempt := 1; attempt <= maxConflictAttempts; attempt++ {
		template, err := r.service.GetTemplate(ctx, templateID)
		if err != nil {
			if !present && client.IsStatus(err, http.StatusBadRequest, http.StatusNotFound) {
				return true
			}
			diagnostics.AddError("Unable to read template membership", err.Error())
			return false
		}
		ids := endpointIDs(template)
		contained := contains(ids, epID)
		if contained == present {
			return true
		}
		if present {
			ids = append(ids, epID)
		} else {
			ids = remove(ids, epID)
		}
		sort.Strings(ids)
		if err := r.service.PutTemplateEndpoints(ctx, templateID, ids); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < maxConflictAttempts {
				continue
			}
			diagnostics.AddError("Unable to update template membership", err.Error())
			return false
		}
		verified, err := r.service.GetTemplate(ctx, templateID)
		if err != nil {
			diagnostics.AddError("Unable to verify template membership", err.Error())
			return false
		}
		if templateContains(verified, epID) != present {
			diagnostics.AddError("Template membership update was not applied", fmt.Sprintf("Template %q did not report the expected membership for application %q.", templateID, epID))
			return false
		}
		return true
	}
	return false
}

func endpointIDs(template client.Template) []string {
	result := make([]string, 0, len(template.Endpoints))
	for _, endpoint := range template.Endpoints {
		if endpoint.EPID != "" && !contains(result, endpoint.EPID) {
			result = append(result, endpoint.EPID)
		}
	}
	return result
}

func templateContains(template client.Template, epID string) bool {
	return contains(endpointIDs(template), epID)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func remove(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func knownIDs(model resourceModel, diagnostics *diag.Diagnostics) (string, string, bool) {
	if model.EPID.IsNull() || model.EPID.IsUnknown() || model.TemplateID.IsNull() || model.TemplateID.IsUnknown() {
		diagnostics.AddError("Unknown template attachment identity", "ep_id and template_id must be known.")
		return "", "", false
	}
	epID, templateID := strings.TrimSpace(model.EPID.ValueString()), strings.TrimSpace(model.TemplateID.ValueString())
	if epID == "" || templateID == "" {
		diagnostics.AddError("Invalid template attachment identity", "ep_id and template_id must not be empty.")
		return "", "", false
	}
	return epID, templateID, true
}

func (r *attachmentResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service == nil {
		diagnostics.AddError("Template attachment client is not configured", "Configure the provider before managing template attachment.")
		return false
	}
	return true
}
