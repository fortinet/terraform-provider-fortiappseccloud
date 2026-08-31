package template

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                   = (*templateResource)(nil)
	_ resource.ResourceWithConfigure      = (*templateResource)(nil)
	_ resource.ResourceWithImportState    = (*templateResource)(nil)
	_ resource.ResourceWithValidateConfig = (*templateResource)(nil)
)

const (
	defaultPollAttempts = 30
	defaultPollDelay    = 2 * time.Second
)

type templateService interface {
	CreateTemplate(context.Context, client.TemplateCreateRequest) (client.TemplateCreateResponse, error)
	GetTemplate(context.Context, string) (client.Template, error)
	TemplateExists(context.Context, string) (bool, error)
	DeleteTemplate(context.Context, string) error
}

type templateResource struct {
	service      templateService
	locks        *locking.Registry
	pollAttempts int
	pollDelay    time.Duration
}

type resourceModel struct {
	TemplateID types.String `tfsdk:"template_id"`
	Name       types.String `tfsdk:"name"`
	Predefined types.Bool   `tfsdk:"predefined"`
	Features   types.List   `tfsdk:"features"`
}

// NewResource creates the base WAF template lifecycle resource.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &templateResource{
		locks:        locks,
		pollAttempts: defaultPollAttempts,
		pollDelay:    defaultPollDelay,
	}
}

func (r *templateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_template"
}

func (r *templateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Creates, reads, and deletes a user WAF template. Application membership is intentionally owned by waf_template_attachment; this resource creates templates with endpoints=[].",
		Attributes: map[string]schema.Attribute{
			"template_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Stable template ID and import identity.",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Template name. The public API has no rename operation, so changes replace the template.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"predefined": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether this is a backend predefined template.",
			},
			"features": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Observed module feature identifiers.",
			},
		},
	}
}

func (r *templateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *templateResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.Name.IsNull() && !config.Name.IsUnknown() && strings.TrimSpace(config.Name.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "Invalid template name", "name must not be empty or whitespace.")
	}
}

func (r *templateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := strings.TrimSpace(plan.Name.ValueString())
	if plan.Name.IsNull() || plan.Name.IsUnknown() || name == "" {
		resp.Diagnostics.AddError("Invalid template name", "name must be known and non-empty during create.")
		return
	}

	created, err := r.service.CreateTemplate(ctx, client.TemplateCreateRequest{
		Name:      name,
		Endpoints: []string{},
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create WAF template", err.Error())
		return
	}
	templateID := strings.TrimSpace(created.Result.TemplateID)
	if templateID == "" {
		resp.Diagnostics.AddError("Unable to create WAF template", "The successful create response did not include result.template_id.")
		return
	}
	r.setState(ctx, created.Result, &resp.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()
	normalized, ok := r.waitForTemplate(ctx, templateID, true, &resp.Diagnostics)
	if !ok {
		return
	}
	if normalized.Name != name {
		resp.Diagnostics.AddError("WAF template create did not converge", fmt.Sprintf("Template %q was created as %q instead of requested name %q.", templateID, normalized.Name, name))
		return
	}
	r.setState(ctx, normalized, &resp.State, &resp.Diagnostics)
}

func (r *templateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID, ok := knownTemplateID(state.TemplateID, &resp.Diagnostics, "read")
	if !ok {
		return
	}
	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()
	current, err := r.service.GetTemplate(ctx, templateID)
	if err != nil {
		if client.IsStatus(err, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound) {
			exists, checkErr := r.service.TemplateExists(ctx, templateID)
			if checkErr != nil {
				resp.Diagnostics.AddError("Unable to resolve WAF template", fmt.Sprintf("Template detail failed: %v; inventory check failed: %v.", err, checkErr))
				return
			}
			if !exists {
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.AddError("Unable to read WAF template", err.Error())
		return
	}
	r.setState(ctx, current, &resp.State, &resp.Diagnostics)
}

func (r *templateResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// name requires replacement and all other fields are computed.
}

func (r *templateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID, ok := knownTemplateID(state.TemplateID, &resp.Diagnostics, "delete")
	if !ok {
		return
	}
	if !state.Predefined.IsNull() && !state.Predefined.IsUnknown() && state.Predefined.ValueBool() {
		resp.Diagnostics.AddError(
			"Unable to delete predefined WAF template",
			"FortiAppSec Cloud predefined templates are not owned by this resource. Remove the imported resource from Terraform state instead of destroying the remote template.",
		)
		return
	}
	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()
	if err := r.service.DeleteTemplate(ctx, templateID); err != nil {
		if !client.IsStatus(err, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound) {
			resp.Diagnostics.AddError("Unable to delete WAF template", err.Error())
			return
		}
		exists, checkErr := r.service.TemplateExists(ctx, templateID)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to resolve WAF template deletion", fmt.Sprintf("Delete failed: %v; inventory check failed: %v.", err, checkErr))
			return
		}
		if exists {
			resp.Diagnostics.AddError("Unable to delete WAF template", err.Error())
			return
		}
		return
	}
	_, _ = r.waitForTemplate(ctx, templateID, false, &resp.Diagnostics)
}

func (r *templateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid WAF template import ID", "Import requires a non-empty template_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("template_id"), id)...)
}

func (r *templateResource) waitForTemplate(ctx context.Context, templateID string, wantPresent bool, diagnostics *diag.Diagnostics) (client.Template, bool) {
	attempts := r.pollAttempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		current, err := r.service.GetTemplate(ctx, templateID)
		if err == nil {
			if wantPresent {
				return current, true
			}
		} else if client.IsStatus(err, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound) {
			exists, checkErr := r.service.TemplateExists(ctx, templateID)
			if checkErr != nil {
				diagnostics.AddError("Unable to verify WAF template lifecycle", fmt.Sprintf("Template detail failed: %v; inventory check failed: %v.", err, checkErr))
				return client.Template{}, false
			}
			if !exists && !wantPresent {
				return client.Template{}, true
			}
		} else {
			diagnostics.AddError("Unable to verify WAF template lifecycle", err.Error())
			return client.Template{}, false
		}
		if attempt < attempts {
			timer := time.NewTimer(r.pollDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				diagnostics.AddError("Unable to verify WAF template lifecycle", ctx.Err().Error())
				return client.Template{}, false
			case <-timer.C:
			}
		}
	}
	state := "appear"
	if !wantPresent {
		state = "disappear"
	}
	diagnostics.AddError("WAF template lifecycle did not converge", fmt.Sprintf("Template %q did not %s after %d checks.", templateID, state, attempts))
	return client.Template{}, false
}

func (r *templateResource) setState(ctx context.Context, current client.Template, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	current.TemplateID = strings.TrimSpace(current.TemplateID)
	current.Name = strings.TrimSpace(current.Name)
	if current.TemplateID == "" {
		diagnostics.AddError("Malformed WAF template result", "The successful template response did not include template_id.")
		return
	}
	if current.Name == "" {
		diagnostics.AddError("Malformed WAF template result", "The successful template response did not include name.")
		return
	}
	if current.Features == nil {
		current.Features = []string{}
	}
	features, featureDiagnostics := types.ListValueFrom(ctx, types.StringType, current.Features)
	diagnostics.Append(featureDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	model := resourceModel{
		TemplateID: types.StringValue(current.TemplateID),
		Name:       types.StringValue(current.Name),
		Predefined: types.BoolValue(current.Predefined),
		Features:   features,
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func knownTemplateID(value types.String, diagnostics *diag.Diagnostics, operation string) (string, bool) {
	if value.IsNull() || value.IsUnknown() || strings.TrimSpace(value.ValueString()) == "" {
		diagnostics.AddError("Invalid WAF template ID", "template_id must be known and non-empty during "+operation+".")
		return "", false
	}
	return strings.TrimSpace(value.ValueString()), true
}

func (r *templateResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the WAF template resource operation.")
	return false
}
