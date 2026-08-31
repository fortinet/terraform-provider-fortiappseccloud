package accounttakeover

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                   = (*accountTakeoverResource)(nil)
	_ resource.ResourceWithConfigure      = (*accountTakeoverResource)(nil)
	_ resource.ResourceWithImportState    = (*accountTakeoverResource)(nil)
	_ resource.ResourceWithValidateConfig = (*accountTakeoverResource)(nil)
)

type accountTakeoverService interface {
	GetAccountTakeover(context.Context, string) (client.AccountTakeoverDocument, error)
	PutAccountTakeover(context.Context, string, client.WAFModuleResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

type accountTakeoverResource struct {
	service accountTakeoverService
	locks   *locking.Registry
}

// NewResource creates the app-scoped account-takeover Framework resource.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &accountTakeoverResource{locks: locks}
}

func (r *accountTakeoverResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_account_takeover"
}

func (r *accountTakeoverResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	stringStateModifier := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	boolStateModifier := []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the app-level FortiAppSec Cloud account takeover module. Destroy disables the module because the API has no DELETE operation.",
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Application endpoint ID. The resource is imported using this value.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"template": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Whether the module inherits effective configuration from the application's attached template.",
			},
		},
		Blocks: map[string]schema.Block{
			"configs": schema.SingleNestedBlock{
				MarkdownDescription: "Locally managed account takeover configuration. Required when template is false and omitted when template is true.",
				Attributes: map[string]schema.Attribute{
					"action": schema.StringAttribute{
						Optional: true, Computed: true,
						Validators:    []validator.String{stringvalidator.OneOf("alert", "alert_deny", "deny_no_log")},
						PlanModifiers: stringStateModifier,
					},
					"auth_url":              schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: stringStateModifier},
					"cred_stuffing_protect": schema.BoolAttribute{Optional: true, Computed: true, PlanModifiers: boolStateModifier},
					"logoff_url":            schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: stringStateModifier},
					"password": schema.StringAttribute{
						Optional: true, Computed: true, Sensitive: true,
						Validators:    []validator.String{stringvalidator.UTF8LengthAtMost(63)},
						PlanModifiers: stringStateModifier,
					},
					"redirect_url":          schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: stringStateModifier},
					"response_body":         schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: stringStateModifier},
					"return_code":           schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: stringStateModifier},
					"sess_fixation_protect": schema.BoolAttribute{Optional: true, Computed: true, PlanModifiers: boolStateModifier},
					"sess_id_name": schema.StringAttribute{
						Optional: true, Computed: true,
						Validators:    []validator.String{stringvalidator.UTF8LengthAtMost(63)},
						PlanModifiers: stringStateModifier,
					},
					"status": schema.BoolAttribute{Optional: true, Computed: true, PlanModifiers: boolStateModifier},
					"username": schema.StringAttribute{
						Optional: true, Computed: true,
						Validators:    []validator.String{stringvalidator.UTF8LengthAtMost(63)},
						PlanModifiers: stringStateModifier,
					},
				},
			},
		},
	}
}

func (r *accountTakeoverResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	apiClient, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T.", req.ProviderData))
		return
	}
	r.service = apiClient
}

func (r *accountTakeoverResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty or whitespace.")
	}
	if err := validateTemplateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid account takeover configuration", err.Error())
	}
}

func (r *accountTakeoverResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

func (r *accountTakeoverResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID := strings.TrimSpace(state.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	document, err := r.service.GetAccountTakeover(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read account takeover", checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read account takeover", err.Error())
		return
	}
	r.setState(ctx, epID, document, &resp.State, &resp.Diagnostics)
}

func (r *accountTakeoverResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

func (r *accountTakeoverResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID := strings.TrimSpace(state.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	current, err := r.service.GetAccountTakeover(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to disable account takeover", checkErr.Error())
			return
		}
		if absent {
			return
		}
		resp.Diagnostics.AddError("Unable to disable account takeover", err.Error())
		return
	}

	updated := current.Clone()
	updated.Result.Template = false
	if err := updated.Merge(client.AccountTakeoverPatch{Status: client.Optional[bool]{Set: true, Value: false}}); err != nil {
		resp.Diagnostics.AddError("Unable to prepare account takeover disable request", err.Error())
		return
	}
	if err := r.service.PutAccountTakeover(ctx, epID, updated.Result); err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to disable account takeover", checkErr.Error())
			return
		}
		if absent {
			return
		}
		resp.Diagnostics.AddError("Unable to disable account takeover", err.Error())
		return
	}

	verified, err := r.service.GetAccountTakeover(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to verify account takeover disable", checkErr.Error())
			return
		}
		if absent {
			return
		}
		resp.Diagnostics.AddError("Unable to verify account takeover disable", err.Error())
		return
	}
	if verified.Result.Template || verified.Config.Status == nil || *verified.Config.Status {
		resp.Diagnostics.AddError("Account takeover disable was not applied", "The API did not report template=false and status=false after the disable request.")
	}
}

func (r *accountTakeoverResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *accountTakeoverResource) apply(ctx context.Context, config, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	if err := validateTemplateConfigs(plan); err != nil {
		diagnostics.AddError("Invalid account takeover configuration", err.Error())
		return
	}
	if plan.EPID.IsNull() || plan.EPID.IsUnknown() || strings.TrimSpace(plan.EPID.ValueString()) == "" {
		diagnostics.AddError("Invalid application ID", "ep_id must be known and non-empty during apply.")
		return
	}
	if plan.Template.IsNull() || plan.Template.IsUnknown() {
		diagnostics.AddError("Unknown template setting", "template must be known during apply.")
		return
	}
	patch, patchDiagnostics := accountTakeoverPatch(ctx, config, plan)
	diagnostics.Append(patchDiagnostics...)
	if diagnostics.HasError() {
		return
	}

	epID := strings.TrimSpace(plan.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	for attempt := 1; attempt <= 3; attempt++ {
		current, err := r.service.GetAccountTakeover(ctx, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read account takeover before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
				return
			}
			diagnostics.AddError("Unable to read account takeover before update", err.Error())
			return
		}

		updated := current.Clone()
		updated.Result.Template = plan.Template.ValueBool()
		if !updated.Result.Template {
			if err := updated.Merge(patch); err != nil {
				diagnostics.AddError("Unable to merge account takeover configuration", err.Error())
				return
			}
		}
		if err := r.service.PutAccountTakeover(ctx, epID, updated.Result); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < 3 {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update account takeover", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed during the update.", epID))
				return
			}
			diagnostics.AddError("Unable to update account takeover", err.Error())
			return
		}

		normalized, err := r.service.GetAccountTakeover(ctx, epID)
		if err != nil {
			diagnostics.AddError("Unable to read normalized account takeover configuration", err.Error())
			return
		}
		r.setState(ctx, epID, normalized, state, diagnostics)
		return
	}
}

func (r *accountTakeoverResource) setState(ctx context.Context, epID string, document client.AccountTakeoverDocument, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	model, modelDiagnostics := stateModel(epID, document)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func (r *accountTakeoverResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("module request failed: %v; parent application check failed: %w", moduleErr, err)
	}
	return !exists, nil
}

func (r *accountTakeoverResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the resource operation.")
	return false
}

func resourceKey(epID string) string {
	return "waf/apps/" + epID + "/account_takeover"
}
