package mlapiprotection

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/contract"
	"terraform-provider-fortiappseccloud/internal/locking"
	"terraform-provider-fortiappseccloud/internal/resources/wafmodule"
)

var (
	_ resource.Resource                   = (*mlApiProtectionResource)(nil)
	_ resource.ResourceWithConfigure      = (*mlApiProtectionResource)(nil)
	_ resource.ResourceWithImportState    = (*mlApiProtectionResource)(nil)
	_ resource.ResourceWithValidateConfig = (*mlApiProtectionResource)(nil)
)

type mlApiProtectionService interface {
	GetMlApiProtection(context.Context, string) (client.MlApiProtectionDocument, error)
	PutMlApiProtection(context.Context, string, client.WAFModuleResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

type mlApiProtectionResource struct {
	service mlApiProtectionService
	locks   *locking.Registry
	destroy contract.CustomResourceContract
}

func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	destroy, _ := contract.ReviewedCustomResourceContract("ml_api_protection")
	return &mlApiProtectionResource{locks: locks, destroy: destroy}
}

func (r *mlApiProtectionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_ml_api_protection"
}

func (r *mlApiProtectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the app-level FortiAppSec Cloud ML API protection module. The public path is ml_api_protection. Destroy forgets the resource with a warning. threat_action=disable is an action value, not module disable.",
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Application endpoint ID.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"template": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Whether the module inherits effective configuration from the template.",
			},
		},
		Blocks: map[string]schema.Block{
			"configs": schema.SingleNestedBlock{
				MarkdownDescription: "Locally managed ML API protection configuration. Required when template is false.",
				Attributes: map[string]schema.Attribute{
					"status": schema.BoolAttribute{
						Optional:            true,
						MarkdownDescription: "Enable or disable ML API protection.",
					},
					"threat_action": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Action when a threat is detected. 'disable' is an action value, not module disable.",
						Validators:          []validator.String{stringvalidator.OneOf("alert", "alert_deny", "disable")},
					},
					"ip_list_type": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Trust or Block IP list type.",
						Validators:          []validator.String{stringvalidator.OneOf("Trust", "Block")},
					},
				},
				Blocks: map[string]schema.Block{
					"ip_list": schema.SingleNestedBlock{
						MarkdownDescription: "Optional ip_list ownership wrapper. Max 30. Wire-only idx regenerated one-based.",
						Blocks: map[string]schema.Block{
							"item": schema.ListNestedBlock{
								MarkdownDescription: "Ordered IP entries.",
								Validators:          []validator.List{listvalidator.SizeAtMost(client.MlApiProtectionIPListMaxEntries)},
								NestedObject: schema.NestedBlockObject{
									Attributes: map[string]schema.Attribute{
										"ip": schema.StringAttribute{Required: true, MarkdownDescription: "IPv4/IPv6 address or range."},
									},
								},
								PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
							},
						},
					},
					"path_list": schema.SingleNestedBlock{
						MarkdownDescription: "Optional path_list ownership wrapper. Max 30. Wire-only idx regenerated one-based.",
						Blocks: map[string]schema.Block{
							"item": schema.ListNestedBlock{
								MarkdownDescription: "Ordered API path entries.",
								Validators:          []validator.List{listvalidator.SizeAtMost(client.MlApiProtectionPathListMaxEntries)},
								NestedObject: schema.NestedBlockObject{
									Attributes: map[string]schema.Attribute{
										"type": schema.StringAttribute{
											Required:            true,
											MarkdownDescription: "API path pattern type.",
											Validators:          []validator.String{stringvalidator.OneOf("plain", "regular")},
										},
										"pattern": schema.StringAttribute{
											Required:            true,
											MarkdownDescription: "API path pattern (must start with /).",
											Validators: []validator.String{
												stringvalidator.RegexMatches(regexp.MustCompile(`^/`), "must start with /"),
											},
										},
									},
								},
								PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
							},
						},
					},
				},
			},
		},
	}
}

func (r *mlApiProtectionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *mlApiProtectionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty.")
	}
	if err := validateTemplateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid ml api protection configuration", err.Error())
		return
	}
	if !config.Template.IsNull() && !config.Template.IsUnknown() && !config.Template.ValueBool() {
		if err := validateRequiredConfigs(ctx, config.Configs); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid ml api protection configuration", err.Error())
		}
	}
}

func (r *mlApiProtectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

func (r *mlApiProtectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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
	document, err := r.service.GetMlApiProtection(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read ml api protection", checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read ml api protection", err.Error())
		return
	}
	source := ownershipPriorState
	if state.Template.IsNull() || state.Template.IsUnknown() {
		source = ownershipImported
	}
	r.setState(ctx, epID, document, source, state.Configs, &resp.State, &resp.Diagnostics)
}

func (r *mlApiProtectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

func (r *mlApiProtectionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.destroy.DestroyPolicy == contract.CustomDestroyDisable {
		epID := strings.TrimSpace(state.EPID.ValueString())
		unlock := r.locks.Lock(resourceKey(epID))
		defer unlock()
		wafmodule.DisableOnDestroy(ctx, wafmodule.DisableRequest{
			ModuleName: "ML API protection",
			EPID:       epID,
			Field:      r.destroy.DestroyField,
			Verified:   r.destroy.DestroyVerified,
		}, wafmodule.DisableAccess{
			Get: func(ctx context.Context) (client.WAFModuleDocument, error) {
				document, err := r.service.GetMlApiProtection(ctx, epID)
				return client.WAFModuleDocument{Result: document.Result}, err
			},
			Put: func(ctx context.Context, result client.WAFModuleResult) error {
				return r.service.PutMlApiProtection(ctx, epID, result)
			},
			ApplicationExists: func(ctx context.Context) (bool, error) {
				return r.service.ApplicationExists(ctx, epID)
			},
		}, &resp.Diagnostics)
		return
	}
	resp.Diagnostics.AddWarning(
		"ML API protection forgotten, not destroyed",
		"Terraform removed the resource from state without changing the remote configuration. "+strings.TrimSpace(r.destroy.DestroyReason),
	)
}

func (r *mlApiProtectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *mlApiProtectionResource) apply(ctx context.Context, config, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	if err := validateTemplateConfigs(plan); err != nil {
		diagnostics.AddError("Invalid ml api protection configuration", err.Error())
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
	if !plan.Template.ValueBool() && (plan.Configs.IsNull() || plan.Configs.IsUnknown()) {
		diagnostics.AddError("Invalid ml api protection configuration", "configs must be configured when template is false.")
		return
	}
	epID := strings.TrimSpace(plan.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()
	for attempt := 1; attempt <= 3; attempt++ {
		current, err := r.service.GetMlApiProtection(ctx, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read ml api protection before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
				return
			}
			diagnostics.AddError("Unable to read ml api protection before update", err.Error())
			return
		}
		updated, mergeDiag := mergeMlApiProtection(ctx, current, plan.Template.ValueBool(), config.Configs, plan.Configs)
		diagnostics.Append(mergeDiag...)
		if diagnostics.HasError() {
			return
		}
		if err := r.service.PutMlApiProtection(ctx, epID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < 3 {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update ml api protection", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed during the update.", epID))
				return
			}
			diagnostics.AddError("Unable to update ml api protection", err.Error())
			return
		}
		normalized, err := r.service.GetMlApiProtection(ctx, epID)
		if err != nil {
			diagnostics.AddError("Unable to read normalized ml api protection", err.Error())
			return
		}
		r.setState(ctx, epID, normalized, ownershipConfigured, plan.Configs, state, diagnostics)
		return
	}
}

func (r *mlApiProtectionResource) setState(ctx context.Context, epID string, document client.MlApiProtectionDocument, source ownershipSource, priorConfigs types.Object, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	model, modelDiagnostics := stateModel(epID, document, source, priorConfigs)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func (r *mlApiProtectionResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("module request failed: %v; parent application check failed: %w", moduleErr, err)
	}
	return !exists, nil
}

func (r *mlApiProtectionResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the resource operation.")
	return false
}

func resourceKey(epID string) string {
	return "waf/apps/" + epID + "/ml_api_protection"
}
