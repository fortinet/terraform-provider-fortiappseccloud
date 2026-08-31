package corsprotection

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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
	_ resource.Resource                   = (*corsProtectionResource)(nil)
	_ resource.ResourceWithConfigure      = (*corsProtectionResource)(nil)
	_ resource.ResourceWithImportState    = (*corsProtectionResource)(nil)
	_ resource.ResourceWithValidateConfig = (*corsProtectionResource)(nil)
)

type corsProtectionService interface {
	GetCorsProtection(context.Context, string) (client.CorsProtectionDocument, error)
	PutCorsProtection(context.Context, string, client.WAFModuleResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

type corsProtectionResource struct {
	service corsProtectionService
	locks   *locking.Registry
	destroy contract.CustomResourceContract
}

// NewResource creates the app-scoped cors-protection Framework resource.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	destroy, _ := contract.ReviewedCustomResourceContract("cors_protection")
	return &corsProtectionResource{locks: locks, destroy: destroy}
}

func (r *corsProtectionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_cors_protection"
}

func (r *corsProtectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the app-level FortiAppSec Cloud CORS-protection module. The API has no DELETE operation; destroy forgets the resource with a warning rather than disabling it.",
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
				MarkdownDescription: "Locally managed CORS-protection configuration. Required when template is false and omitted when template is true.",
				Attributes: map[string]schema.Attribute{
					"status": schema.BoolAttribute{
						Optional:            true,
						MarkdownDescription: "Enable or disable CORS protection.",
					},
					"block_cors_traffic": schema.BoolAttribute{
						Optional:            true,
						MarkdownDescription: "Block all CORS traffic to the protected request URL.",
					},
					"url_pattern": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						MarkdownDescription: "Request URL to protect. Omission preserves the remote value.",
						PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
					"allowed_credentials": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						MarkdownDescription: "Whether CORS requests from foreign applications can include user credentials.",
						Validators:          []validator.String{stringvalidator.OneOf("None", "TRUE", "FALSE")},
						PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
					"allowed_maximum_age": schema.Int64Attribute{
						Optional:            true,
						Computed:            true,
						MarkdownDescription: "Maximum time (seconds) before a preflight request result expires.",
						Validators:          []validator.Int64{int64validator.Between(client.CorsAllowedMaximumAgeMin, client.CorsAllowedMaximumAgeMax)},
						PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
					},
				},
				Blocks: map[string]schema.Block{
					"allowed_origins": schema.SingleNestedBlock{
						MarkdownDescription: "Allowed origins. A single object despite the plural name (per the pinned schema). Required when template is false.",
						Attributes: map[string]schema.Attribute{
							"protocol": schema.StringAttribute{
								Optional:            true,
								MarkdownDescription: "Allowed protocol.",
								Validators:          []validator.String{stringvalidator.OneOf("ANY", "HTTP", "HTTPS")},
							},
							"origin_name": schema.StringAttribute{
								Optional:            true,
								MarkdownDescription: "Foreign application's domain name.",
							},
							"port": schema.Int64Attribute{
								Optional:            true,
								Computed:            true,
								MarkdownDescription: "TCP port for CORS connections.",
								Validators:          []validator.Int64{int64validator.Between(client.CorsPortMin, client.CorsPortMax)},
								PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
							},
							"include_sub_domains": schema.BoolAttribute{
								Optional:            true,
								Computed:            true,
								MarkdownDescription: "Match the Origin Name with sub-level domains.",
								PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
							},
						},
					},
					"allowed_methods": schema.SingleNestedBlock{
						MarkdownDescription: "Allowed methods policy. Required when template is false.",
						Attributes: map[string]schema.Attribute{
							"status": schema.BoolAttribute{
								Optional:            true,
								MarkdownDescription: "Enable or disable the allowed-methods policy.",
							},
							"methods": schema.ListAttribute{
								Optional:            true,
								Computed:            true,
								ElementType:         types.StringType,
								MarkdownDescription: "Allowed methods.",
								Validators: []validator.List{
									listvalidator.ValueStringsAre(stringvalidator.OneOf("GET", "POST", "HEAD", "TRACE", "CONNECT", "DELETE", "PUT", "PATCH")),
								},
								PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
							},
						},
					},
					"allowed_headers": schema.SingleNestedBlock{
						MarkdownDescription: "Allowed headers policy. Required when template is false.",
						Attributes: map[string]schema.Attribute{
							"status": schema.BoolAttribute{
								Optional:            true,
								MarkdownDescription: "Enable or disable the allowed-headers policy.",
							},
							"headers": schema.ListAttribute{
								Optional:            true,
								Computed:            true,
								ElementType:         types.StringType,
								MarkdownDescription: "Allowed header contents.",
								PlanModifiers:       []planmodifier.List{listplanmodifier.UseStateForUnknown()},
							},
						},
					},
					"exposed_headers": schema.SingleNestedBlock{
						MarkdownDescription: "Exposed headers policy. Required when template is false.",
						Attributes: map[string]schema.Attribute{
							"status": schema.BoolAttribute{
								Optional:            true,
								MarkdownDescription: "Enable or disable the exposed-headers policy.",
							},
							"headers": schema.ListAttribute{
								Optional:            true,
								Computed:            true,
								ElementType:         types.StringType,
								MarkdownDescription: "Exposed header contents.",
								PlanModifiers:       []planmodifier.List{listplanmodifier.UseStateForUnknown()},
							},
						},
					},
				},
			},
		},
	}
}

func (r *corsProtectionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *corsProtectionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty or whitespace.")
	}
	if err := validateTemplateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid cors protection configuration", err.Error())
		return
	}
	if !config.Template.IsNull() && !config.Template.IsUnknown() && !config.Template.ValueBool() && !config.Configs.IsNull() && !config.Configs.IsUnknown() {
		if err := validateRequiredConfigs(ctx, config.Configs); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid cors protection configuration", err.Error())
		}
	}
}

func (r *corsProtectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

func (r *corsProtectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

	document, err := r.service.GetCorsProtection(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read cors protection", checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read cors protection", err.Error())
		return
	}
	r.setState(ctx, epID, document, &resp.State, &resp.Diagnostics)
}

func (r *corsProtectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

// Delete forgets the resource with a warning. The cors-protection API has no
// DELETE operation, and no reviewed status=false destroy has been live-verified,
// so destroy removes Terraform state without mutating the remote object. Do not
// infer a disable semantic from the status field.
func (r *corsProtectionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
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
			ModuleName: "CORS protection",
			EPID:       epID,
			Field:      r.destroy.DestroyField,
			Verified:   r.destroy.DestroyVerified,
		}, wafmodule.DisableAccess{
			Get: func(ctx context.Context) (client.WAFModuleDocument, error) {
				document, err := r.service.GetCorsProtection(ctx, epID)
				return client.WAFModuleDocument{Result: document.Result}, err
			},
			Put: func(ctx context.Context, result client.WAFModuleResult) error {
				return r.service.PutCorsProtection(ctx, epID, result)
			},
			ApplicationExists: func(ctx context.Context) (bool, error) {
				return r.service.ApplicationExists(ctx, epID)
			},
		}, &resp.Diagnostics)
		return
	}
	resp.Diagnostics.AddWarning(
		"CORS protection forgotten, not destroyed",
		"Terraform removed the resource from state without changing the remote configuration. "+strings.TrimSpace(r.destroy.DestroyReason),
	)
}

func (r *corsProtectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *corsProtectionResource) apply(ctx context.Context, config, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	if err := validateTemplateConfigs(plan); err != nil {
		diagnostics.AddError("Invalid cors protection configuration", err.Error())
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
		diagnostics.AddError("Invalid cors protection configuration", "configs must be configured when template is false.")
		return
	}

	epID := strings.TrimSpace(plan.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	for attempt := 1; attempt <= 3; attempt++ {
		current, err := r.service.GetCorsProtection(ctx, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read cors protection before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
				return
			}
			diagnostics.AddError("Unable to read cors protection before update", err.Error())
			return
		}

		// Pass both config (for presence/ownership of optional fields) and plan
		// (for resolved values) into the merge. An optional field is overlaid only
		// when the user declared it in config; an omitted optional preserves the
		// fresh-GET value rather than overwriting it with prior-state.
		updated, mergeDiag := mergeCorsProtection(ctx, current, plan.Template.ValueBool(), config.Configs, plan.Configs)
		diagnostics.Append(mergeDiag...)
		if diagnostics.HasError() {
			return
		}
		if err := r.service.PutCorsProtection(ctx, epID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < 3 {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update cors protection", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed during the update.", epID))
				return
			}
			diagnostics.AddError("Unable to update cors protection", err.Error())
			return
		}

		normalized, err := r.service.GetCorsProtection(ctx, epID)
		if err != nil {
			diagnostics.AddError("Unable to read normalized cors protection", err.Error())
			return
		}
		r.setState(ctx, epID, normalized, state, diagnostics)
		return
	}
}

func (r *corsProtectionResource) setState(ctx context.Context, epID string, document client.CorsProtectionDocument, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	model, modelDiagnostics := stateModel(epID, document)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func (r *corsProtectionResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("module request failed: %v; parent application check failed: %w", moduleErr, err)
	}
	return !exists, nil
}

func (r *corsProtectionResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the resource operation.")
	return false
}

func resourceKey(epID string) string {
	return "waf/apps/" + epID + "/cors_protection"
}
