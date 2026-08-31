package anomalydetection

import (
	"context"
	"fmt"
	"net/http"
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
	_ resource.Resource                   = (*anomalyDetectionResource)(nil)
	_ resource.ResourceWithConfigure      = (*anomalyDetectionResource)(nil)
	_ resource.ResourceWithImportState    = (*anomalyDetectionResource)(nil)
	_ resource.ResourceWithValidateConfig = (*anomalyDetectionResource)(nil)
)

type anomalyDetectionService interface {
	GetAnomalyDetection(context.Context, string) (client.AnomalyDetectionDocument, error)
	PutAnomalyDetection(context.Context, string, client.WAFModuleResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

type anomalyDetectionResource struct {
	service anomalyDetectionService
	locks   *locking.Registry
	destroy contract.CustomResourceContract
}

// NewResource creates the app-scoped anomaly-detection Framework resource.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	destroy, _ := contract.ReviewedCustomResourceContract("anomaly_detection")
	return &anomalyDetectionResource{locks: locks, destroy: destroy}
}

func (r *anomalyDetectionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_anomaly_detection"
}

func (r *anomalyDetectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the app-level FortiAppSec Cloud anomaly-detection (machine-learning) module. The API has no DELETE operation; destroy forgets the resource with a warning rather than disabling it.",
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
				MarkdownDescription: "Locally managed anomaly-detection configuration. Required when template is false and omitted when template is true.",
				Attributes: map[string]schema.Attribute{
					"status": schema.BoolAttribute{
						Optional:            true,
						MarkdownDescription: "Enable or disable anomaly detection.",
					},
					"action": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Action taken when an anomaly is detected.",
						Validators:          []validator.String{stringvalidator.OneOf("alert", "alert_deny")},
					},
					"ip_list_type": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Whether to restrict learning (Trust) or not learn (Block) from the listed IPs.",
						Validators:          []validator.String{stringvalidator.OneOf("Trust", "Block")},
					},
				},
				Blocks: map[string]schema.Block{
					"ip_list": schema.SingleNestedBlock{
						MarkdownDescription: "Optional ip_list ownership wrapper. Omit it to preserve the raw remote array; use an empty wrapper to replace the array with []; populate the item block to replace the array in Terraform order. Wire-only idx is regenerated one-based in Terraform order and is not exposed in state.",
						Blocks: map[string]schema.Block{
							"item": schema.ListNestedBlock{
								MarkdownDescription: "Ordered IP entries in Terraform order.",
								Validators: []validator.List{
									listvalidator.SizeAtMost(client.AnomalyDetectionIPListMaxEntries),
								},
								NestedObject: schema.NestedBlockObject{
									Attributes: map[string]schema.Attribute{
										"ip": schema.StringAttribute{
											Required:            true,
											MarkdownDescription: "IPv4/IPv6 address or range (range uses '-' separator).",
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

func (r *anomalyDetectionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *anomalyDetectionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty or whitespace.")
	}
	if err := validateTemplateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid anomaly detection configuration", err.Error())
		return
	}
	if !config.Template.IsNull() && !config.Template.IsUnknown() && !config.Template.ValueBool() {
		if err := validateRequiredConfigs(ctx, config.Configs); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid anomaly detection configuration", err.Error())
		}
	}
}

func (r *anomalyDetectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *anomalyDetectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

	document, err := r.service.GetAnomalyDetection(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read anomaly detection", checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read anomaly detection", err.Error())
		return
	}
	// The first Read after import has only ep_id set (template is null/unknown,
	// since template is required and always set on a normal state). Hydrate the
	// ip_list wrapper from the remote array. A normal Read preserves ownership
	// per the prior state — including a template=true state, whose configs are
	// intentionally null and must NOT be treated as import (which would strictly
	// hydrate an unowned ip_list).
	source := ownershipPriorState
	if state.Template.IsNull() || state.Template.IsUnknown() {
		source = ownershipImported
	}
	r.setState(ctx, epID, document, source, state.Configs, &resp.State, &resp.Diagnostics)
}

func (r *anomalyDetectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *anomalyDetectionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
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
			ModuleName: "anomaly detection",
			EPID:       epID,
			Field:      r.destroy.DestroyField,
			Verified:   r.destroy.DestroyVerified,
		}, wafmodule.DisableAccess{
			Get: func(ctx context.Context) (client.WAFModuleDocument, error) {
				document, err := r.service.GetAnomalyDetection(ctx, epID)
				return client.WAFModuleDocument{Result: document.Result}, err
			},
			Put: func(ctx context.Context, result client.WAFModuleResult) error {
				return r.service.PutAnomalyDetection(ctx, epID, result)
			},
			ApplicationExists: func(ctx context.Context) (bool, error) {
				return r.service.ApplicationExists(ctx, epID)
			},
		}, &resp.Diagnostics)
		return
	}
	resp.Diagnostics.AddWarning(
		"Anomaly detection forgotten, not destroyed",
		"Terraform removed the resource from state without changing the remote configuration. "+strings.TrimSpace(r.destroy.DestroyReason),
	)
}

func (r *anomalyDetectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *anomalyDetectionResource) apply(ctx context.Context, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	if err := validateTemplateConfigs(plan); err != nil {
		diagnostics.AddError("Invalid anomaly detection configuration", err.Error())
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
		diagnostics.AddError("Invalid anomaly detection configuration", "configs must be configured when template is false.")
		return
	}

	epID := strings.TrimSpace(plan.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	for attempt := 1; attempt <= 3; attempt++ {
		current, err := r.service.GetAnomalyDetection(ctx, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read anomaly detection before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
				return
			}
			diagnostics.AddError("Unable to read anomaly detection before update", err.Error())
			return
		}

		updated, mergeDiag := mergeAnomalyDetection(ctx, current, plan.Template.ValueBool(), plan.Configs)
		diagnostics.Append(mergeDiag...)
		if diagnostics.HasError() {
			return
		}
		if err := r.service.PutAnomalyDetection(ctx, epID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < 3 {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update anomaly detection", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed during the update.", epID))
				return
			}
			diagnostics.AddError("Unable to update anomaly detection", err.Error())
			return
		}

		normalized, err := r.service.GetAnomalyDetection(ctx, epID)
		if err != nil {
			diagnostics.AddError("Unable to read normalized anomaly detection", err.Error())
			return
		}
		r.setState(ctx, epID, normalized, ownershipConfigured, plan.Configs, state, diagnostics)
		return
	}
}

func (r *anomalyDetectionResource) setState(ctx context.Context, epID string, document client.AnomalyDetectionDocument, source ownershipSource, priorConfigs types.Object, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	model, modelDiagnostics := stateModel(epID, document, source, priorConfigs)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func (r *anomalyDetectionResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("module request failed: %v; parent application check failed: %w", moduleErr, err)
	}
	return !exists, nil
}

func (r *anomalyDetectionResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the resource operation.")
	return false
}

func resourceKey(epID string) string {
	return "waf/apps/" + epID + "/anomaly_detection"
}
