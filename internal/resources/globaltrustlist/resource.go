package globaltrustlist

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                   = (*globalTrustListResource)(nil)
	_ resource.ResourceWithConfigure      = (*globalTrustListResource)(nil)
	_ resource.ResourceWithImportState    = (*globalTrustListResource)(nil)
	_ resource.ResourceWithValidateConfig = (*globalTrustListResource)(nil)
)

type globalTrustListService interface {
	GetGlobalTrustList(context.Context, string) (client.GlobalTrustListDocument, error)
	PutGlobalTrustList(context.Context, string, client.GlobalTrustListResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

type globalTrustListResource struct {
	service globalTrustListService
	locks   *locking.Registry
}

// NewResource creates the app-scoped global trust-list parameter Framework
// resource. Unlike generated modules, this endpoint has a configs envelope but
// no template, so it is hand-written.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &globalTrustListResource{locks: locks}
}

func (r *globalTrustListResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_global_trust_list_parameter"
}

func (r *globalTrustListResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the app-level FortiAppSec Cloud global trust-list parameter. The API has no DELETE operation; destroy forgets the resource with a warning rather than disabling it.",
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Application endpoint ID. The resource is imported using this value.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: map[string]schema.Block{
			"configs": schema.SingleNestedBlock{
				MarkdownDescription: "Locally managed global trust-list parameter configuration. This endpoint has no template field; configs is always required.",
				Attributes: map[string]schema.Attribute{
					"status": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Enable or disable the global trustlist parameter.",
					},
				},
				Blocks: map[string]schema.Block{
					"trust_list": schema.SingleNestedBlock{
						MarkdownDescription: "Optional trust_list ownership wrapper. Omit it to preserve the raw remote array; use an empty wrapper to replace the array with []; populate the item block to replace the array in Terraform order. Wire-only idx is regenerated one-based in Terraform order and is not exposed in state.",
						Blocks: map[string]schema.Block{
							"item": schema.ListNestedBlock{
								MarkdownDescription: "Ordered trust-list entries in Terraform order.",
								Validators: []validator.List{
									listvalidator.SizeAtMost(client.GlobalTrustListMaxEntries),
								},
								NestedObject: schema.NestedBlockObject{
									Attributes: map[string]schema.Attribute{
										"name": schema.StringAttribute{
											Required:            true,
											MarkdownDescription: "Trust-list entry name (reviewed required Terraform-policy field; the backend schema marks it optional with maxLength 63).",
											Validators:          []validator.String{stringvalidator.UTF8LengthAtMost(client.GlobalTrustListNameMaxLen)},
										},
										"status": schema.BoolAttribute{
											Optional:            true,
											Computed:            true,
											MarkdownDescription: "Enable or disable this entry. Omission preserves the remote value on update; on first create it decodes to the remote/default value.",
											PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
										},
										"url": schema.StringAttribute{
											Optional:            true,
											MarkdownDescription: "Trust-list entry URL. Omission preserves the remote value on update.",
											Validators:          []validator.String{stringvalidator.UTF8LengthAtMost(client.GlobalTrustListURLMaxLen)},
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

func (r *globalTrustListResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *globalTrustListResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty or whitespace.")
	}
	if err := validateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid global trust list configuration", err.Error())
	}
}

func (r *globalTrustListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *globalTrustListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

	document, err := r.service.GetGlobalTrustList(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read global trust list parameter", checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read global trust list parameter", err.Error())
		return
	}
	// The first Read after import has only ep_id set (configs null/unknown);
	// hydrate the trust_list wrapper from the remote array. A normal Read
	// preserves ownership per the prior state.
	source := ownershipPriorState
	if state.Configs.IsNull() || state.Configs.IsUnknown() {
		source = ownershipImported
	}
	r.setState(ctx, epID, document, source, state.Configs, &resp.State, &resp.Diagnostics)
}

func (r *globalTrustListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

// Delete forgets the resource with a warning. The global trust-list parameter
// API has no DELETE operation, and no reviewed status=false destroy has been
// live-verified, so destroy removes Terraform state without mutating the remote
// object. Do not infer a disable semantic from the status field.
func (r *globalTrustListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.AddWarning(
		"Global trust list parameter forgotten, not destroyed",
		"The FortiAppSec Cloud global trust-list parameter API has no DELETE operation. Terraform removed the resource from state without changing the remote configuration. Remove the remote trust list manually if required.",
	)
}

func (r *globalTrustListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *globalTrustListResource) apply(ctx context.Context, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	if err := validateConfigs(plan); err != nil {
		diagnostics.AddError("Invalid global trust list configuration", err.Error())
		return
	}
	if plan.EPID.IsNull() || plan.EPID.IsUnknown() || strings.TrimSpace(plan.EPID.ValueString()) == "" {
		diagnostics.AddError("Invalid application ID", "ep_id must be known and non-empty during apply.")
		return
	}
	if plan.Configs.IsNull() || plan.Configs.IsUnknown() {
		diagnostics.AddError("Invalid global trust list configuration", "configs must be configured during apply.")
		return
	}

	epID := strings.TrimSpace(plan.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	for attempt := 1; attempt <= 3; attempt++ {
		current, err := r.service.GetGlobalTrustList(ctx, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read global trust list parameter before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
				return
			}
			diagnostics.AddError("Unable to read global trust list parameter before update", err.Error())
			return
		}

		updated, mergeDiag := mergeGlobalTrustList(ctx, current, plan.Configs)
		diagnostics.Append(mergeDiag...)
		if diagnostics.HasError() {
			return
		}
		if err := r.service.PutGlobalTrustList(ctx, epID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < 3 {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update global trust list parameter", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed during the update.", epID))
				return
			}
			diagnostics.AddError("Unable to update global trust list parameter", err.Error())
			return
		}

		normalized, err := r.service.GetGlobalTrustList(ctx, epID)
		if err != nil {
			diagnostics.AddError("Unable to read normalized global trust list parameter", err.Error())
			return
		}
		r.setState(ctx, epID, normalized, ownershipConfigured, plan.Configs, state, diagnostics)
		return
	}
}

func (r *globalTrustListResource) setState(ctx context.Context, epID string, document client.GlobalTrustListDocument, source ownershipSource, priorConfigs types.Object, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	model, modelDiagnostics := stateModel(epID, document, source, priorConfigs)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func (r *globalTrustListResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("module request failed: %v; parent application check failed: %w", moduleErr, err)
	}
	return !exists, nil
}

func (r *globalTrustListResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the resource operation.")
	return false
}

func resourceKey(epID string) string {
	return "waf/apps/" + epID + "/global_trust_list_parameter"
}
