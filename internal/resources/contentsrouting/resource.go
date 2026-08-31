package contentsrouting

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
	_ resource.Resource                   = (*contentRoutingResource)(nil)
	_ resource.ResourceWithConfigure      = (*contentRoutingResource)(nil)
	_ resource.ResourceWithImportState    = (*contentRoutingResource)(nil)
	_ resource.ResourceWithValidateConfig = (*contentRoutingResource)(nil)
)

type contentRoutingService interface {
	GetContentRouting(context.Context, string) (client.ContentRoutingDocument, error)
	PutContentRouting(context.Context, string, client.ContentRoutingResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

type contentRoutingResource struct {
	service contentRoutingService
	locks   *locking.Registry
}

// NewResource creates the app-scoped content-routing Framework resource.
// The module-status ID is content_routing; the public path is routings.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &contentRoutingResource{locks: locks}
}

func (r *contentRoutingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_content_routing"
}

func (r *contentRoutingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the app-level FortiAppSec Cloud content-routing (routings) module. The public path is /routings while the module-status ID is content_routing. The API has no DELETE operation; destroy forgets the resource with a warning.",
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Application endpoint ID. The resource is imported using this value.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"status": schema.BoolAttribute{
				Required:            true,
				MarkdownDescription: "Enable or disable content routing for the application.",
			},
		},
		Blocks: map[string]schema.Block{
			"policy_list": schema.SingleNestedBlock{
				MarkdownDescription: "Optional policy_list ownership wrapper (maximum 32 policies, at most one default). Omit it to preserve the raw remote array; use an empty wrapper to replace the array with []; populate the item block to replace the array in Terraform order. Wire-only idx is regenerated one-based in Terraform order and is not exposed in state. Unknown nested keys are preserved opaquely by the reviewed ownership policy.",
				Blocks: map[string]schema.Block{
					"item": schema.ListNestedBlock{
						MarkdownDescription: "Ordered content-routing policies in Terraform order.",
						Validators: []validator.List{
							listvalidator.SizeAtMost(client.ContentRoutingMaxPolicies),
						},
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"name": schema.StringAttribute{
									Required:            true,
									MarkdownDescription: "The name of the content routing policy.",
								},
								"server_pool": schema.StringAttribute{
									Optional:            true,
									MarkdownDescription: "The name of the target server pool (references waf_origin_servers).",
								},
								"is_default": schema.BoolAttribute{
									Optional:            true,
									Computed:            true,
									MarkdownDescription: "Whether to apply this policy to unmatched traffic.",
									PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
								},
							},
							Blocks: map[string]schema.Block{
								"rule_list": schema.SingleNestedBlock{
									MarkdownDescription: "Optional rule_list ownership wrapper inside a policy (maximum 32 rules). Each configured rule is validated against its match_object/match_condition variant.",
									Blocks: map[string]schema.Block{
										"item": schema.ListNestedBlock{
											MarkdownDescription: "Ordered routing rules in Terraform order.",
											Validators: []validator.List{
												listvalidator.SizeAtMost(client.ContentRoutingMaxRules),
											},
											NestedObject: schema.NestedBlockObject{
												Attributes: map[string]schema.Attribute{
													"match_object": schema.StringAttribute{
														Optional:            true,
														MarkdownDescription: "The match object.",
														Validators:          []validator.String{stringvalidator.OneOf("http-cookie", "http-header", "http-host", "http-referer", "http-request", "https-sni", "source-ip", "url-parameter", "x509-certificate-Subject", "x509-certificate-Extension")},
													},
													"match_condition": schema.StringAttribute{
														Optional:            true,
														MarkdownDescription: "The match condition.",
														Validators:          []validator.String{stringvalidator.OneOf("match-begin", "match-end", "match-sub", "match-domain", "match-dir", "match-reg", "ip-range", "ip-range6", "equal", "ip-list")},
													},
													"match_expression": schema.StringAttribute{Optional: true, MarkdownDescription: "The regular expression."},
													"name":             schema.StringAttribute{Optional: true, MarkdownDescription: "The object name to match."},
													"value":            schema.StringAttribute{Optional: true, MarkdownDescription: "The object value to match."},
													"concatenate": schema.StringAttribute{
														Optional:            true,
														MarkdownDescription: "Relation to the previous rule.",
														Validators:          []validator.String{stringvalidator.OneOf("and", "or")},
													},
													"reverse":  schema.BoolAttribute{Optional: true, MarkdownDescription: "Reverse match."},
													"start_ip": schema.StringAttribute{Optional: true, MarkdownDescription: "Start IP for ip-range/ip-range6."},
													"end_ip":   schema.StringAttribute{Optional: true, MarkdownDescription: "End IP for ip-range/ip-range6."},
													"ip_list":  schema.StringAttribute{Optional: true, MarkdownDescription: "IP list for ip-list match."},
													"name_match_condition": schema.StringAttribute{
														Optional:   true,
														Validators: []validator.String{stringvalidator.OneOf("match-begin", "match-end", "match-sub", "equal", "match-reg")},
													},
													"value_match_condition": schema.StringAttribute{
														Optional:   true,
														Validators: []validator.String{stringvalidator.OneOf("match-begin", "match-end", "match-sub", "equal", "match-reg")},
													},
													"x509_subject_name": schema.StringAttribute{Optional: true, MarkdownDescription: "X509 subject name."},
												},
											},
											PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
										},
									},
								},
							},
						},
						PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
					},
				},
			},
		},
	}
}

func (r *contentRoutingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *contentRoutingResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty or whitespace.")
	}
	if err := validateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("status"), "Invalid content routing configuration", err.Error())
		return
	}
	if err := validateCrossFields(ctx, config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("policy_list"), "Invalid content routing configuration", err.Error())
	}
}

func (r *contentRoutingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *contentRoutingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

	document, err := r.service.GetContentRouting(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read content routing", checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read content routing", err.Error())
		return
	}
	source := ownershipPriorState
	if state.Status.IsNull() || state.Status.IsUnknown() {
		source = ownershipImported
	}
	r.setState(ctx, epID, document, source, state.PolicyList, &resp.State, &resp.Diagnostics)
}

func (r *contentRoutingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *contentRoutingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.AddWarning(
		"Content routing forgotten, not destroyed",
		"The FortiAppSec Cloud content-routing API has no DELETE operation. Terraform removed the resource from state without changing the remote configuration. Remove the remote configuration manually if required.",
	)
}

func (r *contentRoutingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *contentRoutingResource) apply(ctx context.Context, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	if err := validateConfigs(plan); err != nil {
		diagnostics.AddError("Invalid content routing configuration", err.Error())
		return
	}
	if err := validateCrossFields(ctx, plan); err != nil {
		diagnostics.AddError("Invalid content routing configuration", err.Error())
		return
	}
	if plan.EPID.IsNull() || plan.EPID.IsUnknown() || strings.TrimSpace(plan.EPID.ValueString()) == "" {
		diagnostics.AddError("Invalid application ID", "ep_id must be known and non-empty during apply.")
		return
	}
	if plan.Status.IsNull() || plan.Status.IsUnknown() {
		diagnostics.AddError("Invalid content routing configuration", "status must be known during apply.")
		return
	}

	epID := strings.TrimSpace(plan.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	for attempt := 1; attempt <= 3; attempt++ {
		current, err := r.service.GetContentRouting(ctx, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read content routing before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
				return
			}
			diagnostics.AddError("Unable to read content routing before update", err.Error())
			return
		}

		updated, mergeDiag := mergeContentRouting(ctx, current, plan)
		diagnostics.Append(mergeDiag...)
		if diagnostics.HasError() {
			return
		}
		if err := r.service.PutContentRouting(ctx, epID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < 3 {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update content routing", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed during the update.", epID))
				return
			}
			diagnostics.AddError("Unable to update content routing", err.Error())
			return
		}

		normalized, err := r.service.GetContentRouting(ctx, epID)
		if err != nil {
			diagnostics.AddError("Unable to read normalized content routing", err.Error())
			return
		}
		r.setState(ctx, epID, normalized, ownershipConfigured, plan.PolicyList, state, diagnostics)
		return
	}
}

func (r *contentRoutingResource) setState(ctx context.Context, epID string, document client.ContentRoutingDocument, source ownershipSource, priorPolicyList types.Object, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	model, modelDiagnostics := stateModel(epID, document, source, priorPolicyList)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func (r *contentRoutingResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("module request failed: %v; parent application check failed: %w", moduleErr, err)
	}
	return !exists, nil
}

func (r *contentRoutingResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the resource operation.")
	return false
}

func resourceKey(epID string) string {
	return "waf/apps/" + epID + "/routings"
}
