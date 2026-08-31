package customrule

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
	_ resource.Resource                   = (*customRuleResource)(nil)
	_ resource.ResourceWithConfigure      = (*customRuleResource)(nil)
	_ resource.ResourceWithImportState    = (*customRuleResource)(nil)
	_ resource.ResourceWithValidateConfig = (*customRuleResource)(nil)
)

type customRuleService interface {
	GetCustomRule(context.Context, string) (client.CustomRuleDocument, error)
	PutCustomRule(context.Context, string, client.WAFModuleResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

type customRuleResource struct {
	service customRuleService
	locks   *locking.Registry
	destroy contract.CustomResourceContract
}

func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	destroy, _ := contract.ReviewedCustomResourceContract("custom_rule")
	return &customRuleResource{locks: locks, destroy: destroy}
}

func (r *customRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_custom_rule"
}

func (r *customRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the app-level FortiAppSec Cloud custom-rule module. Destroy forgets the resource with a warning.",
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
				MarkdownDescription: "Locally managed custom-rule configuration. Required when template is false.",
				Attributes: map[string]schema.Attribute{
					"status": schema.BoolAttribute{
						Optional:            true,
						MarkdownDescription: "Enable or disable custom rule.",
					},
				},
				Blocks: map[string]schema.Block{
					"rule_list": schema.SingleNestedBlock{
						MarkdownDescription: "Optional rule_list ownership wrapper. Omit to preserve the raw remote array; empty sends []; populate to replace in Terraform order. Max 24 rules. Wire-only idx regenerated one-based.",
						Blocks: map[string]schema.Block{
							"item": schema.ListNestedBlock{
								MarkdownDescription: "Ordered custom rules in Terraform order.",
								Validators: []validator.List{
									listvalidator.SizeAtMost(client.CustomRuleRuleListMaxEntries),
								},
								NestedObject: schema.NestedBlockObject{
									Attributes: map[string]schema.Attribute{
										"name": schema.StringAttribute{
											Required:            true,
											MarkdownDescription: "Custom rule name (max 40 UTF-8 characters).",
											Validators:          []validator.String{stringvalidator.UTF8LengthAtMost(client.CustomRuleNameMaxLen)},
										},
										"action": schema.StringAttribute{
											Required:            true,
											MarkdownDescription: "Action when a rule violation is detected.",
											Validators:          []validator.String{stringvalidator.OneOf("alert", "alert_deny", "block_period", "deny_no_log")},
										},
										"block_period": schema.Int64Attribute{
											Optional:            true,
											Computed:            true,
											MarkdownDescription: "Block period in seconds (1..3600). Required only when action is block_period; explicitly configuring it for another action is rejected.",
											Validators:          []validator.Int64{int64validator.Between(client.CustomRuleBlockPeriodMin, client.CustomRuleBlockPeriodMax)},
											PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
										},
										"challenge": schema.StringAttribute{
											Optional:            true,
											Computed:            true,
											MarkdownDescription: "Challenge type.",
											Validators:          []validator.String{stringvalidator.OneOf("real-browser-enforcement", "disabled", "captcha-enforcement")},
											PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
										},
									},
									Blocks: map[string]schema.Block{
										"filter_list": schema.SingleNestedBlock{
											MarkdownDescription: "Optional filter_list ownership wrapper inside a rule. Max 200 filters.",
											Blocks: map[string]schema.Block{
												"item": schema.ListNestedBlock{
													MarkdownDescription: "Ordered filters in Terraform order.",
													Validators: []validator.List{
														listvalidator.SizeAtMost(client.CustomRuleFilterListMaxEntries),
													},
													NestedObject: schema.NestedBlockObject{
														Attributes: map[string]schema.Attribute{
															"type": schema.StringAttribute{
																Required:            true,
																MarkdownDescription: "Filter type discriminator (14 public variants). Fields from another variant are rejected.",
																Validators: []validator.String{stringvalidator.OneOf(
																	"source-ip-filter", "user-filter", "url-filter", "parameter", "http-header-filter",
																	"content-type", "response-code", "security-rules", "access-limit-filter",
																	"packet-interval", "http-transaction", "occurrence", "time-range-filter", "geo-filter",
																)},
															},
															"reverse_match":            schema.BoolAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}},
															"ip":                       schema.StringAttribute{Optional: true},
															"username":                 schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.UTF8LengthAtMost(client.CustomRuleUsernameMaxLen)}},
															"url":                      schema.StringAttribute{Optional: true},
															"name":                     schema.StringAttribute{Optional: true},
															"value":                    schema.StringAttribute{Optional: true},
															"header_check":             schema.BoolAttribute{Optional: true},
															"header_type":              schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.OneOf("predefined", "custom")}},
															"header_name":              schema.StringAttribute{Optional: true},
															"header_value":             schema.StringAttribute{Optional: true},
															"header_reverse_match":     schema.BoolAttribute{Optional: true},
															"method_check":             schema.BoolAttribute{Optional: true},
															"method_value":             schema.StringAttribute{Optional: true},
															"method_reverse_match":     schema.BoolAttribute{Optional: true},
															"http_hline_missing_check": schema.BoolAttribute{Optional: true},
															"http_hline_empty_check":   schema.BoolAttribute{Optional: true},
															"content_types":            schema.ListAttribute{Optional: true, ElementType: types.StringType, Validators: []validator.List{listvalidator.ValueStringsAre(stringvalidator.OneOf("text/plain", "text/html", "text/xml", "application/xml", "application/soap+xml", "application/json"))}},
															"response_code":            schema.Int64Attribute{Optional: true},
															"cross_site_scripting":     schema.BoolAttribute{Optional: true},
															"sql_injection":            schema.BoolAttribute{Optional: true},
															"generic_attacks":          schema.BoolAttribute{Optional: true},
															"known_exploits":           schema.BoolAttribute{Optional: true},
															"trojans":                  schema.BoolAttribute{Optional: true},
															"limit":                    schema.Int64Attribute{Optional: true, Validators: []validator.Int64{int64validator.Between(1, 65535)}},
															"timeout":                  schema.Int64Attribute{Optional: true},
															"occurrence":               schema.Int64Attribute{Optional: true, Validators: []validator.Int64{int64validator.Between(1, 100000)}},
															"within":                   schema.Int64Attribute{Optional: true, Validators: []validator.Int64{int64validator.Between(1, 600)}},
															"time_type":                schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.OneOf("daily", "once")}},
															"start":                    schema.StringAttribute{Optional: true},
															"end":                      schema.StringAttribute{Optional: true},
															"country_list":             schema.ListAttribute{Optional: true, ElementType: types.StringType},
															"match_exclusively":        schema.BoolAttribute{Optional: true},
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
			},
		},
	}
}

func (r *customRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *customRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty.")
	}
	if err := validateTemplateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid custom rule configuration", err.Error())
		return
	}
	if err := validateCrossFields(ctx, config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid custom rule configuration", err.Error())
	}
}

func (r *customRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

func (r *customRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

	document, err := r.service.GetCustomRule(ctx, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read custom rule", checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read custom rule", err.Error())
		return
	}
	source := ownershipPriorState
	if state.Template.IsNull() || state.Template.IsUnknown() {
		source = ownershipImported
	}
	r.setState(ctx, epID, document, source, state.Configs, &resp.State, &resp.Diagnostics)
}

func (r *customRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, config, plan, &resp.State, &resp.Diagnostics)
}

func (r *customRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
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
			ModuleName: "custom rule",
			EPID:       epID,
			Field:      r.destroy.DestroyField,
			Verified:   r.destroy.DestroyVerified,
		}, wafmodule.DisableAccess{
			Get: func(ctx context.Context) (client.WAFModuleDocument, error) {
				document, err := r.service.GetCustomRule(ctx, epID)
				return client.WAFModuleDocument{Result: document.Result}, err
			},
			Put: func(ctx context.Context, result client.WAFModuleResult) error {
				return r.service.PutCustomRule(ctx, epID, result)
			},
			ApplicationExists: func(ctx context.Context) (bool, error) {
				return r.service.ApplicationExists(ctx, epID)
			},
		}, &resp.Diagnostics)
		return
	}
	resp.Diagnostics.AddWarning(
		"Custom rule forgotten, not destroyed",
		"Terraform removed the resource from state without changing the remote configuration. "+strings.TrimSpace(r.destroy.DestroyReason),
	)
}

func (r *customRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *customRuleResource) apply(ctx context.Context, config, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	if err := validateTemplateConfigs(plan); err != nil {
		diagnostics.AddError("Invalid custom rule configuration", err.Error())
		return
	}
	// Cross-field ownership is config-presence-sensitive. Optional+Computed
	// fields may carry remote defaults in plan via UseStateForUnknown; those
	// values are not explicit contradictory user input.
	if err := validateCrossFields(ctx, config); err != nil {
		diagnostics.AddError("Invalid custom rule configuration", err.Error())
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
		diagnostics.AddError("Invalid custom rule configuration", "configs must be configured when template is false.")
		return
	}

	epID := strings.TrimSpace(plan.EPID.ValueString())
	unlock := r.locks.Lock(resourceKey(epID))
	defer unlock()

	for attempt := 1; attempt <= 3; attempt++ {
		current, err := r.service.GetCustomRule(ctx, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read custom rule before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
				return
			}
			diagnostics.AddError("Unable to read custom rule before update", err.Error())
			return
		}

		updated, mergeDiag := mergeCustomRule(ctx, current, plan.Template.ValueBool(), config.Configs, plan.Configs)
		diagnostics.Append(mergeDiag...)
		if diagnostics.HasError() {
			return
		}
		if err := r.service.PutCustomRule(ctx, epID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < 3 {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update custom rule", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed during the update.", epID))
				return
			}
			diagnostics.AddError("Unable to update custom rule", err.Error())
			return
		}

		normalized, err := r.service.GetCustomRule(ctx, epID)
		if err != nil {
			diagnostics.AddError("Unable to read normalized custom rule", err.Error())
			return
		}
		r.setState(ctx, epID, normalized, ownershipConfigured, plan.Configs, state, diagnostics)
		return
	}
}

func (r *customRuleResource) setState(ctx context.Context, epID string, document client.CustomRuleDocument, source ownershipSource, priorConfigs types.Object, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	model, modelDiagnostics := stateModel(epID, document, source, priorConfigs)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &model)...)
}

func (r *customRuleResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("module request failed: %v; parent application check failed: %w", moduleErr, err)
	}
	return !exists, nil
}

func (r *customRuleResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the resource operation.")
	return false
}

func resourceKey(epID string) string {
	return "waf/apps/" + epID + "/custom_rule"
}
