package wafmodule

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                   = (*templateModuleResource)(nil)
	_ resource.ResourceWithConfigure      = (*templateModuleResource)(nil)
	_ resource.ResourceWithImportState    = (*templateModuleResource)(nil)
	_ resource.ResourceWithValidateConfig = (*templateModuleResource)(nil)
)

type templateModuleService interface {
	GetWAFTemplateModule(context.Context, client.WAFTemplateModuleEndpoint, string) (client.WAFTemplateModuleDocument, error)
	PutWAFTemplateModule(context.Context, client.WAFTemplateModuleEndpoint, string, client.WAFModuleResult) error
	TemplateExists(context.Context, string) (bool, error)
}

type templateModuleResource struct {
	descriptor    TemplateDescriptor
	descriptorErr error
	service       templateModuleService
	locks         *locking.Registry
}

// NewTemplateResource creates a descriptor-driven template-scoped WAF module
// resource.
func NewTemplateResource(descriptor TemplateDescriptor, locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &templateModuleResource{
		descriptor:    descriptor,
		descriptorErr: descriptor.Validate(),
		locks:         locks,
	}
}

func (r *templateModuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.descriptor.TypeNameSuffix
}

func (r *templateModuleResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	if err := r.staticError(); err != nil {
		resp.Diagnostics.AddError("Invalid WAF template module descriptor", err.Error())
		return
	}
	resp.Schema = templateModuleSchema(r.descriptor.Codec.Schema(ctx), r.moduleName(), r.descriptor.Destroy)
}

func templateModuleSchema(appSchema schema.Schema, moduleName string, destroyPolicy DestroyPolicy) schema.Schema {
	attributes := make(map[string]schema.Attribute, len(appSchema.Attributes)-1)
	for name, attribute := range appSchema.Attributes {
		if name != "ep_id" && name != "template" {
			attributes[name] = attribute
		}
	}
	attributes["template_id"] = schema.StringAttribute{
		Required:            true,
		MarkdownDescription: "Template ID and import identifier.",
		PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
	}

	blocks := make(map[string]schema.Block, len(appSchema.Blocks))
	for name, block := range appSchema.Blocks {
		if name == "configs" {
			if configs, ok := block.(schema.SingleNestedBlock); ok {
				configs.MarkdownDescription = "Locally managed " + moduleName + " template configuration. This block is required."
				block = configs
			}
		}
		blocks[name] = block
	}
	destroyDescription := "Destroy forgets state without changing the remote module configuration."
	if destroyPolicy.Mode == DestroyDisable {
		destroyDescription = "Destroy disables the remote module with a preserving GET-merge-PUT-GET lifecycle."
		if len(destroyPolicy.CoupledFields) != 0 {
			destroyDescription = "Destroy disables the remote module with a preserving GET-merge-PUT-GET lifecycle that also disables its reviewed coupled nested features."
		}
	}
	appSchema.MarkdownDescription = "Manages template-level FortiAppSec Cloud " + moduleName + ". " + destroyDescription
	appSchema.Attributes = attributes
	appSchema.Blocks = blocks
	return appSchema
}

func (r *templateModuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *templateModuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if err := r.staticError(); err != nil {
		resp.Diagnostics.AddError("Invalid WAF template module descriptor", err.Error())
		return
	}
	var config TemplateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.TemplateID.IsNull() && !config.TemplateID.IsUnknown() && strings.TrimSpace(config.TemplateID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("template_id"), "Invalid "+r.moduleName()+" template ID", "template_id must not be empty or whitespace.")
	}
	if !config.Configs.IsUnknown() && config.Configs.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Missing "+r.moduleName()+" template configuration", "configs must be configured for a template module resource.")
	}
	resp.Diagnostics.Append(r.descriptor.Codec.ValidateTemplateConfig(ctx, req.Config)...)
}

func (r *templateModuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	currentState := tfsdk.State{
		Schema: templateModuleSchema(r.descriptor.Codec.Schema(ctx), r.moduleName(), r.descriptor.Destroy),
		Raw:    tftypes.NewValue(templateModuleSchema(r.descriptor.Codec.Schema(ctx), r.moduleName(), r.descriptor.Destroy).Type().TerraformType(ctx), nil),
	}
	r.apply(ctx, req.Config, req.Plan, currentState, &resp.State, &resp.Diagnostics)
}

func (r *templateModuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var current TemplateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID, ok := r.knownTemplateID(current.TemplateID, &resp.Diagnostics, "read")
	if !ok {
		return
	}

	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()

	document, err := r.service.GetWAFTemplateModule(ctx, r.descriptor.Endpoint, templateID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, templateID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read "+r.moduleName(), checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read "+r.moduleName(), err.Error())
		return
	}
	document.Result.Template = false
	ownership := OwnershipContext{Source: OwnershipPriorState, State: req.State}
	if current.Configs.IsNull() || current.Configs.IsUnknown() {
		ownership.Source = OwnershipImported
	}
	r.setState(ctx, templateID, document.Result, ownership, &resp.State, &resp.Diagnostics)
}

func (r *templateModuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	r.apply(ctx, req.Config, req.Plan, req.State, &resp.State, &resp.Diagnostics)
}

func (r *templateModuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var current TemplateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}
	templateID, ok := r.knownTemplateID(current.TemplateID, &resp.Diagnostics, "destroy")
	if !ok {
		return
	}

	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()
	currentDocument, err := r.service.GetWAFTemplateModule(ctx, r.descriptor.Endpoint, templateID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, templateID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to destroy "+r.moduleName(), checkErr.Error())
			return
		}
		if absent {
			return
		}
		resp.Diagnostics.AddError("Unable to destroy "+r.moduleName(), err.Error())
		return
	}
	switch r.descriptor.Destroy.Mode {
	case DestroyForget:
		resp.Diagnostics.AddWarning(
			"Remote "+r.moduleName()+" template configuration remains",
			"Terraform removed this resource from state without changing the remote configuration. "+strings.TrimSpace(r.descriptor.Destroy.Reason)+".",
		)
	case DestroyDisable:
		DisableTemplateOnDestroy(ctx, TemplateDisableRequest{
			ModuleName:      r.moduleName(),
			TemplateID:      templateID,
			Field:           r.descriptor.Destroy.Field,
			CoupledFields:   r.descriptor.Destroy.CoupledFields,
			Verified:        r.descriptor.Destroy.Verified,
			Current:         &currentDocument,
			NormalizeForPut: r.descriptor.NormalizeForPut,
		}, TemplateDisableAccess{
			Get: func(ctx context.Context) (client.WAFTemplateModuleDocument, error) {
				return r.service.GetWAFTemplateModule(ctx, r.descriptor.Endpoint, templateID)
			},
			Put: func(ctx context.Context, result client.WAFModuleResult) error {
				return r.service.PutWAFTemplateModule(ctx, r.descriptor.Endpoint, templateID, result)
			},
			TemplateExists: func(ctx context.Context) (bool, error) {
				return r.service.TemplateExists(ctx, templateID)
			},
		}, &resp.Diagnostics)
	default:
		resp.Diagnostics.AddError("Unable to destroy "+r.moduleName(), fmt.Sprintf("Unsupported destroy policy %q.", r.descriptor.Destroy.Mode))
	}
}

func (r *templateModuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid "+r.moduleName()+" import ID", "Importing "+r.moduleName()+" requires a non-empty template_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("template_id"), id)...)
}

func (r *templateModuleResource) apply(
	ctx context.Context,
	config tfsdk.Config,
	plan tfsdk.Plan,
	currentState tfsdk.State,
	state *tfsdk.State,
	diagnostics *diag.Diagnostics,
) {
	var configured, planned TemplateModel
	diagnostics.Append(config.Get(ctx, &configured)...)
	diagnostics.Append(plan.Get(ctx, &planned)...)
	if diagnostics.HasError() {
		return
	}
	templateID, ok := r.knownTemplateID(planned.TemplateID, diagnostics, "apply")
	if !ok {
		return
	}
	if planned.Configs.IsNull() || planned.Configs.IsUnknown() {
		diagnostics.AddError("Invalid "+r.moduleName()+" template configuration", "configs must be known and configured during apply.")
		return
	}
	diagnostics.Append(r.descriptor.Codec.ValidateTemplateConfig(ctx, config)...)
	if diagnostics.HasError() {
		return
	}
	patch, patchDiagnostics := r.descriptor.Codec.BuildTemplatePatch(ctx, config, plan, currentState)
	diagnostics.Append(patchDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	if patch == nil {
		diagnostics.AddError("Unable to prepare "+r.moduleName()+" template configuration", "The module codec returned no patch.")
		return
	}

	ownership := OwnershipContext{
		Source: OwnershipConfigured,
		Config: config,
		Plan:   plan,
		State:  currentState,
	}
	unlock := r.locks.Lock("waf-template:" + templateID)
	defer unlock()

	for attempt := 1; attempt <= maxConflictAttempts; attempt++ {
		current, err := r.service.GetWAFTemplateModule(ctx, r.descriptor.Endpoint, templateID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, templateID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read "+r.moduleName()+" before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Template not found", fmt.Sprintf("Template %q does not exist for %s.", templateID, r.moduleName()))
				return
			}
			diagnostics.AddError("Unable to read "+r.moduleName()+" before update", err.Error())
			return
		}
		current.Result.Template = false
		diagnostics.Append(r.descriptor.Codec.ValidateResult(ctx, current.Result, ownership)...)
		if diagnostics.HasError() {
			return
		}
		updated := current.Result.Clone()
		updated.Template = false
		diagnostics.Append(patch.Apply(ctx, &updated)...)
		if diagnostics.HasError() {
			return
		}
		updated.Template = false

		if err := r.service.PutWAFTemplateModule(ctx, r.descriptor.Endpoint, templateID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < maxConflictAttempts {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, templateID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update "+r.moduleName(), checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Template not found", fmt.Sprintf("Template %q was removed while updating %s.", templateID, r.moduleName()))
				return
			}
			diagnostics.AddError("Unable to update "+r.moduleName(), err.Error())
			return
		}

		normalized, err := r.service.GetWAFTemplateModule(ctx, r.descriptor.Endpoint, templateID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, templateID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read normalized "+r.moduleName()+" template configuration", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Template not found", fmt.Sprintf("Template %q was removed after updating %s.", templateID, r.moduleName()))
				return
			}
			diagnostics.AddError("Unable to read normalized "+r.moduleName()+" template configuration", err.Error())
			return
		}
		normalized.Result.Template = false
		r.setState(ctx, templateID, normalized.Result, ownership, state, diagnostics)
		return
	}
}

func (r *templateModuleResource) setState(
	ctx context.Context,
	templateID string,
	result client.WAFModuleResult,
	ownership OwnershipContext,
	state *tfsdk.State,
	diagnostics *diag.Diagnostics,
) {
	result.Template = false
	diagnostics.Append(r.descriptor.Codec.ValidateResult(ctx, result, ownership)...)
	if diagnostics.HasError() {
		return
	}
	model, modelDiagnostics := r.descriptor.Codec.FlattenTemplate(ctx, templateID, result, ownership)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	if model == nil {
		diagnostics.AddError("Unable to flatten "+r.moduleName()+" template configuration", "The module codec returned no Terraform state model.")
		return
	}
	diagnostics.Append(state.Set(ctx, model)...)
}

func (r *templateModuleResource) parentAbsent(ctx context.Context, templateID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.TemplateExists(ctx, templateID)
	if err != nil {
		return false, fmt.Errorf("%s request failed: %v; parent template check failed: %w", r.moduleName(), moduleErr, err)
	}
	return !exists, nil
}

func (r *templateModuleResource) ready(diagnostics *diag.Diagnostics) bool {
	if err := r.staticError(); err != nil {
		diagnostics.AddError("Invalid WAF template module descriptor", err.Error())
		return false
	}
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the "+r.moduleName()+" template resource operation.")
	return false
}

func (r *templateModuleResource) staticError() error {
	if r.descriptorErr != nil {
		return r.descriptorErr
	}
	return r.descriptor.Validate()
}

func (r *templateModuleResource) moduleName() string {
	name := strings.TrimSpace(r.descriptor.Endpoint.Operation)
	if name == "" {
		name = r.descriptor.TypeNameSuffix
	}
	return strings.ReplaceAll(name, "_", " ")
}

func (r *templateModuleResource) knownTemplateID(value types.String, diagnostics *diag.Diagnostics, operation string) (string, bool) {
	if value.IsNull() || value.IsUnknown() || strings.TrimSpace(value.ValueString()) == "" {
		diagnostics.AddError("Invalid "+r.moduleName()+" template ID", "template_id must be known and non-empty during "+r.moduleName()+" "+operation+".")
		return "", false
	}
	return strings.TrimSpace(value.ValueString()), true
}
