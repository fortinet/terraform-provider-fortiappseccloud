package ipprotection

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
	"terraform-provider-fortiappseccloud/internal/resources/wafmodule"
)

var _ wafmodule.TemplateCodec = ipProtectionTemplateCodec{}

type ipProtectionTemplateCodec struct{}

func NewTemplateResource(locks *locking.Registry) resource.Resource {
	return wafmodule.NewTemplateResource(ipProtectionTemplateDescriptor(), locks)
}

func ipProtectionTemplateDescriptor() wafmodule.TemplateDescriptor {
	return wafmodule.TemplateDescriptor{
		TypeNameSuffix: "waf_template_ip_protection",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/ip_protection",
			Operation: "IP protection",
		},
		Codec: ipProtectionTemplateCodec{},
		Destroy: wafmodule.DestroyPolicy{
			Mode:     wafmodule.DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   wafmodule.VerifiedTemplateStatusDisableReason,
		},
		NormalizeForPut: client.NormalizeIPProtectionResultForPut,
	}
}

func (ipProtectionTemplateCodec) Schema(ctx context.Context) schema.Schema {
	var response resource.SchemaResponse
	(&ipProtectionResource{}).Schema(ctx, resource.SchemaRequest{}, &response)
	return response.Schema
}

func (ipProtectionTemplateCodec) ValidateTemplateConfig(ctx context.Context, config tfsdk.Config) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	var model wafmodule.TemplateModel
	diagnostics.Append(config.Get(ctx, &model)...)
	if diagnostics.HasError() {
		return diagnostics
	}
	if err := validateRequiredConfigs(ctx, model.Configs); err != nil {
		diagnostics.AddError("Invalid IP protection template configuration", err.Error())
	}
	return diagnostics
}

func (ipProtectionTemplateCodec) BuildTemplatePatch(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, _ tfsdk.State) (wafmodule.Patch, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var configured, planned wafmodule.TemplateModel
	diagnostics.Append(config.Get(ctx, &configured)...)
	diagnostics.Append(plan.Get(ctx, &planned)...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	return wafmodule.PatchFunc(func(ctx context.Context, result *client.WAFModuleResult) diag.Diagnostics {
		var applyDiagnostics diag.Diagnostics
		if result == nil {
			applyDiagnostics.AddError("Unable to merge IP protection template configuration", "The current API result was nil.")
			return applyDiagnostics
		}
		document, err := client.ProjectIPProtectionResult(result.Clone())
		if err != nil {
			applyDiagnostics.AddError("Unable to decode IP protection template configuration", err.Error())
			return applyDiagnostics
		}
		updated, mergeDiagnostics := mergeIPProtection(ctx, document, false, configured.Configs, planned.Configs)
		applyDiagnostics.Append(mergeDiagnostics...)
		if !applyDiagnostics.HasError() {
			updated.Template = false
			*result = updated
		}
		return applyDiagnostics
	}), diagnostics
}

func (ipProtectionTemplateCodec) ValidateResult(ctx context.Context, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) diag.Diagnostics {
	_, diagnostics := flattenIPProtectionTemplate(ctx, "", result, ownership)
	return diagnostics
}

func (ipProtectionTemplateCodec) FlattenTemplate(ctx context.Context, templateID string, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) (any, diag.Diagnostics) {
	configs, diagnostics := flattenIPProtectionTemplate(ctx, templateID, result, ownership)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	return &wafmodule.TemplateModel{TemplateID: types.StringValue(templateID), Configs: configs}, diagnostics
}

func flattenIPProtectionTemplate(ctx context.Context, templateID string, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) (types.Object, diag.Diagnostics) {
	document, err := client.ProjectIPProtectionResult(result)
	if err != nil {
		var diagnostics diag.Diagnostics
		diagnostics.AddError("Malformed IP protection template result", err.Error())
		return types.ObjectNull(configsAttributeTypes), diagnostics
	}
	source, prior, diagnostics := ipProtectionTemplateOwnership(ctx, ownership)
	model, modelDiagnostics := stateModel(templateID, document, source, prior)
	diagnostics.Append(modelDiagnostics...)
	return model.Configs, diagnostics
}

func ipProtectionTemplateOwnership(ctx context.Context, ownership wafmodule.OwnershipContext) (ownershipSource, types.Object, diag.Diagnostics) {
	if ownership.Source == wafmodule.OwnershipImported {
		return ownershipImported, types.ObjectNull(configsAttributeTypes), nil
	}
	configs, diagnostics := wafmodule.OwnershipConfigs(ctx, ownership)
	if ownership.Source == wafmodule.OwnershipConfigured {
		return ownershipConfigured, configs, diagnostics
	}
	return ownershipPriorState, configs, diagnostics
}
