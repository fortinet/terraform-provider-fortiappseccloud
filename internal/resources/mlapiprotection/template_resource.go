package mlapiprotection

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

var _ wafmodule.TemplateCodec = mlAPIProtectionTemplateCodec{}

type mlAPIProtectionTemplateCodec struct{}

func NewTemplateResource(locks *locking.Registry) resource.Resource {
	return wafmodule.NewTemplateResource(wafmodule.TemplateDescriptor{
		TypeNameSuffix: "waf_template_ml_api_protection",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/ml_api_protection",
			Operation: "ML API protection",
		},
		Codec: mlAPIProtectionTemplateCodec{},
		Destroy: wafmodule.DestroyPolicy{
			Mode:     wafmodule.DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   wafmodule.VerifiedTemplateStatusDisableReason,
		},
	}, locks)
}

func (mlAPIProtectionTemplateCodec) Schema(ctx context.Context) schema.Schema {
	var response resource.SchemaResponse
	(&mlApiProtectionResource{}).Schema(ctx, resource.SchemaRequest{}, &response)
	return response.Schema
}

func (mlAPIProtectionTemplateCodec) ValidateTemplateConfig(ctx context.Context, config tfsdk.Config) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	var model wafmodule.TemplateModel
	diagnostics.Append(config.Get(ctx, &model)...)
	if diagnostics.HasError() {
		return diagnostics
	}
	if err := validateRequiredConfigs(ctx, model.Configs); err != nil {
		diagnostics.AddError("Invalid ML API protection template configuration", err.Error())
	}
	return diagnostics
}

func (mlAPIProtectionTemplateCodec) BuildTemplatePatch(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, _ tfsdk.State) (wafmodule.Patch, diag.Diagnostics) {
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
			applyDiagnostics.AddError("Unable to merge ML API protection template configuration", "The current API result was nil.")
			return applyDiagnostics
		}
		document, err := client.ProjectMlApiProtectionResult(result.Clone())
		if err != nil {
			applyDiagnostics.AddError("Unable to decode ML API protection template configuration", err.Error())
			return applyDiagnostics
		}
		updated, mergeDiagnostics := mergeMlApiProtection(ctx, document, false, configured.Configs, planned.Configs)
		applyDiagnostics.Append(mergeDiagnostics...)
		if !applyDiagnostics.HasError() {
			updated.Template = false
			*result = updated
		}
		return applyDiagnostics
	}), diagnostics
}

func (mlAPIProtectionTemplateCodec) ValidateResult(ctx context.Context, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) diag.Diagnostics {
	_, diagnostics := flattenMLAPIProtectionTemplate(ctx, "", result, ownership)
	return diagnostics
}

func (mlAPIProtectionTemplateCodec) FlattenTemplate(ctx context.Context, templateID string, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) (any, diag.Diagnostics) {
	configs, diagnostics := flattenMLAPIProtectionTemplate(ctx, templateID, result, ownership)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	return &wafmodule.TemplateModel{TemplateID: types.StringValue(templateID), Configs: configs}, diagnostics
}

func flattenMLAPIProtectionTemplate(ctx context.Context, templateID string, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) (types.Object, diag.Diagnostics) {
	document, err := client.ProjectMlApiProtectionResult(result)
	if err != nil {
		var diagnostics diag.Diagnostics
		diagnostics.AddError("Malformed ML API protection template result", err.Error())
		return types.ObjectNull(configsAttributeTypes), diagnostics
	}
	source, prior, diagnostics := mlAPIProtectionTemplateOwnership(ctx, ownership)
	model, modelDiagnostics := stateModel(templateID, document, source, prior)
	diagnostics.Append(modelDiagnostics...)
	return model.Configs, diagnostics
}

func mlAPIProtectionTemplateOwnership(ctx context.Context, ownership wafmodule.OwnershipContext) (ownershipSource, types.Object, diag.Diagnostics) {
	if ownership.Source == wafmodule.OwnershipImported {
		return ownershipImported, types.ObjectNull(configsAttributeTypes), nil
	}
	configs, diagnostics := wafmodule.OwnershipConfigs(ctx, ownership)
	if ownership.Source == wafmodule.OwnershipConfigured {
		return ownershipConfigured, configs, diagnostics
	}
	return ownershipPriorState, configs, diagnostics
}
