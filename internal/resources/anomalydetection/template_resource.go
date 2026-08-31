package anomalydetection

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

var _ wafmodule.TemplateCodec = anomalyDetectionTemplateCodec{}

type anomalyDetectionTemplateCodec struct{}

func NewTemplateResource(locks *locking.Registry) resource.Resource {
	return wafmodule.NewTemplateResource(wafmodule.TemplateDescriptor{
		TypeNameSuffix: "waf_template_anomaly_detection",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/anomaly_detection",
			Operation: "anomaly detection",
		},
		Codec: anomalyDetectionTemplateCodec{},
		Destroy: wafmodule.DestroyPolicy{
			Mode:     wafmodule.DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   wafmodule.VerifiedTemplateStatusDisableReason,
		},
	}, locks)
}

func (anomalyDetectionTemplateCodec) Schema(ctx context.Context) schema.Schema {
	var response resource.SchemaResponse
	(&anomalyDetectionResource{}).Schema(ctx, resource.SchemaRequest{}, &response)
	return response.Schema
}

func (anomalyDetectionTemplateCodec) ValidateTemplateConfig(ctx context.Context, config tfsdk.Config) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	var model wafmodule.TemplateModel
	diagnostics.Append(config.Get(ctx, &model)...)
	if diagnostics.HasError() {
		return diagnostics
	}
	if err := validateRequiredConfigs(ctx, model.Configs); err != nil {
		diagnostics.AddError("Invalid anomaly detection template configuration", err.Error())
	}
	return diagnostics
}

func (anomalyDetectionTemplateCodec) BuildTemplatePatch(ctx context.Context, _ tfsdk.Config, plan tfsdk.Plan, _ tfsdk.State) (wafmodule.Patch, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var planned wafmodule.TemplateModel
	diagnostics.Append(plan.Get(ctx, &planned)...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	return wafmodule.PatchFunc(func(ctx context.Context, result *client.WAFModuleResult) diag.Diagnostics {
		var applyDiagnostics diag.Diagnostics
		if result == nil {
			applyDiagnostics.AddError("Unable to merge anomaly detection template configuration", "The current API result was nil.")
			return applyDiagnostics
		}
		document, err := client.ProjectAnomalyDetectionResult(result.Clone())
		if err != nil {
			applyDiagnostics.AddError("Unable to decode anomaly detection template configuration", err.Error())
			return applyDiagnostics
		}
		updated, mergeDiagnostics := mergeAnomalyDetection(ctx, document, false, planned.Configs)
		applyDiagnostics.Append(mergeDiagnostics...)
		if !applyDiagnostics.HasError() {
			updated.Template = false
			*result = updated
		}
		return applyDiagnostics
	}), diagnostics
}

func (anomalyDetectionTemplateCodec) ValidateResult(ctx context.Context, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) diag.Diagnostics {
	_, diagnostics := flattenAnomalyTemplate(ctx, "", result, ownership)
	return diagnostics
}

func (anomalyDetectionTemplateCodec) FlattenTemplate(ctx context.Context, templateID string, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) (any, diag.Diagnostics) {
	configs, diagnostics := flattenAnomalyTemplate(ctx, templateID, result, ownership)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	return &wafmodule.TemplateModel{TemplateID: types.StringValue(templateID), Configs: configs}, diagnostics
}

func flattenAnomalyTemplate(ctx context.Context, templateID string, result client.WAFModuleResult, ownership wafmodule.OwnershipContext) (types.Object, diag.Diagnostics) {
	document, err := client.ProjectAnomalyDetectionResult(result)
	if err != nil {
		var diagnostics diag.Diagnostics
		diagnostics.AddError("Malformed anomaly detection template result", err.Error())
		return types.ObjectNull(configsAttributeTypes), diagnostics
	}
	source, prior, diagnostics := anomalyTemplateOwnership(ctx, ownership)
	model, modelDiagnostics := stateModel(templateID, document, source, prior)
	diagnostics.Append(modelDiagnostics...)
	return model.Configs, diagnostics
}

func anomalyTemplateOwnership(ctx context.Context, ownership wafmodule.OwnershipContext) (ownershipSource, types.Object, diag.Diagnostics) {
	if ownership.Source == wafmodule.OwnershipImported {
		return ownershipImported, types.ObjectNull(configsAttributeTypes), nil
	}
	configs, diagnostics := wafmodule.OwnershipConfigs(ctx, ownership)
	if ownership.Source == wafmodule.OwnershipConfigured {
		return ownershipConfigured, configs, diagnostics
	}
	return ownershipPriorState, configs, diagnostics
}
