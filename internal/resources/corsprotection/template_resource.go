package corsprotection

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

var _ wafmodule.TemplateCodec = corsProtectionTemplateCodec{}

type corsProtectionTemplateCodec struct{}

func NewTemplateResource(locks *locking.Registry) resource.Resource {
	return wafmodule.NewTemplateResource(wafmodule.TemplateDescriptor{
		TypeNameSuffix: "waf_template_cors_protection",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/cors_protection",
			Operation: "CORS protection",
		},
		Codec: corsProtectionTemplateCodec{},
		Destroy: wafmodule.DestroyPolicy{
			Mode:     wafmodule.DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   wafmodule.VerifiedTemplateStatusDisableReason,
		},
	}, locks)
}

func (corsProtectionTemplateCodec) Schema(ctx context.Context) schema.Schema {
	var response resource.SchemaResponse
	(&corsProtectionResource{}).Schema(ctx, resource.SchemaRequest{}, &response)
	return response.Schema
}

func (corsProtectionTemplateCodec) ValidateTemplateConfig(ctx context.Context, config tfsdk.Config) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	var model wafmodule.TemplateModel
	diagnostics.Append(config.Get(ctx, &model)...)
	if diagnostics.HasError() {
		return diagnostics
	}
	if err := validateRequiredConfigs(ctx, model.Configs); err != nil {
		diagnostics.AddError("Invalid CORS protection template configuration", err.Error())
	}
	return diagnostics
}

func (corsProtectionTemplateCodec) BuildTemplatePatch(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, _ tfsdk.State) (wafmodule.Patch, diag.Diagnostics) {
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
			applyDiagnostics.AddError("Unable to merge CORS protection template configuration", "The current API result was nil.")
			return applyDiagnostics
		}
		document, err := client.ProjectCorsProtectionResult(result.Clone())
		if err != nil {
			applyDiagnostics.AddError("Unable to decode CORS protection template configuration", err.Error())
			return applyDiagnostics
		}
		updated, mergeDiagnostics := mergeCorsProtection(ctx, document, false, configured.Configs, planned.Configs)
		applyDiagnostics.Append(mergeDiagnostics...)
		if !applyDiagnostics.HasError() {
			updated.Template = false
			*result = updated
		}
		return applyDiagnostics
	}), diagnostics
}

func (corsProtectionTemplateCodec) ValidateResult(_ context.Context, result client.WAFModuleResult, _ wafmodule.OwnershipContext) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	if _, err := client.ProjectCorsProtectionResult(result); err != nil {
		diagnostics.AddError("Malformed CORS protection template result", err.Error())
	}
	return diagnostics
}

func (corsProtectionTemplateCodec) FlattenTemplate(_ context.Context, templateID string, result client.WAFModuleResult, _ wafmodule.OwnershipContext) (any, diag.Diagnostics) {
	document, err := client.ProjectCorsProtectionResult(result)
	if err != nil {
		var diagnostics diag.Diagnostics
		diagnostics.AddError("Malformed CORS protection template result", err.Error())
		return nil, diagnostics
	}
	model, diagnostics := stateModel(templateID, document)
	return &wafmodule.TemplateModel{TemplateID: types.StringValue(templateID), Configs: model.Configs}, diagnostics
}
