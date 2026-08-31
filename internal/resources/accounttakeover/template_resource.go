package accounttakeover

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

var _ wafmodule.TemplateCodec = accountTakeoverTemplateCodec{}

type accountTakeoverTemplateCodec struct{}

// NewTemplateResource creates the template-scoped account-takeover resource.
func NewTemplateResource(locks *locking.Registry) resource.Resource {
	return wafmodule.NewTemplateResource(wafmodule.TemplateDescriptor{
		TypeNameSuffix: "waf_template_account_takeover",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/account_takeover",
			Operation: "account takeover",
		},
		Codec: accountTakeoverTemplateCodec{},
		Destroy: wafmodule.DestroyPolicy{
			Mode:     wafmodule.DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   wafmodule.VerifiedTemplateStatusDisableReason,
		},
	}, locks)
}

func (accountTakeoverTemplateCodec) Schema(ctx context.Context) schema.Schema {
	var response resource.SchemaResponse
	(&accountTakeoverResource{}).Schema(ctx, resource.SchemaRequest{}, &response)
	return response.Schema
}

func (accountTakeoverTemplateCodec) ValidateTemplateConfig(ctx context.Context, config tfsdk.Config) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	var model wafmodule.TemplateModel
	diagnostics.Append(config.Get(ctx, &model)...)
	return diagnostics
}

func (accountTakeoverTemplateCodec) BuildTemplatePatch(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, _ tfsdk.State) (wafmodule.Patch, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var configured, planned wafmodule.TemplateModel
	diagnostics.Append(config.Get(ctx, &configured)...)
	diagnostics.Append(plan.Get(ctx, &planned)...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	patch, patchDiagnostics := accountTakeoverPatch(ctx,
		resourceModel{Template: types.BoolValue(false), Configs: configured.Configs},
		resourceModel{Template: types.BoolValue(false), Configs: planned.Configs},
	)
	diagnostics.Append(patchDiagnostics...)
	return wafmodule.PatchFunc(func(_ context.Context, result *client.WAFModuleResult) diag.Diagnostics {
		var applyDiagnostics diag.Diagnostics
		if result == nil {
			applyDiagnostics.AddError("Unable to merge account takeover template configuration", "The current API result was nil.")
			return applyDiagnostics
		}
		document, err := client.ProjectAccountTakeoverResult(result.Clone())
		if err != nil {
			applyDiagnostics.AddError("Unable to decode account takeover template configuration", err.Error())
			return applyDiagnostics
		}
		if err := document.Merge(patch); err != nil {
			applyDiagnostics.AddError("Unable to merge account takeover template configuration", err.Error())
			return applyDiagnostics
		}
		document.Result.Template = false
		*result = document.Result
		return applyDiagnostics
	}), diagnostics
}

func (accountTakeoverTemplateCodec) ValidateResult(_ context.Context, result client.WAFModuleResult, _ wafmodule.OwnershipContext) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	if _, err := client.ProjectAccountTakeoverResult(result); err != nil {
		diagnostics.AddError("Malformed account takeover template result", err.Error())
	}
	return diagnostics
}

func (accountTakeoverTemplateCodec) FlattenTemplate(_ context.Context, templateID string, result client.WAFModuleResult, _ wafmodule.OwnershipContext) (any, diag.Diagnostics) {
	document, err := client.ProjectAccountTakeoverResult(result)
	if err != nil {
		var diagnostics diag.Diagnostics
		diagnostics.AddError("Malformed account takeover template result", err.Error())
		return nil, diagnostics
	}
	model, diagnostics := stateModel(templateID, document)
	return &wafmodule.TemplateModel{TemplateID: types.StringValue(templateID), Configs: model.Configs}, diagnostics
}
