package accounttakeover

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
)

type resourceModel struct {
	EPID     types.String `tfsdk:"ep_id"`
	Template types.Bool   `tfsdk:"template"`
	Configs  types.Object `tfsdk:"configs"`
}

type configsModel struct {
	Action                 types.String `tfsdk:"action"`
	AuthURL                types.String `tfsdk:"auth_url"`
	CredentialStuffing     types.Bool   `tfsdk:"cred_stuffing_protect"`
	LogoffURL              types.String `tfsdk:"logoff_url"`
	Password               types.String `tfsdk:"password"`
	RedirectURL            types.String `tfsdk:"redirect_url"`
	ResponseBody           types.String `tfsdk:"response_body"`
	ReturnCode             types.String `tfsdk:"return_code"`
	SessionFixationProtect types.Bool   `tfsdk:"sess_fixation_protect"`
	SessionIDName          types.String `tfsdk:"sess_id_name"`
	Status                 types.Bool   `tfsdk:"status"`
	Username               types.String `tfsdk:"username"`
}

var configAttributeTypes = map[string]attr.Type{
	"action":                types.StringType,
	"auth_url":              types.StringType,
	"cred_stuffing_protect": types.BoolType,
	"logoff_url":            types.StringType,
	"password":              types.StringType,
	"redirect_url":          types.StringType,
	"response_body":         types.StringType,
	"return_code":           types.StringType,
	"sess_fixation_protect": types.BoolType,
	"sess_id_name":          types.StringType,
	"status":                types.BoolType,
	"username":              types.StringType,
}

func validateTemplateConfigs(model resourceModel) error {
	if model.Template.IsUnknown() || model.Configs.IsUnknown() {
		return nil
	}
	if model.Template.IsNull() {
		return fmt.Errorf("template must be configured")
	}
	if model.Template.ValueBool() && !model.Configs.IsNull() {
		return fmt.Errorf("configs must be omitted when template is true")
	}
	if !model.Template.ValueBool() && model.Configs.IsNull() {
		return fmt.Errorf("configs must be configured when template is false")
	}
	return nil
}

func accountTakeoverPatch(ctx context.Context, config, plan resourceModel) (client.AccountTakeoverPatch, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if config.Configs.IsNull() {
		return client.AccountTakeoverPatch{}, diagnostics
	}
	if config.Configs.IsUnknown() {
		diagnostics.AddError("Unknown account takeover configuration", "The configs block is still unknown during apply.")
		return client.AccountTakeoverPatch{}, diagnostics
	}

	var configValues configsModel
	diagnostics.Append(config.Configs.As(ctx, &configValues, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return client.AccountTakeoverPatch{}, diagnostics
	}
	var planValues configsModel
	diagnostics.Append(plan.Configs.As(ctx, &planValues, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return client.AccountTakeoverPatch{}, diagnostics
	}

	patch := client.AccountTakeoverPatch{}
	patch.Action, diagnostics = configuredString(configValues.Action, planValues.Action, "action", diagnostics)
	patch.AuthURL, diagnostics = configuredString(configValues.AuthURL, planValues.AuthURL, "auth_url", diagnostics)
	patch.CredentialStuffing, diagnostics = configuredBool(configValues.CredentialStuffing, planValues.CredentialStuffing, "cred_stuffing_protect", diagnostics)
	patch.LogoffURL, diagnostics = configuredString(configValues.LogoffURL, planValues.LogoffURL, "logoff_url", diagnostics)
	patch.Password, diagnostics = configuredString(configValues.Password, planValues.Password, "password", diagnostics)
	patch.RedirectURL, diagnostics = configuredString(configValues.RedirectURL, planValues.RedirectURL, "redirect_url", diagnostics)
	patch.ResponseBody, diagnostics = configuredString(configValues.ResponseBody, planValues.ResponseBody, "response_body", diagnostics)
	patch.ReturnCode, diagnostics = configuredString(configValues.ReturnCode, planValues.ReturnCode, "return_code", diagnostics)
	patch.SessionFixationProtect, diagnostics = configuredBool(configValues.SessionFixationProtect, planValues.SessionFixationProtect, "sess_fixation_protect", diagnostics)
	patch.SessionIDName, diagnostics = configuredString(configValues.SessionIDName, planValues.SessionIDName, "sess_id_name", diagnostics)
	patch.Status, diagnostics = configuredBool(configValues.Status, planValues.Status, "status", diagnostics)
	patch.Username, diagnostics = configuredString(configValues.Username, planValues.Username, "username", diagnostics)
	return patch, diagnostics
}

func configuredString(config, plan types.String, name string, diagnostics diag.Diagnostics) (client.Optional[string], diag.Diagnostics) {
	if config.IsNull() {
		return client.Optional[string]{}, diagnostics
	}
	if config.IsUnknown() {
		if plan.IsNull() || plan.IsUnknown() {
			diagnostics.AddError("Unknown account takeover value", fmt.Sprintf("The configured value for %s is still unknown during apply.", name))
			return client.Optional[string]{}, diagnostics
		}
		return client.Optional[string]{Set: true, Value: plan.ValueString()}, diagnostics
	}
	return client.Optional[string]{Set: true, Value: config.ValueString()}, diagnostics
}

func configuredBool(config, plan types.Bool, name string, diagnostics diag.Diagnostics) (client.Optional[bool], diag.Diagnostics) {
	if config.IsNull() {
		return client.Optional[bool]{}, diagnostics
	}
	if config.IsUnknown() {
		if plan.IsNull() || plan.IsUnknown() {
			diagnostics.AddError("Unknown account takeover value", fmt.Sprintf("The configured value for %s is still unknown during apply.", name))
			return client.Optional[bool]{}, diagnostics
		}
		return client.Optional[bool]{Set: true, Value: plan.ValueBool()}, diagnostics
	}
	return client.Optional[bool]{Set: true, Value: config.ValueBool()}, diagnostics
}

func stateModel(epID string, document client.AccountTakeoverDocument) (resourceModel, diag.Diagnostics) {
	model := resourceModel{
		EPID:     types.StringValue(epID),
		Template: types.BoolValue(document.Result.Template),
		Configs:  types.ObjectNull(configAttributeTypes),
	}
	if document.Result.Template {
		return model, nil
	}

	attributes := map[string]attr.Value{
		"action":                types.StringPointerValue(document.Config.Action),
		"auth_url":              types.StringPointerValue(document.Config.AuthURL),
		"cred_stuffing_protect": types.BoolPointerValue(document.Config.CredentialStuffing),
		"logoff_url":            types.StringPointerValue(document.Config.LogoffURL),
		"password":              types.StringPointerValue(document.Config.Password),
		"redirect_url":          types.StringPointerValue(document.Config.RedirectURL),
		"response_body":         types.StringPointerValue(document.Config.ResponseBody),
		"return_code":           types.StringPointerValue(document.Config.ReturnCode),
		"sess_fixation_protect": types.BoolPointerValue(document.Config.SessionFixationProtect),
		"sess_id_name":          types.StringPointerValue(document.Config.SessionIDName),
		"status":                types.BoolPointerValue(document.Config.Status),
		"username":              types.StringPointerValue(document.Config.Username),
	}
	configs, diagnostics := types.ObjectValue(configAttributeTypes, attributes)
	model.Configs = configs
	return model, diagnostics
}
