package accounttakeover

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
)

func TestValidateTemplateConfigs(t *testing.T) {
	t.Parallel()

	configs := testConfigsObject(t, nil)
	tests := map[string]struct {
		model   resourceModel
		wantErr bool
	}{
		"local configs": {
			model: resourceModel{Template: types.BoolValue(false), Configs: configs},
		},
		"template inheritance": {
			model: resourceModel{Template: types.BoolValue(true), Configs: types.ObjectNull(configAttributeTypes)},
		},
		"missing local configs": {
			model:   resourceModel{Template: types.BoolValue(false), Configs: types.ObjectNull(configAttributeTypes)},
			wantErr: true,
		},
		"configs with template": {
			model:   resourceModel{Template: types.BoolValue(true), Configs: configs},
			wantErr: true,
		},
		"unknown template defers": {
			model: resourceModel{Template: types.BoolUnknown(), Configs: configs},
		},
		"unknown configs defers": {
			model: resourceModel{Template: types.BoolValue(false), Configs: types.ObjectUnknown(configAttributeTypes)},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := validateTemplateConfigs(test.model)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateTemplateConfigs() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestAccountTakeoverPatchUsesConfigurationPresence(t *testing.T) {
	t.Parallel()

	config := resourceModel{Configs: testConfigsObject(t, map[string]attr.Value{
		"auth_url": types.StringValue(""),
		"status":   types.BoolValue(false),
	})}
	plan := resourceModel{Configs: testConfigsObject(t, map[string]attr.Value{
		"action":   types.StringValue("alert_deny"),
		"auth_url": types.StringValue(""),
		"status":   types.BoolValue(false),
	})}

	patch, diagnostics := accountTakeoverPatch(context.Background(), config, plan)
	if diagnostics.HasError() {
		t.Fatalf("accountTakeoverPatch() diagnostics = %v", diagnostics)
	}
	if patch.Action.Set {
		t.Fatal("unconfigured computed action was included in patch")
	}
	if !patch.AuthURL.Set || patch.AuthURL.Value != "" {
		t.Fatalf("auth_url patch = %#v", patch.AuthURL)
	}
	if !patch.Status.Set || patch.Status.Value {
		t.Fatalf("status patch = %#v", patch.Status)
	}
	if patch.Username.Set {
		t.Fatal("unconfigured username was included in patch")
	}
}

func TestAccountTakeoverPatchUsesResolvedPlanForConfiguredUnknown(t *testing.T) {
	t.Parallel()

	config := resourceModel{Configs: testConfigsObject(t, map[string]attr.Value{
		"action": types.StringUnknown(),
	})}
	plan := resourceModel{Configs: testConfigsObject(t, map[string]attr.Value{
		"action": types.StringValue("alert"),
	})}

	patch, diagnostics := accountTakeoverPatch(context.Background(), config, plan)
	if diagnostics.HasError() {
		t.Fatalf("accountTakeoverPatch() diagnostics = %v", diagnostics)
	}
	if !patch.Action.Set || patch.Action.Value != "alert" {
		t.Fatalf("action patch = %#v", patch.Action)
	}
}

func TestAccountTakeoverPatchRejectsUnresolvedConfiguredValue(t *testing.T) {
	t.Parallel()

	config := resourceModel{Configs: testConfigsObject(t, map[string]attr.Value{
		"status": types.BoolUnknown(),
	})}
	plan := resourceModel{Configs: testConfigsObject(t, map[string]attr.Value{
		"status": types.BoolUnknown(),
	})}

	_, diagnostics := accountTakeoverPatch(context.Background(), config, plan)
	if !diagnostics.HasError() {
		t.Fatal("accountTakeoverPatch() diagnostics did not report unresolved status")
	}
}

func TestStateModelHidesEffectiveConfigsForTemplateInheritance(t *testing.T) {
	t.Parallel()

	document := testAccountTakeoverDocument(t, true, "alert", true)
	model, diagnostics := stateModel("123", document)
	if diagnostics.HasError() {
		t.Fatalf("stateModel() diagnostics = %v", diagnostics)
	}
	if !model.Configs.IsNull() {
		t.Fatalf("configs = %#v, want null", model.Configs)
	}
	if !model.Template.ValueBool() || model.EPID.ValueString() != "123" {
		t.Fatalf("state model = %#v", model)
	}
}

func testConfigsObject(t *testing.T, overrides map[string]attr.Value) types.Object {
	t.Helper()

	values := map[string]attr.Value{
		"action":                types.StringNull(),
		"auth_url":              types.StringNull(),
		"cred_stuffing_protect": types.BoolNull(),
		"logoff_url":            types.StringNull(),
		"password":              types.StringNull(),
		"redirect_url":          types.StringNull(),
		"response_body":         types.StringNull(),
		"return_code":           types.StringNull(),
		"sess_fixation_protect": types.BoolNull(),
		"sess_id_name":          types.StringNull(),
		"status":                types.BoolNull(),
		"username":              types.StringNull(),
	}
	for name, value := range overrides {
		values[name] = value
	}
	result, diagnostics := types.ObjectValue(configAttributeTypes, values)
	if diagnostics.HasError() {
		t.Fatalf("types.ObjectValue() diagnostics = %v", diagnostics)
	}
	return result
}

func testAccountTakeoverDocument(t *testing.T, template bool, action string, status bool) client.AccountTakeoverDocument {
	t.Helper()

	result := client.WAFModuleResult{Template: template}
	if err := result.SetConfig("action", action); err != nil {
		t.Fatalf("SetConfig(action) error = %v", err)
	}
	if err := result.SetConfig("status", status); err != nil {
		t.Fatalf("SetConfig(status) error = %v", err)
	}
	document := client.AccountTakeoverDocument{Result: result}
	data, err := document.Result.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if err := document.UnmarshalJSON([]byte(`{"result":` + string(data) + `}`)); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	return document
}
