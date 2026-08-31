package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/resources/wafmodule"
)

func TestCSRFProtectionSchemaUsesProtocol5OwnershipBlocks(t *testing.T) {
	t.Parallel()

	resourceSchema := csrfProtectionCodec{}.Schema(context.Background())
	configs, ok := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	if !ok {
		t.Fatalf("configs block type = %T", resourceSchema.Blocks["configs"])
	}
	for _, name := range []string{"page_list", "url_list"} {
		wrapper, ok := configs.Blocks[name].(schema.SingleNestedBlock)
		if !ok {
			t.Fatalf("%s block type = %T", name, configs.Blocks[name])
		}
		item, ok := wrapper.Blocks["item"].(schema.ListNestedBlock)
		if !ok {
			t.Fatalf("%s.item block type = %T", name, wrapper.Blocks["item"])
		}
		if _, exists := item.NestedObject.Attributes["idx"]; exists {
			t.Fatalf("%s.item exposes wire-only idx", name)
		}
		filter, ok := item.NestedObject.Attributes["filter"].(schema.BoolAttribute)
		if !ok || !filter.Optional || !filter.Computed || len(filter.PlanModifiers) != 1 {
			t.Fatalf("%s.item.filter = %#v", name, item.NestedObject.Attributes["filter"])
		}
		url, ok := item.NestedObject.Attributes["url"].(schema.StringAttribute)
		if !ok || !url.Required || len(url.Validators) != 2 {
			t.Fatalf("%s.item.url = %#v", name, item.NestedObject.Attributes["url"])
		}
		for _, optional := range []string{"name", "value"} {
			attribute, ok := item.NestedObject.Attributes[optional].(schema.StringAttribute)
			if !ok || !attribute.Optional || !attribute.Computed || len(attribute.PlanModifiers) != 1 {
				t.Fatalf("%s.item.%s = %#v", name, optional, item.NestedObject.Attributes[optional])
			}
		}
	}

	defaultModifier := csrfProtectionDefaultFalseModifier{}
	boolResponse := &planmodifier.BoolResponse{PlanValue: types.BoolValue(true)}
	defaultModifier.PlanModifyBool(context.Background(), planmodifier.BoolRequest{
		ConfigValue: types.BoolNull(),
		PlanValue:   types.BoolValue(true),
	}, boolResponse)
	if boolResponse.PlanValue.IsNull() || boolResponse.PlanValue.IsUnknown() || boolResponse.PlanValue.ValueBool() {
		t.Fatalf("defaulted filter = %#v", boolResponse.PlanValue)
	}

	clearModifier := csrfProtectionClearStringModifier{}
	stringResponse := &planmodifier.StringResponse{PlanValue: types.StringValue("prior")}
	clearModifier.PlanModifyString(context.Background(), planmodifier.StringRequest{
		ConfigValue: types.StringNull(),
		PlanValue:   types.StringValue("prior"),
	}, stringResponse)
	if !stringResponse.PlanValue.IsNull() {
		t.Fatalf("cleared optional string = %#v", stringResponse.PlanValue)
	}
}

func TestCSRFProtectionStrictScalarResultDecoding(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing action": `{"status":true}`,
		"null action":    `{"action":null,"status":true}`,
		"wrong action":   `{"action":"block","status":true}`,
		"action type":    `{"action":false,"status":true}`,
		"missing status": `{"action":"alert"}`,
		"null status":    `{"action":"alert","status":null}`,
		"status type":    `{"action":"alert","status":"true"}`,
	}
	for name, configs := range tests {
		configs := configs
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := csrfTestResult(t, configs, false)
			diagnostics := (csrfProtectionCodec{}).ValidateResult(context.Background(), result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
			if !diagnostics.HasError() {
				t.Fatal("ValidateResult() accepted malformed required scalars")
			}
		})
	}

	valid := csrfTestResult(t, `{"action":"deny_no_log","status":false}`, false)
	if diagnostics := (csrfProtectionCodec{}).ValidateResult(context.Background(), valid, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); diagnostics.HasError() {
		t.Fatalf("ValidateResult(valid) diagnostics = %v", diagnostics)
	}
}

func TestCSRFProtectionBuildPatchPreservesScalarAndListPresence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := csrfProtectionCodec{}.Schema(ctx)
	config := csrfTestResourceModel(t,
		types.StringNull(), types.BoolNull(),
		csrfTestWrapper(t, []csrfTestItem{}), types.ObjectNull(csrfProtectionWrapperAttributeTypes),
	)
	plan := csrfTestResourceModel(t,
		types.StringValue("alert"), types.BoolValue(true),
		csrfTestWrapper(t, []csrfTestItem{}), types.ObjectNull(csrfProtectionWrapperAttributeTypes),
	)
	patch, diagnostics := (csrfProtectionCodec{}).BuildPatch(ctx,
		csrfTestConfig(t, ctx, resourceSchema, config),
		csrfTestPlan(t, ctx, resourceSchema, plan),
		tfsdk.State{Schema: resourceSchema},
	)
	if diagnostics.HasError() {
		t.Fatalf("BuildPatch() diagnostics = %v", diagnostics)
	}
	result := csrfTestResult(t, `{"action":"alert_deny","status":true,"page_list":[{"idx":7,"filter":true,"url":"/old"}],"url_list":[{"idx":1,"filter":true,"url":"/opaque","future":true}],"future_config":{"keep":true}}`, false)
	beforeURL := append([]byte(nil), result.Configs["url_list"]...)
	if applyDiagnostics := patch.Apply(ctx, &result); applyDiagnostics.HasError() {
		t.Fatalf("Patch.Apply() diagnostics = %v", applyDiagnostics)
	}
	csrfAssertRawString(t, result.Configs["action"], "alert_deny")
	csrfAssertRawBool(t, result.Configs["status"], true)
	csrfAssertRawArrayLength(t, result.Configs["page_list"], 0)
	if string(result.Configs["url_list"]) != string(beforeURL) {
		t.Fatalf("omitted url_list changed: got %s want %s", result.Configs["url_list"], beforeURL)
	}
	if _, ok := result.Configs["future_config"]; !ok {
		t.Fatal("patch lost unknown top-level config data")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, ok := envelope["future_envelope"]; !ok {
		t.Fatal("patch lost unknown envelope data")
	}
}

func TestCSRFProtectionBuildPatchReplacesOrderedLists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := csrfProtectionCodec{}.Schema(ctx)
	configItems := []csrfTestItem{
		{Filter: types.BoolValue(false), URL: types.StringValue("/same"), Name: types.StringValue(""), Value: types.StringValue("")},
		{Filter: types.BoolNull(), URL: types.StringValue("/same"), Name: types.StringNull(), Value: types.StringNull()},
	}
	planItems := []csrfTestItem{
		configItems[0],
		{Filter: types.BoolValue(false), URL: types.StringValue("/same"), Name: types.StringNull(), Value: types.StringNull()},
	}
	config := csrfTestResourceModel(t, types.StringValue("alert"), types.BoolValue(false), csrfTestWrapper(t, configItems), csrfTestWrapper(t, configItems))
	plan := csrfTestResourceModel(t, types.StringValue("alert"), types.BoolValue(false), csrfTestWrapper(t, planItems), csrfTestWrapper(t, planItems))
	patch, diagnostics := (csrfProtectionCodec{}).BuildPatch(ctx,
		csrfTestConfig(t, ctx, resourceSchema, config), csrfTestPlan(t, ctx, resourceSchema, plan), tfsdk.State{Schema: resourceSchema})
	if diagnostics.HasError() {
		t.Fatalf("BuildPatch() diagnostics = %v", diagnostics)
	}
	result := csrfTestResult(t, `{"action":"alert","status":true,"page_list":[],"url_list":[]}`, false)
	if applyDiagnostics := patch.Apply(ctx, &result); applyDiagnostics.HasError() {
		t.Fatalf("Patch.Apply() diagnostics = %v", applyDiagnostics)
	}
	csrfAssertRawBool(t, result.Configs["status"], false)
	for _, listName := range []string{"page_list", "url_list"} {
		var items []map[string]json.RawMessage
		if err := json.Unmarshal(result.Configs[listName], &items); err != nil {
			t.Fatal(err)
		}
		if len(items) != 2 {
			t.Fatalf("%s length = %d, want 2", listName, len(items))
		}
		for index := range items {
			csrfAssertRawInt(t, items[index]["idx"], index+1)
			csrfAssertRawBool(t, items[index]["filter"], false)
			csrfAssertRawString(t, items[index]["url"], "/same")
		}
		csrfAssertRawString(t, items[0]["name"], "")
		csrfAssertRawString(t, items[0]["value"], "")
		if _, ok := items[1]["name"]; ok {
			t.Fatalf("%s second duplicate unexpectedly sent omitted name", listName)
		}
		if _, ok := items[1]["value"]; ok {
			t.Fatalf("%s second duplicate unexpectedly sent omitted value", listName)
		}
	}
}

func TestCSRFProtectionConfiguredValueConstraints(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := csrfProtectionCodec{}.Schema(ctx)
	tests := map[string]csrfTestItem{
		"missing url":  {Filter: types.BoolValue(false), URL: types.StringNull(), Name: types.StringNull(), Value: types.StringNull()},
		"url pattern":  {Filter: types.BoolValue(false), URL: types.StringValue("relative"), Name: types.StringNull(), Value: types.StringNull()},
		"url length":   {Filter: types.BoolValue(false), URL: types.StringValue("/" + strings.Repeat("x", 255)), Name: types.StringNull(), Value: types.StringNull()},
		"name length":  {Filter: types.BoolValue(false), URL: types.StringValue("/ok"), Name: types.StringValue(strings.Repeat("n", 64)), Value: types.StringNull()},
		"value length": {Filter: types.BoolValue(false), URL: types.StringValue("/ok"), Name: types.StringNull(), Value: types.StringValue(strings.Repeat("v", 256))},
	}
	for name, item := range tests {
		item := item
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			model := csrfTestResourceModel(t, types.StringValue("alert"), types.BoolValue(true), csrfTestWrapper(t, []csrfTestItem{item}), types.ObjectNull(csrfProtectionWrapperAttributeTypes))
			diagnostics := (csrfProtectionCodec{}).ValidateConfig(ctx, csrfTestConfig(t, ctx, resourceSchema, model))
			if !diagnostics.HasError() {
				t.Fatal("ValidateConfig() accepted an invalid configured item")
			}
		})
	}

	tooMany := make([]csrfTestItem, csrfProtectionPageListMaxItems+1)
	for index := range tooMany {
		tooMany[index] = csrfTestItem{Filter: types.BoolValue(false), URL: types.StringValue(fmt.Sprintf("/%d", index)), Name: types.StringNull(), Value: types.StringNull()}
	}
	model := csrfTestResourceModel(t, types.StringValue("alert"), types.BoolValue(true), csrfTestWrapper(t, tooMany), types.ObjectNull(csrfProtectionWrapperAttributeTypes))
	if diagnostics := (csrfProtectionCodec{}).ValidateConfig(ctx, csrfTestConfig(t, ctx, resourceSchema, model)); !diagnostics.HasError() {
		t.Fatal("ValidateConfig() accepted more than 256 items")
	}
}

func TestCSRFProtectionOwnedResultSortsIndicesAndAcceptsOptionalNulls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	result := csrfTestResult(t, `{"action":"alert","status":false,"page_list":[{"idx":2,"filter":false,"url":"/two","name":null,"value":null},{"idx":1,"filter":true,"url":"/one","name":"","value":""}],"url_list":[]}`, false)
	modelAny, diagnostics := (csrfProtectionCodec{}).Flatten(ctx, "ep-1", result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
	if diagnostics.HasError() {
		t.Fatalf("Flatten() diagnostics = %v", diagnostics)
	}
	model := modelAny.(*csrfProtectionResourceModel)
	configs := csrfDecodeConfigs(t, ctx, model.Configs)
	if configs.PageList.IsNull() || configs.URLList.IsNull() {
		t.Fatalf("import did not hydrate both wrappers: %#v", configs)
	}
	page := csrfDecodeWrapper(t, ctx, configs.PageList)
	var items []csrfProtectionItemModel
	if itemDiagnostics := page.Items.ElementsAs(ctx, &items, false); itemDiagnostics.HasError() {
		t.Fatalf("ElementsAs() diagnostics = %v", itemDiagnostics)
	}
	if len(items) != 2 || items[0].URL.ValueString() != "/one" || items[1].URL.ValueString() != "/two" {
		t.Fatalf("sorted items = %#v", items)
	}
	if items[0].Name.ValueString() != "" || items[0].Value.ValueString() != "" || !items[1].Name.IsNull() || !items[1].Value.IsNull() {
		t.Fatalf("optional string state = %#v", items)
	}
}

func TestCSRFProtectionRejectsInvalidOwnedIndices(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing":        `[{"filter":false,"url":"/x"}]`,
		"null":           `[{"idx":null,"filter":false,"url":"/x"}]`,
		"string":         `[{"idx":"1","filter":false,"url":"/x"}]`,
		"fraction":       `[{"idx":1.5,"filter":false,"url":"/x"}]`,
		"exponent":       `[{"idx":1e0,"filter":false,"url":"/x"}]`,
		"zero":           `[{"idx":0,"filter":false,"url":"/x"}]`,
		"negative":       `[{"idx":-1,"filter":false,"url":"/x"}]`,
		"duplicate":      `[{"idx":1,"filter":false,"url":"/x"},{"idx":1,"filter":true,"url":"/y"}]`,
		"missing filter": `[{"idx":1,"url":"/x"}]`,
		"missing url":    `[{"idx":1,"filter":false}]`,
	}
	for name, array := range tests {
		array := array
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := csrfTestResult(t, `{"action":"alert","status":true,"page_list":`+array+`,"url_list":[]}`, false)
			diagnostics := (csrfProtectionCodec{}).ValidateResult(context.Background(), result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
			if !diagnostics.HasError() {
				t.Fatal("ValidateResult() accepted malformed owned items")
			}
		})
	}
}

func TestCSRFProtectionUnknownItemKeysFailOnlyWhenOwned(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := csrfProtectionCodec{}.Schema(ctx)
	result := csrfTestResult(t, `{"action":"alert","status":true,"page_list":[{"idx":1,"filter":false,"url":"/opaque","future":{"keep":true}}],"url_list":[{"idx":1,"filter":false,"url":"/owned"}]}`, false)
	pageBefore := append([]byte(nil), result.Configs["page_list"]...)

	unownedModel := csrfTestResourceModel(t, types.StringNull(), types.BoolNull(), types.ObjectNull(csrfProtectionWrapperAttributeTypes), csrfTestWrapper(t, []csrfTestItem{}))
	ownership := wafmodule.OwnershipContext{Source: wafmodule.OwnershipConfigured, Config: csrfTestConfig(t, ctx, resourceSchema, unownedModel)}
	if diagnostics := (csrfProtectionCodec{}).ValidateResult(ctx, result, ownership); diagnostics.HasError() {
		t.Fatalf("ValidateResult(unowned page_list) diagnostics = %v", diagnostics)
	}
	modelAny, diagnostics := (csrfProtectionCodec{}).Flatten(ctx, "ep", result, ownership)
	if diagnostics.HasError() {
		t.Fatalf("Flatten(unowned page_list) diagnostics = %v", diagnostics)
	}
	configs := csrfDecodeConfigs(t, ctx, modelAny.(*csrfProtectionResourceModel).Configs)
	if !configs.PageList.IsNull() || configs.URLList.IsNull() {
		t.Fatalf("independent ownership = %#v", configs)
	}
	if string(result.Configs["page_list"]) != string(pageBefore) {
		t.Fatal("unowned raw array changed during validation/flatten")
	}

	ownedModel := csrfTestResourceModel(t, types.StringNull(), types.BoolNull(), csrfTestWrapper(t, []csrfTestItem{}), types.ObjectNull(csrfProtectionWrapperAttributeTypes))
	owned := wafmodule.OwnershipContext{Source: wafmodule.OwnershipConfigured, Config: csrfTestConfig(t, ctx, resourceSchema, ownedModel)}
	if diagnostics := (csrfProtectionCodec{}).ValidateResult(ctx, result, owned); !diagnostics.HasError() {
		t.Fatal("ValidateResult() accepted an unknown key in an owned array")
	}
	if diagnostics := (csrfProtectionCodec{}).ValidateResult(ctx, result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); !diagnostics.HasError() {
		t.Fatal("ValidateResult() accepted an unknown key during import hydration")
	}
}

func TestCSRFProtectionTemplateSuppressesConfigs(t *testing.T) {
	t.Parallel()

	result := csrfTestResult(t, `{"action":"alert","status":true,"page_list":[{"idx":null,"future":true}],"url_list":"opaque"}`, true)
	modelAny, diagnostics := (csrfProtectionCodec{}).Flatten(context.Background(), "ep", result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
	if diagnostics.HasError() {
		t.Fatalf("Flatten(template=true) diagnostics = %v", diagnostics)
	}
	model := modelAny.(*csrfProtectionResourceModel)
	if !model.Template.ValueBool() || !model.Configs.IsNull() {
		t.Fatalf("template state = %#v", model)
	}
}

func TestCSRFProtectionRemoteItemConstraints(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"url pattern":  `[{"idx":1,"filter":false,"url":"relative"}]`,
		"url length":   `[{"idx":1,"filter":false,"url":"/` + strings.Repeat("x", 255) + `"}]`,
		"name length":  `[{"idx":1,"filter":false,"url":"/ok","name":"` + strings.Repeat("n", 64) + `"}]`,
		"value length": `[{"idx":1,"filter":false,"url":"/ok","value":"` + strings.Repeat("v", 256) + `"}]`,
		"name type":    `[{"idx":1,"filter":false,"url":"/ok","name":false}]`,
		"null array":   `null`,
	}
	for name, array := range tests {
		array := array
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := csrfTestResult(t, `{"action":"alert","status":true,"page_list":`+array+`,"url_list":[]}`, false)
			if diagnostics := (csrfProtectionCodec{}).ValidateResult(context.Background(), result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); !diagnostics.HasError() {
				t.Fatal("ValidateResult() accepted invalid remote item data")
			}
		})
	}
}

type csrfTestItem struct {
	Filter types.Bool
	Name   types.String
	URL    types.String
	Value  types.String
}

func csrfTestResourceModel(t *testing.T, action types.String, status types.Bool, pageList, urlList types.Object) *csrfProtectionResourceModel {
	t.Helper()
	configs, diagnostics := types.ObjectValue(csrfProtectionConfigAttributeTypes, map[string]attr.Value{
		"action":    action,
		"page_list": pageList,
		"status":    status,
		"url_list":  urlList,
	})
	if diagnostics.HasError() {
		t.Fatalf("types.ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return &csrfProtectionResourceModel{
		EPID:     types.StringValue("ep"),
		Template: types.BoolValue(false),
		Configs:  configs,
	}
}

func csrfTestWrapper(t *testing.T, items []csrfTestItem) types.Object {
	t.Helper()
	elements := make([]attr.Value, 0, len(items))
	for _, item := range items {
		object, diagnostics := types.ObjectValue(csrfProtectionItemAttributeTypes, map[string]attr.Value{
			"filter": item.Filter,
			"name":   item.Name,
			"url":    item.URL,
			"value":  item.Value,
		})
		if diagnostics.HasError() {
			t.Fatalf("types.ObjectValue(item) diagnostics = %v", diagnostics)
		}
		elements = append(elements, object)
	}
	list, diagnostics := types.ListValue(types.ObjectType{AttrTypes: csrfProtectionItemAttributeTypes}, elements)
	if diagnostics.HasError() {
		t.Fatalf("types.ListValue() diagnostics = %v", diagnostics)
	}
	wrapper, diagnostics := types.ObjectValue(csrfProtectionWrapperAttributeTypes, map[string]attr.Value{"item": list})
	if diagnostics.HasError() {
		t.Fatalf("types.ObjectValue(wrapper) diagnostics = %v", diagnostics)
	}
	return wrapper
}

func csrfTestConfig(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Config {
	t.Helper()
	state := tfsdk.State{Schema: resourceSchema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("State.Set(config) diagnostics = %v", diagnostics)
	}
	return tfsdk.Config{Schema: resourceSchema, Raw: state.Raw.Copy()}
}

func csrfTestPlan(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Plan {
	t.Helper()
	plan := tfsdk.Plan{Schema: resourceSchema}
	if diagnostics := plan.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("Plan.Set() diagnostics = %v", diagnostics)
	}
	return plan
}

func csrfTestResult(t *testing.T, configs string, template bool) client.WAFModuleResult {
	t.Helper()
	payload := fmt.Sprintf(`{"result":{"configs":%s,"template":%t,"future_envelope":{"keep":true}}}`, configs, template)
	var document client.WAFModuleDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(result) error = %v; payload=%s", err, payload)
	}
	return document.Result
}

func csrfDecodeConfigs(t *testing.T, ctx context.Context, object types.Object) csrfProtectionConfigsModel {
	t.Helper()
	var configs csrfProtectionConfigsModel
	if diagnostics := object.As(ctx, &configs, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("configs.As() diagnostics = %v", diagnostics)
	}
	return configs
}

func csrfDecodeWrapper(t *testing.T, ctx context.Context, object types.Object) csrfProtectionWrapperModel {
	t.Helper()
	var wrapper csrfProtectionWrapperModel
	if diagnostics := object.As(ctx, &wrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("wrapper.As() diagnostics = %v", diagnostics)
	}
	return wrapper
}

func csrfAssertRawString(t *testing.T, raw json.RawMessage, want string) {
	t.Helper()
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("string = %q, want %q", got, want)
	}
}

func csrfAssertRawBool(t *testing.T, raw json.RawMessage, want bool) {
	t.Helper()
	var got bool
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("bool = %t, want %t", got, want)
	}
}

func csrfAssertRawInt(t *testing.T, raw json.RawMessage, want int) {
	t.Helper()
	var got int
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("int = %d, want %d", got, want)
	}
}

func csrfAssertRawArrayLength(t *testing.T, raw json.RawMessage, want int) {
	t.Helper()
	var got []json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if len(got) != want {
		t.Fatalf("array length = %d, want %d", len(got), want)
	}
}

func TestCSRFProtectionRegistryIsUnique(t *testing.T) {
	t.Parallel()

	descriptor := csrfProtectionDescriptor()
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("descriptor.Validate() error = %v", err)
	}
	if descriptor.TypeNameSuffix != "waf_csrf_protection" || descriptor.Endpoint.Path != "/waf/apps/{ep_id}/csrf_protection" || descriptor.Endpoint.Operation != "CSRF protection" || descriptor.Destroy.Mode != wafmodule.DestroyDisable || !descriptor.Destroy.Verified || descriptor.Destroy.Field != "status" {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	templateDescriptor := csrfProtectionTemplateDescriptor()
	if err := templateDescriptor.Validate(); err != nil {
		t.Fatalf("template descriptor.Validate() error = %v", err)
	}
	if templateDescriptor.TypeNameSuffix != "waf_template_csrf_protection" ||
		templateDescriptor.Endpoint.Path != "/waf/template/{template_id}/csrf_protection" ||
		templateDescriptor.Destroy.Mode != wafmodule.DestroyDisable || !templateDescriptor.Destroy.Verified ||
		templateDescriptor.Destroy.Field != "status" {
		t.Fatalf("template descriptor = %#v", templateDescriptor)
	}

	constructors := Resources(nil)
	if len(constructors) != 50 {
		t.Fatalf("Resources() = %d, want 50", len(constructors))
	}
	ctx := context.Background()
	seen := map[string]struct{}{}
	for _, constructor := range constructors {
		var response struct{ TypeName string }
		resource := constructor()
		var metadataResponse = csrfMetadataResponse(resource, ctx)
		response.TypeName = metadataResponse
		if _, duplicate := seen[response.TypeName]; duplicate {
			t.Fatalf("duplicate generated resource %q", response.TypeName)
		}
		seen[response.TypeName] = struct{}{}
	}
	for _, name := range []string{
		"fortiappseccloud_waf_csrf_protection",
		"fortiappseccloud_waf_request_limits",
		"fortiappseccloud_waf_url_access",
		"fortiappseccloud_waf_known_attacks",
		"fortiappseccloud_waf_http_header_security",
		"fortiappseccloud_waf_graphql_protection",
		"fortiappseccloud_waf_json_protection",
		"fortiappseccloud_waf_template_csrf_protection",
		"fortiappseccloud_waf_template_url_access",
		"fortiappseccloud_waf_template_json_protection",
	} {
		if _, ok := seen[name]; !ok {
			t.Fatalf("generated resource names = %#v", reflect.ValueOf(seen).MapKeys())
		}
	}
}

func csrfMetadataResponse(implementation interface {
	Metadata(context.Context, resource.MetadataRequest, *resource.MetadataResponse)
}, ctx context.Context) string {
	var response resource.MetadataResponse
	implementation.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &response)
	return response.TypeName
}
