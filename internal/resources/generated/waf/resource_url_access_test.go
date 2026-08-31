package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/resources/wafmodule"
)

func TestURLAccessSchemaUsesProtocol5OwnershipBlocks(t *testing.T) {
	t.Parallel()

	resourceSchema := urlAccessCodec{}.Schema(context.Background())
	configs, ok := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	if !ok {
		t.Fatalf("configs block type = %T", resourceSchema.Blocks["configs"])
	}
	wrapper, ok := configs.Blocks["rule_list"].(schema.SingleNestedBlock)
	if !ok {
		t.Fatalf("rule_list block type = %T", configs.Blocks["rule_list"])
	}
	item, ok := wrapper.Blocks["item"].(schema.ListNestedBlock)
	if !ok {
		t.Fatalf("rule_list.item block type = %T", wrapper.Blocks["item"])
	}
	if _, exists := item.NestedObject.Attributes["idx"]; exists {
		t.Fatal("rule_list.item exposes wire-only idx")
	}
	for _, required := range []string{"action", "name", "url", "url_type"} {
		attribute, ok := item.NestedObject.Attributes[required].(schema.StringAttribute)
		if !ok || !attribute.Required {
			t.Fatalf("rule_list.item.%s = %#v", required, item.NestedObject.Attributes[required])
		}
	}
	action, ok := item.NestedObject.Attributes["action"].(schema.StringAttribute)
	if !ok || len(action.Validators) != 1 {
		t.Fatalf("rule_list.item.action validators = %#v", item.NestedObject.Attributes["action"])
	}
	name, ok := item.NestedObject.Attributes["name"].(schema.StringAttribute)
	if !ok || len(name.Validators) != 1 {
		t.Fatalf("rule_list.item.name validators = %#v", item.NestedObject.Attributes["name"])
	}
	url, ok := item.NestedObject.Attributes["url"].(schema.StringAttribute)
	if !ok || len(url.Validators) != 1 {
		t.Fatalf("rule_list.item.url validators = %#v", item.NestedObject.Attributes["url"])
	}
	urlType, ok := item.NestedObject.Attributes["url_type"].(schema.StringAttribute)
	if !ok || len(urlType.Validators) != 1 {
		t.Fatalf("rule_list.item.url_type validators = %#v", item.NestedObject.Attributes["url_type"])
	}
	if len(item.Validators) != 1 {
		t.Fatalf("rule_list.item list validators = %#v", item.Validators)
	}
}

func TestURLAccessStrictScalarResultDecoding(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing status": `{"status":null}`,
		"null status":    `{"status":null}`,
		"status type":    `{"status":"true"}`,
		"status object":  `{"status":{"ok":true}}`,
		"empty configs":  `{}`,
	}
	for name, configs := range tests {
		configs := configs
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := urlAccessTestResult(t, configs, false)
			diagnostics := (urlAccessCodec{}).ValidateResult(context.Background(), result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
			if !diagnostics.HasError() {
				t.Fatal("ValidateResult() accepted malformed status scalar")
			}
		})
	}

	valid := urlAccessTestResult(t, `{"status":false}`, false)
	if diagnostics := (urlAccessCodec{}).ValidateResult(context.Background(), valid, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); diagnostics.HasError() {
		t.Fatalf("ValidateResult(valid) diagnostics = %v", diagnostics)
	}
}

func TestURLAccessBuildPatchPreservesScalarAndListPresence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := urlAccessCodec{}.Schema(ctx)
	config := urlAccessTestResourceModel(t, types.BoolValue(true), types.ObjectNull(urlAccessWrapperAttributeTypes))
	plan := urlAccessTestResourceModel(t, types.BoolValue(true), types.ObjectNull(urlAccessWrapperAttributeTypes))
	patch, diagnostics := (urlAccessCodec{}).BuildPatch(ctx,
		urlAccessTestConfig(t, ctx, resourceSchema, config),
		urlAccessTestPlan(t, ctx, resourceSchema, plan),
		tfsdk.State{Schema: resourceSchema},
	)
	if diagnostics.HasError() {
		t.Fatalf("BuildPatch() diagnostics = %v", diagnostics)
	}
	result := urlAccessTestResult(t, `{"status":true,"rule_list":[{"idx":7,"action":"pass","name":"opaque","url":"/opaque","future":true}],"future_config":{"keep":true}}`, false)
	beforeRule := append([]byte(nil), result.Configs["rule_list"]...)
	if applyDiagnostics := patch.Apply(ctx, &result); applyDiagnostics.HasError() {
		t.Fatalf("Patch.Apply() diagnostics = %v", applyDiagnostics)
	}
	urlAccessAssertRawBool(t, result.Configs["status"], true)
	if string(result.Configs["rule_list"]) != string(beforeRule) {
		t.Fatalf("omitted rule_list changed: got %s want %s", result.Configs["rule_list"], beforeRule)
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

func TestURLAccessBuildPatchEmptyWrapperSendsEmptyArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := urlAccessCodec{}.Schema(ctx)
	config := urlAccessTestResourceModel(t, types.BoolValue(false), urlAccessTestWrapper(t, []urlAccessTestItem{}))
	plan := urlAccessTestResourceModel(t, types.BoolValue(false), urlAccessTestWrapper(t, []urlAccessTestItem{}))
	patch, diagnostics := (urlAccessCodec{}).BuildPatch(ctx,
		urlAccessTestConfig(t, ctx, resourceSchema, config),
		urlAccessTestPlan(t, ctx, resourceSchema, plan),
		tfsdk.State{Schema: resourceSchema},
	)
	if diagnostics.HasError() {
		t.Fatalf("BuildPatch() diagnostics = %v", diagnostics)
	}
	result := urlAccessTestResult(t, `{"status":true,"rule_list":[{"idx":1,"action":"pass","name":"drop","url":"/old"}]}`, false)
	if applyDiagnostics := patch.Apply(ctx, &result); applyDiagnostics.HasError() {
		t.Fatalf("Patch.Apply() diagnostics = %v", applyDiagnostics)
	}
	urlAccessAssertRawBool(t, result.Configs["status"], false)
	urlAccessAssertRawArrayLength(t, result.Configs["rule_list"], 0)
}

func TestURLAccessBuildPatchReplacesOrderedLists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := urlAccessCodec{}.Schema(ctx)
	configItems := []urlAccessTestItem{
		{Action: types.StringValue("pass"), Name: types.StringValue("first"), URL: types.StringValue("/same"), URLType: types.StringValue("string")},
		{Action: types.StringValue("deny_no_log"), Name: types.StringValue("second"), URL: types.StringValue("^/api/(login|v1/.*)$"), URLType: types.StringValue("regex")},
	}
	config := urlAccessTestResourceModel(t, types.BoolValue(false), urlAccessTestWrapper(t, configItems))
	plan := urlAccessTestResourceModel(t, types.BoolValue(false), urlAccessTestWrapper(t, configItems))
	patch, diagnostics := (urlAccessCodec{}).BuildPatch(ctx,
		urlAccessTestConfig(t, ctx, resourceSchema, config), urlAccessTestPlan(t, ctx, resourceSchema, plan), tfsdk.State{Schema: resourceSchema})
	if diagnostics.HasError() {
		t.Fatalf("BuildPatch() diagnostics = %v", diagnostics)
	}
	result := urlAccessTestResult(t, `{"status":true,"rule_list":[]}`, false)
	if applyDiagnostics := patch.Apply(ctx, &result); applyDiagnostics.HasError() {
		t.Fatalf("Patch.Apply() diagnostics = %v", applyDiagnostics)
	}
	urlAccessAssertRawBool(t, result.Configs["status"], false)
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(result.Configs["rule_list"], &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("rule_list length = %d, want 2", len(items))
	}
	for index := range items {
		urlAccessAssertRawInt(t, items[index]["idx"], index+1)
	}
	urlAccessAssertRawString(t, items[0]["action"], "pass")
	urlAccessAssertRawString(t, items[0]["name"], "first")
	urlAccessAssertRawString(t, items[0]["url"], "/same")
	urlAccessAssertRawString(t, items[0]["url_type"], "string")
	urlAccessAssertRawString(t, items[1]["action"], "deny_no_log")
	urlAccessAssertRawString(t, items[1]["name"], "second")
	urlAccessAssertRawString(t, items[1]["url"], "^/api/(login|v1/.*)$")
	urlAccessAssertRawString(t, items[1]["url_type"], "regex")
	if _, ok := items[0]["future"]; ok {
		t.Fatal("patched items carried unexpected future keys")
	}
}

func TestURLAccessConfiguredValueConstraints(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := urlAccessCodec{}.Schema(ctx)
	tests := map[string]urlAccessTestItem{
		"missing action":   {Action: types.StringNull(), Name: types.StringValue("n"), URL: types.StringValue("/ok"), URLType: types.StringValue("string")},
		"missing name":     {Action: types.StringValue("pass"), Name: types.StringNull(), URL: types.StringValue("/ok"), URLType: types.StringValue("string")},
		"missing url":      {Action: types.StringValue("pass"), Name: types.StringValue("n"), URL: types.StringNull(), URLType: types.StringValue("string")},
		"invalid action":   {Action: types.StringValue("block"), Name: types.StringValue("n"), URL: types.StringValue("/ok"), URLType: types.StringValue("string")},
		"name length":      {Action: types.StringValue("pass"), Name: types.StringValue(strings.Repeat("n", 40)), URL: types.StringValue("/ok"), URLType: types.StringValue("string")},
		"url length":       {Action: types.StringValue("pass"), Name: types.StringValue("n"), URL: types.StringValue("/" + strings.Repeat("x", 255)), URLType: types.StringValue("string")},
		"missing url_type": {Action: types.StringValue("pass"), Name: types.StringValue("n"), URL: types.StringValue("/ok"), URLType: types.StringNull()},
		"invalid url_type": {Action: types.StringValue("pass"), Name: types.StringValue("n"), URL: types.StringValue("/ok"), URLType: types.StringValue("glob")},
	}
	for name, item := range tests {
		item := item
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			model := urlAccessTestResourceModel(t, types.BoolValue(true), urlAccessTestWrapper(t, []urlAccessTestItem{item}))
			diagnostics := (urlAccessCodec{}).ValidateConfig(ctx, urlAccessTestConfig(t, ctx, resourceSchema, model))
			if !diagnostics.HasError() {
				t.Fatal("ValidateConfig() accepted an invalid configured item")
			}
		})
	}

	tooMany := make([]urlAccessTestItem, urlAccessRuleListMaxItems+1)
	for index := range tooMany {
		tooMany[index] = urlAccessTestItem{Action: types.StringValue("pass"), Name: types.StringValue("n"), URL: types.StringValue(fmt.Sprintf("/%d", index)), URLType: types.StringValue("string")}
	}
	model := urlAccessTestResourceModel(t, types.BoolValue(true), urlAccessTestWrapper(t, tooMany))
	if diagnostics := (urlAccessCodec{}).ValidateConfig(ctx, urlAccessTestConfig(t, ctx, resourceSchema, model)); !diagnostics.HasError() {
		t.Fatalf("ValidateConfig() accepted more than %d items", urlAccessRuleListMaxItems)
	}
}

func TestURLAccessOwnedResultSortsIndices(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	result := urlAccessTestResult(t, `{"status":false,"rule_list":[{"idx":2,"action":"pass","name":"two","url":"/two","url_type":"string"},{"idx":1,"action":"alert_deny","name":"one","url":"/one","url_type":"regex"}]}`, false)
	modelAny, diagnostics := (urlAccessCodec{}).Flatten(ctx, "ep-1", result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
	if diagnostics.HasError() {
		t.Fatalf("Flatten() diagnostics = %v", diagnostics)
	}
	model := modelAny.(*urlAccessResourceModel)
	configs := urlAccessDecodeConfigs(t, ctx, model.Configs)
	if configs.RuleList.IsNull() {
		t.Fatalf("import did not hydrate rule_list: %#v", configs)
	}
	wrapper := urlAccessDecodeWrapper(t, ctx, configs.RuleList)
	var items []urlAccessItemModel
	if itemDiagnostics := wrapper.Items.ElementsAs(ctx, &items, false); itemDiagnostics.HasError() {
		t.Fatalf("ElementsAs() diagnostics = %v", itemDiagnostics)
	}
	if len(items) != 2 || items[0].URL.ValueString() != "/one" || items[1].URL.ValueString() != "/two" {
		t.Fatalf("sorted items = %#v", items)
	}
	if items[0].Action.ValueString() != "alert_deny" || items[0].Name.ValueString() != "one" || items[0].URLType.ValueString() != "regex" {
		t.Fatalf("first item fields = %#v", items[0])
	}
	if items[1].Action.ValueString() != "pass" || items[1].Name.ValueString() != "two" || items[1].URLType.ValueString() != "string" {
		t.Fatalf("second item fields = %#v", items[1])
	}
}

func TestURLAccessRejectsInvalidOwnedIndices(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing":          `[{"action":"pass","name":"n","url":"/x","url_type":"string"}]`,
		"null":             `[{"idx":null,"action":"pass","name":"n","url":"/x","url_type":"string"}]`,
		"string":           `[{"idx":"1","action":"pass","name":"n","url":"/x","url_type":"string"}]`,
		"fraction":         `[{"idx":1.5,"action":"pass","name":"n","url":"/x","url_type":"string"}]`,
		"exponent":         `[{"idx":1e0,"action":"pass","name":"n","url":"/x","url_type":"string"}]`,
		"zero":             `[{"idx":0,"action":"pass","name":"n","url":"/x","url_type":"string"}]`,
		"negative":         `[{"idx":-1,"action":"pass","name":"n","url":"/x","url_type":"string"}]`,
		"duplicate":        `[{"idx":1,"action":"pass","name":"n","url":"/x","url_type":"string"},{"idx":1,"action":"deny_no_log","name":"m","url":"/y","url_type":"string"}]`,
		"missing action":   `[{"idx":1,"name":"n","url":"/x","url_type":"string"}]`,
		"missing name":     `[{"idx":1,"action":"pass","url":"/x","url_type":"string"}]`,
		"missing url":      `[{"idx":1,"action":"pass","name":"n","url_type":"string"}]`,
		"action type":      `[{"idx":1,"action":false,"name":"n","url":"/x","url_type":"string"}]`,
		"name type":        `[{"idx":1,"action":"pass","name":false,"url":"/x","url_type":"string"}]`,
		"url type":         `[{"idx":1,"action":"pass","name":"n","url":false,"url_type":"string"}]`,
		"invalid action":   `[{"idx":1,"action":"block","name":"n","url":"/x","url_type":"string"}]`,
		"missing url_type": `[{"idx":1,"action":"pass","name":"n","url":"/x"}]`,
		"null url_type":    `[{"idx":1,"action":"pass","name":"n","url":"/x","url_type":null}]`,
		"url_type type":    `[{"idx":1,"action":"pass","name":"n","url":"/x","url_type":false}]`,
		"invalid url_type": `[{"idx":1,"action":"pass","name":"n","url":"/x","url_type":"glob"}]`,
	}
	for name, array := range tests {
		array := array
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := urlAccessTestResult(t, `{"status":true,"rule_list":`+array+`}`, false)
			diagnostics := (urlAccessCodec{}).ValidateResult(context.Background(), result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
			if !diagnostics.HasError() {
				t.Fatal("ValidateResult() accepted malformed owned items")
			}
		})
	}
}

func TestURLAccessRejectsTooManyRemoteItems(t *testing.T) {
	t.Parallel()

	items := make([]string, urlAccessRuleListMaxItems+1)
	for index := range items {
		items[index] = fmt.Sprintf(`{"idx":%d,"action":"pass","name":"n%d","url":"/%d","url_type":"string"}`, index+1, index, index)
	}
	array := "[" + strings.Join(items, ",") + "]"
	result := urlAccessTestResult(t, `{"status":true,"rule_list":`+array+`}`, false)
	if diagnostics := (urlAccessCodec{}).ValidateResult(context.Background(), result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); !diagnostics.HasError() {
		t.Fatalf("ValidateResult() accepted more than %d remote items", urlAccessRuleListMaxItems)
	}
}

func TestURLAccessUnknownItemKeysFailOnlyWhenOwned(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := urlAccessCodec{}.Schema(ctx)
	result := urlAccessTestResult(t, `{"status":true,"rule_list":[{"idx":1,"action":"pass","name":"n","url":"/opaque","url_type":"string","future":{"keep":true}}]}`, false)
	ruleBefore := append([]byte(nil), result.Configs["rule_list"]...)

	unownedModel := urlAccessTestResourceModel(t, types.BoolNull(), types.ObjectNull(urlAccessWrapperAttributeTypes))
	ownership := wafmodule.OwnershipContext{Source: wafmodule.OwnershipConfigured, Config: urlAccessTestConfig(t, ctx, resourceSchema, unownedModel)}
	if diagnostics := (urlAccessCodec{}).ValidateResult(ctx, result, ownership); diagnostics.HasError() {
		t.Fatalf("ValidateResult(unowned rule_list) diagnostics = %v", diagnostics)
	}
	modelAny, diagnostics := (urlAccessCodec{}).Flatten(ctx, "ep", result, ownership)
	if diagnostics.HasError() {
		t.Fatalf("Flatten(unowned rule_list) diagnostics = %v", diagnostics)
	}
	configs := urlAccessDecodeConfigs(t, ctx, modelAny.(*urlAccessResourceModel).Configs)
	if !configs.RuleList.IsNull() {
		t.Fatalf("unowned rule_list was hydrated: %#v", configs)
	}
	if string(result.Configs["rule_list"]) != string(ruleBefore) {
		t.Fatal("unowned raw array changed during validation/flatten")
	}

	ownedModel := urlAccessTestResourceModel(t, types.BoolNull(), urlAccessTestWrapper(t, []urlAccessTestItem{}))
	owned := wafmodule.OwnershipContext{Source: wafmodule.OwnershipConfigured, Config: urlAccessTestConfig(t, ctx, resourceSchema, ownedModel)}
	if diagnostics := (urlAccessCodec{}).ValidateResult(ctx, result, owned); !diagnostics.HasError() {
		t.Fatal("ValidateResult() accepted an unknown key in an owned array")
	}
	if diagnostics := (urlAccessCodec{}).ValidateResult(ctx, result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); !diagnostics.HasError() {
		t.Fatal("ValidateResult() accepted an unknown key during import hydration")
	}
}

func TestURLAccessURLTypeAcceptedAsKnownWhileUnknownKeysFail(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// Both enum values (string and regex) are accepted as known item keys.
	// The regex value below is a clearly compilable RE2 expression; the
	// provider does not validate the regex server-side, only the enum.
	for _, urlType := range []string{"string", "regex"} {
		urlType := urlType
		t.Run(urlType, func(t *testing.T) {
			t.Parallel()
			result := urlAccessTestResult(t, `{"status":true,"rule_list":[{"idx":1,"action":"pass","name":"n","url":"/x","url_type":"`+urlType+`"}]}`, false)
			if diagnostics := (urlAccessCodec{}).ValidateResult(ctx, result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); diagnostics.HasError() {
				t.Fatalf("ValidateResult(url_type=%q) diagnostics = %v", urlType, diagnostics)
			}
			modelAny, diagnostics := (urlAccessCodec{}).Flatten(ctx, "ep", result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
			if diagnostics.HasError() {
				t.Fatalf("Flatten(url_type=%q) diagnostics = %v", urlType, diagnostics)
			}
			configs := urlAccessDecodeConfigs(t, ctx, modelAny.(*urlAccessResourceModel).Configs)
			wrapper := urlAccessDecodeWrapper(t, ctx, configs.RuleList)
			var items []urlAccessItemModel
			if diag := wrapper.Items.ElementsAs(ctx, &items, false); diag.HasError() {
				t.Fatalf("ElementsAs() diagnostics = %v", diag)
			}
			if len(items) != 1 || items[0].URLType.ValueString() != urlType {
				t.Fatalf("flattened url_type item = %#v", items)
			}
		})
	}

	// url_type is a known key, but an unrelated unknown key still fails closed
	// when the collection is owned/imported.
	result := urlAccessTestResult(t, `{"status":true,"rule_list":[{"idx":1,"action":"pass","name":"n","url":"/x","url_type":"string","mystery":true}]}`, false)
	if diagnostics := (urlAccessCodec{}).ValidateResult(ctx, result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); !diagnostics.HasError() {
		t.Fatal("ValidateResult() accepted an unrelated unknown key alongside a known url_type")
	}
}

func TestURLAccessTemplateSuppressesConfigs(t *testing.T) {
	t.Parallel()

	result := urlAccessTestResult(t, `{"status":true,"rule_list":[{"idx":null,"future":true}]}`, true)
	modelAny, diagnostics := (urlAccessCodec{}).Flatten(context.Background(), "ep", result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported})
	if diagnostics.HasError() {
		t.Fatalf("Flatten(template=true) diagnostics = %v", diagnostics)
	}
	model := modelAny.(*urlAccessResourceModel)
	if !model.Template.ValueBool() || !model.Configs.IsNull() {
		t.Fatalf("template state = %#v", model)
	}
}

func TestURLAccessRemoteItemConstraints(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"action type":      `[{"idx":1,"action":false,"name":"n","url":"/ok","url_type":"string"}]`,
		"name type":        `[{"idx":1,"action":"pass","name":false,"url":"/ok","url_type":"string"}]`,
		"url type":         `[{"idx":1,"action":"pass","name":"n","url":false,"url_type":"string"}]`,
		"invalid action":   `[{"idx":1,"action":"block","name":"n","url":"/ok","url_type":"string"}]`,
		"name length":      `[{"idx":1,"action":"pass","name":"` + strings.Repeat("n", 40) + `","url":"/ok","url_type":"string"}]`,
		"url length":       `[{"idx":1,"action":"pass","name":"n","url":"/` + strings.Repeat("x", 255) + `","url_type":"string"}]`,
		"missing url_type": `[{"idx":1,"action":"pass","name":"n","url":"/ok"}]`,
		"invalid url_type": `[{"idx":1,"action":"pass","name":"n","url":"/ok","url_type":"glob"}]`,
		"null array":       `null`,
		"non-array":        `"opaque"`,
		"object item":      `{"idx":1}`,
	}
	for name, array := range tests {
		array := array
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := urlAccessTestResult(t, `{"status":true,"rule_list":`+array+`}`, false)
			if diagnostics := (urlAccessCodec{}).ValidateResult(context.Background(), result, wafmodule.OwnershipContext{Source: wafmodule.OwnershipImported}); !diagnostics.HasError() {
				t.Fatal("ValidateResult() accepted invalid remote item data")
			}
		})
	}
}

func TestURLAccessDescriptorMetadata(t *testing.T) {
	t.Parallel()

	descriptor := urlAccessDescriptor()
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("descriptor.Validate() error = %v", err)
	}
	if descriptor.TypeNameSuffix != "waf_url_access" || descriptor.Endpoint.Path != "/waf/apps/{ep_id}/url_access" || descriptor.Endpoint.Operation != "URL access" {
		t.Fatalf("descriptor metadata = %#v", descriptor)
	}
	if descriptor.Destroy.Mode != wafmodule.DestroyDisable || !descriptor.Destroy.Verified ||
		descriptor.Destroy.Field != "status" {
		t.Fatalf("destroy policy = %#v", descriptor.Destroy)
	}
	if strings.TrimSpace(descriptor.Destroy.Reason) == "" {
		t.Fatal("disable destroy policy must include verification provenance")
	}
}

type urlAccessTestItem struct {
	Action  types.String
	Name    types.String
	URL     types.String
	URLType types.String
}

func urlAccessTestResourceModel(t *testing.T, status types.Bool, ruleList types.Object) *urlAccessResourceModel {
	t.Helper()
	configs, diagnostics := types.ObjectValue(urlAccessConfigAttributeTypes, map[string]attr.Value{
		"status":    status,
		"rule_list": ruleList,
	})
	if diagnostics.HasError() {
		t.Fatalf("types.ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return &urlAccessResourceModel{
		EPID:     types.StringValue("ep"),
		Template: types.BoolValue(false),
		Configs:  configs,
	}
}

func urlAccessTestWrapper(t *testing.T, items []urlAccessTestItem) types.Object {
	t.Helper()
	elements := make([]attr.Value, 0, len(items))
	for _, item := range items {
		object, diagnostics := types.ObjectValue(urlAccessItemAttributeTypes, map[string]attr.Value{
			"action":   item.Action,
			"name":     item.Name,
			"url":      item.URL,
			"url_type": item.URLType,
		})
		if diagnostics.HasError() {
			t.Fatalf("types.ObjectValue(item) diagnostics = %v", diagnostics)
		}
		elements = append(elements, object)
	}
	list, diagnostics := types.ListValue(types.ObjectType{AttrTypes: urlAccessItemAttributeTypes}, elements)
	if diagnostics.HasError() {
		t.Fatalf("types.ListValue() diagnostics = %v", diagnostics)
	}
	wrapper, diagnostics := types.ObjectValue(urlAccessWrapperAttributeTypes, map[string]attr.Value{"item": list})
	if diagnostics.HasError() {
		t.Fatalf("types.ObjectValue(wrapper) diagnostics = %v", diagnostics)
	}
	return wrapper
}

func urlAccessTestConfig(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Config {
	t.Helper()
	state := tfsdk.State{Schema: resourceSchema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("State.Set(config) diagnostics = %v", diagnostics)
	}
	return tfsdk.Config{Schema: resourceSchema, Raw: state.Raw.Copy()}
}

func urlAccessTestPlan(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Plan {
	t.Helper()
	plan := tfsdk.Plan{Schema: resourceSchema}
	if diagnostics := plan.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("Plan.Set() diagnostics = %v", diagnostics)
	}
	return plan
}

func urlAccessTestResult(t *testing.T, configs string, template bool) client.WAFModuleResult {
	t.Helper()
	payload := fmt.Sprintf(`{"result":{"configs":%s,"template":%t,"future_envelope":{"keep":true}}}`, configs, template)
	var document client.WAFModuleDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(result) error = %v; payload=%s", err, payload)
	}
	return document.Result
}

func urlAccessDecodeConfigs(t *testing.T, ctx context.Context, object types.Object) urlAccessConfigsModel {
	t.Helper()
	var configs urlAccessConfigsModel
	if diagnostics := object.As(ctx, &configs, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("configs.As() diagnostics = %v", diagnostics)
	}
	return configs
}

func urlAccessDecodeWrapper(t *testing.T, ctx context.Context, object types.Object) urlAccessWrapperModel {
	t.Helper()
	var wrapper urlAccessWrapperModel
	if diagnostics := object.As(ctx, &wrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("wrapper.As() diagnostics = %v", diagnostics)
	}
	return wrapper
}

func urlAccessAssertRawString(t *testing.T, raw json.RawMessage, want string) {
	t.Helper()
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("string = %q, want %q", got, want)
	}
}

func urlAccessAssertRawBool(t *testing.T, raw json.RawMessage, want bool) {
	t.Helper()
	var got bool
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("bool = %t, want %t", got, want)
	}
}

func urlAccessAssertRawInt(t *testing.T, raw json.RawMessage, want int) {
	t.Helper()
	var got int
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("int = %d, want %d", got, want)
	}
}

func urlAccessAssertRawArrayLength(t *testing.T, raw json.RawMessage, want int) {
	t.Helper()
	var got []json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if len(got) != want {
		t.Fatalf("array length = %d, want %d", len(got), want)
	}
}
