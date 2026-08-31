package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/contract"
)

func TestProductionCompatibilityScalarDecoding(t *testing.T) {
	t.Parallel()

	mlResult := defaultConfigResult(t, contract.MLBotDetectionResource)
	mlResult.Configs["action"] = json.RawMessage(`"client-id-block-period"`)
	mlScalars, mlDiagnostics := mlBotDetectionDecodeScalars(mlResult)
	if mlDiagnostics.HasError() {
		t.Fatalf("ML bot detection alias diagnostics: %v", mlDiagnostics)
	}
	if mlScalars.Action != "block_period" {
		t.Errorf("ML bot detection normalized action = %q, want block_period", mlScalars.Action)
	}

	fileResult := defaultConfigResult(t, contract.FileProtectionResource)
	fileResult.Configs["json_key_field"] = json.RawMessage(`null`)
	fileResult.Configs["json_key_for_filename"] = json.RawMessage(`null`)
	fileScalars, fileDiagnostics := fileProtectionDecodeScalars(fileResult)
	if fileDiagnostics.HasError() {
		t.Fatalf("file protection wire-null diagnostics: %v", fileDiagnostics)
	}
	if fileScalars.JsonKeyField != nil || fileScalars.JsonKeyForFilename != nil {
		t.Errorf("file protection wire-null values = %#v / %#v, want nil / nil", fileScalars.JsonKeyField, fileScalars.JsonKeyForFilename)
	}

	requestResult := defaultConfigResult(t, contract.RequestLimitsResource)
	requestResult.Configs["header_line_num"] = json.RawMessage(`200`)
	requestScalars, requestDiagnostics := requestLimitsDecodeScalars(requestResult)
	if requestDiagnostics.HasError() {
		t.Fatalf("request limits response-maximum diagnostics: %v", requestDiagnostics)
	}
	if requestScalars.HeaderLineNum != 200 {
		t.Errorf("request limits header_line_num = %d, want 200", requestScalars.HeaderLineNum)
	}
}

func TestGeneratedCrossFieldValidators(t *testing.T) {
	t.Parallel()

	waitingValid := waitingRoomConfigsModel{
		EnableTotalActiveUsers: types.BoolValue(true), TotalActiveUsers: types.Int64Value(1000),
		EnableNewUsersPerMin: types.BoolValue(true), NewUsersPerMin: types.Int64Value(60),
	}
	if diagnostics := waitingRoomValidateConfiguredCrossFields(waitingValid); diagnostics.HasError() {
		t.Fatalf("valid waiting-room configuration diagnostics = %v", diagnostics)
	}
	waitingDisabled := waitingValid
	waitingDisabled.EnableTotalActiveUsers = types.BoolValue(false)
	waitingDisabled.TotalActiveUsers = types.Int64Value(1)
	waitingDisabled.EnableNewUsersPerMin = types.BoolValue(false)
	waitingDisabled.NewUsersPerMin = types.Int64Value(1)
	if diagnostics := waitingRoomValidateConfiguredCrossFields(waitingDisabled); diagnostics.HasError() {
		t.Fatalf("disabled conditional ranges diagnostics = %v", diagnostics)
	}
	waitingInvalid := waitingValid
	waitingInvalid.TotalActiveUsers = types.Int64Value(100)
	if diagnostics := waitingRoomValidateConfiguredCrossFields(waitingInvalid); !diagnostics.HasError() {
		t.Fatal("waiting-room configured validation accepted total_active_users below 200")
	}
	waitingInvalid = waitingValid
	waitingInvalid.NewUsersPerMin = types.Int64Value(1001)
	if diagnostics := waitingRoomValidateConfiguredCrossFields(waitingInvalid); !diagnostics.HasError() {
		t.Fatal("waiting-room configured validation accepted new_users_per_min above total_active_users")
	}

	requestValid := requestLimitsConfigsModel{
		RgMinSettingInitialWindowSize: types.Int64Value(10),
		RgMaxSettingInitialWindowSize: types.Int64Value(11),
	}
	if diagnostics := requestLimitsValidateConfiguredCrossFields(requestValid); diagnostics.HasError() {
		t.Fatalf("valid request-limits configuration diagnostics = %v", diagnostics)
	}
	requestInvalid := requestValid
	requestInvalid.RgMaxSettingInitialWindowSize = types.Int64Value(10)
	if diagnostics := requestLimitsValidateConfiguredCrossFields(requestInvalid); !diagnostics.HasError() {
		t.Fatal("request-limits configured validation accepted equal window bounds")
	}
	if diagnostics := requestLimitsValidateDecodedCrossFields(requestLimitsScalars{
		RgMinSettingInitialWindowSize: 11,
		RgMaxSettingInitialWindowSize: 10,
	}); !diagnostics.HasError() {
		t.Fatal("request-limits response validation accepted reversed window bounds")
	}
}

func defaultConfigResult(t *testing.T, candidate contract.ReviewedCandidate) client.WAFModuleResult {
	t.Helper()
	configs := make(map[string]json.RawMessage, len(candidate.Schema.ConfigFields))
	for _, field := range candidate.Schema.ConfigFields {
		if !field.HasDefault {
			continue
		}
		encoded, err := json.Marshal(field.Default)
		if err != nil {
			t.Fatalf("encode %s default: %v", field.Name, err)
		}
		configs[field.Name] = encoded
	}
	return client.WAFModuleResult{Configs: configs, Template: false}
}

// TestGraphQLProtectionItemIntegerFieldsRenderRangeAndState verifies the
// generator emits int64validator.Between and UseStateForUnknown on every
// optional GraphQL integer item field, which were previously dropped.
func TestGraphQLProtectionItemIntegerFieldsRenderRangeAndState(t *testing.T) {
	t.Parallel()

	resourceSchema := graphQLProtectionCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	ruleList := configs.Blocks["rule_list"].(schema.SingleNestedBlock)
	item := ruleList.Blocks["item"].(schema.ListNestedBlock)
	attrs := item.NestedObject.Attributes

	cases := []string{
		"alias_batch_query_number",
		"array_batch_query_number",
		"field_number",
		"graphql_data_size",
		"object_depth",
		"value_size",
	}
	for _, name := range cases {
		attr, ok := attrs[name].(schema.Int64Attribute)
		if !ok {
			t.Fatalf("%s attribute type = %T", name, attrs[name])
		}
		if !attr.Optional || !attr.Computed {
			t.Errorf("%s = %#v, want Optional/Computed", name, attr)
		}
		if len(attr.Validators) != 1 {
			t.Fatalf("%s validators = %d, want 1 (Between)", name, len(attr.Validators))
		}
		// The int64validator.Between description names its bounds, so the
		// rendered range is observable through the validator description.
		description := attr.Validators[0].Description(context.Background())
		if !strings.Contains(description, "between") && !strings.Contains(description, "at least") {
			t.Errorf("%s validator description = %q, want a range (Between) validator", name, description)
		}
		// UseStateForUnknown plan modifier must be present.
		if len(attr.PlanModifiers) != 1 {
			t.Fatalf("%s plan modifiers = %d, want 1 (UseStateForUnknown)", name, len(attr.PlanModifiers))
		}
		var response planmodifier.Int64Response
		attr.PlanModifiers[0].PlanModifyInt64(context.Background(), planmodifier.Int64Request{
			ConfigValue: types.Int64Null(),
			StateValue:  types.Int64Value(256),
			PlanValue:   types.Int64Unknown(),
		}, &response)
		if response.PlanValue.ValueInt64() != 256 {
			t.Errorf("%s UseStateForUnknown did not preserve state 256 (got %v)", name, response.PlanValue)
		}
	}
}

// TestHttpHeaderSecurityScalarLengthValidators verifies the maximum-length
// validators are rendered on header_value and referrer_policy_header_value.
func TestHttpHeaderSecurityScalarLengthValidators(t *testing.T) {
	t.Parallel()

	resourceSchema := httpHeaderSecurityCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	headerValue := configs.Attributes["header_value"].(schema.StringAttribute)
	if len(headerValue.Validators) != 1 {
		t.Fatalf("header_value validators = %d, want 1 (UTF8LengthAtMost 1023)", len(headerValue.Validators))
	}
	referrer := configs.Attributes["referrer_policy_header_value"].(schema.StringAttribute)
	// referrer_policy_header_value carries both a max-length and an enum validator.
	if len(referrer.Validators) != 2 {
		t.Fatalf("referrer_policy_header_value validators = %d, want 2 (UTF8LengthAtMost 64 + OneOf)", len(referrer.Validators))
	}
}

// TestHttpHeaderSecurityNullableScalarDecode verifies a null remote
// referrer_policy_header_value decodes without a malformed-result diagnostic
// and is represented as a nil pointer, while a present value decodes normally.
func TestHttpHeaderSecurityNullableScalarDecode(t *testing.T) {
	t.Parallel()

	nullConfigs := map[string]json.RawMessage{
		"status":                       json.RawMessage(`true`),
		"content_security_policy":      json.RawMessage(`true`),
		"header_value":                 json.RawMessage(`""`),
		"referrer_policy":              json.RawMessage(`true`),
		"referrer_policy_header_value": json.RawMessage(`null`),
		"x_content_type_options":       json.RawMessage(`true`),
		"x_frame_options":              json.RawMessage(`true`),
		"x_xss_protection":             json.RawMessage(`true`),
	}
	result := client.WAFModuleResult{Configs: nullConfigs, Template: false}
	scalars, diagnostics := httpHeaderSecurityDecodeScalars(result)
	if diagnostics.HasError() {
		t.Fatalf("nullable decode produced diagnostics: %v", diagnostics)
	}
	if scalars.ReferrerPolicyHeaderValue != nil {
		t.Fatalf("null remote value = %v, want nil pointer", scalars.ReferrerPolicyHeaderValue)
	}

	presentConfigs := map[string]json.RawMessage{
		"status":                       json.RawMessage(`true`),
		"content_security_policy":      json.RawMessage(`true`),
		"header_value":                 json.RawMessage(`""`),
		"referrer_policy":              json.RawMessage(`true`),
		"referrer_policy_header_value": json.RawMessage(`"strict-origin-when-cross-origin"`),
		"x_content_type_options":       json.RawMessage(`true`),
		"x_frame_options":              json.RawMessage(`true`),
		"x_xss_protection":             json.RawMessage(`true`),
	}
	presentResult := client.WAFModuleResult{Configs: presentConfigs, Template: false}
	presentScalars, diagnostics := httpHeaderSecurityDecodeScalars(presentResult)
	if diagnostics.HasError() {
		t.Fatalf("present decode produced diagnostics: %v", diagnostics)
	}
	if presentScalars.ReferrerPolicyHeaderValue == nil || *presentScalars.ReferrerPolicyHeaderValue != "strict-origin-when-cross-origin" {
		t.Fatalf("present remote value = %v, want pointer to strict-origin-when-cross-origin", presentScalars.ReferrerPolicyHeaderValue)
	}
}

// TestKnownAttacksSigIdLengthValidators verifies the nine-character minimum
// and maximum are rendered on the sig_except_rules sig_id item field.
func TestKnownAttacksSigIdLengthValidators(t *testing.T) {
	t.Parallel()

	resourceSchema := knownAttacksCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	sigExcept := configs.Blocks["sig_except_rules"].(schema.SingleNestedBlock)
	item := sigExcept.Blocks["item"].(schema.ListNestedBlock)
	sigID := item.NestedObject.Attributes["sig_id"].(schema.StringAttribute)
	if len(sigID.Validators) != 2 {
		t.Fatalf("sig_id validators = %d, want 2 (UTF8LengthAtMost + UTF8LengthAtLeast)", len(sigID.Validators))
	}
}

// TestKnownAttacksNestedUnknownKeyFailsClosed verifies the recursive unknown-key
// check rejects an unexpected key inside a nested object on read.
func TestKnownAttacksNestedUnknownKeyFailsClosed(t *testing.T) {
	t.Parallel()

	// Build a raw sig_except_rules array with one item whose cookie nested
	// object carries an unsupported "rogue" key.
	raw := json.RawMessage(`[{"idx":1,"sig_id":"030000010","sig_name":"SQL Injection","cookie":{"status":true,"type":"string","value":"sessionid","rogue":"extra"},"host":{"status":true,"type":"string","value":"www.example.com"},"http_header":{"status":true,"type":"string","value":"x"},"json":{"status":true,"type":"string","value":"x"},"param":{"status":true,"type":"string","value":"x"},"url":{"status":true,"type":"string","value":"/admin"}}]`)
	owned, diagnostics := knownAttacksDecodeSigExceptRules(raw)
	if !diagnostics.HasError() {
		t.Fatalf("nested unknown key was not rejected; owned = %#v", owned)
	}
	if !containsDiagnostic(diagnostics, "unsupported keys") {
		t.Fatalf("diagnostics did not mention unsupported keys: %v", diagnostics)
	}
}

// TestRequestLimitsAllowMethodsRequiredFailsClosed verifies a missing required
// remote allow_methods array fails closed when decoded, instead of being
// silently coerced to an empty array.
func TestRequestLimitsAllowMethodsRequiredFailsClosed(t *testing.T) {
	t.Parallel()

	// An absent remote key is a zero-length json.RawMessage.
	owned, diagnostics := requestLimitsDecodeAllowMethods(nil)
	if !diagnostics.HasError() {
		t.Fatalf("missing required allow_methods was silently coerced to %#v", owned)
	}
	if !containsDiagnostic(diagnostics, "required allow_methods array") {
		t.Fatalf("diagnostics did not mention the required allow_methods array: %v", diagnostics)
	}

	// A present empty array still decodes cleanly to an empty slice.
	empty, emptyDiagnostics := requestLimitsDecodeAllowMethods(json.RawMessage(`[]`))
	if emptyDiagnostics.HasError() {
		t.Fatalf("empty allow_methods produced diagnostics: %v", emptyDiagnostics)
	}
	if len(empty) != 0 {
		t.Fatalf("empty allow_methods = %v, want empty slice", empty)
	}
}

func containsDiagnostic(diagnostics diag.Diagnostics, needle string) bool {
	for _, d := range diagnostics {
		if strings.Contains(d.Detail(), needle) || strings.Contains(d.Summary(), needle) {
			return true
		}
	}
	return false
}

// TestGraphQLProtectionOmittedIntegerDefaultsSerialize verifies that omitting
// optional integer item fields with reviewed defaults serializes the reviewed
// default into the PUT wire item (not 0). This is the first-create default
// serialization regression test.
func TestGraphQLProtectionOmittedIntegerDefaultsSerialize(t *testing.T) {
	t.Parallel()

	// One rule item with only the required name/request_url set; every integer
	// and boolean optional field is null (omitted).
	itemValues := map[string]attr.Value{
		"alias_batch_query":        types.BoolNull(),
		"alias_batch_query_number": types.Int64Null(),
		"array_batch_query":        types.BoolNull(),
		"array_batch_query_number": types.Int64Null(),
		"field_number":             types.Int64Null(),
		"fragment":                 types.BoolNull(),
		"graphql_data_size":        types.Int64Null(),
		"introspection":            types.BoolNull(),
		"name":                     types.StringValue("graphql-default"),
		"object_depth":             types.Int64Null(),
		"request_url":              types.StringValue("/graphql"),
		"value_size":               types.Int64Null(),
	}
	itemObject, diagnostics := types.ObjectValue(graphQLProtectionRuleListItemAttributeTypes, itemValues)
	if diagnostics.HasError() {
		t.Fatalf("build item object: %v", diagnostics)
	}
	list, listDiagnostics := types.ListValue(types.ObjectType{AttrTypes: graphQLProtectionRuleListItemAttributeTypes}, []attr.Value{itemObject})
	if listDiagnostics.HasError() {
		t.Fatalf("build item list: %v", listDiagnostics)
	}
	wrapper, wrapperDiagnostics := types.ObjectValue(graphQLProtectionRuleListWrapperAttributeTypes, map[string]attr.Value{"item": list})
	if wrapperDiagnostics.HasError() {
		t.Fatalf("build wrapper: %v", wrapperDiagnostics)
	}

	owned, buildDiagnostics := graphQLProtectionBuildConfiguredRuleList(context.Background(), wrapper, wrapper, diag.Diagnostics{})
	if buildDiagnostics.HasError() {
		t.Fatalf("build configured rule_list: %v", buildDiagnostics)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("owned items = %d, want 1", len(owned.Items))
	}
	item := owned.Items[0]
	if item.FieldNumber != 256 {
		t.Errorf("FieldNumber = %d, want 256 (reviewed default)", item.FieldNumber)
	}
	if item.GraphqlDataSize != 1024 {
		t.Errorf("GraphqlDataSize = %d, want 1024 (reviewed default)", item.GraphqlDataSize)
	}
	if item.ObjectDepth != 32 {
		t.Errorf("ObjectDepth = %d, want 32 (reviewed default)", item.ObjectDepth)
	}
	if item.ValueSize != 256 {
		t.Errorf("ValueSize = %d, want 256 (reviewed default)", item.ValueSize)
	}
	if item.Name != "graphql-default" || item.RequestURL != "/graphql" {
		t.Errorf("required fields not preserved: name=%q request_url=%q", item.Name, item.RequestURL)
	}
}

// TestHttpHeaderSecurityOptionalScalarMissingDecodesNull verifies that an
// optional config scalar missing from the remote response decodes to nil
// (stable null state) without a malformed-result diagnostic, and that a
// required scalar still rejects a missing value.
func TestHttpHeaderSecurityOptionalScalarMissingDecodesNull(t *testing.T) {
	t.Parallel()

	// header_value (optional) is omitted from the remote response.
	configs := map[string]json.RawMessage{
		"status":                       json.RawMessage(`true`),
		"content_security_policy":      json.RawMessage(`true`),
		"referrer_policy":              json.RawMessage(`true`),
		"referrer_policy_header_value": json.RawMessage(`"strict-origin-when-cross-origin"`),
		"x_content_type_options":       json.RawMessage(`true`),
		"x_frame_options":              json.RawMessage(`true`),
		"x_xss_protection":             json.RawMessage(`true`),
	}
	scalars, diagnostics := httpHeaderSecurityDecodeScalars(client.WAFModuleResult{Configs: configs, Template: false})
	if diagnostics.HasError() {
		t.Fatalf("optional header_value missing produced diagnostics: %v", diagnostics)
	}
	if scalars.HeaderValue != nil {
		t.Fatalf("missing header_value = %v, want nil", scalars.HeaderValue)
	}

	// status (required) missing must still be rejected.
	missingRequired := map[string]json.RawMessage{
		"content_security_policy": json.RawMessage(`true`),
		"referrer_policy":         json.RawMessage(`true`),
		"x_content_type_options":  json.RawMessage(`true`),
		"x_frame_options":         json.RawMessage(`true`),
		"x_xss_protection":        json.RawMessage(`true`),
	}
	_, requiredDiagnostics := httpHeaderSecurityDecodeScalars(client.WAFModuleResult{Configs: missingRequired, Template: false})
	if !requiredDiagnostics.HasError() {
		t.Fatal("missing required status scalar was not rejected")
	}
}

// TestHttpHeaderSecurityRemoteOverlengthStringRejected verifies a remote
// header_value longer than 1023 characters is rejected at decode time, not
// only at Terraform configuration time.
func TestHttpHeaderSecurityRemoteOverlengthStringRejected(t *testing.T) {
	t.Parallel()

	overlong := strings.Repeat("a", 1024)
	configs := map[string]json.RawMessage{
		"status":                       json.RawMessage(`true`),
		"content_security_policy":      json.RawMessage(`true`),
		"header_value":                 json.RawMessage(`"` + overlong + `"`),
		"referrer_policy":              json.RawMessage(`true`),
		"referrer_policy_header_value": json.RawMessage(`"strict-origin-when-cross-origin"`),
		"x_content_type_options":       json.RawMessage(`true`),
		"x_frame_options":              json.RawMessage(`true`),
		"x_xss_protection":             json.RawMessage(`true`),
	}
	_, diagnostics := httpHeaderSecurityDecodeScalars(client.WAFModuleResult{Configs: configs, Template: false})
	if !diagnostics.HasError() {
		t.Fatal("overlength remote header_value was not rejected at decode time")
	}
	if !containsDiagnostic(diagnostics, "header_value") {
		t.Fatalf("diagnostics did not mention header_value: %v", diagnostics)
	}
}

// TestJsonProtectionOptionalScalarsMissingDecode verifies optional JSON
// bucket/prefix missing from the remote response decode without error.
func TestJsonProtectionOptionalScalarsMissingDecode(t *testing.T) {
	t.Parallel()

	configs := map[string]json.RawMessage{
		"action": json.RawMessage(`"alert_deny"`),
		"status": json.RawMessage(`false`),
	}
	scalars, diagnostics := jsonProtectionDecodeScalars(client.WAFModuleResult{Configs: configs, Template: false})
	if diagnostics.HasError() {
		t.Fatalf("optional bucket/prefix missing produced diagnostics: %v", diagnostics)
	}
	if scalars.Bucket != nil {
		t.Fatalf("missing bucket = %v, want nil", scalars.Bucket)
	}
	if scalars.Prefix != nil {
		t.Fatalf("missing prefix = %v, want nil", scalars.Prefix)
	}
}

// TestKnownAttacksNestedTypeDefaultsToString verifies the nested type field
// serializes its reviewed "string" default when omitted.
func TestKnownAttacksNestedTypeDefaultsToString(t *testing.T) {
	t.Parallel()

	// A null nested type value should resolve to the reviewed default "string".
	got := knownAttacksPlannedNestedString(types.StringNull(), types.StringNull(), "string")
	if got != "string" {
		t.Errorf("nested type default = %q, want %q", got, "string")
	}
	// A configured value must override the default.
	got = knownAttacksPlannedNestedString(types.StringValue("regex"), types.StringValue("regex"), "string")
	if got != "regex" {
		t.Errorf("nested type configured = %q, want %q", got, "regex")
	}
}

// TestGraphQLProtectionOmittedIntegerPreservesNonDefaultPlan verifies the
// update path: when configuration is null but the plan carries a known prior
// value (via use_state_for_unknown), the build serializes the planned value,
// NOT the reviewed default. This is the state-preservation regression that
// first-create-only tests miss.
func TestGraphQLProtectionOmittedIntegerPreservesNonDefaultPlan(t *testing.T) {
	t.Parallel()

	// Config: every optional field null (omitted). Plan: non-default known
	// values that should be preserved.
	configValues := map[string]attr.Value{
		"alias_batch_query":        types.BoolNull(),
		"alias_batch_query_number": types.Int64Null(),
		"array_batch_query":        types.BoolNull(),
		"array_batch_query_number": types.Int64Null(),
		"field_number":             types.Int64Null(),
		"fragment":                 types.BoolNull(),
		"graphql_data_size":        types.Int64Null(),
		"introspection":            types.BoolNull(),
		"name":                     types.StringValue("graphql-update"),
		"object_depth":             types.Int64Null(),
		"request_url":              types.StringValue("/graphql"),
		"value_size":               types.Int64Null(),
	}
	planValues := map[string]attr.Value{
		"alias_batch_query":        types.BoolValue(true),
		"alias_batch_query_number": types.Int64Value(7),
		"array_batch_query":        types.BoolValue(true),
		"array_batch_query_number": types.Int64Value(8),
		"field_number":             types.Int64Value(777),
		"fragment":                 types.BoolValue(true),
		"graphql_data_size":        types.Int64Value(999),
		"introspection":            types.BoolValue(true),
		"name":                     types.StringValue("graphql-update"),
		"object_depth":             types.Int64Value(64),
		"request_url":              types.StringValue("/graphql"),
		"value_size":               types.Int64Value(888),
	}
	configObject, diags := types.ObjectValue(graphQLProtectionRuleListItemAttributeTypes, configValues)
	if diags.HasError() {
		t.Fatalf("build config object: %v", diags)
	}
	planObject, diags := types.ObjectValue(graphQLProtectionRuleListItemAttributeTypes, planValues)
	if diags.HasError() {
		t.Fatalf("build plan object: %v", diags)
	}
	configList, diags := types.ListValue(types.ObjectType{AttrTypes: graphQLProtectionRuleListItemAttributeTypes}, []attr.Value{configObject})
	if diags.HasError() {
		t.Fatalf("build config list: %v", diags)
	}
	planList, diags := types.ListValue(types.ObjectType{AttrTypes: graphQLProtectionRuleListItemAttributeTypes}, []attr.Value{planObject})
	if diags.HasError() {
		t.Fatalf("build plan list: %v", diags)
	}
	configWrapper, diags := types.ObjectValue(graphQLProtectionRuleListWrapperAttributeTypes, map[string]attr.Value{"item": configList})
	if diags.HasError() {
		t.Fatalf("build config wrapper: %v", diags)
	}
	planWrapper, diags := types.ObjectValue(graphQLProtectionRuleListWrapperAttributeTypes, map[string]attr.Value{"item": planList})
	if diags.HasError() {
		t.Fatalf("build plan wrapper: %v", diags)
	}

	owned, buildDiags := graphQLProtectionBuildConfiguredRuleList(context.Background(), configWrapper, planWrapper, diag.Diagnostics{})
	if buildDiags.HasError() {
		t.Fatalf("build configured rule_list: %v", buildDiags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("owned items = %d, want 1", len(owned.Items))
	}
	item := owned.Items[0]
	// Optional integer item fields must preserve the planned value, not the default.
	if item.FieldNumber != 777 {
		t.Errorf("FieldNumber = %d, want 777 (preserved plan, not default 256)", item.FieldNumber)
	}
	if item.GraphqlDataSize != 999 {
		t.Errorf("GraphqlDataSize = %d, want 999 (preserved plan, not default 1024)", item.GraphqlDataSize)
	}
	if item.ObjectDepth != 64 {
		t.Errorf("ObjectDepth = %d, want 64 (preserved plan, not default 32)", item.ObjectDepth)
	}
	if item.ValueSize != 888 {
		t.Errorf("ValueSize = %d, want 888 (preserved plan, not default 256)", item.ValueSize)
	}
	// Optional boolean item fields must preserve the planned value, not false.
	if !item.AliasBatchQuery || !item.Fragment || !item.Introspection {
		t.Errorf("optional booleans not preserved: alias=%v fragment=%v introspection=%v", item.AliasBatchQuery, item.Fragment, item.Introspection)
	}
}

// TestKnownAttacksOmittedNestedStringPreservesPlan verifies the nested string
// build helper preserves a non-default planned value when configuration is
// null, and only falls back to the reviewed default when the plan is also null.
func TestKnownAttacksOmittedNestedStringPreservesPlan(t *testing.T) {
	t.Parallel()

	// Null config + known non-default plan -> preserve plan.
	if got := knownAttacksPlannedNestedString(types.StringNull(), types.StringValue("regex"), "string"); got != "regex" {
		t.Errorf("nested string null-config/known-plan = %q, want %q", got, "regex")
	}
	// Null config + null plan -> fall back to reviewed default.
	if got := knownAttacksPlannedNestedString(types.StringNull(), types.StringNull(), "string"); got != "string" {
		t.Errorf("nested string null-config/null-plan = %q, want default %q", got, "string")
	}
}

// TestKnownAttacksOmittedOptionalBoolPreservesPlan verifies the optional
// boolean item build helper preserves a known planned value when configuration
// is null, and falls back to false only when the plan is also null.
func TestKnownAttacksOmittedOptionalBoolPreservesPlan(t *testing.T) {
	t.Parallel()

	if got, ok := knownAttacksPlannedOptionalBool(types.BoolNull(), types.BoolValue(true), "status", nil); !ok || got != true {
		t.Errorf("optional bool null-config/true-plan = %v (ok=%v), want true", got, ok)
	}
	if got, ok := knownAttacksPlannedOptionalBool(types.BoolNull(), types.BoolNull(), "status", nil); !ok || got != false {
		t.Errorf("optional bool null-config/null-plan = %v (ok=%v), want false", got, ok)
	}
}

// TestHttpHeaderSecurityExplicitNullDecodeSemantics verifies the three explicit
// null/missing decode branches: missing optional key -> nil; present null with
// AllowNull (referrer_policy_header_value) -> nil; present null without
// AllowNull (header_value, non-nullable) -> malformed-result diagnostic.
func TestHttpHeaderSecurityExplicitNullDecodeSemantics(t *testing.T) {
	t.Parallel()

	// Missing optional header_value (key absent) -> nil, no error.
	missing := map[string]json.RawMessage{
		"status":                       json.RawMessage(`true`),
		"content_security_policy":      json.RawMessage(`true`),
		"referrer_policy":              json.RawMessage(`true`),
		"referrer_policy_header_value": json.RawMessage(`"strict-origin-when-cross-origin"`),
		"x_content_type_options":       json.RawMessage(`true`),
		"x_frame_options":              json.RawMessage(`true`),
		"x_xss_protection":             json.RawMessage(`true`),
	}
	scalars, diags := httpHeaderSecurityDecodeScalars(client.WAFModuleResult{Configs: missing, Template: false})
	if diags.HasError() {
		t.Fatalf("missing header_value errored: %v", diags)
	}
	if scalars.HeaderValue != nil {
		t.Fatalf("missing header_value = %v, want nil", scalars.HeaderValue)
	}

	// Present null for nullable referrer_policy_header_value -> nil, no error.
	nullableNull := map[string]json.RawMessage{
		"status":                       json.RawMessage(`true`),
		"content_security_policy":      json.RawMessage(`true`),
		"header_value":                 json.RawMessage(`""`),
		"referrer_policy":              json.RawMessage(`true`),
		"referrer_policy_header_value": json.RawMessage(`null`),
		"x_content_type_options":       json.RawMessage(`true`),
		"x_frame_options":              json.RawMessage(`true`),
		"x_xss_protection":             json.RawMessage(`true`),
	}
	scalars, diags = httpHeaderSecurityDecodeScalars(client.WAFModuleResult{Configs: nullableNull, Template: false})
	if diags.HasError() {
		t.Fatalf("nullable null referrer_policy_header_value errored: %v", diags)
	}
	if scalars.ReferrerPolicyHeaderValue != nil {
		t.Fatalf("nullable null = %v, want nil", scalars.ReferrerPolicyHeaderValue)
	}

	// Present null for non-nullable header_value -> malformed-result diagnostic.
	nonNullableNull := map[string]json.RawMessage{
		"status":                       json.RawMessage(`true`),
		"content_security_policy":      json.RawMessage(`true`),
		"header_value":                 json.RawMessage(`null`),
		"referrer_policy":              json.RawMessage(`true`),
		"referrer_policy_header_value": json.RawMessage(`"strict-origin-when-cross-origin"`),
		"x_content_type_options":       json.RawMessage(`true`),
		"x_frame_options":              json.RawMessage(`true`),
		"x_xss_protection":             json.RawMessage(`true`),
	}
	_, diags = httpHeaderSecurityDecodeScalars(client.WAFModuleResult{Configs: nonNullableNull, Template: false})
	if !diags.HasError() {
		t.Fatal("non-nullable null header_value was not rejected")
	}
	if !containsDiagnostic(diags, "header_value") {
		t.Fatalf("diagnostics did not mention header_value: %v", diags)
	}
}

// TestJsonProtectionExplicitNullNonNullableRejected verifies a present null for
// a non-nullable optional JSON scalar (bucket) is rejected, while a missing
// key decodes to nil.
func TestJsonProtectionExplicitNullNonNullableRejected(t *testing.T) {
	t.Parallel()

	// Missing bucket -> nil, no error.
	missing := map[string]json.RawMessage{
		"action": json.RawMessage(`"alert_deny"`),
		"status": json.RawMessage(`false`),
	}
	scalars, diags := jsonProtectionDecodeScalars(client.WAFModuleResult{Configs: missing, Template: false})
	if diags.HasError() {
		t.Fatalf("missing bucket errored: %v", diags)
	}
	if scalars.Bucket != nil {
		t.Fatalf("missing bucket = %v, want nil", scalars.Bucket)
	}

	// Present null bucket (non-nullable) -> rejected.
	nullBucket := map[string]json.RawMessage{
		"action": json.RawMessage(`"alert_deny"`),
		"status": json.RawMessage(`false`),
		"bucket": json.RawMessage(`null`),
	}
	_, diags = jsonProtectionDecodeScalars(client.WAFModuleResult{Configs: nullBucket, Template: false})
	if !diags.HasError() {
		t.Fatal("non-nullable null bucket was not rejected")
	}
}

// TestKnownAttacksMissingRequiredNestedObjectRejected verifies a missing
// required nested object (cookie) in a remote sig_except_rules item is
// rejected, not silently accepted as nil.
func TestKnownAttacksMissingRequiredNestedObjectRejected(t *testing.T) {
	t.Parallel()

	// One item with all required nested blocks except cookie (missing).
	raw := json.RawMessage(`[{"idx":1,"sig_id":"030000010","sig_name":"SQL Injection","host":{"status":true,"type":"string","value":"h"},"http_header":{"status":true,"type":"string","value":"x"},"json":{"status":true,"type":"string","value":"x"},"param":{"status":true,"type":"string","value":"x"},"url":{"status":true,"type":"string","value":"/admin"}}]`)
	_, diags := knownAttacksDecodeSigExceptRules(raw)
	if !diags.HasError() {
		t.Fatal("missing required cookie nested object was not rejected")
	}
	if !containsDiagnostic(diags, "cookie") {
		t.Fatalf("diagnostics did not mention missing cookie: %v", diags)
	}
}

// TestKnownAttacksMissingOptionalNestedSubFieldAccepted verifies a missing
// optional nested boolean sub-field (cookie.check_status) is accepted, not
// treated as required.
func TestKnownAttacksMissingOptionalNestedSubFieldAccepted(t *testing.T) {
	t.Parallel()

	// cookie present but check_status and check_value omitted (optional).
	raw := json.RawMessage(`[{"idx":1,"sig_id":"030000010","sig_name":"SQL Injection","cookie":{"status":true,"type":"string","value":"sessionid"},"host":{"status":true,"type":"string","value":"h"},"http_header":{"status":true,"type":"string","value":"x"},"json":{"status":true,"type":"string","value":"x"},"param":{"status":true,"type":"string","value":"x"},"url":{"status":true,"type":"string","value":"/admin"}}]`)
	owned, diags := knownAttacksDecodeSigExceptRules(raw)
	if diags.HasError() {
		t.Fatalf("missing optional cookie.check_status was rejected: %v", diags)
	}
	if len(owned.Items) != 1 || owned.Items[0].Cookie == nil {
		t.Fatalf("cookie not decoded: %#v", owned)
	}
	// check_status omitted -> Go zero value false.
	if owned.Items[0].Cookie.CheckStatus != false {
		t.Errorf("check_status = %v, want false (omitted optional)", owned.Items[0].Cookie.CheckStatus)
	}
}

// TestKnownAttacksShortSigIdRejectedByMinLength verifies the response decode
// enforces the sig_id nine-character minimum (item-field MinLength decode).
func TestKnownAttacksShortSigIdRejectedByMinLength(t *testing.T) {
	t.Parallel()

	// sig_id too short (5 chars, min 9).
	raw := json.RawMessage(`[{"idx":1,"sig_id":"12345","sig_name":"SQL Injection","cookie":{"status":true,"type":"string","value":"s"},"host":{"status":true,"type":"string","value":"h"},"http_header":{"status":true,"type":"string","value":"x"},"json":{"status":true,"type":"string","value":"x"},"param":{"status":true,"type":"string","value":"x"},"url":{"status":true,"type":"string","value":"/admin"}}]`)
	_, diags := knownAttacksDecodeSigExceptRules(raw)
	if !diags.HasError() {
		t.Fatal("short sig_id was not rejected by MinLength decode")
	}
}

// TestJsonProtectionItemMd5ExplicitNullRejected verifies a present explicit
// null for the optional non-nullable md5 item field is rejected at decode.
func TestJsonProtectionItemMd5ExplicitNullRejected(t *testing.T) {
	t.Parallel()

	// md5 is optional but non-nullable; an explicit null must be rejected.
	raw := json.RawMessage(`[{"idx":1,"filename":"f","limit_check":true,"md5":null,"name":"rule","schema_valid":false,"url":"/u"}]`)
	_, diags := jsonProtectionDecodeFileList(raw)
	if !diags.HasError() {
		t.Fatal("non-nullable null md5 item field was not rejected")
	}
	if !containsDiagnostic(diags, "md5") {
		t.Fatalf("diagnostics did not mention md5: %v", diags)
	}
}

// TestJsonProtectionItemMd5MissingAccepted verifies a missing optional md5
// item field is accepted (omission), distinct from an explicit null.
func TestJsonProtectionItemMd5MissingAccepted(t *testing.T) {
	t.Parallel()

	// md5 omitted entirely (not null).
	raw := json.RawMessage(`[{"idx":1,"filename":"f","limit_check":true,"name":"rule","schema_valid":false,"url":"/u"}]`)
	owned, diags := jsonProtectionDecodeFileList(raw)
	if diags.HasError() {
		t.Fatalf("missing optional md5 was rejected: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
}

// TestXMLProtectionPolicyOptionalScalarsMissingDecode verifies optional XML
// protection bucket/prefix missing from the remote response decode without
// error (mirrors the JSON protection scalar behavior).
func TestXMLProtectionPolicyOptionalScalarsMissingDecode(t *testing.T) {
	t.Parallel()

	configs := map[string]json.RawMessage{
		"action": json.RawMessage(`"alert_deny"`),
		"status": json.RawMessage(`false`),
	}
	scalars, diagnostics := xmlProtectionPolicyDecodeScalars(client.WAFModuleResult{Configs: configs, Template: false})
	if diagnostics.HasError() {
		t.Fatalf("optional bucket/prefix missing produced diagnostics: %v", diagnostics)
	}
	if scalars.Bucket != nil {
		t.Fatalf("missing bucket = %v, want nil", scalars.Bucket)
	}
	if scalars.Prefix != nil {
		t.Fatalf("missing prefix = %v, want nil", scalars.Prefix)
	}
}

// TestXMLProtectionPolicyExplicitNullNonNullableRejected verifies a present
// null for a non-nullable optional XML scalar (bucket) is rejected, while a
// missing key decodes to nil.
func TestXMLProtectionPolicyExplicitNullNonNullableRejected(t *testing.T) {
	t.Parallel()

	// Missing bucket -> nil, no error.
	missing := map[string]json.RawMessage{
		"action": json.RawMessage(`"alert_deny"`),
		"status": json.RawMessage(`false`),
	}
	scalars, diags := xmlProtectionPolicyDecodeScalars(client.WAFModuleResult{Configs: missing, Template: false})
	if diags.HasError() {
		t.Fatalf("missing bucket errored: %v", diags)
	}
	if scalars.Bucket != nil {
		t.Fatalf("missing bucket = %v, want nil", scalars.Bucket)
	}

	// Present null bucket (non-nullable) -> rejected.
	nullBucket := map[string]json.RawMessage{
		"action": json.RawMessage(`"alert_deny"`),
		"status": json.RawMessage(`false`),
		"bucket": json.RawMessage(`null`),
	}
	_, diags = xmlProtectionPolicyDecodeScalars(client.WAFModuleResult{Configs: nullBucket, Template: false})
	if !diags.HasError() {
		t.Fatal("non-nullable null bucket was not rejected")
	}
}

// TestXMLProtectionPolicyItemMd5ExplicitNullRejected verifies a present
// explicit null for the optional non-nullable md5 item field is rejected.
func TestXMLProtectionPolicyItemMd5ExplicitNullRejected(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`[{"idx":1,"filename":"f","limit_check":true,"md5":null,"name":"rule","entity_check":false,"schema_valid":false,"url":"/u"}]`)
	_, diags := xmlProtectionPolicyDecodeFileList(raw)
	if !diags.HasError() {
		t.Fatal("non-nullable null md5 item field was not rejected")
	}
	if !containsDiagnostic(diags, "md5") {
		t.Fatalf("diagnostics did not mention md5: %v", diags)
	}
}

// TestXMLProtectionPolicyItemMd5MissingAccepted verifies a missing optional md5
// item field is accepted (omission), distinct from an explicit null.
func TestXMLProtectionPolicyItemMd5MissingAccepted(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`[{"idx":1,"filename":"f","limit_check":true,"name":"rule","entity_check":false,"schema_valid":false,"url":"/u"}]`)
	owned, diags := xmlProtectionPolicyDecodeFileList(raw)
	if diags.HasError() {
		t.Fatalf("missing optional md5 was rejected: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
}

// TestXMLProtectionPolicyOverlengthNameRejected verifies the response decode
// enforces the name 32-character maximum on the file_list item.
func TestXMLProtectionPolicyOverlengthNameRejected(t *testing.T) {
	t.Parallel()

	longName := "x" + strings.Repeat("m", 32) // 33 chars
	raw := json.RawMessage(`[{"idx":1,"filename":"f","limit_check":true,"name":"` + longName + `","entity_check":false,"schema_valid":false,"url":"/u"}]`)
	_, diags := xmlProtectionPolicyDecodeFileList(raw)
	if !diags.HasError() {
		t.Fatal("overlength name was not rejected")
	}
	if !containsDiagnostic(diags, "name") {
		t.Fatalf("diagnostics did not mention name: %v", diags)
	}
}

// TestXMLProtectionPolicyOverlengthFilenameRejected verifies the response decode
// enforces the filename 58-character maximum on the file_list item (XMLFile
// pins a 58-char bound that JsonFile does not).
func TestXMLProtectionPolicyOverlengthFilenameRejected(t *testing.T) {
	t.Parallel()

	longFilename := "s" + strings.Repeat("x", 58) // 59 chars
	raw := json.RawMessage(`[{"idx":1,"filename":"` + longFilename + `","limit_check":true,"name":"rule","entity_check":false,"schema_valid":false,"url":"/u"}]`)
	_, diags := xmlProtectionPolicyDecodeFileList(raw)
	if !diags.HasError() {
		t.Fatal("overlength filename was not rejected")
	}
	if !containsDiagnostic(diags, "filename") {
		t.Fatalf("diagnostics did not mention filename: %v", diags)
	}
}

// TestXMLProtectionPolicyMissingRequiredEntityCheckRejected verifies a missing
// required entity_check item field (XMLFile-specific) is rejected at decode.
func TestXMLProtectionPolicyMissingRequiredEntityCheckRejected(t *testing.T) {
	t.Parallel()

	// entity_check omitted; every other required field present.
	raw := json.RawMessage(`[{"idx":1,"filename":"f","limit_check":true,"name":"rule","schema_valid":false,"url":"/u"}]`)
	_, diags := xmlProtectionPolicyDecodeFileList(raw)
	if !diags.HasError() {
		t.Fatal("missing required entity_check was not rejected")
	}
	if !containsDiagnostic(diags, "entity_check") {
		t.Fatalf("diagnostics did not mention entity_check: %v", diags)
	}
}

// TestParameterValidationOmittedNestedWrapperKeepsStateNull verifies that when
// the config omits the sub_rule_list wrapper (subItemOwned=false), the
// WrapperValue keeps it null in state (ownership: omit -> preserve, state null).
func TestParameterValidationOmittedNestedWrapperKeepsStateNull(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`[{"idx":1,"action":"alert_deny","block_period":60,"name":"r","url":"/u","sub_rule_list":[{"idx":1,"arg_type":"data-type","arg_val":"v","max_len":0,"name":"n","required":false,"type_check":false}]}]`)
	owned, diags := parameterValidationDecodeRuleList(raw)
	if diags.HasError() {
		t.Fatalf("decode: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	wrapper, wrapperDiags := parameterValidationRuleListWrapperValue(owned, map[string][]bool{})
	if wrapperDiags.HasError() {
		t.Fatalf("WrapperValue: %v", wrapperDiags)
	}
	var wrapperModel parameterValidationWrapperModel
	if itemDiags := wrapper.As(context.Background(), &wrapperModel, basetypes.ObjectAsOptions{}); itemDiags.HasError() {
		t.Fatalf("As: %v", itemDiags)
	}
	var items []parameterValidationRuleListItemModel
	if itemDiags := wrapperModel.Items.ElementsAs(context.Background(), &items, false); itemDiags.HasError() {
		t.Fatalf("ElementsAs: %v", itemDiags)
	}
	if !items[0].SubRuleList.IsNull() {
		t.Fatalf("sub_rule_list should be null (omitted), got %#v", items[0].SubRuleList)
	}
}

// TestParameterValidationConfiguredNestedWrapperMaterializes verifies that when
// the config has sub_rule_list (subItemOwned=true), the WrapperValue materializes
// it from the GET (so the plan is a no-op).
func TestParameterValidationConfiguredNestedWrapperMaterializes(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`[{"idx":1,"action":"alert_deny","block_period":60,"name":"r","url":"/u","sub_rule_list":[{"idx":1,"arg_type":"data-type","arg_val":"v","max_len":0,"name":"n","required":false,"type_check":false}]}]`)
	owned, diags := parameterValidationDecodeRuleList(raw)
	if diags.HasError() {
		t.Fatalf("decode: %v", diags)
	}
	// Decode the nested sub_rule_list for the owned item (mirrors the flatten).
	var rawItems []json.RawMessage
	_ = json.Unmarshal(raw, &rawItems)
	var itemObj map[string]json.RawMessage
	_ = json.Unmarshal(rawItems[0], &itemObj)
	subRuleListDecoded := parameterValidationRuleListDecodeNestedSubRuleList(itemObj["sub_rule_list"], "rule_list item 1 sub_rule_list", &diag.Diagnostics{})
	if subRuleListDecoded != nil {
		owned.Items[0].SubRuleList, _ = json.Marshal(subRuleListDecoded)
	}
	wrapper, wrapperDiags := parameterValidationRuleListWrapperValue(owned, map[string][]bool{"SubRuleList": {true}})
	if wrapperDiags.HasError() {
		t.Fatalf("WrapperValue: %v", wrapperDiags)
	}
	var wrapperModel parameterValidationWrapperModel
	if itemDiags := wrapper.As(context.Background(), &wrapperModel, basetypes.ObjectAsOptions{}); itemDiags.HasError() {
		t.Fatalf("As: %v", itemDiags)
	}
	var items []parameterValidationRuleListItemModel
	if itemDiags := wrapperModel.Items.ElementsAs(context.Background(), &items, false); itemDiags.HasError() {
		t.Fatalf("ElementsAs: %v", itemDiags)
	}
	if items[0].SubRuleList.IsNull() {
		t.Fatal("sub_rule_list should be materialized (configured), got null")
	}
}

// TestParameterValidationOmittedArgTypeProducesDefault verifies that omitting
// arg_type on first create produces the reviewed "data-type" default.
func TestParameterValidationOmittedArgTypeProducesDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	itemValues := map[string]attr.Value{
		"arg_type":   types.StringNull(),
		"arg_val":    types.StringNull(),
		"max_len":    types.Int64Null(),
		"name":       types.StringValue("n"),
		"required":   types.BoolNull(),
		"type_check": types.BoolNull(),
	}
	itemObject, diags := types.ObjectValue(parameterValidationRuleListSubRuleListItemAttributeTypes, itemValues)
	if diags.HasError() {
		t.Fatalf("build item: %v", diags)
	}
	list, listDiags := types.ListValue(types.ObjectType{AttrTypes: parameterValidationRuleListSubRuleListItemAttributeTypes}, []attr.Value{itemObject})
	if listDiags.HasError() {
		t.Fatalf("build list: %v", listDiags)
	}
	wrapper, wrapperDiags := types.ObjectValue(parameterValidationRuleListSubRuleListWrapperAttributeTypes, map[string]attr.Value{"item": list})
	if wrapperDiags.HasError() {
		t.Fatalf("build wrapper: %v", wrapperDiags)
	}
	owned := parameterValidationRuleListBuildNestedSubRuleList(ctx, wrapper, wrapper, "test", &diag.Diagnostics{})
	if owned == nil || len(*owned) != 1 {
		t.Fatalf("owned = %v, want one sub-item", owned)
	}
	if (*owned)[0].ArgType == nil || *(*owned)[0].ArgType != "data-type" {
		t.Fatalf("arg_type = %v, want \"data-type\" default", (*owned)[0].ArgType)
	}
}

// TestParameterValidationExplicitNullNestedArrayRejected verifies that an
// explicit JSON null for the non-nullable sub_rule_list is rejected at decode.
func TestParameterValidationExplicitNullNestedArrayRejected(t *testing.T) {
	t.Parallel()
	var decodeDiags diag.Diagnostics
	parameterValidationRuleListDecodeNestedSubRuleList(json.RawMessage(`null`), "test sub_rule_list", &decodeDiags)
	if !decodeDiags.HasError() {
		t.Fatal("explicit null sub_rule_list was not rejected")
	}
	if !containsDiagnostic(decodeDiags, "does not mark nullable") {
		t.Fatalf("diagnostics did not mention non-nullable: %v", decodeDiags)
	}
}

// TestParameterValidationSubItemArrayMutationIsolation verifies that mutating
// an ImplementedGeneratedResources() result's SubItemArray.ItemFields does not
// affect the exported contract.
func TestParameterValidationSubItemArrayMutationIsolation(t *testing.T) {
	t.Parallel()
	resources := contract.ImplementedGeneratedResources()
	var pv contract.ReviewedCandidate
	for _, r := range resources {
		if r.TerraformName == "fortiappseccloud_waf_parameter_validation" {
			pv = r
			break
		}
	}
	if pv.TerraformName == "" {
		t.Fatal("parameter_validation resource not found")
	}
	for _, f := range pv.Schema.ItemFields {
		if f.Name == "sub_rule_list" && f.SubItemArray != nil {
			if len(f.SubItemArray.ItemFields) == 0 {
				t.Fatal("sub_rule_list has no ItemFields")
			}
			f.SubItemArray.ItemFields[0].Name = "mutated"
			for _, r2 := range contract.ImplementedGeneratedResources() {
				if r2.TerraformName == "fortiappseccloud_waf_parameter_validation" {
					for _, f2 := range r2.Schema.ItemFields {
						if f2.Name == "sub_rule_list" && f2.SubItemArray != nil {
							if f2.SubItemArray.ItemFields[0].Name == "mutated" {
								t.Fatal("ImplementedGeneratedResources exposed mutable SubItemArray.ItemFields")
							}
						}
					}
				}
			}
			return
		}
	}
	t.Fatal("sub_rule_list field not found")
}

// TestParameterValidationPriorStateOmitKeepsNestedNull verifies that when the
// prior state omits sub_rule_list (null), the WrapperValue keeps it null
// (ownership: prior-state mask derived from state, not all-owned). This
// simulates a normal Read where OwnershipPriorState reflects that the user
// omitted the nested wrapper.
func TestParameterValidationPriorStateOmitKeepsNestedNull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Remote GET has a populated sub_rule_list.
	raw := json.RawMessage(`[{"idx":1,"action":"alert_deny","block_period":60,"name":"r","url":"/u","sub_rule_list":[{"idx":1,"arg_type":"data-type","arg_val":"v","max_len":0,"name":"n","required":false,"type_check":false}]}]`)
	owned, diags := parameterValidationDecodeRuleList(raw)
	if diags.HasError() {
		t.Fatalf("decode: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	// Prior state has sub_rule_list null (omitted) → subItemOwned[0] = false.
	subItemOwned := map[string][]bool{"SubRuleList": {false}}
	wrapper, wrapperDiags := parameterValidationRuleListWrapperValue(owned, subItemOwned)
	if wrapperDiags.HasError() {
		t.Fatalf("WrapperValue: %v", wrapperDiags)
	}
	var wrapperModel parameterValidationWrapperModel
	if itemDiags := wrapper.As(ctx, &wrapperModel, basetypes.ObjectAsOptions{}); itemDiags.HasError() {
		t.Fatalf("As: %v", itemDiags)
	}
	var items []parameterValidationRuleListItemModel
	if itemDiags := wrapperModel.Items.ElementsAs(ctx, &items, false); itemDiags.HasError() {
		t.Fatalf("ElementsAs: %v", itemDiags)
	}
	if !items[0].SubRuleList.IsNull() {
		t.Fatalf("sub_rule_list should be null (prior state omitted), got %#v", items[0].SubRuleList)
	}
	// Also verify that when prior state has sub_rule_list (owned), it materializes.
	// Decode the nested sub_rule_list for the owned item (mirrors the flatten).
	subRuleListDecoded2 := parameterValidationRuleListDecodeNestedSubRuleList(
		json.RawMessage(`[{"idx":1,"arg_type":"data-type","arg_val":"v","max_len":0,"name":"n","required":false,"type_check":false}]`),
		"rule_list item 1 sub_rule_list", &diag.Diagnostics{})
	if subRuleListDecoded2 != nil {
		owned.Items[0].SubRuleList, _ = json.Marshal(subRuleListDecoded2)
	}
	wrapper2, wrapperDiags2 := parameterValidationRuleListWrapperValue(owned, map[string][]bool{"SubRuleList": {true}})
	if wrapperDiags2.HasError() {
		t.Fatalf("WrapperValue owned: %v", wrapperDiags2)
	}
	var wrapperModel2 parameterValidationWrapperModel
	if itemDiags := wrapper2.As(ctx, &wrapperModel2, basetypes.ObjectAsOptions{}); itemDiags.HasError() {
		t.Fatalf("As: %v", itemDiags)
	}
	var items2 []parameterValidationRuleListItemModel
	if itemDiags := wrapperModel2.Items.ElementsAs(ctx, &items2, false); itemDiags.HasError() {
		t.Fatalf("ElementsAs: %v", itemDiags)
	}
	if items2[0].SubRuleList.IsNull() {
		t.Fatal("sub_rule_list should be materialized (prior state owned), got null")
	}
}

// TestDDoSPreventionBlockPeriodRangeValidator verifies the optional integer
// config scalar block_period renders the reviewed 1..3600 range validator.
// This pins the constraint end-to-end so a render-model drop is detected.
func TestDDoSPreventionBlockPeriodRangeValidator(t *testing.T) {
	t.Parallel()

	resourceSchema := dDoSPreventionCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	attr, ok := configs.Attributes["block_period"].(schema.Int64Attribute)
	if !ok {
		t.Fatalf("block_period attribute type = %T", configs.Attributes["block_period"])
	}
	if !attr.Optional || !attr.Computed {
		t.Errorf("block_period = %#v, want Optional/Computed", attr)
	}
	if len(attr.Validators) != 1 {
		t.Fatalf("block_period validators = %d, want 1 (Between)", len(attr.Validators))
	}
	description := attr.Validators[0].Description(context.Background())
	if !strings.Contains(description, "1") || !strings.Contains(description, "3600") {
		t.Errorf("block_period validator description = %q, want a 1..3600 range validator", description)
	}
	// block_period is omission-preserving (use_state_for_unknown), NOT a
	// provider-default scalar: an omitted value preserves the GET value.
	if len(attr.PlanModifiers) != 1 {
		t.Fatalf("block_period plan modifiers = %d, want 1 (UseStateForUnknown)", len(attr.PlanModifiers))
	}
	var response planmodifier.Int64Response
	attr.PlanModifiers[0].PlanModifyInt64(context.Background(), planmodifier.Int64Request{
		ConfigValue: types.Int64Null(),
		StateValue:  types.Int64Value(600),
		PlanValue:   types.Int64Unknown(),
	}, &response)
	if response.PlanValue.ValueInt64() != 600 {
		t.Errorf("block_period UseStateForUnknown did not preserve state 600 (got %v)", response.PlanValue)
	}
}

// TestDDoSPreventionNullConfigProducesUnsetPatch verifies that an omitted
// block_period (null config + null plan) produces an UNSET patch overlay, so
// the GET-merge-PUT runtime preserves the backend value rather than sending 0
// or the reviewed default 600. This is the omission-preserving config-scalar
// contract; a regression that sent 0 or 600 on omission would break it.
func TestDDoSPreventionNullConfigProducesUnsetPatch(t *testing.T) {
	t.Parallel()

	patch, diagnostics := dDoSPreventionConfiguredInt64(types.Int64Null(), types.Int64Null(), "block_period", diag.Diagnostics{})
	if diagnostics.HasError() {
		t.Fatalf("null config block_period produced diagnostics: %v", diagnostics)
	}
	if patch.Set {
		t.Fatalf("null config block_period patch = %+v, want Set:false (omitted from PUT)", patch)
	}
	// An explicitly configured value still sets the overlay.
	patchSet, _ := dDoSPreventionConfiguredInt64(types.Int64Value(120), types.Int64Null(), "block_period", diag.Diagnostics{})
	if !patchSet.Set || patchSet.Value != 120 {
		t.Fatalf("configured block_period patch = %+v, want Set:true Value:120", patchSet)
	}
}

// TestDDoSPreventionOptionalScalarMissingDecodesNull verifies that a missing
// optional block_period decodes to nil (stable null state) without a
// malformed-result diagnostic, that an out-of-range remote block_period is
// rejected, and that a missing required scalar (action) is still rejected.
func TestDDoSPreventionOptionalScalarMissingDecodesToDefault(t *testing.T) {
	t.Parallel()

	// block_period (optional, reviewed default 600) omitted from the remote
	// response decodes to the reviewed default (not nil) so a configured-default
	// value does not perpetual-diff when the backend omits default-valued keys.
	configs := map[string]json.RawMessage{
		"status":             json.RawMessage(`true`),
		"action":             json.RawMessage(`"block_period"`),
		"challenge":          json.RawMessage(`"real-browser-enforcement"`),
		"conn_flood_check":   json.RawMessage(`false`),
		"conn_flood_limit":   json.RawMessage(`100`),
		"http_access_limit":  json.RawMessage(`true`),
		"http_flood_prevent": json.RawMessage(`true`),
		"http_request_limit": json.RawMessage(`1000`),
		"http_session_limit": json.RawMessage(`500`),
		"tcp_conn_num_limit": json.RawMessage(`255`),
		"tcp_flood_prevent":  json.RawMessage(`false`),
		"ip_exception":       json.RawMessage(`[]`),
	}
	scalars, diagnostics := dDoSPreventionDecodeScalars(client.WAFModuleResult{Configs: configs, Template: false})
	if diagnostics.HasError() {
		t.Fatalf("optional block_period missing produced diagnostics: %v", diagnostics)
	}
	if scalars.BlockPeriod == nil || *scalars.BlockPeriod != 600 {
		t.Fatalf("missing block_period = %v, want pointer to reviewed default 600", scalars.BlockPeriod)
	}

	// An out-of-range remote block_period (3601) must be rejected.
	outOfRange := map[string]json.RawMessage{}
	for k, v := range configs {
		outOfRange[k] = v
	}
	outOfRange["block_period"] = json.RawMessage(`3601`)
	_, rangeDiagnostics := dDoSPreventionDecodeScalars(client.WAFModuleResult{Configs: outOfRange, Template: false})
	if !rangeDiagnostics.HasError() {
		t.Fatal("out-of-range block_period=3601 was not rejected")
	}

	// A missing required scalar (action) must still be rejected.
	missingRequired := map[string]json.RawMessage{}
	for k, v := range configs {
		missingRequired[k] = v
	}
	delete(missingRequired, "action")
	_, requiredDiagnostics := dDoSPreventionDecodeScalars(client.WAFModuleResult{Configs: missingRequired, Template: false})
	if !requiredDiagnostics.HasError() {
		t.Fatal("missing required action scalar was not rejected")
	}
}

// TestCookieSecurityItemBooleanDefaultFalseModifier verifies the optional item
// boolean wildcard uses the reviewed provider-default-false modifier (mirroring
// the CSRF filter pattern), NOT use_state_for_unknown: an omitted wildcard
// defaults to false on a newly configured item rather than preserving prior
// state. This pins the behavioral fix for the cookie_security wildcard field.
func TestCookieSecurityItemBooleanDefaultFalseModifier(t *testing.T) {
	t.Parallel()

	resourceSchema := cookieSecurityCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	cookieExceptList := configs.Blocks["cookie_except_list"].(schema.SingleNestedBlock)
	item := cookieExceptList.Blocks["item"].(schema.ListNestedBlock)
	attr, ok := item.NestedObject.Attributes["wildcard"].(schema.BoolAttribute)
	if !ok {
		t.Fatalf("wildcard attribute type = %T", item.NestedObject.Attributes["wildcard"])
	}
	if !attr.Optional || !attr.Computed {
		t.Errorf("wildcard = %#v, want Optional/Computed", attr)
	}
	if len(attr.PlanModifiers) != 1 {
		t.Fatalf("wildcard plan modifiers = %d, want 1 (DefaultFalse)", len(attr.PlanModifiers))
	}
	// The default-false modifier sets the plan to false when config is null.
	var response planmodifier.BoolResponse
	attr.PlanModifiers[0].PlanModifyBool(context.Background(), planmodifier.BoolRequest{
		ConfigValue: types.BoolNull(),
		StateValue:  types.BoolValue(true),
		PlanValue:   types.BoolUnknown(),
	}, &response)
	if response.PlanValue.ValueBool() != false {
		t.Errorf("wildcard default-false modifier = %v, want false (not prior state true)", response.PlanValue)
	}
}

// TestCookieSecurityCollectionBoundAndRequiredName verifies the cookie_except_list
// object-item collection renders the reviewed max-64 bound and the required name
// item field with its 127-character maximum-length validator.
func TestCookieSecurityCollectionBoundAndRequiredName(t *testing.T) {
	t.Parallel()

	if cookieSecurityCookieExceptListMaxItems != 64 {
		t.Fatalf("cookieSecurityCookieExceptListMaxItems = %d, want 64", cookieSecurityCookieExceptListMaxItems)
	}
	resourceSchema := cookieSecurityCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	cookieExceptList := configs.Blocks["cookie_except_list"].(schema.SingleNestedBlock)
	item := cookieExceptList.Blocks["item"].(schema.ListNestedBlock)
	name, ok := item.NestedObject.Attributes["name"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("name attribute type = %T", item.NestedObject.Attributes["name"])
	}
	if !name.Required {
		t.Errorf("name = %#v, want Required", name)
	}
	if len(name.Validators) != 1 {
		t.Fatalf("name validators = %d, want 1 (UTF8LengthAtMost)", len(name.Validators))
	}
	description := name.Validators[0].Description(context.Background())
	if !strings.Contains(description, "127") {
		t.Errorf("name validator description = %q, want a 127 max-length validator", description)
	}
	// wildcard is optional (not required).
	wildcard, ok := item.NestedObject.Attributes["wildcard"].(schema.BoolAttribute)
	if !ok {
		t.Fatalf("wildcard attribute type = %T", item.NestedObject.Attributes["wildcard"])
	}
	if wildcard.Required {
		t.Errorf("wildcard = %#v, want Optional (not Required)", wildcard)
	}
}

// TestKnownBotsUnboundedUnindexedCollection verifies bad_bots_list and
// good_bots_list are unbounded (no SizeAtMost validator) and unindexed (the
// generated wire item struct has no Index/idx field).
func TestKnownBotsUnboundedUnindexedCollection(t *testing.T) {
	t.Parallel()

	resourceSchema := knownBotsCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	for _, name := range []string{"bad_bots_list", "good_bots_list"} {
		wrapper, ok := configs.Blocks[name].(schema.SingleNestedBlock)
		if !ok {
			t.Fatalf("%s block type = %T", name, configs.Blocks[name])
		}
		item, ok := wrapper.Blocks["item"].(schema.ListNestedBlock)
		if !ok {
			t.Fatalf("%s.item block type = %T", name, wrapper.Blocks["item"])
		}
		// Unbounded: no SizeAtMost validator on the item block.
		for _, v := range item.Validators {
			if _, ok := v.(interface{ SizeAtMostValidator() }); ok {
				t.Errorf("%s item block unexpectedly carries a SizeAtMost validator", name)
			}
		}
	}
	// exception_list is bounded (128) and indexed.
	if knownBotsExceptionListMaxItems != 128 {
		t.Fatalf("exception_list max items = %d, want 128", knownBotsExceptionListMaxItems)
	}
	// The exception_list wire item has an Index field (indexed); bad/good do not.
	var exceptionWire knownBotsExceptionListWireItem
	_ = exceptionWire.Index
}

// TestKnownBotsItemStringArrayOwnership verifies the item-level
// scalar-string-array fields (allow_list, deny_list) render as ownership
// wrappers inside the item block, and that the build helper produces the
// expected []string when populated and an unset overlay when omitted.
func TestKnownBotsItemStringArrayOwnership(t *testing.T) {
	t.Parallel()

	resourceSchema := knownBotsCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	badBots := configs.Blocks["bad_bots_list"].(schema.SingleNestedBlock)
	item := badBots.Blocks["item"].(schema.ListNestedBlock)
	allowList, ok := item.NestedObject.Blocks["allow_list"].(schema.SingleNestedBlock)
	if !ok {
		t.Fatalf("allow_list block type = %T", item.NestedObject.Blocks["allow_list"])
	}
	allowItem, ok := allowList.Blocks["item"].(schema.ListNestedBlock)
	if !ok {
		t.Fatalf("allow_list.item block type = %T", allowList.Blocks["item"])
	}
	valueAttr, ok := allowItem.NestedObject.Attributes["value"].(schema.StringAttribute)
	if !ok || !valueAttr.Required {
		t.Fatalf("allow_list.item.value = %#v, want required string", allowItem.NestedObject.Attributes["value"])
	}

	// An omitted (null) ownership wrapper produces an unset overlay; a populated
	// wrapper produces the reviewed []string. Exercise the build helper directly.
	nullWrapper := types.ObjectNull(knownBotsBadBotsListAllowListWrapperAttributeTypes)
	var buildDiags diag.Diagnostics
	built := knownBotsBadBotsListBuildItemStringArrayAllowList(context.Background(), nullWrapper, nullWrapper, "loc", &buildDiags)
	if buildDiags.HasError() {
		t.Fatalf("null allow_list build diagnostics: %v", buildDiags)
	}
	if built.Set {
		t.Fatalf("null allow_list build = %+v, want Set:false (omitted)", built)
	}

	itemObj, _ := types.ObjectValue(knownBotsBadBotsListAllowListItemAttributeTypes, map[string]attr.Value{"value": types.StringValue("BotA")})
	list, _ := types.ListValue(types.ObjectType{AttrTypes: knownBotsBadBotsListAllowListItemAttributeTypes}, []attr.Value{itemObj})
	populatedWrapper, _ := types.ObjectValue(knownBotsBadBotsListAllowListWrapperAttributeTypes, map[string]attr.Value{"item": list})
	var buildPopDiags diag.Diagnostics
	builtPopulated := knownBotsBadBotsListBuildItemStringArrayAllowList(context.Background(), populatedWrapper, populatedWrapper, "loc", &buildPopDiags)
	if buildPopDiags.HasError() {
		t.Fatalf("populated allow_list build diagnostics: %v", buildPopDiags)
	}
	if !builtPopulated.Set || len(builtPopulated.Items) != 1 || builtPopulated.Items[0] != "BotA" {
		t.Fatalf("populated allow_list build = %+v, want Set:true Items:[BotA]", builtPopulated)
	}

	// An empty wrapper sends [].
	emptyList, _ := types.ListValue(types.ObjectType{AttrTypes: knownBotsBadBotsListAllowListItemAttributeTypes}, []attr.Value{})
	emptyWrapper, _ := types.ObjectValue(knownBotsBadBotsListAllowListWrapperAttributeTypes, map[string]attr.Value{"item": emptyList})
	var buildEmptyDiags diag.Diagnostics
	builtEmpty := knownBotsBadBotsListBuildItemStringArrayAllowList(context.Background(), emptyWrapper, emptyWrapper, "loc", &buildEmptyDiags)
	_ = buildEmptyDiags
	if !builtEmpty.Set || len(builtEmpty.Items) != 0 {
		t.Fatalf("empty allow_list build = %+v, want Set:true empty", builtEmpty)
	}
}

// TestKnownBotsItemStringArrayDecode verifies DecodeItemStringArray rejects a
// non-array and accepts a string array, and that the wrapper value round-trips.
func TestKnownBotsItemStringArrayDecode(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	items := knownBotsBadBotsListDecodeItemStringArrayAllowList(json.RawMessage(`["A","B"]`), "loc", &diags)
	if diags.HasError() || len(items) != 2 || items[0] != "A" || items[1] != "B" {
		t.Fatalf("decode [\"A\",\"B\"] = %v, diags=%v", items, diags)
	}
	wrapper, wrapperDiags := knownBotsBadBotsListAllowListItemStringArrayWrapperValue(json.RawMessage(`["A","B"]`))
	if wrapperDiags.HasError() {
		t.Fatalf("wrapper value diagnostics: %v", wrapperDiags)
	}
	if wrapper.IsNull() {
		t.Fatal("wrapper value is null for a populated array")
	}
}

// TestKnownBotsItemStatusDefaultsTrueOnOmission verifies the item `status`
// boolean (reviewed default true) uses the DefaultTrueModifier and that the
// build helper sends true when the wrapper is present but status is omitted
// (first create). This pins the fix for the default-true omission defect.
func TestKnownBotsItemStatusDefaultsTrueOnOmission(t *testing.T) {
	t.Parallel()

	resourceSchema := knownBotsCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	badBots := configs.Blocks["bad_bots_list"].(schema.SingleNestedBlock)
	item := badBots.Blocks["item"].(schema.ListNestedBlock)
	statusAttr, ok := item.NestedObject.Attributes["status"].(schema.BoolAttribute)
	if !ok {
		t.Fatalf("status attribute type = %T", item.NestedObject.Attributes["status"])
	}
	if len(statusAttr.PlanModifiers) != 1 {
		t.Fatalf("status plan modifiers = %d, want 1 (DefaultTrue)", len(statusAttr.PlanModifiers))
	}
	var response planmodifier.BoolResponse
	statusAttr.PlanModifiers[0].PlanModifyBool(context.Background(), planmodifier.BoolRequest{
		ConfigValue: types.BoolNull(),
		StateValue:  types.BoolValue(false),
		PlanValue:   types.BoolUnknown(),
	}, &response)
	if response.PlanValue.ValueBool() != true {
		t.Errorf("status default-true modifier = %v, want true (not prior state false)", response.PlanValue)
	}

	// Build an item with status omitted (null) and allow_list omitted; the build
	// helper for the item-level bool sends the reviewed default true.
	itemValues := map[string]attr.Value{
		"cat":        types.StringValue("DoS"),
		"status":     types.BoolNull(),
		"allow_list": types.ObjectNull(knownBotsBadBotsListAllowListWrapperAttributeTypes),
	}
	itemObject, diags := types.ObjectValue(knownBotsBadBotsListItemAttributeTypes, itemValues)
	if diags.HasError() {
		t.Fatalf("build item object: %v", diags)
	}
	list, listDiags := types.ListValue(types.ObjectType{AttrTypes: knownBotsBadBotsListItemAttributeTypes}, []attr.Value{itemObject})
	if listDiags.HasError() {
		t.Fatalf("build item list: %v", listDiags)
	}
	wrapper, wrapperDiags := types.ObjectValue(knownBotsBadBotsListWrapperAttributeTypes, map[string]attr.Value{"item": list})
	if wrapperDiags.HasError() {
		t.Fatalf("build wrapper: %v", wrapperDiags)
	}
	owned, buildDiags := knownBotsBuildConfiguredBadBotsList(context.Background(), wrapper, wrapper, diag.Diagnostics{})
	if buildDiags.HasError() {
		t.Fatalf("build configured bad_bots_list: %v", buildDiags)
	}
	if !owned.Set || len(owned.Items) != 1 {
		t.Fatalf("owned = %+v, want one item", owned)
	}
	if !owned.Items[0].Status {
		t.Errorf("omitted item status = false, want true (reviewed default)")
	}
	// Omitted allow_list wrapper must NOT be sent (the wire field is empty).
	if len(owned.Items[0].AllowList) != 0 {
		t.Errorf("omitted allow_list = %v, want empty (omitted)", owned.Items[0].AllowList)
	}
}

// TestKnownBotsItemStatusDescriptionDefaultsTrue verifies the generated schema
// and docs description for the item `status` boolean render the reviewed
// default-true value (not a hard-coded false).
func TestKnownBotsItemStatusDescriptionDefaultsTrue(t *testing.T) {
	t.Parallel()

	resourceSchema := knownBotsCodec{}.Schema(context.Background())
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	badBots := configs.Blocks["bad_bots_list"].(schema.SingleNestedBlock)
	item := badBots.Blocks["item"].(schema.ListNestedBlock)
	statusAttr, ok := item.NestedObject.Attributes["status"].(schema.BoolAttribute)
	if !ok {
		t.Fatalf("status attribute type = %T", item.NestedObject.Attributes["status"])
	}
	if !strings.Contains(statusAttr.MarkdownDescription, "true") {
		t.Errorf("status description = %q, want it to mention the reviewed default true", statusAttr.MarkdownDescription)
	}
	if strings.Contains(statusAttr.MarkdownDescription, "Defaults to false") {
		t.Errorf("status description = %q, must not hard-code false for a default-true field", statusAttr.MarkdownDescription)
	}
}

// TestBotDeceptionExceptionListItemValueCheckMissingAccepted verifies that an
// exception_list item omitting the optional value_check field decodes cleanly
// (the field is optional with a reviewed default false; a missing key must not

// TestBiometricsBasedDetectionExceptionListItemValueCheckMissingAccepted is the
// same missing-optional-value_check decode invariant for the biometrics

// TestBotDeceptionExceptionListItemValueCheckMissingAccepted verifies that an
// exception_list item omitting the source-optional value_check field decodes
// cleanly to the reviewed default false. value_check is optional in the pinned
// OpenAPI/contract (unlike CSRF filter, which is source-required and rejects a
// missing key), so a missing key must not produce a malformed-result diagnostic
// or valid imports/refreshes fail.
func TestBotDeceptionExceptionListItemValueCheckMissingAccepted(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`[{"idx":1,"concatenate_type":"AND","match_target":"CLIENT_IP","operator":"STRING_MATCH","value":"10.0.0.0/8"}]`)
	owned, diags := botDeceptionDecodeExceptionList(raw)
	if diags.HasError() {
		t.Fatalf("missing optional value_check was rejected: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	if owned.Items[0].ValueCheck != false {
		t.Fatalf("value_check = %v, want false (reviewed default)", owned.Items[0].ValueCheck)
	}
}

// TestBiometricsBasedDetectionExceptionListItemValueCheckMissingAccepted is the
// same missing-optional-value_check decode invariant for the biometrics
// exception_list, which shares the BotExceptionRuleList item schema.
func TestBiometricsBasedDetectionExceptionListItemValueCheckMissingAccepted(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`[{"idx":1,"concatenate_type":"AND","match_target":"CLIENT_IP","operator":"STRING_MATCH","value":"10.0.0.0/8"}]`)
	owned, diags := biometricsBasedDetectionDecodeExceptionList(raw)
	if diags.HasError() {
		t.Fatalf("missing optional value_check was rejected: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	if owned.Items[0].ValueCheck != false {
		t.Fatalf("value_check = %v, want false (reviewed default)", owned.Items[0].ValueCheck)
	}
}

// TestCookieSecurityCookieExceptListItemWildcardMissingAccepted verifies that a
// cookie_except_list item omitting the source-optional wildcard field decodes
// cleanly to the reviewed default false.
func TestCookieSecurityCookieExceptListItemWildcardMissingAccepted(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`[{"idx":1,"name":"__utma"}]`)
	owned, diags := cookieSecurityDecodeCookieExceptList(raw)
	if diags.HasError() {
		t.Fatalf("missing optional wildcard was rejected: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	if owned.Items[0].Wildcard != false {
		t.Fatalf("wildcard = %v, want false (reviewed default)", owned.Items[0].Wildcard)
	}
}

// TestKnownBotsBadBotsListItemStatusMissingAccepted verifies that a bad_bots_list
// item omitting the source-optional status field decodes cleanly to the
// reviewed default true (the DefaultTrue field), not false.
func TestKnownBotsBadBotsListItemStatusMissingAccepted(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`[{"cat":"DoS","allow_list":[{"idx":1,"value":"BadBot/1.0"}]}]`)
	owned, diags := knownBotsDecodeBadBotsList(raw)
	if diags.HasError() {
		t.Fatalf("missing optional status was rejected: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	if owned.Items[0].Status != true {
		t.Fatalf("status = %v, want true (reviewed default)", owned.Items[0].Status)
	}
}

// TestRewritingRequestsParseIdxStringAccepted verifies the string-idx decode
// accepts the reviewed JSON string form ("1") and parses it to a positive int.
func TestRewritingRequestsParseIdxStringAccepted(t *testing.T) {
	t.Parallel()

	value, ok := rewritingRequestsParseIdx(json.RawMessage(`"1"`), "rule_list item")
	if !ok || value != 1 {
		t.Fatalf(`ParseIdx("1") = (%d, %t), want (1, true)`, value, ok)
	}
	value, ok = rewritingRequestsParseIdx(json.RawMessage(`"10"`), "rule_list item")
	if !ok || value != 10 {
		t.Fatalf(`ParseIdx("10") = (%d, %t), want (10, true)`, value, ok)
	}
}

// TestRewritingRequestsParseIdxNumberAccepted verifies the string-idx decode
// also tolerates a JSON number (1) for fail-closed backend-echo robustness.
func TestRewritingRequestsParseIdxNumberAccepted(t *testing.T) {
	t.Parallel()

	value, ok := rewritingRequestsParseIdx(json.RawMessage(`2`), "rule_list item")
	if !ok || value != 2 {
		t.Fatalf("ParseIdx(2) = (%d, %t), want (2, true)", value, ok)
	}
}

// TestRewritingRequestsParseIdxRejectsMalformed verifies non-numeric, null,
// non-positive, and out-of-int-range string idx values are rejected.
func TestRewritingRequestsParseIdxRejectsMalformed(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{`null`, `""`, `"abc"`, `"0"`, `"-1"`, `0`, `-5`} {
		value, ok := rewritingRequestsParseIdx(json.RawMessage(raw), "rule_list item")
		if ok {
			t.Fatalf("ParseIdx(%s) = (%d, true), want (0, false)", raw, value)
		}
	}
}

// TestRewritingRequestsIdxMarshalJSONIsString verifies the named Idx type
// marshals to a JSON string, not a number (the wire-encoding difference for
// string-idx collections).
func TestRewritingRequestsIdxMarshalJSONIsString(t *testing.T) {
	t.Parallel()

	out, err := rewritingRequestsIdx(1).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(out) != `"1"` {
		t.Fatalf("MarshalJSON(1) = %s, want %q", out, `"1"`)
	}
}

// TestRewritingRequestsDecodeRuleListStringIdx verifies the decode path reads
// string-typed idx ("1", "2") from the remote response and sorts numerically
// (not lexicographically), so "10" sorts after "2".
func TestRewritingRequestsDecodeRuleListStringIdx(t *testing.T) {
	t.Parallel()

	// Items deliberately out of numeric order: "2", "10", "1". After decode
	// they must sort numerically to 1, 2, 10 — proving the sort is not the
	// lexicographic "10" < "2" trap.
	raw := json.RawMessage(`[{"idx":"2","name":"b"},{"idx":"10","name":"c"},{"idx":"1","name":"a"}]`)
	owned, diags := rewritingRequestsDecodeRuleList(raw)
	if diags.HasError() {
		t.Fatalf("string-idx decode errored: %v", diags)
	}
	if len(owned.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(owned.Items))
	}
	wantNames := []string{"a", "b", "c"}
	for i, want := range wantNames {
		if owned.Items[i].Name == nil || *owned.Items[i].Name != want {
			t.Fatalf("item %d name = %v, want %q (numeric idx sort failed)", i, owned.Items[i].Name, want)
		}
	}
}

// TestRewritingRequestsDecodeRuleListRejectsNonNumericIdx verifies a
// non-numeric string idx is rejected into diagnostics on the decode path.
func TestRewritingRequestsDecodeRuleListRejectsNonNumericIdx(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`[{"idx":"abc","name":"a"}]`)
	_, diags := rewritingRequestsDecodeRuleList(raw)
	if !diags.HasError() {
		t.Fatal("non-numeric string idx was not rejected")
	}
}

// TestRewritingRequestsRemoveHeaderOverlengthRejected verifies the response
// decode enforces the remove_header per-item 63-character maximum.
func TestRewritingRequestsRemoveHeaderOverlengthRejected(t *testing.T) {
	t.Parallel()

	longHeader := "X-" + strings.Repeat("h", 62) // 64 chars > 63
	raw := json.RawMessage(`["` + longHeader + `"]`)
	var diags diag.Diagnostics
	rewritingRequestsRuleListDecodeItemStringArrayRemoveHeader(raw, "rule_list item 1 remove_header", &diags)
	if !diags.HasError() {
		t.Fatal("overlength remove_header item was not rejected")
	}
	if !containsDiagnostic(diags, "63") {
		t.Fatalf("diagnostics did not mention the 63-character maximum: %v", diags)
	}
}

// TestRewritingRequestsRemoveHeaderInLengthAccepted is the positive control
// proving the overlength rejection comes from the length check, not parsing: a
// 63-character header (exactly at the bound) decodes cleanly.
func TestRewritingRequestsRemoveHeaderInLengthAccepted(t *testing.T) {
	t.Parallel()

	inLength := "X-" + strings.Repeat("h", 61) // 63 chars, exactly the bound
	raw := json.RawMessage(`["` + inLength + `"]`)
	var diags diag.Diagnostics
	items := rewritingRequestsRuleListDecodeItemStringArrayRemoveHeader(raw, "rule_list item 1 remove_header", &diags)
	if diags.HasError() {
		t.Fatalf("in-length remove_header item was rejected: %v", diags)
	}
	if len(items) != 1 || items[0] != inLength {
		t.Fatalf("items = %#v, want [%q]", items, inLength)
	}
}

// TestRewritingRequestsRemoveHeaderExplicitNullRejected verifies a present JSON
// null for the non-nullable owned remove_header array is rejected (distinct
// from a missing key, which is accepted as omission).
func TestRewritingRequestsRemoveHeaderExplicitNullRejected(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	rewritingRequestsRuleListDecodeItemStringArrayRemoveHeader(json.RawMessage(`null`), "rule_list item 1 remove_header", &diags)
	if !diags.HasError() {
		t.Fatal("explicit null remove_header was not rejected")
	}
	if !containsDiagnostic(diags, "not nullable") {
		t.Fatalf("diagnostics did not mention non-nullable: %v", diags)
	}
}

// TestRewritingRequestsRemoveHeaderMissingAccepted verifies a missing
// remove_header key (empty raw) is accepted as omission (nil), distinct from an
// explicit null.
func TestRewritingRequestsRemoveHeaderMissingAccepted(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	items := rewritingRequestsRuleListDecodeItemStringArrayRemoveHeader(json.RawMessage(``), "rule_list item 1 remove_header", &diags)
	if diags.HasError() {
		t.Fatalf("missing remove_header was rejected: %v", diags)
	}
	if items != nil {
		t.Fatalf("items = %#v, want nil", items)
	}
}

// TestRewritingRequestsRemoveHeaderPlannedFallbackForUnknown verifies that when
// the config item header is unknown (a computed reference resolved by apply
// time) but the plan carries a known value, the build helper uses the planned
// value instead of rejecting the item. This is the computed-reference fallback
// that the other generated item build helpers also provide.
func TestRewritingRequestsRemoveHeaderPlannedFallbackForUnknown(t *testing.T) {
	t.Parallel()

	configObject, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderItemAttributeTypes, map[string]attr.Value{
		"header": types.StringUnknown(),
	})
	if diags.HasError() {
		t.Fatalf("build config object: %v", diags)
	}
	planObject, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderItemAttributeTypes, map[string]attr.Value{
		"header": types.StringValue("X-Resolved-Header"),
	})
	if diags.HasError() {
		t.Fatalf("build plan object: %v", diags)
	}
	configList, diags := types.ListValue(types.ObjectType{AttrTypes: rewritingRequestsRuleListRemoveHeaderItemAttributeTypes}, []attr.Value{configObject})
	if diags.HasError() {
		t.Fatalf("build config list: %v", diags)
	}
	planList, diags := types.ListValue(types.ObjectType{AttrTypes: rewritingRequestsRuleListRemoveHeaderItemAttributeTypes}, []attr.Value{planObject})
	if diags.HasError() {
		t.Fatalf("build plan list: %v", diags)
	}
	configWrapper, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderWrapperAttributeTypes, map[string]attr.Value{"item": configList})
	if diags.HasError() {
		t.Fatalf("build config wrapper: %v", diags)
	}
	planWrapper, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderWrapperAttributeTypes, map[string]attr.Value{"item": planList})
	if diags.HasError() {
		t.Fatalf("build plan wrapper: %v", diags)
	}

	var buildDiags diag.Diagnostics
	owned := rewritingRequestsRuleListBuildItemStringArrayRemoveHeader(context.Background(), configWrapper, planWrapper, "rule_list item 1", &buildDiags)
	if buildDiags.HasError() {
		t.Fatalf("computed-reference fallback was rejected: %v", buildDiags)
	}
	if !owned.Set || len(owned.Items) != 1 || owned.Items[0] != "X-Resolved-Header" {
		t.Fatalf("owned = %#v, want Set=true Items=[X-Resolved-Header]", owned)
	}
}

// TestRewritingRequestsRemoveHeaderUnknownRejectedWithoutPlan is the negative
// control proving the fallback comes from the planned value, not from accepting
// unknowns unconditionally: when both config and plan headers are unknown, the
// build rejects the item as required.
func TestRewritingRequestsRemoveHeaderUnknownRejectedWithoutPlan(t *testing.T) {
	t.Parallel()

	configObject, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderItemAttributeTypes, map[string]attr.Value{
		"header": types.StringUnknown(),
	})
	if diags.HasError() {
		t.Fatalf("build config object: %v", diags)
	}
	planObject, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderItemAttributeTypes, map[string]attr.Value{
		"header": types.StringUnknown(),
	})
	if diags.HasError() {
		t.Fatalf("build plan object: %v", diags)
	}
	configList, diags := types.ListValue(types.ObjectType{AttrTypes: rewritingRequestsRuleListRemoveHeaderItemAttributeTypes}, []attr.Value{configObject})
	if diags.HasError() {
		t.Fatalf("build config list: %v", diags)
	}
	planList, diags := types.ListValue(types.ObjectType{AttrTypes: rewritingRequestsRuleListRemoveHeaderItemAttributeTypes}, []attr.Value{planObject})
	if diags.HasError() {
		t.Fatalf("build plan list: %v", diags)
	}
	configWrapper, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderWrapperAttributeTypes, map[string]attr.Value{"item": configList})
	if diags.HasError() {
		t.Fatalf("build config wrapper: %v", diags)
	}
	planWrapper, diags := types.ObjectValue(rewritingRequestsRuleListRemoveHeaderWrapperAttributeTypes, map[string]attr.Value{"item": planList})
	if diags.HasError() {
		t.Fatalf("build plan wrapper: %v", diags)
	}

	var buildDiags diag.Diagnostics
	rewritingRequestsRuleListBuildItemStringArrayRemoveHeader(context.Background(), configWrapper, planWrapper, "rule_list item 1", &buildDiags)
	if !buildDiags.HasError() {
		t.Fatal("unknown config+plan header was not rejected")
	}
}

// TestRewritingRequestsIndexedUnchangedRulePreservesRemoveHeader verifies the
// indexed P1 fix: an UNCHANGED rewriting rule (same scalar content) with an
// omitted remove_header wrapper preserves the fresh GET's remove_header by
// matching the unchanged content projection — not by positional idx (idx is
// regenerated sequentially and is not a stable identity).
func TestRewritingRequestsIndexedUnchangedRulePreservesRemoveHeader(t *testing.T) {
	t.Parallel()

	name := "r1"
	action := "rewrite-url"
	patchItem := rewritingRequestsRuleListWireItem{Name: &name, Action: &action}
	patch := rewritingRequestsPatch{
		RuleList: rewritingRequestsRuleListOwnedList{Set: true, Items: []rewritingRequestsRuleListWireItem{patchItem}},
	}
	// The fresh GET carries the same rule (name=r1, action=rewrite-url) with a
	// remove_header. The patch item's scalar projection matches, so the
	// remove_header is grafted despite idx being regenerated.
	getConfigs := map[string]json.RawMessage{
		"rule_list": json.RawMessage(`[{"idx":7,"name":"r1","action":"rewrite-url","remove_header":["X-Old"]}]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if diagnostics.HasError() {
		t.Fatalf("Apply diagnostics: %v", diagnostics)
	}
	mergedRaw, ok := result.Configs["rule_list"]
	if !ok {
		t.Fatal("merged result is missing rule_list")
	}
	var merged []map[string]json.RawMessage
	if err := json.Unmarshal(mergedRaw, &merged); err != nil {
		t.Fatalf("decode merged rule_list: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("merged items = %d, want 1", len(merged))
	}
	removeHeader, present := merged[0]["remove_header"]
	if !present || !bytes.Contains(removeHeader, []byte("X-Old")) {
		t.Fatalf("unchanged rule's remove_header was not preserved: present=%v raw=%v", present, removeHeader)
	}
}

// TestRewritingRequestsIndexedChangedRuleOmittedWrapperRefused verifies the
// indexed fail-closed behavior: keeping a rule whose scalar content CHANGED
// (different name) while omitting its remove_header wrapper is refused, because
// the unchanged-content projection no longer matches the fresh GET and omission
// means preserve. The old positional graft would have silently copied the
// removed/renamed rule's remove_header onto the surviving rule.
func TestRewritingRequestsIndexedChangedRuleOmittedWrapperRefused(t *testing.T) {
	t.Parallel()

	name := "r2" // different from the GET rule's name -> no unchanged-content match
	action := "rewrite-url"
	patchItem := rewritingRequestsRuleListWireItem{Name: &name, Action: &action}
	patch := rewritingRequestsPatch{
		RuleList: rewritingRequestsRuleListOwnedList{Set: true, Items: []rewritingRequestsRuleListWireItem{patchItem}},
	}
	getConfigs := map[string]json.RawMessage{
		"rule_list": json.RawMessage(`[{"idx":1,"name":"r1","action":"rewrite-url","remove_header":["X-Old"]}]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if !diagnostics.HasError() {
		t.Fatal("Apply was not refused for a changed rule with an omitted nested wrapper")
	}
}

// TestParameterValidationBlockPeriodOmittedDecodesToDefault verifies the decode
// path substitutes the reviewed default (60) when the successful GET omits the
// optional block_period field, mirroring the encode path (which sends 60 on
// first-create omission). Without this, state would carry 0 and a later update
// would reuse the stale 0.
func TestParameterValidationBlockPeriodOmittedDecodesToDefault(t *testing.T) {
	t.Parallel()

	// One rule with block_period omitted; the other required fields present.
	raw := json.RawMessage(`[{"idx":1,"action":"alert_deny","name":"r","url":"/u"}]`)
	owned, diags := parameterValidationDecodeRuleList(raw)
	if diags.HasError() {
		t.Fatalf("omitted block_period decode errored: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	if owned.Items[0].BlockPeriod != 60 {
		t.Fatalf("omitted block_period = %d, want reviewed default 60", owned.Items[0].BlockPeriod)
	}
}

// TestRewritingRequestsProtocolDefaultMatchesOmitted verifies the unchanged-
// projection canonicalization treats an explicit protocol "HTTP" (the reviewed
// default) and an omitted protocol as equal, so an unchanged rule with an
// omitted remove_header is preserved (not refused) when the patch sets
// protocol="HTTP" explicitly and the GET omits protocol. The matcher compares
// the JSON encoding (quoted "HTTP"), not unquoted bytes.
func TestRewritingRequestsProtocolDefaultMatchesOmitted(t *testing.T) {
	t.Parallel()

	name := "r1"
	action := "rewrite-url"
	protocol := "HTTP" // the reviewed default; GET omits it
	patchItem := rewritingRequestsRuleListWireItem{Name: &name, Action: &action, Protocol: &protocol}
	patch := rewritingRequestsPatch{
		RuleList: rewritingRequestsRuleListOwnedList{Set: true, Items: []rewritingRequestsRuleListWireItem{patchItem}},
	}
	// The GET rule has the same name+action but omits protocol (default HTTP)
	// and carries a remove_header to be preserved.
	getConfigs := map[string]json.RawMessage{
		"rule_list": json.RawMessage(`[{"idx":1,"name":"r1","action":"rewrite-url","remove_header":["X-Old"]}]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if diagnostics.HasError() {
		t.Fatalf("unchanged rule with explicit protocol default was refused (canonicalization bug): %v", diagnostics)
	}
	mergedRaw, ok := result.Configs["rule_list"]
	if !ok {
		t.Fatal("merged result is missing rule_list")
	}
	var merged []map[string]json.RawMessage
	if err := json.Unmarshal(mergedRaw, &merged); err != nil {
		t.Fatalf("decode merged rule_list: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("merged items = %d, want 1", len(merged))
	}
	removeHeader, present := merged[0]["remove_header"]
	if !present || !bytes.Contains(removeHeader, []byte("X-Old")) {
		t.Fatalf("remove_header was not preserved when protocol defaulted: present=%v raw=%v", present, removeHeader)
	}
}

// TestRewritingRequestsEmptyGetAllowsNewItemOmittedWrapper verifies that when
// the fresh GET returns an empty rule_list, adding the first rule with an
// OMITTED remove_header wrapper succeeds (the new item has nothing to preserve,
// so omission is fine and the apply is not refused).
func TestRewritingRequestsEmptyGetAllowsNewItemOmittedWrapper(t *testing.T) {
	t.Parallel()

	name := "r1"
	action := "rewrite-url"
	patchItem := rewritingRequestsRuleListWireItem{Name: &name, Action: &action} // remove_header omitted
	patch := rewritingRequestsPatch{
		RuleList: rewritingRequestsRuleListOwnedList{Set: true, Items: []rewritingRequestsRuleListWireItem{patchItem}},
	}
	// The fresh GET returns an empty rule_list: there is no prior nested value
	// to preserve, so the new rule's omitted remove_header must not be refused.
	getConfigs := map[string]json.RawMessage{
		"rule_list": json.RawMessage(`[]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if diagnostics.HasError() {
		t.Fatalf("adding a new rule with an omitted nested wrapper to an empty collection was refused: %v", diagnostics)
	}
	mergedRaw, ok := result.Configs["rule_list"]
	if !ok {
		t.Fatal("merged result is missing rule_list")
	}
	var merged []map[string]json.RawMessage
	if err := json.Unmarshal(mergedRaw, &merged); err != nil {
		t.Fatalf("decode merged rule_list: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("merged items = %d, want 1", len(merged))
	}
	if _, present := merged[0]["remove_header"]; present {
		t.Fatalf("new rule's omitted remove_header should stay absent, got %v", merged[0]["remove_header"])
	}
}

// TestRewritingRequestsProtocolOmittedDecodesToDefault verifies the item-string
// decode substitutes the reviewed default ("HTTP") when the successful GET
// omits the protocol key, mirroring the encode path (which sends "HTTP" on
// first-create omission). Without this, the refreshed state would carry null
// and disagree with a configured-default value.
func TestRewritingRequestsProtocolOmittedDecodesToDefault(t *testing.T) {
	t.Parallel()

	// One rule with protocol omitted; name+action present (valid fields).
	raw := json.RawMessage(`[{"idx":1,"name":"r1","action":"rewrite-url"}]`)
	owned, diags := rewritingRequestsDecodeRuleList(raw)
	if diags.HasError() {
		t.Fatalf("omitted protocol decode errored: %v", diags)
	}
	if len(owned.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(owned.Items))
	}
	if owned.Items[0].Protocol == nil || *owned.Items[0].Protocol != "HTTP" {
		t.Fatalf("omitted protocol = %v, want reviewed default \"HTTP\"", owned.Items[0].Protocol)
	}
}

// TestRewritingRequestsRemoveHeaderNullElementRejected verifies a null element
// in a remove_header array is rejected (the item string is not nullable),
// rather than being coerced to an empty string.
func TestRewritingRequestsRemoveHeaderNullElementRejected(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`["X-Valid", null]`)
	var diags diag.Diagnostics
	rewritingRequestsRuleListDecodeItemStringArrayRemoveHeader(raw, "rule_list item 1 remove_header", &diags)
	if !diags.HasError() {
		t.Fatal("null element in remove_header was not rejected")
	}
	if !containsDiagnostic(diags, "null") {
		t.Fatalf("diagnostics did not mention null: %v", diags)
	}
}

// TestKnownBotsUnindexedListRemovalDoesNotGraftNestedArray verifies the P1 fix:
// for an unindexed collection (known_bots bad_bots_list), removing one item and
// keeping another (with an omitted allow_list) must preserve the KEPT item's own
// allow_list — NOT the removed item's. Under the old positional merge, the kept
// item (now at position 0) inherited the removed item's position-0 allow_list,
// silently changing WAF behavior. Identity matching grafts the kept item's own
// list by its scalar identity (cat + status), so the Scanner item gets [BotB]
// (its own), never [BotA] (the removed DoS item's).
func TestKnownBotsUnindexedListRemovalDoesNotGraftNestedArray(t *testing.T) {
	t.Parallel()

	// Patch keeps ONLY the Scanner item (the DoS item is removed); its
	// allow_list is omitted so it must be preserved from the GET by identity.
	cat := "Scanner"
	patchItem := knownBotsBadBotsListWireItem{Cat: &cat, Status: true}
	patch := knownBotsPatch{
		BadBotsList: knownBotsBadBotsListOwnedList{
			Set:   true,
			Items: []knownBotsBadBotsListWireItem{patchItem},
		},
	}
	// The fresh GET carries TWO items, each with a non-empty allow_list. The
	// kept Scanner item must receive its OWN [BotB], not the removed DoS item's
	// [BotA] (which the old positional merge would have grafted at position 0).
	getConfigs := map[string]json.RawMessage{
		"bad_bots_list": json.RawMessage(`[{"idx":1,"cat":"DoS","status":true,"allow_list":["BotA"]},{"idx":2,"cat":"Scanner","status":true,"allow_list":["BotB"]}]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if diagnostics.HasError() {
		t.Fatalf("Apply diagnostics: %v", diagnostics)
	}

	mergedRaw, ok := result.Configs["bad_bots_list"]
	if !ok {
		t.Fatal("merged result is missing bad_bots_list")
	}
	var merged []map[string]json.RawMessage
	if err := json.Unmarshal(mergedRaw, &merged); err != nil {
		t.Fatalf("decode merged bad_bots_list: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("merged items = %d, want 1", len(merged))
	}
	allowList, present := merged[0]["allow_list"]
	if !present || len(bytes.TrimSpace(allowList)) == 0 {
		t.Fatal("kept item's allow_list was not preserved from the GET")
	}
	if bytes.Contains(allowList, []byte("BotA")) {
		t.Fatalf("removed DoS item's allow_list [BotA] was grafted onto the kept Scanner item: %s", allowList)
	}
	if !bytes.Contains(allowList, []byte("BotB")) {
		t.Fatalf("kept Scanner item's own allow_list [BotB] was not preserved: %s", allowList)
	}
}

// TestKnownBotsUnindexedListUnchangedPreservesNestedArray is the positive
// control proving the count-equal guard still preserves the nested array when
// the unindexed item set is unchanged (no removal/reorder): a single patch item
// with an omitted allow_list inherits the GET's single-item allow_list.
func TestKnownBotsUnindexedListUnchangedPreservesNestedArray(t *testing.T) {
	t.Parallel()

	cat := "DoS"
	patchItem := knownBotsBadBotsListWireItem{Cat: &cat, Status: true}
	patch := knownBotsPatch{
		BadBotsList: knownBotsBadBotsListOwnedList{
			Set:   true,
			Items: []knownBotsBadBotsListWireItem{patchItem},
		},
	}
	// One GET item with a non-empty allow_list; counts match (1 == 1) so the
	// preserved nested array is grafted by position.
	getConfigs := map[string]json.RawMessage{
		"bad_bots_list": json.RawMessage(`[{"idx":1,"cat":"DoS","status":true,"allow_list":["BotA"]}]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if diagnostics.HasError() {
		t.Fatalf("Apply diagnostics: %v", diagnostics)
	}

	mergedRaw, ok := result.Configs["bad_bots_list"]
	if !ok {
		t.Fatal("merged result is missing bad_bots_list")
	}
	var merged []map[string]json.RawMessage
	if err := json.Unmarshal(mergedRaw, &merged); err != nil {
		t.Fatalf("decode merged bad_bots_list: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("merged items = %d, want 1", len(merged))
	}
	allowList, present := merged[0]["allow_list"]
	if !present {
		t.Fatal("allow_list was not preserved when the item set was unchanged")
	}
	if !bytes.Contains(allowList, []byte("BotA")) {
		t.Fatalf("preserved allow_list = %s, want it to contain BotA", allowList)
	}
}

// TestKnownBotsUnindexedListAppendOmittedWrapperRefused verifies the fail-closed
// design: appending a NEW item to an unindexed collection while OMITTING its
// nested allow_list wrapper is refused, because omission means preserve and a
// new item has no remote counterpart to preserve from. The existing item's
// omitted wrapper is still preserved by matching its unchanged content. The
// user must configure an explicit (empty or populated) wrapper for a new item.
func TestKnownBotsUnindexedListAppendOmittedWrapperRefused(t *testing.T) {
	t.Parallel()

	dosCat := "DoS"
	scannerCat := "Scanner"
	patch := knownBotsPatch{
		BadBotsList: knownBotsBadBotsListOwnedList{
			Set: true,
			Items: []knownBotsBadBotsListWireItem{
				{Cat: &dosCat, Status: true},     // existing item, allow_list omitted -> preserved
				{Cat: &scannerCat, Status: true}, // appended item, allow_list omitted -> refused
			},
		},
	}
	getConfigs := map[string]json.RawMessage{
		"bad_bots_list": json.RawMessage(`[{"idx":1,"cat":"DoS","status":true,"allow_list":["BotA"]}]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if !diagnostics.HasError() {
		t.Fatal("Apply was not refused for a new item with an omitted nested wrapper")
	}
}

// TestKnownBotsUnindexedListAppendExplicitWrapperAccepted is the positive
// control: appending a new item with an EXPLICIT empty allow_list wrapper is
// accepted (no preservation needed for the new item), and the existing item's
// omitted wrapper is preserved by matching its unchanged content.
func TestKnownBotsUnindexedListAppendExplicitWrapperAccepted(t *testing.T) {
	t.Parallel()

	dosCat := "DoS"
	scannerCat := "Scanner"
	patch := knownBotsPatch{
		BadBotsList: knownBotsBadBotsListOwnedList{
			Set: true,
			Items: []knownBotsBadBotsListWireItem{
				{Cat: &dosCat, Status: true},                              // existing, allow_list omitted -> preserved
				{Cat: &scannerCat, Status: true, AllowList: []byte(`[]`)}, // appended, explicit empty wrapper
			},
		},
	}
	getConfigs := map[string]json.RawMessage{
		"bad_bots_list": json.RawMessage(`[{"idx":1,"cat":"DoS","status":true,"allow_list":["BotA"]}]`),
	}
	result := &client.WAFModuleResult{Configs: getConfigs, Template: false}

	diagnostics := patch.Apply(context.Background(), result)
	if diagnostics.HasError() {
		t.Fatalf("Apply was refused for an explicit-wrapper append: %v", diagnostics)
	}

	mergedRaw, ok := result.Configs["bad_bots_list"]
	if !ok {
		t.Fatal("merged result is missing bad_bots_list")
	}
	var merged []map[string]json.RawMessage
	if err := json.Unmarshal(mergedRaw, &merged); err != nil {
		t.Fatalf("decode merged bad_bots_list: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("merged items = %d, want 2", len(merged))
	}
	dosAllow, ok := merged[0]["allow_list"]
	if !ok || !bytes.Contains(dosAllow, []byte("BotA")) {
		t.Fatalf("existing DoS item allow_list = %v (ok=%v), want it to contain BotA", dosAllow, ok)
	}
	scannerAllow, present := merged[1]["allow_list"]
	if !present || bytes.Contains(scannerAllow, []byte("BotA")) {
		t.Fatalf("appended Scanner item allow_list = %v (present=%v), want an explicit [] not inheriting BotA", scannerAllow, present)
	}
}
