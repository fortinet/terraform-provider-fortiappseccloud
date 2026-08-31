package customrule

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

const crGetFalse = `{"result":{"configs":{"status":false,"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
const crGetTrue = `{"result":{"configs":{"status":true,"rule_list":[{"idx":1,"name":"p1","action":"alert","filter_list":[{"idx":1,"type":"source-ip-filter","ip":"10.0.0.1"}]}]},"template":false,"future_envelope":"keep"}}`

func TestNewResourceLoadsReviewedDestroyPromotion(t *testing.T) {
	t.Parallel()

	implementation := NewResource(locking.NewRegistry()).(*customRuleResource)
	if implementation.destroy.Module != "custom_rule" ||
		string(implementation.destroy.DestroyPolicy) != "disable" ||
		implementation.destroy.DestroyField != "status" ||
		!implementation.destroy.DestroyVerified {
		t.Fatalf("reviewed destroy policy = %#v", implementation.destroy)
	}
}

func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCustomRuleService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, crGetTrue)},
		},
		exists: true,
	}
	implementation := &customRuleResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, testRuleListWrapper(t, testRuleItem(t, "p1", "alert", testFilterListWrapper(t, testFilterItem(t, "source-ip-filter"))))),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}

	if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "put:123", "get:123"}) {
		t.Fatalf("calls = %#v", calls)
	}
	puts := service.putDocuments()
	if len(puts) != 1 || puts[0].Template {
		t.Fatalf("PUT documents = %#v", puts)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["configs"], &configs); err != nil {
		// puts[0].Configs is the raw configs map; let me check the structure
		// Actually WAFModuleResult.Configs is map[string]json.RawMessage
	}
	// WAFModuleResult stores configs as raw map; status should be true.
	var status bool
	if err := json.Unmarshal(puts[0].Configs["status"], &status); err != nil || !status {
		t.Fatalf("PUT status = %s, want true", puts[0].Configs["status"])
	}
	var rules []map[string]any
	if err := json.Unmarshal(puts[0].Configs["rule_list"], &rules); err != nil {
		t.Fatalf("decode rule_list: %v", err)
	}
	if len(rules) != 1 || rules[0]["name"] != "p1" || rules[0]["action"] != "alert" {
		t.Fatalf("PUT rule_list = %#v", rules)
	}
	if rules[0]["idx"] != float64(1) {
		t.Fatalf("PUT rule_list[0].idx = %v, want 1", rules[0]["idx"])
	}
	filters, _ := rules[0]["filter_list"].([]any)
	if len(filters) != 1 {
		t.Fatalf("filter_list length = %d, want 1", len(filters))
	}
	filter, _ := filters[0].(map[string]any)
	if filter["type"] != "source-ip-filter" || filter["ip"] != "10.0.0.1" {
		t.Fatalf("PUT filter = %#v", filter)
	}
	if filter["idx"] != float64(1) {
		t.Fatalf("PUT filter[0].idx = %v, want 1", filter["idx"])
	}
}

func TestResponseCodeUsesOpenAPI263AWireField(t *testing.T) {
	t.Parallel()

	filter := testFilterItem(t, "response-code")
	filter.IP = types.StringNull()
	filter.ResponseCode = types.Int64Value(404)
	wrapper := testFilterListWrapper(t, filter)
	items, diagnostics := buildFilterList(context.Background(), wrapper, 1)
	if diagnostics.HasError() || len(items) != 1 {
		t.Fatalf("buildFilterList diagnostics/items = %v / %#v", diagnostics, items)
	}
	wire := items[0].(map[string]any)
	if wire["code"] != "404" {
		t.Fatalf("wire code = %#v, want string 404", wire["code"])
	}
	if _, obsolete := wire["response_code"]; obsolete {
		t.Fatalf("wire payload retained obsolete response_code: %#v", wire)
	}

	var flattenDiagnostics diag.Diagnostics
	state := stateFilterListWrapper(json.RawMessage(`[{"idx":1,"type":"response-code","code":"404"}]`), &flattenDiagnostics)
	if flattenDiagnostics.HasError() {
		t.Fatalf("stateFilterListWrapper diagnostics = %v", flattenDiagnostics)
	}
	var stateWrapper filterListWrapperModel
	flattenDiagnostics.Append(state.As(context.Background(), &stateWrapper, basetypes.ObjectAsOptions{})...)
	var stateItems []filterItemModel
	flattenDiagnostics.Append(stateWrapper.Item.ElementsAs(context.Background(), &stateItems, false)...)
	if flattenDiagnostics.HasError() || len(stateItems) != 1 || stateItems[0].ResponseCode.ValueInt64() != 404 {
		t.Fatalf("flattened response_code diagnostics/items = %v / %#v", flattenDiagnostics, stateItems)
	}
}

func TestCreateTemplateTrueOmitsConfigs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCustomRuleService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false},"template":true,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &customRuleResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(true),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 || !puts[0].Template {
		t.Fatalf("PUT documents = %#v", puts)
	}
	state := testStateModelValue(t, ctx, response.State)
	if !state.Configs.IsNull() {
		t.Fatalf("state configs = %#v, want null for template=true", state.Configs)
	}
}

func TestRuleListOmittedPreservesRemoteArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const getWithRules = `{"result":{"configs":{"status":false,"rule_list":[{"idx":1,"name":"old","action":"alert"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	service := &fakeCustomRuleService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithRules)},
			{document: testDocumentFromJSON(t, getWithRules)},
		},
		exists: true,
	}
	implementation := &customRuleResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	// rule_list must be carried forward from the GET (clone preserves it).
	if _, ok := puts[0].Configs["rule_list"]; !ok {
		t.Fatal("PUT omitted rule_list when the wrapper was omitted; the remote array must be carried forward")
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.RuleList.IsNull() {
		t.Fatalf("state rule_list wrapper = %#v, want null", configs.RuleList)
	}
}

func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCustomRuleService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, crGetTrue)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put custom rule", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &customRuleResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, testRuleListWrapper(t, testRuleItem(t, "p1", "alert", testFilterListWrapper(t, testFilterItem(t, "source-ip-filter"))))),
	}

	response := resource.UpdateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Update(ctx, resource.UpdateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "put:123", "get:123", "put:123", "get:123"}) {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestDeleteForgetsWithWarning(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCustomRuleService{exists: true}
	implementation := &customRuleResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.DeleteResponse{State: testCopyState(prior)}
	implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", response.Diagnostics)
	}
	if len(response.Diagnostics.Warnings()) == 0 {
		t.Fatal("Delete() did not emit a forget warning")
	}
	if calls := service.callLog(); len(calls) != 0 {
		t.Fatalf("Delete() made remote calls = %#v", calls)
	}
}

func TestReadRemovesStateWhenParentAbsent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCustomRuleService{
		gets:   []fakeGetResult{{err: &client.APIError{Operation: "get custom rule", StatusCode: http.StatusNotFound}}},
		exists: false,
	}
	implementation := &customRuleResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.ReadResponse{State: testCopyState(prior)}
	implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read() diagnostics = %v", response.Diagnostics)
	}
	if response.State.Raw.Equal(prior.Raw) {
		t.Fatal("Read() kept state after parent app disappeared")
	}
}

func TestImportState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	implementation := &customRuleResource{locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	empty := testStateFor(t, ctx, resourceSchema, &resourceModel{
		EPID:     types.StringNull(),
		Template: types.BoolNull(),
		Configs:  types.ObjectNull(configsAttributeTypes),
	})
	response := resource.ImportStateResponse{State: empty}
	implementation.ImportState(ctx, resource.ImportStateRequest{ID: " 123 "}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("ImportState() diagnostics = %v", response.Diagnostics)
	}
	var id types.String
	if diagnostics := response.State.GetAttribute(ctx, path.Root("ep_id"), &id); diagnostics.HasError() {
		t.Fatalf("State.GetAttribute(ep_id) diagnostics = %v", diagnostics)
	}
	if id.ValueString() != "123" {
		t.Fatalf("imported ep_id = %q", id.ValueString())
	}
}

func TestResourceConfigureRejectsUnexpectedProviderData(t *testing.T) {
	t.Parallel()

	implementation := &customRuleResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

func TestUsernameValidatorUsesReviewedUTF8Bound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema := testResourceSchema(t, ctx, &customRuleResource{locks: locking.NewRegistry()})
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	ruleList := configs.Blocks["rule_list"].(schema.SingleNestedBlock)
	rules := ruleList.Blocks["item"].(schema.ListNestedBlock)
	filterList := rules.NestedObject.Blocks["filter_list"].(schema.SingleNestedBlock)
	filters := filterList.Blocks["item"].(schema.ListNestedBlock)
	username := filters.NestedObject.Attributes["username"].(schema.StringAttribute)
	if len(username.Validators) == 0 {
		t.Fatal("username has no validators")
	}

	validate := func(value string) validator.StringResponse {
		t.Helper()
		var response validator.StringResponse
		for _, implementation := range username.Validators {
			implementation.ValidateString(ctx, validator.StringRequest{
				Path:        path.Root("username"),
				ConfigValue: types.StringValue(value),
			}, &response)
		}
		return response
	}
	if response := validate(strings.Repeat("界", client.CustomRuleUsernameMaxLen)); response.Diagnostics.HasError() {
		t.Fatalf("valid UTF-8 bound diagnostics = %v", response.Diagnostics)
	}
	if response := validate(strings.Repeat("界", client.CustomRuleUsernameMaxLen+1)); !response.Diagnostics.HasError() {
		t.Fatal("username validator accepted more than the reviewed UTF-8 bound")
	}
}

func TestImportedOwnedRulesFailClosedOnMalformedKnownField(t *testing.T) {
	t.Parallel()

	document := testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"rule_list":[{"idx":1,"name":null,"action":"alert"}]},"template":false}}`)
	_, diagnostics := stateModel(
		"123",
		document,
		ownershipImported,
		types.ObjectNull(configsAttributeTypes),
	)
	if !diagnostics.HasError() {
		t.Fatal("imported owned rule_list accepted a malformed known field")
	}
}

func TestImportedRuleAndFilterListsSortByWireIndex(t *testing.T) {
	t.Parallel()

	document := testDocumentFromJSON(t, `{
		"result":{
			"template":false,
			"configs":{
				"status":true,
				"rule_list":[
					{"idx":2,"name":"second","action":"alert"},
					{"idx":1,"name":"first","action":"alert","filter_list":[
						{"idx":2,"type":"user-filter","username":"second"},
						{"idx":1,"type":"source-ip-filter","ip":"198.51.100.1"}
					]}
				]
			}
		}
	}`)
	model, diagnostics := stateModel(
		"123",
		document,
		ownershipImported,
		types.ObjectNull(configsAttributeTypes),
	)
	if diagnostics.HasError() {
		t.Fatalf("stateModel diagnostics = %v", diagnostics)
	}
	configs := testDecodeConfigs(t, context.Background(), model.Configs)
	var rulesWrapper ruleListWrapperModel
	if diagnostics := configs.RuleList.As(context.Background(), &rulesWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("rule_list.As diagnostics = %v", diagnostics)
	}
	var rules []ruleItemModel
	if diagnostics := rulesWrapper.Item.ElementsAs(context.Background(), &rules, false); diagnostics.HasError() {
		t.Fatalf("rule_list items diagnostics = %v", diagnostics)
	}
	if len(rules) != 2 || rules[0].Name.ValueString() != "first" || rules[1].Name.ValueString() != "second" {
		t.Fatalf("rule order = %#v", rules)
	}
	var filtersWrapper filterListWrapperModel
	if diagnostics := rules[0].FilterList.As(context.Background(), &filtersWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("filter_list.As diagnostics = %v", diagnostics)
	}
	var filters []filterItemModel
	if diagnostics := filtersWrapper.Item.ElementsAs(context.Background(), &filters, false); diagnostics.HasError() {
		t.Fatalf("filter_list items diagnostics = %v", diagnostics)
	}
	if len(filters) != 2 ||
		filters[0].Type.ValueString() != "source-ip-filter" ||
		filters[1].Type.ValueString() != "user-filter" {
		t.Fatalf("filter order = %#v", filters)
	}
}

func TestCreateRejectsOverlongUTF8Username(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCustomRuleService{
		gets:   []fakeGetResult{{document: testDocumentFromJSON(t, crGetFalse)}},
		exists: true,
	}
	implementation := &customRuleResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	filter := testFilterItem(t, "user-filter")
	filter.IP = types.StringNull()
	filter.Username = types.StringValue(strings.Repeat("界", client.CustomRuleUsernameMaxLen+1))
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, testRuleListWrapper(t, testRuleItem(t, "rule", "alert", testFilterListWrapper(t, filter)))),
	}
	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Create() accepted an overlong UTF-8 username")
	}
	if len(service.putDocuments()) != 0 {
		t.Fatal("Create() sent a PUT for an overlong username")
	}
}

type fakeGetResult struct {
	document client.CustomRuleDocument
	err      error
}

type fakeCustomRuleService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	calls     []string
	puts      []client.WAFModuleResult
}

func (s *fakeCustomRuleService) GetCustomRule(_ context.Context, epID string) (client.CustomRuleDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.CustomRuleDocument{}, errors.New("unexpected GetCustomRule call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeCustomRuleService) PutCustomRule(_ context.Context, epID string, result client.WAFModuleResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "put:"+epID)
	s.puts = append(s.puts, result.Clone())
	if len(s.putErrors) == 0 {
		return nil
	}
	err := s.putErrors[0]
	s.putErrors = s.putErrors[1:]
	return err
}

func (s *fakeCustomRuleService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, nil
}

func (s *fakeCustomRuleService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeCustomRuleService) putDocuments() []client.WAFModuleResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]client.WAFModuleResult, len(s.puts))
	for i := range s.puts {
		result[i] = s.puts[i].Clone()
	}
	return result
}

func testResourceSchema(t *testing.T, ctx context.Context, implementation resource.Resource) schema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	implementation.Schema(ctx, resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Schema() diagnostics = %v", response.Diagnostics)
	}
	return response.Schema
}

func testStateFor(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.State {
	t.Helper()
	state := tfsdk.State{Schema: resourceSchema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("State.Set() diagnostics = %v", diagnostics)
	}
	return state
}

func testPlanFor(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Plan {
	t.Helper()
	plan := tfsdk.Plan{Schema: resourceSchema}
	if diagnostics := plan.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("Plan.Set() diagnostics = %v", diagnostics)
	}
	return plan
}

func testConfigFor(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Config {
	t.Helper()
	state := testStateFor(t, ctx, resourceSchema, model)
	return tfsdk.Config{Schema: resourceSchema, Raw: state.Raw.Copy()}
}

func testNullState(ctx context.Context, resourceSchema schema.Schema) tfsdk.State {
	return tfsdk.State{Schema: resourceSchema, Raw: tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil)}
}

func testCopyState(state tfsdk.State) tfsdk.State {
	return tfsdk.State{Schema: state.Schema, Raw: state.Raw.Copy()}
}

func testStateModelValue(t *testing.T, ctx context.Context, state tfsdk.State) resourceModel {
	t.Helper()
	var model resourceModel
	if diagnostics := state.Get(ctx, &model); diagnostics.HasError() {
		t.Fatalf("State.Get() diagnostics = %v", diagnostics)
	}
	return model
}

func testDecodeConfigs(t *testing.T, ctx context.Context, object types.Object) configsModel {
	t.Helper()
	if object.IsNull() || object.IsUnknown() {
		t.Fatalf("configs object = %#v", object)
	}
	var configs configsModel
	if diagnostics := object.As(ctx, &configs, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("configs.As() diagnostics = %v", diagnostics)
	}
	return configs
}

func testDocumentFromJSON(t *testing.T, payload string) client.CustomRuleDocument {
	t.Helper()
	var document client.CustomRuleDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(document) error = %v", err)
	}
	return document
}

func testFilterItem(t *testing.T, filterType string) filterItemModel {
	t.Helper()
	return filterItemModel{
		Type:         types.StringValue(filterType),
		IP:           types.StringValue("10.0.0.1"),
		ContentTypes: types.ListNull(types.StringType),
		CountryList:  types.ListNull(types.StringType),
	}
}

func testFilterListWrapper(t *testing.T, filters ...filterItemModel) types.Object {
	t.Helper()
	values := make([]attr.Value, 0, len(filters))
	for _, f := range filters {
		attrs := map[string]attr.Value{
			"type":                     f.Type,
			"reverse_match":            f.ReverseMatch,
			"ip":                       f.IP,
			"username":                 f.Username,
			"url":                      f.URL,
			"name":                     f.Name,
			"value":                    f.Value,
			"header_check":             f.HeaderCheck,
			"header_type":              f.HeaderType,
			"header_name":              f.HeaderName,
			"header_value":             f.HeaderValue,
			"header_reverse_match":     f.HeaderReverseMatch,
			"method_check":             f.MethodCheck,
			"method_value":             f.MethodValue,
			"method_reverse_match":     f.MethodReverseMatch,
			"http_hline_missing_check": f.HttpHlineMissing,
			"http_hline_empty_check":   f.HttpHlineEmpty,
			"content_types":            f.ContentTypes,
			"response_code":            f.ResponseCode,
			"cross_site_scripting":     f.CrossSiteScripting,
			"sql_injection":            f.SqlInjection,
			"generic_attacks":          f.GenericAttacks,
			"known_exploits":           f.KnownExploits,
			"trojans":                  f.Trojans,
			"limit":                    f.Limit,
			"timeout":                  f.Timeout,
			"occurrence":               f.Occurrence,
			"within":                   f.Within,
			"time_type":                f.TimeType,
			"start":                    f.Start,
			"end":                      f.End,
			"country_list":             f.CountryList,
			"match_exclusively":        f.MatchExclusively,
		}
		// Set null defaults for unset fields
		for k, v := range attrs {
			if v == (attr.Value)(nil) {
				attrs[k] = types.StringNull()
			}
		}
		// Fix non-string nulls
		for _, boolKey := range []string{"reverse_match", "header_check", "header_reverse_match", "method_check", "method_reverse_match", "http_hline_missing_check", "http_hline_empty_check", "cross_site_scripting", "sql_injection", "generic_attacks", "known_exploits", "trojans", "match_exclusively"} {
			if _, ok := attrs[boolKey].(types.Bool); !ok {
				attrs[boolKey] = types.BoolNull()
			}
		}
		for _, listKey := range []string{"content_types", "country_list"} {
			if _, ok := attrs[listKey].(types.List); !ok {
				attrs[listKey] = types.ListNull(types.StringType)
			}
		}
		for _, intKey := range []string{"response_code", "limit", "timeout", "occurrence", "within"} {
			if _, ok := attrs[intKey].(types.Int64); !ok {
				attrs[intKey] = types.Int64Null()
			}
		}
		obj, diag := types.ObjectValue(filterItemObjectTypes().AttrTypes, attrs)
		if diag.HasError() {
			t.Fatalf("ObjectValue(filter) diagnostics = %v", diag)
		}
		values = append(values, obj)
	}
	list, diag := types.ListValue(filterItemObjectTypes(), values)
	if diag.HasError() {
		t.Fatalf("ListValue(filters) diagnostics = %v", diag)
	}
	wrapper, diag := types.ObjectValue(filterListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	if diag.HasError() {
		t.Fatalf("ObjectValue(filter_list wrapper) diagnostics = %v", diag)
	}
	return wrapper
}

func testRuleItem(t *testing.T, name, action string, filterList types.Object) ruleItemModel {
	t.Helper()
	return ruleItemModel{
		Name:       types.StringValue(name),
		Action:     types.StringValue(action),
		FilterList: filterList,
	}
}

func testRuleListWrapper(t *testing.T, items ...ruleItemModel) types.Object {
	t.Helper()
	values := make([]attr.Value, 0, len(items))
	for _, item := range items {
		attrs := map[string]attr.Value{
			"name":         item.Name,
			"action":       item.Action,
			"block_period": types.Int64Null(),
			"challenge":    types.StringNull(),
			"filter_list":  item.FilterList,
		}
		obj, diag := types.ObjectValue(ruleItemObjectTypes().AttrTypes, attrs)
		if diag.HasError() {
			t.Fatalf("ObjectValue(rule) diagnostics = %v", diag)
		}
		values = append(values, obj)
	}
	list, diag := types.ListValue(ruleItemObjectTypes(), values)
	if diag.HasError() {
		t.Fatalf("ListValue(rules) diagnostics = %v", diag)
	}
	wrapper, diag := types.ObjectValue(ruleListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	if diag.HasError() {
		t.Fatalf("ObjectValue(rule_list wrapper) diagnostics = %v", diag)
	}
	return wrapper
}

func testConfigsObject(t *testing.T, status bool, ruleList types.Object) types.Object {
	t.Helper()
	configs, diag := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":    types.BoolValue(status),
		"rule_list": ruleList,
	})
	if diag.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diag)
	}
	return configs
}

var _ customRuleService = (*fakeCustomRuleService)(nil)
