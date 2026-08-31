package contentsrouting

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

const crGetFalse = `{"result":{"status":false,"policy_list":[{"idx":1,"name":"old","server_pool":"old_pool","is_default":true,"rule_list":[{"idx":1,"match_object":"http-host","match_condition":"match-sub","value":"old.example"}]}],"future_envelope":"keep"}}`

const crGetTrue = `{"result":{"status":true,"policy_list":[{"idx":1,"name":"p1","server_pool":"pool1","is_default":false,"rule_list":[{"idx":1,"match_object":"http-request","match_condition":"match-end","match_expression":".html","concatenate":"or","reverse":false}]}],"future_envelope":"keep"}}`

func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeContentRoutingService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, crGetTrue)},
		},
		exists: true,
	}
	implementation := &contentRoutingResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:       types.StringValue("123"),
		Status:     types.BoolValue(true),
		PolicyList: testPolicyListWrapper(t, testPolicyItem(t, "p1", "pool1", false, testRuleListWrapper(t, testRuleItem(t, "http-request", "match-end", ".html", "or", false)))),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Plan: testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}

	if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "put:123", "get:123"}) {
		t.Fatalf("calls = %#v", calls)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	if !puts[0].Status {
		t.Fatal("PUT status = false, want true")
	}
	var policies []map[string]any
	policyListBytes, _ := json.Marshal(puts[0].PolicyList)
	if err := json.Unmarshal(policyListBytes, &policies); err != nil {
		t.Fatalf("decode policy_list: %v", err)
	}
	if len(policies) != 1 || policies[0]["name"] != "p1" || policies[0]["server_pool"] != "pool1" {
		t.Fatalf("PUT policy_list = %#v", policies)
	}
	if policies[0]["idx"] != float64(1) {
		t.Fatalf("PUT policy_list[0].idx = %v, want 1", policies[0]["idx"])
	}
	rules, _ := policies[0]["rule_list"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rule_list length = %d, want 1", len(rules))
	}
	rule, _ := rules[0].(map[string]any)
	if rule["match_object"] != "http-request" || rule["match_condition"] != "match-end" {
		t.Fatalf("PUT rule = %#v", rule)
	}
	if rule["idx"] != float64(1) {
		t.Fatalf("PUT rule[0].idx = %v, want 1", rule["idx"])
	}
}

func TestPolicyListOmittedPreservesRemoteArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeContentRoutingService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, crGetFalse)},
		},
		exists: true,
	}
	implementation := &contentRoutingResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:       types.StringValue("123"),
		Status:     types.BoolValue(true),
		PolicyList: types.ObjectNull(policyListWrapperObjectTypes().AttrTypes),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Plan: testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	if !puts[0].Status {
		t.Fatal("PUT status = false, want true")
	}
	// policy_list must be carried forward (it's in the raw envelope from GET).
	if len(puts[0].PolicyList) == 0 {
		t.Fatal("PUT omitted policy_list when the wrapper was omitted; the remote array must be carried forward")
	}
	state := testStateModelValue(t, ctx, response.State)
	if !state.PolicyList.IsNull() {
		t.Fatalf("state policy_list wrapper = %#v, want null", state.PolicyList)
	}
}

func TestDeleteForgetsWithWarning(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeContentRoutingService{exists: true}
	implementation := &contentRoutingResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:       types.StringValue("123"),
		Status:     types.BoolValue(false),
		PolicyList: types.ObjectNull(policyListWrapperObjectTypes().AttrTypes),
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

// TestCreatePreservesOwnedNestedUnknownKeys proves the owned policy_list
// replacement grafts unknown keys from the fresh GET (INCLUDE semantics).
func TestCreatePreservesOwnedNestedUnknownKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const getWithUnknown = `{"result":{"status":false,"policy_list":[{"idx":1,"name":"old","server_pool":"old_pool","is_default":true,"future_policy_key":"keep","rule_list":[{"idx":1,"match_object":"http-host","future_rule_key":"keep","value":"old.example"}]}],"future_envelope":"keep"}}`
	service := &fakeContentRoutingService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithUnknown)},
			{document: testDocumentFromJSON(t, getWithUnknown)},
		},
		exists: true,
	}
	implementation := &contentRoutingResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:       types.StringValue("123"),
		Status:     types.BoolValue(true),
		PolicyList: testPolicyListWrapper(t, testPolicyItem(t, "p1", "pool1", false, testRuleListWrapper(t, testRuleItem(t, "http-request", "match-end", ".html", "or", false)))),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Plan: testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	policyListBytes, _ := json.Marshal(puts[0].PolicyList)
	var policies []map[string]any
	if err := json.Unmarshal(policyListBytes, &policies); err != nil {
		t.Fatalf("decode policy_list: %v", err)
	}
	if _, ok := policies[0]["future_policy_key"]; !ok {
		t.Fatal("PUT policy_list lost future_policy_key (unknown=INCLUDE)")
	}
	rules, _ := policies[0]["rule_list"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rule_list length = %d, want 1", len(rules))
	}
	rule, _ := rules[0].(map[string]any)
	if _, ok := rule["future_rule_key"]; !ok {
		t.Fatal("PUT rule_list lost future_rule_key (unknown=INCLUDE)")
	}
	if rule["match_object"] != "http-request" {
		t.Fatalf("PUT rule match_object = %v, want http-request", rule["match_object"])
	}
}

// TestPolicyListEmptyWrapperSendsEmptyArray proves a present empty wrapper
// serializes policy_list as [] rather than retaining the cloned remote array.
func TestPolicyListEmptyWrapperSendsEmptyArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeContentRoutingService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, `{"result":{"status":true,"policy_list":[]}}`)},
		},
		exists: true,
	}
	implementation := &contentRoutingResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:       types.StringValue("123"),
		Status:     types.BoolValue(true),
		PolicyList: testPolicyListWrapper(t), // empty wrapper (no items)
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Plan: testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	policyListBytes, _ := json.Marshal(puts[0].PolicyList)
	if string(policyListBytes) != "[]" {
		t.Fatalf("PUT policy_list = %s, want []", string(policyListBytes))
	}
}

func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeContentRoutingService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, crGetFalse)},
			{document: testDocumentFromJSON(t, crGetTrue)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put content routing", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &contentRoutingResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:       types.StringValue("123"),
		Status:     types.BoolValue(true),
		PolicyList: testPolicyListWrapper(t, testPolicyItem(t, "p1", "pool1", false, testRuleListWrapper(t, testRuleItem(t, "http-request", "match-end", ".html", "or", false)))),
	}

	response := resource.UpdateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Update(ctx, resource.UpdateRequest{
		Plan: testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "put:123", "get:123", "put:123", "get:123"}) {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestReadRemovesStateWhenParentAbsent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeContentRoutingService{
		gets:   []fakeGetResult{{err: &client.APIError{Operation: "get content routing", StatusCode: http.StatusNotFound}}},
		exists: false,
	}
	implementation := &contentRoutingResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:       types.StringValue("123"),
		Status:     types.BoolValue(false),
		PolicyList: types.ObjectNull(policyListWrapperObjectTypes().AttrTypes),
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
	implementation := &contentRoutingResource{locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	empty := testStateFor(t, ctx, resourceSchema, &resourceModel{
		EPID:       types.StringNull(),
		Status:     types.BoolNull(),
		PolicyList: types.ObjectNull(policyListWrapperObjectTypes().AttrTypes),
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

	implementation := &contentRoutingResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

func TestImportedOwnedPolicyListFailsClosedOnMalformedKnownField(t *testing.T) {
	t.Parallel()

	document := testDocumentFromJSON(t, `{"result":{"status":true,"policy_list":[{"idx":1,"name":null,"future_key":"preserve"}]}}`)
	_, diagnostics := stateModel(
		"123",
		document,
		ownershipImported,
		types.ObjectNull(policyListWrapperObjectTypes().AttrTypes),
	)
	if !diagnostics.HasError() {
		t.Fatal("imported owned policy_list accepted a malformed known field")
	}
}

func TestImportedPolicyAndRuleListsSortByWireIndex(t *testing.T) {
	t.Parallel()

	document := testDocumentFromJSON(t, `{
		"result":{
			"status":true,
			"policy_list":[
				{"idx":2,"name":"second","rule_list":[]},
				{"idx":1,"name":"first","rule_list":[
					{"idx":2,"match_object":"http-request","match_expression":"/two"},
					{"idx":1,"match_object":"http-host","match_expression":"one.example"}
				]}
			]
		}
	}`)
	model, diagnostics := stateModel(
		"123",
		document,
		ownershipImported,
		types.ObjectNull(policyListWrapperObjectTypes().AttrTypes),
	)
	if diagnostics.HasError() {
		t.Fatalf("stateModel diagnostics = %v", diagnostics)
	}
	var policiesWrapper policyListWrapperModel
	if diagnostics := model.PolicyList.As(context.Background(), &policiesWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("policy_list.As diagnostics = %v", diagnostics)
	}
	var policies []policyItemModel
	if diagnostics := policiesWrapper.Item.ElementsAs(context.Background(), &policies, false); diagnostics.HasError() {
		t.Fatalf("policy_list items diagnostics = %v", diagnostics)
	}
	if len(policies) != 2 || policies[0].Name.ValueString() != "first" || policies[1].Name.ValueString() != "second" {
		t.Fatalf("policy order = %#v", policies)
	}
	var rulesWrapper ruleListWrapperModel
	if diagnostics := policies[0].RuleList.As(context.Background(), &rulesWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("rule_list.As diagnostics = %v", diagnostics)
	}
	var rules []ruleItemModel
	if diagnostics := rulesWrapper.Item.ElementsAs(context.Background(), &rules, false); diagnostics.HasError() {
		t.Fatalf("rule_list items diagnostics = %v", diagnostics)
	}
	if len(rules) != 2 ||
		rules[0].MatchExpression.ValueString() != "one.example" ||
		rules[1].MatchExpression.ValueString() != "/two" {
		t.Fatalf("rule order = %#v", rules)
	}
}

type fakeGetResult struct {
	document client.ContentRoutingDocument
	err      error
}

type fakeContentRoutingService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	calls     []string
	puts      []client.ContentRoutingResult
}

func (s *fakeContentRoutingService) GetContentRouting(_ context.Context, epID string) (client.ContentRoutingDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.ContentRoutingDocument{}, errors.New("unexpected GetContentRouting call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeContentRoutingService) PutContentRouting(_ context.Context, epID string, result client.ContentRoutingResult) error {
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

func (s *fakeContentRoutingService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, nil
}

func (s *fakeContentRoutingService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeContentRoutingService) putDocuments() []client.ContentRoutingResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]client.ContentRoutingResult, len(s.puts))
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

func testDocumentFromJSON(t *testing.T, payload string) client.ContentRoutingDocument {
	t.Helper()
	var document client.ContentRoutingDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(document) error = %v", err)
	}
	return document
}

func testRuleItem(t *testing.T, matchObject, matchCondition, matchExpression, concatenate string, reverse bool) ruleItemModel {
	t.Helper()
	return ruleItemModel{
		MatchObject:     types.StringValue(matchObject),
		MatchCondition:  types.StringValue(matchCondition),
		MatchExpression: types.StringValue(matchExpression),
		Concatenate:     types.StringValue(concatenate),
		Reverse:         types.BoolValue(reverse),
	}
}

func testRuleListWrapper(t *testing.T, rules ...ruleItemModel) types.Object {
	t.Helper()
	values := make([]attr.Value, 0, len(rules))
	for _, rule := range rules {
		obj, diag := types.ObjectValue(ruleItemObjectTypes().AttrTypes, map[string]attr.Value{
			"match_object":          rule.MatchObject,
			"match_condition":       rule.MatchCondition,
			"match_expression":      rule.MatchExpression,
			"name":                  types.StringNull(),
			"value":                 types.StringNull(),
			"concatenate":           rule.Concatenate,
			"reverse":               rule.Reverse,
			"start_ip":              types.StringNull(),
			"end_ip":                types.StringNull(),
			"ip_list":               types.StringNull(),
			"name_match_condition":  types.StringNull(),
			"value_match_condition": types.StringNull(),
			"x509_subject_name":     types.StringNull(),
		})
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

func testPolicyItem(t *testing.T, name, serverPool string, isDefault bool, ruleList types.Object) policyItemModel {
	t.Helper()
	return policyItemModel{
		Name:       types.StringValue(name),
		ServerPool: types.StringValue(serverPool),
		IsDefault:  types.BoolValue(isDefault),
		RuleList:   ruleList,
	}
}

func testPolicyListWrapper(t *testing.T, items ...policyItemModel) types.Object {
	t.Helper()
	values := make([]attr.Value, 0, len(items))
	for _, item := range items {
		obj, diag := types.ObjectValue(policyItemObjectTypes().AttrTypes, map[string]attr.Value{
			"name":        item.Name,
			"server_pool": item.ServerPool,
			"is_default":  item.IsDefault,
			"rule_list":   item.RuleList,
		})
		if diag.HasError() {
			t.Fatalf("ObjectValue(policy) diagnostics = %v", diag)
		}
		values = append(values, obj)
	}
	list, diag := types.ListValue(policyItemObjectTypes(), values)
	if diag.HasError() {
		t.Fatalf("ListValue(policies) diagnostics = %v", diag)
	}
	wrapper, diag := types.ObjectValue(policyListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	if diag.HasError() {
		t.Fatalf("ObjectValue(policy_list wrapper) diagnostics = %v", diag)
	}
	return wrapper
}

var _ contentRoutingService = (*fakeContentRoutingService)(nil)
var _ basetypes.ObjectAsOptions = basetypes.ObjectAsOptions{}
