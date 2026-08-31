package accounttakeover

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

func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAccountTakeoverService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"alert","status":true,"auth_url":"/old","username":"existing","future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"alert_deny","status":false,"auth_url":"","username":"existing","future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &accountTakeoverResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	configModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs: testConfigsObject(t, map[string]attr.Value{
			"action":   types.StringValue("alert_deny"),
			"auth_url": types.StringValue(""),
			"status":   types.BoolValue(false),
		}),
	}
	planModel := configModel

	request := resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &configModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}
	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, request, &response)
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
	assertRawString(t, puts[0].Configs["action"], "alert_deny")
	assertRawString(t, puts[0].Configs["auth_url"], "")
	assertRawBool(t, puts[0].Configs["status"], false)
	if _, ok := puts[0].Configs["future_config"]; !ok {
		t.Fatal("PUT document lost future_config")
	}
	encoded, err := json.Marshal(puts[0])
	if err != nil {
		t.Fatalf("json.Marshal(PUT) error = %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("json.Unmarshal(PUT) error = %v", err)
	}
	if _, ok := envelope["future_envelope"]; !ok {
		t.Fatal("PUT document lost future_envelope")
	}

	state := testStateModelValue(t, ctx, response.State)
	if state.EPID.ValueString() != "123" || state.Template.ValueBool() {
		t.Fatalf("state = %#v", state)
	}
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if configs.Action.ValueString() != "alert_deny" || configs.Status.ValueBool() || configs.AuthURL.ValueString() != "" {
		t.Fatalf("normalized configs = %#v", configs)
	}
	if configs.Username.ValueString() != "existing" {
		t.Fatalf("username = %q, want existing", configs.Username.ValueString())
	}
}

func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAccountTakeoverService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"alert","status":true},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"deny_no_log","status":true},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"deny_no_log","status":false},"template":false}}`)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put account takeover", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &accountTakeoverResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, map[string]attr.Value{"action": types.StringValue("alert"), "status": types.BoolValue(true)}),
	}
	configModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, map[string]attr.Value{"status": types.BoolValue(false)}),
	}
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, map[string]attr.Value{"action": types.StringValue("alert"), "status": types.BoolValue(false)}),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	request := resource.UpdateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &configModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
		State:  prior,
	}
	response := resource.UpdateResponse{State: testCopyState(prior)}
	implementation.Update(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}

	wantCalls := []string{"get:123", "put:123", "get:123", "put:123", "get:123"}
	if calls := service.callLog(); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	puts := service.putDocuments()
	if len(puts) != 2 {
		t.Fatalf("PUT documents = %d, want 2", len(puts))
	}
	assertRawString(t, puts[0].Configs["action"], "alert")
	assertRawString(t, puts[1].Configs["action"], "deny_no_log")
	assertRawBool(t, puts[1].Configs["status"], false)
}

func TestReadParentDrift(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		exists      bool
		wantRemoved bool
		wantError   bool
	}{
		"parent absent removes state":  {exists: false, wantRemoved: true},
		"parent present retains state": {exists: true, wantError: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			service := &fakeAccountTakeoverService{
				gets:   []fakeGetResult{{err: &client.APIError{Operation: "get account takeover", StatusCode: http.StatusNotFound}}},
				exists: test.exists,
			}
			implementation := &accountTakeoverResource{service: service, locks: locking.NewRegistry()}
			resourceSchema := testResourceSchema(t, ctx, implementation)
			priorModel := resourceModel{
				EPID:     types.StringValue("123"),
				Template: types.BoolValue(false),
				Configs:  testConfigsObject(t, map[string]attr.Value{"action": types.StringValue("alert"), "status": types.BoolValue(true)}),
			}
			prior := testStateFor(t, ctx, resourceSchema, &priorModel)
			response := resource.ReadResponse{State: testCopyState(prior)}
			implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)

			if response.Diagnostics.HasError() != test.wantError {
				t.Fatalf("Read() diagnostics = %v, wantError %t", response.Diagnostics, test.wantError)
			}
			if test.wantRemoved {
				if !response.State.Raw.Equal(testNullState(ctx, resourceSchema).Raw) {
					t.Fatal("Read() did not remove state for an absent parent")
				}
			} else if !response.State.Raw.Equal(prior.Raw) {
				t.Fatal("Read() changed state after a module error with an existing parent")
			}
			if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "exists:123"}) {
				t.Fatalf("calls = %#v", calls)
			}
		})
	}
}

func TestDeleteDisablesAndVerifies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAccountTakeoverService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"alert_deny","status":true,"future_config":"keep"},"template":true,"future_envelope":"keep"}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"alert_deny","status":false,"future_config":"keep"},"template":false,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &accountTakeoverResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(true),
		Configs:  types.ObjectNull(configAttributeTypes),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.DeleteResponse{State: testCopyState(prior)}
	implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", response.Diagnostics)
	}
	if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "put:123", "get:123"}) {
		t.Fatalf("calls = %#v", calls)
	}
	puts := service.putDocuments()
	if len(puts) != 1 || puts[0].Template {
		t.Fatalf("PUT documents = %#v", puts)
	}
	assertRawBool(t, puts[0].Configs["status"], false)
	if _, ok := puts[0].Configs["future_config"]; !ok {
		t.Fatal("disable PUT lost future_config")
	}
	encoded, err := json.Marshal(puts[0])
	if err != nil {
		t.Fatalf("json.Marshal(PUT) error = %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("json.Unmarshal(PUT) error = %v", err)
	}
	if _, ok := envelope["future_envelope"]; !ok {
		t.Fatal("disable PUT lost future_envelope")
	}
}

func TestDeleteFailureRetainsState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAccountTakeoverService{
		gets: []fakeGetResult{{document: testDocumentFromJSON(t, `{"result":{"configs":{"action":"alert","status":true},"template":false}}`)}},
		putErrors: []error{
			&client.APIError{Operation: "put account takeover", StatusCode: http.StatusInternalServerError},
		},
		exists: true,
	}
	implementation := &accountTakeoverResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, map[string]attr.Value{"action": types.StringValue("alert"), "status": types.BoolValue(true)}),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.DeleteResponse{State: testCopyState(prior)}
	implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Delete() diagnostics did not report PUT failure")
	}
	if !response.State.Raw.Equal(prior.Raw) {
		t.Fatal("Delete() changed state after PUT failure")
	}
}

func TestImportState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	implementation := &accountTakeoverResource{locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	empty := testStateFor(t, ctx, resourceSchema, &resourceModel{
		EPID:     types.StringNull(),
		Template: types.BoolNull(),
		Configs:  types.ObjectNull(configAttributeTypes),
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

	emptyResponse := resource.ImportStateResponse{State: empty}
	implementation.ImportState(ctx, resource.ImportStateRequest{ID: "  "}, &emptyResponse)
	if !emptyResponse.Diagnostics.HasError() {
		t.Fatal("ImportState() accepted an empty ID")
	}
}

func TestResourceConfigureRejectsUnexpectedProviderData(t *testing.T) {
	t.Parallel()

	implementation := &accountTakeoverResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

type fakeGetResult struct {
	document client.AccountTakeoverDocument
	err      error
}

type fakeAccountTakeoverService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	existsErr error
	calls     []string
	puts      []client.WAFModuleResult
}

func (s *fakeAccountTakeoverService) GetAccountTakeover(_ context.Context, epID string) (client.AccountTakeoverDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.AccountTakeoverDocument{}, errors.New("unexpected GetAccountTakeover call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeAccountTakeoverService) PutAccountTakeover(_ context.Context, epID string, result client.WAFModuleResult) error {
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

func (s *fakeAccountTakeoverService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, s.existsErr
}

func (s *fakeAccountTakeoverService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeAccountTakeoverService) putDocuments() []client.WAFModuleResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]client.WAFModuleResult, len(s.puts))
	for index := range s.puts {
		result[index] = s.puts[index].Clone()
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
	return tfsdk.State{
		Schema: resourceSchema,
		Raw:    tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil),
	}
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

func testDocumentFromJSON(t *testing.T, payload string) client.AccountTakeoverDocument {
	t.Helper()

	var document client.AccountTakeoverDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(document) error = %v", err)
	}
	return document
}

func assertRawString(t *testing.T, raw json.RawMessage, want string) {
	t.Helper()

	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("value = %q, want %q", got, want)
	}
}

func assertRawBool(t *testing.T, raw json.RawMessage, want bool) {
	t.Helper()

	var got bool
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("value = %t, want %t", got, want)
	}
}

var _ accountTakeoverService = (*fakeAccountTakeoverService)(nil)
