package mlapiprotection

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

const mlGetFalse = `{"result":{"configs":{"status":false,"threat_action":"alert","ip_list_type":"Block","future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
const mlGetTrue = `{"result":{"configs":{"status":true,"threat_action":"alert_deny","ip_list_type":"Trust","ip_list":[{"idx":1,"ip":"10.0.0.1"}],"path_list":[{"idx":1,"type":"plain","pattern":"/api"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`

func TestNewResourceLoadsReviewedDestroyPromotion(t *testing.T) {
	t.Parallel()

	implementation := NewResource(locking.NewRegistry()).(*mlApiProtectionResource)
	if implementation.destroy.Module != "ml_api_protection" ||
		string(implementation.destroy.DestroyPolicy) != "disable" ||
		implementation.destroy.DestroyField != "status" ||
		!implementation.destroy.DestroyVerified {
		t.Fatalf("reviewed destroy policy = %#v", implementation.destroy)
	}
}

func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeMlApiProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, mlGetFalse)},
			{document: testDocumentFromJSON(t, mlGetTrue)},
		},
		exists: true,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert_deny", "Trust", testIPListWrapper(t, ipEntry("10.0.0.1")), testPathListWrapper(t, pathEntry("plain", "/api"))),
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
	var status bool
	if err := json.Unmarshal(puts[0].Configs["status"], &status); err != nil || !status {
		t.Fatalf("PUT status = %s", puts[0].Configs["status"])
	}
	var threatAction string
	if err := json.Unmarshal(puts[0].Configs["threat_action"], &threatAction); err != nil || threatAction != "alert_deny" {
		t.Fatalf("PUT threat_action = %s", puts[0].Configs["threat_action"])
	}
	var ipEntries []client.MlApiProtectionIPListEntry
	if err := json.Unmarshal(puts[0].Configs["ip_list"], &ipEntries); err != nil {
		t.Fatalf("decode ip_list: %v", err)
	}
	if len(ipEntries) != 1 || ipEntries[0].IP != "10.0.0.1" || ipEntries[0].IDX != 1 {
		t.Fatalf("PUT ip_list = %#v", ipEntries)
	}
	var pathEntries []client.MlApiProtectionPathListEntry
	if err := json.Unmarshal(puts[0].Configs["path_list"], &pathEntries); err != nil {
		t.Fatalf("decode path_list: %v", err)
	}
	if len(pathEntries) != 1 || pathEntries[0].Type != "plain" || pathEntries[0].Pattern != "/api" || pathEntries[0].IDX != 1 {
		t.Fatalf("PUT path_list = %#v", pathEntries)
	}
	if _, ok := puts[0].Configs["future_config"]; !ok {
		t.Fatal("PUT document lost future_config")
	}
}

func TestCreateTemplateTrueOmitsConfigs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeMlApiProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, mlGetFalse)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"threat_action":"alert","ip_list_type":"Block"},"template":true,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
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

func TestIPListOmittedPreservesRemoteArray(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const getWithIP = `{"result":{"configs":{"status":false,"threat_action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`
	service := &fakeMlApiProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithIP)},
			{document: testDocumentFromJSON(t, getWithIP)},
		},
		exists: true,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", types.ObjectNull(ipListWrapperObjectTypes().AttrTypes), types.ObjectNull(pathListWrapperObjectTypes().AttrTypes)),
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
	raw, ok := puts[0].Configs["ip_list"]
	if !ok {
		t.Fatal("PUT body omitted ip_list when wrapper omitted; remote must be carried forward")
	}
	var entries []client.MlApiProtectionIPListEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 1 || entries[0].IP != "10.0.0.1" {
		t.Fatalf("PUT ip_list = %#v", entries)
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.IPList.IsNull() {
		t.Fatalf("state ip_list = %#v, want null", configs.IPList)
	}
}

func TestPathListOmittedPreservesRemoteArray(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const getWithPath = `{"result":{"configs":{"status":false,"threat_action":"alert","ip_list_type":"Block","path_list":[{"idx":1,"type":"plain","pattern":"/api"}]},"template":false}}`
	service := &fakeMlApiProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithPath)},
			{document: testDocumentFromJSON(t, getWithPath)},
		},
		exists: true,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs: testConfigsObject(
			t,
			true,
			"alert",
			"Block",
			types.ObjectNull(ipListWrapperObjectTypes().AttrTypes),
			types.ObjectNull(pathListWrapperObjectTypes().AttrTypes),
		),
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
	var entries []client.MlApiProtectionPathListEntry
	if err := json.Unmarshal(puts[0].Configs["path_list"], &entries); err != nil {
		t.Fatalf("decode path_list: %v", err)
	}
	if len(entries) != 1 || entries[0].Pattern != "/api" {
		t.Fatalf("PUT path_list = %#v", entries)
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.PathList.IsNull() {
		t.Fatalf("state path_list = %#v, want null", configs.PathList)
	}
}

func TestEmptyListWrappersSendEmptyArrays(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const getWithLists = `{"result":{"configs":{"status":false,"threat_action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"198.51.100.1"}],"path_list":[{"idx":1,"type":"plain","pattern":"/api"}]},"template":false}}`
	const getEmpty = `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","ip_list":[],"path_list":[]},"template":false}}`
	service := &fakeMlApiProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithLists)},
			{document: testDocumentFromJSON(t, getEmpty)},
		},
		exists: true,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs: testConfigsObject(
			t,
			true,
			"alert",
			"Block",
			testIPListWrapper(t),
			testPathListWrapper(t),
		),
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
	if len(puts) != 1 || string(puts[0].Configs["ip_list"]) != "[]" || string(puts[0].Configs["path_list"]) != "[]" {
		t.Fatalf("PUT list bodies = ip:%s path:%s, want []/[]", puts[0].Configs["ip_list"], puts[0].Configs["path_list"])
	}
}

func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeMlApiProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, mlGetFalse)},
			{document: testDocumentFromJSON(t, mlGetFalse)},
			{document: testDocumentFromJSON(t, mlGetTrue)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put ml api protection", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert_deny", "Trust", testIPListWrapper(t, ipEntry("10.0.0.1")), testPathListWrapper(t, pathEntry("plain", "/api"))),
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
	service := &fakeMlApiProtectionService{exists: true}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", types.ObjectNull(ipListWrapperObjectTypes().AttrTypes), types.ObjectNull(pathListWrapperObjectTypes().AttrTypes)),
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
	service := &fakeMlApiProtectionService{
		gets:   []fakeGetResult{{err: &client.APIError{Operation: "get ml api protection", StatusCode: http.StatusNotFound}}},
		exists: false,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", types.ObjectNull(ipListWrapperObjectTypes().AttrTypes), types.ObjectNull(pathListWrapperObjectTypes().AttrTypes)),
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
	implementation := &mlApiProtectionResource{locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	empty := testStateFor(t, ctx, resourceSchema, &resourceModel{
		EPID: types.StringNull(), Template: types.BoolNull(), Configs: types.ObjectNull(configsAttributeTypes),
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
	implementation := &mlApiProtectionResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

func TestImportedOwnedListsFailClosedAndSortByWireIndex(t *testing.T) {
	t.Parallel()

	malformed := testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","path_list":[{"idx":1,"type":"plain","pattern":"missing-slash"}]},"template":false}}`)
	_, malformedDiagnostics := stateModel(
		"123",
		malformed,
		ownershipImported,
		types.ObjectNull(configsAttributeTypes),
	)
	if !malformedDiagnostics.HasError() {
		t.Fatal("imported owned path_list accepted malformed known input")
	}

	document := testDocumentFromJSON(t, `{
		"result":{
			"template":false,
			"configs":{
				"status":true,
				"threat_action":"alert",
				"ip_list_type":"Block",
				"ip_list":[
					{"idx":2,"ip":"198.51.100.2"},
					{"idx":1,"ip":"198.51.100.1"}
				],
				"path_list":[
					{"idx":2,"type":"regular","pattern":"/two"},
					{"idx":1,"type":"plain","pattern":"/one"}
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

	var ipWrapper ipListWrapperModel
	if diagnostics := configs.IPList.As(context.Background(), &ipWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("ip_list.As diagnostics = %v", diagnostics)
	}
	var ips []ipEntryModel
	if diagnostics := ipWrapper.Item.ElementsAs(context.Background(), &ips, false); diagnostics.HasError() {
		t.Fatalf("ip_list items diagnostics = %v", diagnostics)
	}
	if len(ips) != 2 || ips[0].IP.ValueString() != "198.51.100.1" || ips[1].IP.ValueString() != "198.51.100.2" {
		t.Fatalf("IP order = %#v", ips)
	}

	var pathWrapper pathListWrapperModel
	if diagnostics := configs.PathList.As(context.Background(), &pathWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("path_list.As diagnostics = %v", diagnostics)
	}
	var paths []pathEntryModel
	if diagnostics := pathWrapper.Item.ElementsAs(context.Background(), &paths, false); diagnostics.HasError() {
		t.Fatalf("path_list items diagnostics = %v", diagnostics)
	}
	if len(paths) != 2 || paths[0].Pattern.ValueString() != "/one" || paths[1].Pattern.ValueString() != "/two" {
		t.Fatalf("path order = %#v", paths)
	}
}

func TestCreateRejectsPathWithoutLeadingSlash(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeMlApiProtectionService{
		gets:   []fakeGetResult{{document: testDocumentFromJSON(t, mlGetFalse)}},
		exists: true,
	}
	implementation := &mlApiProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs: testConfigsObject(
			t,
			true,
			"alert",
			"Block",
			types.ObjectNull(ipListWrapperObjectTypes().AttrTypes),
			testPathListWrapper(t, pathEntry("plain", "api")),
		),
	}
	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Create() accepted a path pattern without a leading slash")
	}
	if len(service.putDocuments()) != 0 {
		t.Fatal("Create() sent a PUT for an invalid path pattern")
	}
}

type fakeGetResult struct {
	document client.MlApiProtectionDocument
	err      error
}

type fakeMlApiProtectionService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	calls     []string
	puts      []client.WAFModuleResult
}

func (s *fakeMlApiProtectionService) GetMlApiProtection(_ context.Context, epID string) (client.MlApiProtectionDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.MlApiProtectionDocument{}, errors.New("unexpected GetMlApiProtection call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeMlApiProtectionService) PutMlApiProtection(_ context.Context, epID string, result client.WAFModuleResult) error {
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

func (s *fakeMlApiProtectionService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, nil
}

func (s *fakeMlApiProtectionService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}
func (s *fakeMlApiProtectionService) putDocuments() []client.WAFModuleResult {
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

func testDocumentFromJSON(t *testing.T, payload string) client.MlApiProtectionDocument {
	t.Helper()
	var document client.MlApiProtectionDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	return document
}

func ipEntry(ip string) ipEntryModel { return ipEntryModel{IP: types.StringValue(ip)} }
func pathEntry(typ, pattern string) pathEntryModel {
	return pathEntryModel{Type: types.StringValue(typ), Pattern: types.StringValue(pattern)}
}

func testIPListWrapper(t *testing.T, entries ...ipEntryModel) types.Object {
	t.Helper()
	values := make([]attr.Value, 0, len(entries))
	for _, e := range entries {
		obj, _ := types.ObjectValue(ipEntryObjectTypes().AttrTypes, map[string]attr.Value{"ip": e.IP})
		values = append(values, obj)
	}
	list, _ := types.ListValue(ipEntryObjectTypes(), values)
	wrapper, _ := types.ObjectValue(ipListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	return wrapper
}

func testPathListWrapper(t *testing.T, entries ...pathEntryModel) types.Object {
	t.Helper()
	values := make([]attr.Value, 0, len(entries))
	for _, e := range entries {
		obj, _ := types.ObjectValue(pathEntryObjectTypes().AttrTypes, map[string]attr.Value{"type": e.Type, "pattern": e.Pattern})
		values = append(values, obj)
	}
	list, _ := types.ListValue(pathEntryObjectTypes(), values)
	wrapper, _ := types.ObjectValue(pathListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	return wrapper
}

func testConfigsObject(t *testing.T, status bool, threatAction, ipListType string, ipList, pathList types.Object) types.Object {
	t.Helper()
	configs, diag := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":        types.BoolValue(status),
		"threat_action": types.StringValue(threatAction),
		"ip_list_type":  types.StringValue(ipListType),
		"ip_list":       ipList,
		"path_list":     pathList,
	})
	if diag.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diag)
	}
	return configs
}

var _ mlApiProtectionService = (*fakeMlApiProtectionService)(nil)
