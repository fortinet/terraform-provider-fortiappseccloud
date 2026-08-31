package anomalydetection

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/contract"
	"terraform-provider-fortiappseccloud/internal/locking"
)

func TestNewResourceLoadsReviewedDestroyPromotion(t *testing.T) {
	t.Parallel()

	implementation := NewResource(locking.NewRegistry()).(*anomalyDetectionResource)
	if implementation.destroy.Module != "anomaly_detection" ||
		implementation.destroy.DestroyPolicy != contract.CustomDestroyDisable ||
		implementation.destroy.DestroyField != "status" ||
		!implementation.destroy.DestroyVerified {
		t.Fatalf("reviewed destroy policy = %#v", implementation.destroy)
	}
}

// TestCreateGetMergePutGet proves the {template, configs} envelope path with an
// owned ip_list: unknown envelope/config fields are preserved and wire-only idx
// is regenerated one-based in Terraform order.
func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":9,"ip":"10.0.0.9"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert_deny","ip_list_type":"Trust","ip_list":[{"idx":1,"ip":"10.0.0.1"},{"idx":2,"ip":"10.0.0.2"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert_deny", "Trust", testIPListWrapper(t, ipEntry("10.0.0.1"), ipEntry("10.0.0.2"))),
	}

	request := resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
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
	if puts[0].Template {
		t.Fatal("PUT template = true, want false")
	}
	assertConfigBool(t, puts[0].Configs, "status", true)
	assertConfigString(t, puts[0].Configs, "action", "alert_deny")
	assertConfigString(t, puts[0].Configs, "ip_list_type", "Trust")
	var entries []client.AnomalyDetectionIPListEntry
	if err := json.Unmarshal(puts[0].Configs["ip_list"], &entries); err != nil {
		t.Fatalf("unmarshal ip_list: %v", err)
	}
	if len(entries) != 2 || entries[0].IDX != 1 || entries[1].IDX != 2 ||
		entries[0].IP != "10.0.0.1" || entries[1].IP != "10.0.0.2" {
		t.Fatalf("PUT ip_list entries = %#v", entries)
	}
	if _, ok := puts[0].Configs["future_config"]; !ok {
		t.Fatal("PUT document lost future_config")
	}

	state := testStateModelValue(t, ctx, response.State)
	if state.EPID.ValueString() != "123" || state.Template.ValueBool() {
		t.Fatalf("state = %#v", state)
	}
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.Status.ValueBool() || configs.Action.ValueString() != "alert_deny" || configs.IPListType.ValueString() != "Trust" {
		t.Fatalf("normalized configs = %#v", configs)
	}
	stateEntries := decodeStateIPList(t, ctx, configs.IPList)
	if len(stateEntries) != 2 || stateEntries[0].IP.ValueString() != "10.0.0.1" || stateEntries[1].IP.ValueString() != "10.0.0.2" {
		t.Fatalf("normalized ip_list = %#v", stateEntries)
	}
}

// TestCreateTemplateTrueOmitsConfigs proves template=true sends no owned configs
// and the state configs stays null.
func TestCreateTemplateTrueOmitsConfigs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block"},"template":true,"future_envelope":"keep"}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block"},"template":true,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
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
	// template=true replays the complete effective wire request: the remote
	// configs are carried forward opaquely (Terraform does not own them), and
	// the state configs stays null.
	if _, ok := puts[0].Configs["status"]; !ok {
		t.Fatal("template=true PUT dropped the carried-forward remote configs")
	}
	state := testStateModelValue(t, ctx, response.State)
	if !state.Configs.IsNull() {
		t.Fatalf("state configs = %#v, want null for template=true", state.Configs)
	}
}

// TestIPListOmittedPreservesRemoteArray proves omitting the ip_list wrapper
// preserves the remote array opaquely (PUT carries it forward; state wrapper
// stays null).
func TestIPListOmittedPreservesRemoteArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", testOmittedIPListWrapper()),
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
		t.Fatal("PUT body omitted ip_list when the wrapper was omitted; the remote array must be carried forward opaquely")
	}
	var entries []client.AnomalyDetectionIPListEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("decode preserved ip_list: %v", err)
	}
	if len(entries) != 1 || entries[0].IP != "10.0.0.1" {
		t.Fatalf("PUT ip_list = %#v, want the remote entry carried forward", entries)
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.IPList.IsNull() {
		t.Fatalf("state ip_list wrapper = %#v, want null", configs.IPList)
	}
}

func TestIPListEmptyWrapperSendsEmptyArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", testEmptyIPListWrapper(t)),
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
	raw, ok := puts[0].Configs["ip_list"]
	if !ok {
		t.Fatal("PUT body omitted ip_list when the wrapper was present and empty")
	}
	var entries []client.AnomalyDetectionIPListEntry
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) != 0 {
		t.Fatalf("PUT ip_list = %s, want []", string(raw))
	}
}

func TestIPListPriorStateOmittedStaysNullOnRead(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", testOmittedIPListWrapper()),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.ReadResponse{State: testCopyState(prior)}
	implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read() diagnostics = %v", response.Diagnostics)
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.IPList.IsNull() {
		t.Fatalf("Read populated the ip_list wrapper from the remote array when prior state omitted it: %#v", configs.IPList)
	}
}

func TestIPListImportHydratesFromRemote(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":2,"ip":"10.0.0.2"},{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolNull(),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.ReadResponse{State: testCopyState(prior)}
	implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read() diagnostics = %v", response.Diagnostics)
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	entries := decodeStateIPList(t, ctx, configs.IPList)
	if len(entries) != 2 || entries[0].IP.ValueString() != "10.0.0.1" || entries[1].IP.ValueString() != "10.0.0.2" {
		t.Fatalf("imported ip_list = %#v, want hydrated and idx-sorted [10.0.0.1, 10.0.0.2]", entries)
	}
}

// TestIPListPriorTemplateTrueRemoteTemplateFalseStaysNull proves a prior
// template=true state (configs null) whose remote flipped to template=false is
// NOT treated as import (template is set in prior state): the ip_list wrapper
// stays null and the remote array is preserved opaquely rather than strictly
// hydrated. This guards against misclassifying template=true state as import.
func TestIPListPriorTemplateTrueRemoteTemplateFalseStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1","future_key":"x"}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	// Prior state is template=true with configs null (the normal template=true shape).
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(true),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.ReadResponse{State: testCopyState(prior)}
	implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read() diagnostics = %v", response.Diagnostics)
	}
	state := testStateModelValue(t, ctx, response.State)
	// The remote flipped to template=false, so configs is now populated, but the
	// ip_list wrapper stays null (PriorState, prior configs null → not owned),
	// and the remote ip_list (with its unknown item key) is preserved opaquely
	// rather than strictly decoded (which would have failed on "future_key").
	if state.Template.ValueBool() {
		t.Fatalf("state template = true, want false (remote flipped)")
	}
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.IPList.IsNull() {
		t.Fatalf("Read hydrated the ip_list wrapper from the remote array for a prior template=true state: %#v", configs.IPList)
	}
}

// TestIPListIdxNotPersistedInState proves wire-only idx is not in state: the
// entry schema attribute keys are exactly [ip].
func TestIPListIdxNotPersistedInState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	document := testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":7,"ip":"10.0.0.7"}]},"template":false}}`)
	model, diagnostics := stateModel("123", document, ownershipImported, types.ObjectNull(configsAttributeTypes))
	if diagnostics.HasError() {
		t.Fatalf("stateModel() diagnostics = %v", diagnostics)
	}
	configs := testDecodeConfigs(t, ctx, model.Configs)
	entries := decodeStateIPList(t, ctx, configs.IPList)
	if len(entries) != 1 || entries[0].IP.ValueString() != "10.0.0.7" {
		t.Fatalf("state ip_list = %#v", entries)
	}
	entryTypes := ipEntryObjectTypes().AttrTypes
	gotKeys := make([]string, 0, len(entryTypes))
	for key := range entryTypes {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, []string{"ip"}) {
		t.Fatalf("ip entry schema attribute keys = %#v, want exactly [ip]", gotKeys)
	}
}

func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block"},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block"},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert_deny","ip_list_type":"Trust","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put anomaly detection", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert_deny", "Trust", testIPListWrapper(t, ipEntry("10.0.0.1"))),
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
	service := &fakeAnomalyDetectionService{exists: true}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", testOmittedIPListWrapper()),
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

func TestDeleteIndividuallyVerifiedPolicyDisablesWithExactLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fresh := testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","future_config":{"keep":true}},"template":true,"future_envelope":{"keep":true}}}`)
	disabled := testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block","future_config":{"keep":true}},"template":false,"future_envelope":{"keep":true}}}`)
	service := &fakeAnomalyDetectionService{
		gets:   []fakeGetResult{{document: fresh}, {document: disabled}},
		exists: true,
	}
	implementation := &anomalyDetectionResource{
		service: service,
		locks:   locking.NewRegistry(),
		destroy: contract.CustomResourceContract{
			DestroyPolicy:   contract.CustomDestroyDisable,
			DestroyField:    "status",
			DestroyVerified: true,
			DestroyReason:   "test-only individually verified policy",
		},
	}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(true),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.DeleteResponse{State: testCopyState(prior)}
	implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", response.Diagnostics)
	}
	if len(response.Diagnostics.Warnings()) != 0 {
		t.Fatalf("Delete() warnings = %v", response.Diagnostics.Warnings())
	}
	if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "put:123", "get:123"}) {
		t.Fatalf("calls = %#v, want exact GET/PUT/GET", calls)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	putJSON, putErr := json.Marshal(puts[0])
	wantJSON, wantErr := json.Marshal(disabled.Result)
	if putErr != nil || wantErr != nil {
		t.Fatalf("marshal PUT/expected result: %v/%v", putErr, wantErr)
	}
	var putValue, wantValue any
	if err := json.Unmarshal(putJSON, &putValue); err != nil {
		t.Fatalf("decode PUT result: %v", err)
	}
	if err := json.Unmarshal(wantJSON, &wantValue); err != nil {
		t.Fatalf("decode expected result: %v", err)
	}
	if !reflect.DeepEqual(putValue, wantValue) {
		t.Fatalf("PUT did not preserve the fresh response exactly:\n got: %s\nwant: %s", putJSON, wantJSON)
	}
}

func TestReadRemovesStateWhenParentAbsent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeAnomalyDetectionService{
		gets:   []fakeGetResult{{err: &client.APIError{Operation: "get anomaly detection", StatusCode: http.StatusNotFound}}},
		exists: false,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", testOmittedIPListWrapper()),
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
	implementation := &anomalyDetectionResource{locks: locking.NewRegistry()}
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

	emptyResponse := resource.ImportStateResponse{State: empty}
	implementation.ImportState(ctx, resource.ImportStateRequest{ID: "  "}, &emptyResponse)
	if !emptyResponse.Diagnostics.HasError() {
		t.Fatal("ImportState() accepted an empty ID")
	}
}

func TestValidateTemplateConfigsErrors(t *testing.T) {
	t.Parallel()

	configs := testConfigsObject(t, false, "alert_deny", "Trust", testOmittedIPListWrapper())
	tests := map[string]struct {
		model   resourceModel
		wantErr bool
	}{
		"local configs": {
			model: resourceModel{Template: types.BoolValue(false), Configs: configs},
		},
		"template inheritance": {
			model: resourceModel{Template: types.BoolValue(true), Configs: types.ObjectNull(configsAttributeTypes)},
		},
		"missing local configs": {
			model:   resourceModel{Template: types.BoolValue(false), Configs: types.ObjectNull(configsAttributeTypes)},
			wantErr: true,
		},
		"configs with template": {
			model:   resourceModel{Template: types.BoolValue(true), Configs: configs},
			wantErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := validateTemplateConfigs(test.model)
			if test.wantErr && err == nil {
				t.Fatalf("validateTemplateConfigs() expected an error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validateTemplateConfigs() error = %v", err)
			}
		})
	}
}

func TestResourceConfigureRejectsUnexpectedProviderData(t *testing.T) {
	t.Parallel()

	implementation := &anomalyDetectionResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

// TestCreateRejectsTooManyIPEntries proves the build/apply path enforces the
// 30-item bound (a GET is seeded so apply reaches the build step).
func TestCreateRejectsTooManyIPEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	entries := make([]ipEntryModel, 31)
	for i := range entries {
		entries[i] = ipEntry("10.0.0.1")
	}
	service := &fakeAnomalyDetectionService{
		gets:   []fakeGetResult{{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block"},"template":false}}`)}},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", testIPListWrapper(t, entries...)),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Create() with 31 ip_list entries did not error")
	}
	if !diagnosticsContainDetail(response.Diagnostics.Errors(), "ip_list may contain at most 30 item blocks") {
		t.Fatalf("Create() diagnostics did not report the ip_list bound: %v", response.Diagnostics)
	}
	if len(service.putDocuments()) != 0 {
		t.Fatal("Create() sent a PUT despite an over-bound ip_list")
	}
}

// TestCreateAcceptsExactly30IPEntries is the in-range build-path control for
// the 30-item bound: exactly 30 entries pass build and the PUT carries 30
// one-based indices. (Negative: TestCreateRejectsTooManyIPEntries with 31.)
func TestCreateAcceptsExactly30IPEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	entries := make([]ipEntryModel, 30)
	for i := range entries {
		entries[i] = ipEntry("10.0.0.1")
	}
	service := &fakeAnomalyDetectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block"},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &anomalyDetectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, "alert", "Block", testIPListWrapper(t, entries...)),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() with exactly 30 ip_list entries diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	var putEntries []client.AnomalyDetectionIPListEntry
	if err := json.Unmarshal(puts[0].Configs["ip_list"], &putEntries); err != nil {
		t.Fatalf("decode ip_list: %v", err)
	}
	if len(putEntries) != 30 {
		t.Fatalf("PUT ip_list length = %d, want 30", len(putEntries))
	}
	for index, entry := range putEntries {
		if entry.IDX != index+1 {
			t.Fatalf("PUT ip_list[%d].idx = %d, want %d", index, entry.IDX, index+1)
		}
	}
}

type fakeGetResult struct {
	document client.AnomalyDetectionDocument
	err      error
}

type fakeAnomalyDetectionService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	existsErr error
	calls     []string
	puts      []client.WAFModuleResult
}

func (s *fakeAnomalyDetectionService) GetAnomalyDetection(_ context.Context, epID string) (client.AnomalyDetectionDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.AnomalyDetectionDocument{}, errors.New("unexpected GetAnomalyDetection call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeAnomalyDetectionService) PutAnomalyDetection(_ context.Context, epID string, result client.WAFModuleResult) error {
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

func (s *fakeAnomalyDetectionService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, s.existsErr
}

func (s *fakeAnomalyDetectionService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeAnomalyDetectionService) putDocuments() []client.WAFModuleResult {
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

func testDocumentFromJSON(t *testing.T, payload string) client.AnomalyDetectionDocument {
	t.Helper()
	var document client.AnomalyDetectionDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(document) error = %v", err)
	}
	return document
}

func assertConfigBool(t *testing.T, configs map[string]json.RawMessage, name string, want bool) {
	t.Helper()
	var got bool
	if err := json.Unmarshal(configs[name], &got); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if got != want {
		t.Fatalf("%s = %t, want %t", name, got, want)
	}
}

func assertConfigString(t *testing.T, configs map[string]json.RawMessage, name, want string) {
	t.Helper()
	var got string
	if err := json.Unmarshal(configs[name], &got); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func ipEntry(ip string) ipEntryModel {
	return ipEntryModel{IP: types.StringValue(ip)}
}

func testIPList(t *testing.T, entries ...ipEntryModel) types.List {
	t.Helper()
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		object, diagnostics := types.ObjectValue(ipEntryObjectTypes().AttrTypes, map[string]attr.Value{"ip": entry.IP})
		if diagnostics.HasError() {
			t.Fatalf("ObjectValue() diagnostics = %v", diagnostics)
		}
		values = append(values, object)
	}
	list, diagnostics := types.ListValue(ipEntryObjectTypes(), values)
	if diagnostics.HasError() {
		t.Fatalf("ListValue() diagnostics = %v", diagnostics)
	}
	return list
}

func testIPListWrapper(t *testing.T, entries ...ipEntryModel) types.Object {
	t.Helper()
	list := testIPList(t, entries...)
	wrapper, diagnostics := types.ObjectValue(ipListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(wrapper) diagnostics = %v", diagnostics)
	}
	return wrapper
}

func testOmittedIPListWrapper() types.Object {
	return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
}

func testEmptyIPListWrapper(t *testing.T) types.Object {
	t.Helper()
	return testIPListWrapper(t)
}

func testConfigsObject(t *testing.T, status bool, action, ipListType string, ipList types.Object) types.Object {
	t.Helper()
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":       types.BoolValue(status),
		"action":       types.StringValue(action),
		"ip_list_type": types.StringValue(ipListType),
		"ip_list":      ipList,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue() diagnostics = %v", diagnostics)
	}
	return configs
}

func decodeStateIPList(t *testing.T, ctx context.Context, wrapper types.Object) []ipEntryModel {
	t.Helper()
	if wrapper.IsNull() || wrapper.IsUnknown() {
		return nil
	}
	var wrapperModel ipListWrapperModel
	if diagnostics := wrapper.As(ctx, &wrapperModel, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("wrapper.As() diagnostics = %v", diagnostics)
	}
	if wrapperModel.Item.IsNull() || wrapperModel.Item.IsUnknown() {
		return nil
	}
	elements := wrapperModel.Item.Elements()
	entries := make([]ipEntryModel, 0, len(elements))
	for _, element := range elements {
		object, ok := element.(basetypes.ObjectValue)
		if !ok {
			t.Fatalf("ip list element = %#v", element)
		}
		var entry ipEntryModel
		if diagnostics := object.As(ctx, &entry, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
			t.Fatalf("ip entry.As() diagnostics = %v", diagnostics)
		}
		entries = append(entries, entry)
	}
	return entries
}

func diagnosticsContainDetail(diagnostics diag.Diagnostics, substring string) bool {
	for _, d := range diagnostics {
		if strings.Contains(d.Detail(), substring) {
			return true
		}
	}
	return false
}

var _ anomalyDetectionService = (*fakeAnomalyDetectionService)(nil)
