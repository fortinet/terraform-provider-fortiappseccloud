package globaltrustlist

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
	"terraform-provider-fortiappseccloud/internal/locking"
)

// TestTrustListOmittedPreservesRemoteArray proves that omitting the trust_list
// ownership wrapper preserves the remote array opaquely: the PUT body does not
// contain a trust_list key, so the remote value is carried forward unchanged.
func TestTrustListOmittedPreservesRemoteArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"trust_list":[{"idx":1,"name":"remote","status":true,"url":"/remote"}]}}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"remote","status":true,"url":"/remote"}]}}}`)},
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testOmittedTrustListWrapper()),
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
	// Omitting the wrapper preserves the remote array opaquely: the PUT body
	// carries the remote trust_list forward unchanged (it is not overwritten
	// with [] or a Terraform-owned list).
	raw, ok := puts[0].Configs["trust_list"]
	if !ok {
		t.Fatal("PUT body omitted trust_list when the wrapper was omitted; the remote array must be carried forward opaquely")
	}
	var entries []client.GlobalTrustListEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("decode preserved trust_list: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "remote" || entries[0].URL == nil || *entries[0].URL != "/remote" {
		t.Fatalf("PUT trust_list = %#v, want the remote entry carried forward unchanged", entries)
	}
	// The wrapper was omitted in the plan, so Terraform does not own the
	// collection: the state wrapper stays null (the remote array is preserved
	// opaquely, NOT imported into Terraform ownership). A later plan therefore
	// shows no diff for trust_list.
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.TrustList.IsNull() {
		t.Fatalf("state trust_list wrapper = %#v, want null (omitted preserves remote opaquely)", configs.TrustList)
	}
}

// TestTrustListPriorStateOmittedStaysNullOnRead proves a normal Read keeps the
// wrapper null when the prior state omitted it (the remote array is preserved
// opaquely and not imported into state).
func TestTrustListPriorStateOmittedStaysNullOnRead(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"remote","url":"/remote"}]}}}`)},
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	// Prior state has the wrapper omitted (null).
	priorModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testOmittedTrustListWrapper()),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.ReadResponse{State: testCopyState(prior)}
	implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read() diagnostics = %v", response.Diagnostics)
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.TrustList.IsNull() {
		t.Fatalf("Read populated the trust_list wrapper from the remote array when prior state omitted it: %#v", configs.TrustList)
	}
}

// TestTrustListImportHydratesFromRemote proves import hydrates the wrapper from
// the remote array (strict decode, fail-closed).
func TestTrustListImportHydratesFromRemote(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":2,"name":"b"},{"idx":1,"name":"a"}]}}}`)},
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	// Import: only ep_id is set; configs is null/unknown.
	priorModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: types.ObjectNull(configsAttributeTypes),
	}
	prior := testStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.ReadResponse{State: testCopyState(prior)}
	implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read() diagnostics = %v", response.Diagnostics)
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	entries := decodeStateTrustList(t, ctx, configs.TrustList)
	if len(entries) != 2 || entries[0].Name.ValueString() != "a" || entries[1].Name.ValueString() != "b" {
		t.Fatalf("imported trust_list = %#v, want hydrated and idx-sorted [a, b]", entries)
	}
}

// TestTrustListEmptyWrapperSendsEmptyArray proves a present empty wrapper sends
// trust_list: [] and replaces the remote array.
func TestTrustListEmptyWrapperSendsEmptyArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"trust_list":[{"idx":1,"name":"remote","url":"/remote"}]}}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[]}}}`)},
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testEmptyTrustListWrapper(t)),
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
	raw, ok := puts[0].Configs["trust_list"]
	if !ok {
		t.Fatal("PUT body omitted trust_list when the wrapper was present and empty")
	}
	var entries []client.GlobalTrustListEntry
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) != 0 {
		t.Fatalf("PUT trust_list = %s, want []", string(raw))
	}
}

// TestTrustListIdxNotPersistedInState proves the wire-only idx is regenerated
// one-based in Terraform order and never appears in Terraform state: the state
// object attributes are exactly name, status, and url (no idx).
func TestTrustListIdxNotPersistedInState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	document := testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":7,"name":"remote","status":true,"url":"/remote"}]}}}`)
	// Import hydrates the wrapper from the remote array (strict decode).
	model, diagnostics := stateModel("123", document, ownershipImported, types.ObjectNull(configsAttributeTypes))
	if diagnostics.HasError() {
		t.Fatalf("stateModel() diagnostics = %v", diagnostics)
	}
	configs := testDecodeConfigs(t, ctx, model.Configs)
	entries := decodeStateTrustList(t, ctx, configs.TrustList)
	if len(entries) != 1 || entries[0].Name.ValueString() != "remote" {
		t.Fatalf("state trust_list = %#v", entries)
	}
	// The entry object's attribute types must be exactly name/status/url (no idx).
	entryTypes := trustEntryObjectTypes().AttrTypes
	if _, hasIdx := entryTypes["idx"]; hasIdx {
		t.Fatalf("trust entry schema exposes idx; wire-only idx must not be in state: %#v", entryTypes)
	}
	gotKeys := make([]string, 0, len(entryTypes))
	for key := range entryTypes {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if !reflect.DeepEqual(gotKeys, []string{"name", "status", "url"}) {
		t.Fatalf("trust entry schema attribute keys = %#v, want exactly [name status url]", gotKeys)
	}
}

// TestCreateGetMergePutGet proves the hand-written custom resource does not
// need the generated {template, configs} envelope: the global trust-list
// parameter envelope is {configs} only. It also proves unknown envelope/config
// fields are preserved and wire-only idx is regenerated one-based in Terraform
// order.
func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"trust_list":[{"idx":9,"name":"old","status":true,"url":"/old"}],"future_config":{"keep":true}},"future_envelope":"keep"}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"one","status":true,"url":"/one"},{"idx":2,"name":"two","status":false,"url":"/two"}],"future_config":{"keep":true}},"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testTrustListWrapper(t, trustEntry("one", true, "/one"), trustEntry("two", false, "/two"))),
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
	assertRawBool(t, puts[0].Configs["status"], true)
	var entries []client.GlobalTrustListEntry
	if err := json.Unmarshal(puts[0].Configs["trust_list"], &entries); err != nil {
		t.Fatalf("unmarshal trust_list: %v", err)
	}
	if len(entries) != 2 || entries[0].IDX != 1 || entries[1].IDX != 2 ||
		entries[0].Name != "one" || entries[1].Name != "two" ||
		entries[0].URL == nil || *entries[0].URL != "/one" || entries[1].URL == nil || *entries[1].URL != "/two" {
		t.Fatalf("PUT trust_list entries = %#v", entries)
	}
	if entries[0].Status == nil || !*entries[0].Status || entries[1].Status == nil || *entries[1].Status {
		t.Fatalf("PUT trust_list status = %#v / %#v", entries[0].Status, entries[1].Status)
	}
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
	if _, ok := envelope["template"]; ok {
		t.Fatal("PUT document emitted a template field; this endpoint has no template")
	}

	state := testStateModelValue(t, ctx, response.State)
	if state.EPID.ValueString() != "123" {
		t.Fatalf("state ep_id = %q", state.EPID.ValueString())
	}
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.Status.ValueBool() {
		t.Fatalf("normalized status = %v", configs.Status)
	}
	stateEntries := decodeStateTrustList(t, ctx, configs.TrustList)
	if len(stateEntries) != 2 || stateEntries[0].Name.ValueString() != "one" || stateEntries[1].Name.ValueString() != "two" {
		t.Fatalf("normalized trust_list = %#v", stateEntries)
	}
}

// TestCreateAcceptsMultibyteNameAtBound proves the build/apply path enforces
// the name length bound in UTF-8 runes (not bytes): a 63-rune multibyte name
// passes build and is sent on the wire with idx 1.
func TestCreateAcceptsMultibyteNameAtBound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// 62 ASCII 'n' + 1 multibyte rune (é, 2 bytes) = 63 runes, 64 bytes.
	name := strings.Repeat("n", 62) + "é"
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false}}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"`+name+`","url":"/u"}]}}}`)},
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testTrustListWrapper(t, trustEntryModel{Name: types.StringValue(name), URL: types.StringValue("/u")})),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() with a 63-rune multibyte name diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	var entries []client.GlobalTrustListEntry
	if err := json.Unmarshal(puts[0].Configs["trust_list"], &entries); err != nil {
		t.Fatalf("decode trust_list: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != name || entries[0].IDX != 1 {
		t.Fatalf("PUT trust_list = %#v, want the 63-rune multibyte name with idx 1", entries)
	}
}

// TestCreateRejectsMultibyteNameOverBound proves the build/apply path rejects a
// 64-rune multibyte name (the byte length is 65, the rune count is 64) so the
// rune-count bound is enforced consistently with the schema and strict decoder.
// A GET is seeded so apply reaches the build step (rather than failing on the
// GET) and the bound-specific diagnostic is asserted.
func TestCreateRejectsMultibyteNameOverBound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// 63 ASCII 'n' + 1 multibyte rune (é) = 64 runes, 65 bytes.
	name := strings.Repeat("n", 63) + "é"
	service := &fakeGlobalTrustListService{
		gets:   []fakeGetResult{{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false}}}`)}},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testTrustListWrapper(t, trustEntryModel{Name: types.StringValue(name), URL: types.StringValue("/u")})),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Create() with a 64-rune multibyte name did not error")
	}
	if !diagnosticsContainDetail(response.Diagnostics.Errors(), "name length 64 exceeds limit 63 UTF-8 characters") {
		t.Fatalf("Create() diagnostics did not report the name bound: %v", response.Diagnostics)
	}
	if len(service.putDocuments()) != 0 {
		t.Fatal("Create() sent a PUT despite an over-bound name")
	}
}

// TestCreateAcceptsMultibyteURLAtBound proves the build/apply path accepts a
// 255-rune multibyte URL (the byte length exceeds 255) so the url bound is
// counted in runes consistently with the schema and strict decoder.
func TestCreateAcceptsMultibyteURLAtBound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// "/" (1 rune) + 253 ASCII 'u' + 1 multibyte rune (é, 2 bytes) = 255 runes, 256 bytes.
	url := "/" + strings.Repeat("u", 253) + "é"
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false}}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"n","url":"`+url+`"}]}}}`)},
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testTrustListWrapper(t, trustEntryModel{Name: types.StringValue("n"), URL: types.StringValue(url)})),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() with a 255-rune multibyte url diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	var entries []client.GlobalTrustListEntry
	if err := json.Unmarshal(puts[0].Configs["trust_list"], &entries); err != nil {
		t.Fatalf("decode trust_list: %v", err)
	}
	if len(entries) != 1 || entries[0].URL == nil || *entries[0].URL != url {
		t.Fatalf("PUT trust_list url = %#v, want the 255-rune multibyte url", entries)
	}
}

// TestCreateRejectsMultibyteURLOverBound proves the build/apply path rejects a
// 256-rune multibyte URL with the bound-specific diagnostic and no PUT.
func TestCreateRejectsMultibyteURLOverBound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// "/" (1 rune) + 254 ASCII 'u' + 1 multibyte rune (é) = 256 runes, 257 bytes.
	url := "/" + strings.Repeat("u", 254) + "é"
	service := &fakeGlobalTrustListService{
		gets:   []fakeGetResult{{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false}}}`)}},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testTrustListWrapper(t, trustEntryModel{Name: types.StringValue("n"), URL: types.StringValue(url)})),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Create() with a 256-rune multibyte url did not error")
	}
	if !diagnosticsContainDetail(response.Diagnostics.Errors(), "url length 256 exceeds limit 255 UTF-8 characters") {
		t.Fatalf("Create() diagnostics did not report the url bound: %v", response.Diagnostics)
	}
	if len(service.putDocuments()) != 0 {
		t.Fatal("Create() sent a PUT despite an over-bound url")
	}
}

// TestUpdateRefreshesAfterConflict retries the GET-merge-PUT-GET cycle on a
// 409 conflict.
func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"trust_list":[]}}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[]}}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"one","status":true,"url":"/one"}]}}}`)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put global trust list parameter", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testTrustListWrapper(t, trustEntry("one", true, "/one"))),
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

// TestDeleteForgetsWithWarning proves destroy removes state without a remote
// mutation; the API has no DELETE and no reviewed status=false destroy.
func TestDeleteForgetsWithWarning(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{exists: true}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testOmittedTrustListWrapper()),
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

// TestReadRemovesStateWhenParentAbsent distinguishes a missing parent app
// from a missing module.
func TestReadRemovesStateWhenParentAbsent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeGlobalTrustListService{
		gets:   []fakeGetResult{{err: &client.APIError{Operation: "get global trust list parameter", StatusCode: http.StatusNotFound}}},
		exists: false,
	}
	implementation := &globalTrustListResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, testOmittedTrustListWrapper()),
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
	implementation := &globalTrustListResource{locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	empty := testStateFor(t, ctx, resourceSchema, &resourceModel{
		EPID:    types.StringNull(),
		Configs: types.ObjectNull(configsAttributeTypes),
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

	implementation := &globalTrustListResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

type fakeGetResult struct {
	document client.GlobalTrustListDocument
	err      error
}

type fakeGlobalTrustListService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	existsErr error
	calls     []string
	puts      []client.GlobalTrustListResult
}

func (s *fakeGlobalTrustListService) GetGlobalTrustList(_ context.Context, epID string) (client.GlobalTrustListDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.GlobalTrustListDocument{}, errors.New("unexpected GetGlobalTrustList call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeGlobalTrustListService) PutGlobalTrustList(_ context.Context, epID string, result client.GlobalTrustListResult) error {
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

func (s *fakeGlobalTrustListService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, s.existsErr
}

func (s *fakeGlobalTrustListService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeGlobalTrustListService) putDocuments() []client.GlobalTrustListResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]client.GlobalTrustListResult, len(s.puts))
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

func testDocumentFromJSON(t *testing.T, payload string) client.GlobalTrustListDocument {
	t.Helper()

	var document client.GlobalTrustListDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(document) error = %v", err)
	}
	return document
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

// diagnosticsContainDetail reports whether any diagnostic's Detail() contains
// the substring.
func diagnosticsContainDetail(diagnostics diag.Diagnostics, substring string) bool {
	for _, d := range diagnostics {
		if strings.Contains(d.Detail(), substring) {
			return true
		}
	}
	return false
}

func trustEntry(name string, status bool, url string) trustEntryModel {
	return trustEntryModel{
		Name:   types.StringValue(name),
		Status: types.BoolValue(status),
		URL:    types.StringValue(url),
	}
}

func testTrustList(t *testing.T, entries ...trustEntryModel) types.List {
	t.Helper()
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		object, diagnostics := types.ObjectValue(trustEntryObjectTypes().AttrTypes, map[string]attr.Value{
			"name":   entry.Name,
			"status": entry.Status,
			"url":    entry.URL,
		})
		if diagnostics.HasError() {
			t.Fatalf("ObjectValue() diagnostics = %v", diagnostics)
		}
		values = append(values, object)
	}
	list, diagnostics := types.ListValue(trustEntryObjectTypes(), values)
	if diagnostics.HasError() {
		t.Fatalf("ListValue() diagnostics = %v", diagnostics)
	}
	return list
}

// testTrustListWrapper builds a present trust_list ownership wrapper containing
// the given entries as its item list.
func testTrustListWrapper(t *testing.T, entries ...trustEntryModel) types.Object {
	t.Helper()
	list := testTrustList(t, entries...)
	wrapper, diagnostics := types.ObjectValue(trustListWrapperObjectTypes().AttrTypes, map[string]attr.Value{
		"item": list,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(wrapper) diagnostics = %v", diagnostics)
	}
	return wrapper
}

// testOmittedTrustListWrapper returns a null trust_list wrapper (omitted),
// which preserves the remote array opaquely.
func testOmittedTrustListWrapper() types.Object {
	return types.ObjectNull(trustListWrapperObjectTypes().AttrTypes)
}

// testEmptyTrustListWrapper returns a present but empty trust_list wrapper,
// which sends [].
func testEmptyTrustListWrapper(t *testing.T) types.Object {
	t.Helper()
	return testTrustListWrapper(t)
}

func testConfigsObject(t *testing.T, status bool, trustList types.Object) types.Object {
	t.Helper()
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":     types.BoolValue(status),
		"trust_list": trustList,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue() diagnostics = %v", diagnostics)
	}
	return configs
}

func decodeStateTrustList(t *testing.T, ctx context.Context, wrapper types.Object) []trustEntryModel {
	t.Helper()
	if wrapper.IsNull() || wrapper.IsUnknown() {
		return nil
	}
	var wrapperModel trustListWrapperModel
	if diagnostics := wrapper.As(ctx, &wrapperModel, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("wrapper.As() diagnostics = %v", diagnostics)
	}
	if wrapperModel.Item.IsNull() || wrapperModel.Item.IsUnknown() {
		return nil
	}
	elements := wrapperModel.Item.Elements()
	entries := make([]trustEntryModel, 0, len(elements))
	for _, element := range elements {
		object, ok := element.(basetypes.ObjectValue)
		if !ok {
			t.Fatalf("trust list element = %#v", element)
		}
		var entry trustEntryModel
		if diagnostics := object.As(ctx, &entry, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
			t.Fatalf("trust entry.As() diagnostics = %v", diagnostics)
		}
		entries = append(entries, entry)
	}
	return entries
}

var _ globalTrustListService = (*fakeGlobalTrustListService)(nil)
