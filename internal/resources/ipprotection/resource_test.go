package ipprotection

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
	"terraform-provider-fortiappseccloud/internal/resources/wafmodule"
)

const ipGetFalse = `{"result":{"configs":{"status":false,"ip_reputation":true,"geo_ip_mode":"block","future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`

const ipGetTrue = `{"result":{"configs":{"status":true,"ip_reputation":false,"geo_ip_mode":"allow","block_country_list":["United States"],"ip_list":[{"idx":1,"type":"block-ip","ip":"10.0.0.1"},{"idx":2,"ip":"10.0.0.2"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`

func TestNewResourceLoadsReviewedDestroyPromotion(t *testing.T) {
	t.Parallel()

	implementation := NewResource(locking.NewRegistry()).(*ipProtectionResource)
	if implementation.destroy.Module != "ip_protection" ||
		string(implementation.destroy.DestroyPolicy) != "disable" ||
		implementation.destroy.DestroyField != "status" ||
		!implementation.destroy.DestroyVerified {
		t.Fatalf("reviewed destroy policy = %#v", implementation.destroy)
	}
}

func TestTemplateResourceLoadsReviewedDestroyAndPutNormalization(t *testing.T) {
	t.Parallel()

	descriptor := ipProtectionTemplateDescriptor()
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("template descriptor validation failed: %v", err)
	}
	if descriptor.Destroy.Mode != wafmodule.DestroyDisable || !descriptor.Destroy.Verified ||
		descriptor.Destroy.Field != "status" || descriptor.NormalizeForPut == nil {
		t.Fatalf("reviewed template destroy policy = %#v", descriptor)
	}
}

func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, ipGetFalse)},
			{document: testDocumentFromJSON(t, ipGetTrue)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs: testConfigsObject(t, true, false, "allow", []string{"United States"},
			testIPListWrapper(t, ipEntry("block-ip", "10.0.0.1"), ipEntry("", "10.0.0.2"))),
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
	assertConfigBool(t, puts[0].Configs, "status", true)
	assertConfigString(t, puts[0].Configs, "geo_ip_mode", "allow")
	// The PUT/write shape omits wire-only idx per the pinned PutIPProtection
	// schema; only type and ip are sent. Decode into the PUT shape and assert
	// no idx key appears in the raw PUT JSON.
	var entries []client.IPProtectionIPListPutEntry
	if err := json.Unmarshal(puts[0].Configs["ip_list"], &entries); err != nil {
		t.Fatalf("unmarshal ip_list: %v", err)
	}
	if len(entries) != 2 ||
		entries[0].IP != "10.0.0.1" || entries[1].IP != "10.0.0.2" {
		t.Fatalf("PUT ip_list entries = %#v", entries)
	}
	if entries[0].Type != "block-ip" {
		t.Fatalf("PUT ip_list[0].type = %q, want block-ip", entries[0].Type)
	}
	if entries[1].Type != "" {
		t.Fatalf("PUT ip_list[1].type = %q, want empty (omitted)", entries[1].Type)
	}
	var rawPutItems []map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["ip_list"], &rawPutItems); err != nil {
		t.Fatalf("decode raw ip_list: %v", err)
	}
	for i, item := range rawPutItems {
		if _, hasIdx := item["idx"]; hasIdx {
			t.Fatalf("PUT ip_list item %d carries wire-only idx; the PUT shape must omit it: %s", i, string(puts[0].Configs["ip_list"]))
		}
	}
	if _, ok := puts[0].Configs["future_config"]; !ok {
		t.Fatal("PUT document lost future_config")
	}
}

func TestCreateTemplateTrueOmitsConfigs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, ipGetFalse)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"ip_reputation":true},"template":true,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
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
	if _, ok := puts[0].Configs["status"]; !ok {
		t.Fatal("template=true PUT dropped the carried-forward remote configs")
	}
	state := testStateModelValue(t, ctx, response.State)
	if !state.Configs.IsNull() {
		t.Fatalf("state configs = %#v, want null for template=true", state.Configs)
	}
}

// TestCreateTemplateTrueStripsRemoteIPListIdx proves the template-inheritance
// replay path strips GET-only idx from the carried-forward remote ip_list. The
// pinned PutIPProtection schema omits idx, so switching to template=true must
// not forward an idx the PUT contract rejects even though configs is replayed
// opaquely. Unknown item keys are preserved.
func TestCreateTemplateTrueStripsRemoteIPListIdx(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// The fresh GET carries a remote ip_list whose items include GET-only idx
	// plus an unknown key that must be carried forward opaquely. The post-PUT
	// GET reflects the template=true result (configs still present on the wire,
	// but state keeps configs null for template=true).
	const getWithRemoteIPList = `{"result":{"configs":{"status":false,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1","future_key":"x"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":false,"future_envelope":"keep"}}`
	const getAfterTemplateTrue = `{"result":{"configs":{"status":false,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1","future_key":"x"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":true,"future_envelope":"keep"}}`
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithRemoteIPList)},
			{document: testDocumentFromJSON(t, getAfterTemplateTrue)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
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
	raw, ok := puts[0].Configs["ip_list"]
	if !ok {
		t.Fatal("template=true PUT dropped the carried-forward remote ip_list")
	}
	var rawItems []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawItems); err != nil {
		t.Fatalf("decode raw ip_list: %v", err)
	}
	if len(rawItems) != 1 {
		t.Fatalf("PUT ip_list length = %d, want 1 active item (null placeholders filtered)", len(rawItems))
	}
	if _, hasIdx := rawItems[0]["idx"]; hasIdx {
		t.Fatalf("template=true PUT ip_list item carries wire-only idx; the PUT shape must omit it: %s", string(raw))
	}
	if string(rawItems[0]["ip"]) != `"10.0.0.1"` || string(rawItems[0]["type"]) != `"trust-ip"` {
		t.Fatalf("template=true PUT ip_list item lost type/ip when stripping idx: %s", string(raw))
	}
	if _, hasFuture := rawItems[0]["future_key"]; !hasFuture {
		t.Fatalf("template=true PUT ip_list item lost the unknown future_key when stripping idx: %s", string(raw))
	}
	state := testStateModelValue(t, ctx, response.State)
	if !state.Configs.IsNull() {
		t.Fatalf("state configs = %#v, want null for template=true", state.Configs)
	}
}

func TestIPListOmittedPreservesRemoteArray(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testOmittedIPListWrapper()),
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
	var entries []client.IPProtectionIPListEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("decode preserved ip_list: %v", err)
	}
	if len(entries) != 1 || entries[0].IP != "10.0.0.1" || entries[0].Type != "trust-ip" {
		t.Fatalf("PUT ip_list = %#v, want the remote entry carried forward (type+ip preserved)", entries)
	}
	// The omitted/unowned path carries the remote array forward but must strip
	// the GET-only idx so the PUT conforms to the pinned PutIPProtection schema.
	var rawPutItems []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawPutItems); err != nil {
		t.Fatalf("decode raw ip_list: %v", err)
	}
	for i, item := range rawPutItems {
		if _, hasIdx := item["idx"]; hasIdx {
			t.Fatalf("PUT ip_list item %d carries wire-only idx on the omitted path; the PUT shape must omit it: %s", i, string(raw))
		}
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
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":false,"ip_reputation":true,"ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":null},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testEmptyIPListWrapper(t)),
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
	var entries []client.IPProtectionIPListEntry
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) != 0 {
		t.Fatalf("PUT ip_list = %s, want []", string(raw))
	}
	state := testStateModelValue(t, ctx, response.State)
	configs := testDecodeConfigs(t, ctx, state.Configs)
	stateEntries := decodeStateIPList(t, ctx, configs.IPList)
	if len(stateEntries) != 0 {
		t.Fatalf("canonical all-null GET hydrated state entries = %#v, want empty", stateEntries)
	}
}

func TestIPListPriorStateOmittedStaysNullOnRead(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testOmittedIPListWrapper()),
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

func TestIPListPriorTemplateTrueRemoteTemplateFalseStaysNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"ip":"10.0.0.1","future_key":"x"}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
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
	if state.Template.ValueBool() {
		t.Fatalf("state template = true, want false (remote flipped)")
	}
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.IPList.IsNull() {
		t.Fatalf("Read hydrated the ip_list wrapper for a prior template=true state: %#v", configs.IPList)
	}
}

func TestIPListImportHydratesFromRemote(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":null},{"idx":2,"type":"block-ip","ip":"10.0.0.1"},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
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
	if len(entries) != 1 || entries[0].Type.ValueString() != "block-ip" || entries[0].IP.ValueString() != "10.0.0.1" {
		t.Fatalf("imported ip_list = %#v, want only the active block-ip slot", entries)
	}
}

// TestIPListIdxNotPersistedInState proves wire-only idx is not in state: the
// entry schema attribute keys are exactly [ip, type] (sorted).
func TestIPListIdxNotPersistedInState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	document := testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":7,"type":"block-ip","ip":"10.0.0.7"}]},"template":false}}`)
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
	if !reflect.DeepEqual(gotKeys, []string{"ip", "type"}) {
		t.Fatalf("ip entry schema attribute keys = %#v, want exactly [ip type]", gotKeys)
	}
}

func TestUpdateOmittedOptionalPreservesFreshGET(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const getWithMode = `{"result":{"configs":{"status":true,"ip_reputation":true,"geo_ip_mode":"allow","future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithMode)},
			{document: testDocumentFromJSON(t, getWithMode)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	// Config omits geo_ip_mode (null); plan carries prior-state geo_ip_mode "block".
	configModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testOmittedIPListWrapper()),
	}
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "block", nil, testOmittedIPListWrapper()),
	}

	response := resource.UpdateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Update(ctx, resource.UpdateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &configModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	var mode string
	if err := json.Unmarshal(puts[0].Configs["geo_ip_mode"], &mode); err != nil {
		t.Fatalf("decode geo_ip_mode: %v", err)
	}
	if mode != "allow" {
		t.Fatalf("PUT geo_ip_mode = %q, want allow (fresh-GET value preserved, not prior-state block)", mode)
	}
}

// TestUpdateOmittedIPListStripsRemoteIdx proves the omitted/unowned ip_list
// merge path carries the remote array forward but strips the GET-only idx so a
// scalar-only update (here, geo_ip_mode) does not forward an idx the pinned
// PutIPProtection schema rejects. Unknown item keys are preserved opaquely.
func TestUpdateOmittedIPListStripsRemoteIdx(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// The fresh GET carries a remote ip_list whose items include GET-only idx
	// plus an unknown key that must be carried forward opaquely.
	const getWithRemoteIPList = `{"result":{"configs":{"status":true,"ip_reputation":true,"geo_ip_mode":"allow","ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1","future_key":"x"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":"10.0.0.2"}]},"template":false}}`
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithRemoteIPList)},
			{document: testDocumentFromJSON(t, getWithRemoteIPList)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	// Both config and plan omit the ip_list wrapper (unowned); only geo_ip_mode
	// is updated. The remote ip_list must be carried forward without idx.
	configModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testOmittedIPListWrapper()),
	}
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "block", nil, testOmittedIPListWrapper()),
	}

	response := resource.UpdateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Update(ctx, resource.UpdateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &configModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	raw, ok := puts[0].Configs["ip_list"]
	if !ok {
		t.Fatal("PUT body omitted ip_list when the wrapper was omitted; the remote array must be carried forward opaquely")
	}
	var rawItems []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawItems); err != nil {
		t.Fatalf("decode raw ip_list: %v", err)
	}
	if len(rawItems) != 2 {
		t.Fatalf("PUT ip_list length = %d, want 2 active items (null placeholder filtered)", len(rawItems))
	}
	for i, item := range rawItems {
		if _, hasIdx := item["idx"]; hasIdx {
			t.Fatalf("PUT ip_list item %d carries wire-only idx on the omitted path; the PUT shape must omit it: %s", i, string(raw))
		}
	}
	// Non-idx fields are preserved opaquely, including the unknown future_key.
	if string(rawItems[0]["ip"]) != `"10.0.0.1"` || string(rawItems[0]["type"]) != `"trust-ip"` {
		t.Fatalf("PUT ip_list[0] lost type/ip when stripping idx: %s", string(raw))
	}
	if _, hasFuture := rawItems[0]["future_key"]; !hasFuture {
		t.Fatalf("PUT ip_list[0] lost the unknown future_key when stripping idx: %s", string(raw))
	}
}

func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, ipGetFalse)},
			{document: testDocumentFromJSON(t, ipGetFalse)},
			{document: testDocumentFromJSON(t, ipGetTrue)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put ip protection", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs: testConfigsObject(t, true, false, "allow", []string{"United States"},
			testIPListWrapper(t, ipEntry("block-ip", "10.0.0.1"), ipEntry("", "10.0.0.2"))),
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
	service := &fakeIPProtectionService{exists: true}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testOmittedIPListWrapper()),
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
	service := &fakeIPProtectionService{
		gets:   []fakeGetResult{{err: &client.APIError{Operation: "get ip protection", StatusCode: http.StatusNotFound}}},
		exists: false,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testOmittedIPListWrapper()),
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
	implementation := &ipProtectionResource{locks: locking.NewRegistry()}
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

	configs := testConfigsObject(t, true, true, "", nil, testOmittedIPListWrapper())
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

func TestCreateRejectsTooManyIPEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	entries := make([]ipEntryModel, 257)
	for i := range entries {
		entries[i] = ipEntry("", "10.0.0.1")
	}
	service := &fakeIPProtectionService{
		gets:   []fakeGetResult{{document: testDocumentFromJSON(t, ipGetFalse)}},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testIPListWrapper(t, entries...)),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Create() with 257 ip_list entries did not error")
	}
	if !diagnosticsContainDetail(response.Diagnostics.Errors(), "ip_list may contain at most 256 item blocks") {
		t.Fatalf("Create() diagnostics did not report the ip_list bound: %v", response.Diagnostics)
	}
	if len(service.putDocuments()) != 0 {
		t.Fatal("Create() sent a PUT despite an over-bound ip_list")
	}
}

func TestCreateAcceptsExactly256IPEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	entries := make([]ipEntryModel, 256)
	for i := range entries {
		entries[i] = ipEntry("", "10.0.0.1")
	}
	service := &fakeIPProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, ipGetFalse)},
			{document: testDocumentFromJSON(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[]},"template":false}}`)},
		},
		exists: true,
	}
	implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "", nil, testIPListWrapper(t, entries...)),
	}

	response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testConfigFor(t, ctx, resourceSchema, &planModel),
		Plan:   testPlanFor(t, ctx, resourceSchema, &planModel),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() with exactly 256 ip_list entries diagnostics = %v", response.Diagnostics)
	}
	puts := service.putDocuments()
	if len(puts) != 1 {
		t.Fatalf("PUT documents = %d, want 1", len(puts))
	}
	// The PUT/write shape omits wire-only idx per the pinned PutIPProtection
	// schema; only type and ip are sent. Assert the bound is honored and no idx
	// key appears in the raw PUT JSON.
	var putEntries []client.IPProtectionIPListPutEntry
	if err := json.Unmarshal(puts[0].Configs["ip_list"], &putEntries); err != nil {
		t.Fatalf("decode ip_list: %v", err)
	}
	if len(putEntries) != 256 {
		t.Fatalf("PUT ip_list length = %d, want 256", len(putEntries))
	}
	for index, entry := range putEntries {
		if entry.IP != "10.0.0.1" {
			t.Fatalf("PUT ip_list[%d].ip = %q, want 10.0.0.1", index, entry.IP)
		}
	}
	var rawPutItems []map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["ip_list"], &rawPutItems); err != nil {
		t.Fatalf("decode raw ip_list: %v", err)
	}
	for i, item := range rawPutItems {
		if _, hasIdx := item["idx"]; hasIdx {
			t.Fatalf("PUT ip_list item %d carries wire-only idx; the PUT shape must omit it: %s", i, string(puts[0].Configs["ip_list"]))
		}
	}
}

// TestCreateRejectsNullRequiredScalars proves required status/ip_reputation
// reject null during apply with an error diagnostic and no PUT.
func TestCreateRejectsNullRequiredScalars(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		config resourceModel
	}{
		{
			name: "null status",
			config: resourceModel{
				EPID:     types.StringValue("123"),
				Template: types.BoolValue(false),
				Configs:  testConfigsObjectWithNullStatus(t, true, "", nil, testOmittedIPListWrapper()),
			},
		},
		{
			name: "null ip_reputation",
			config: resourceModel{
				EPID:     types.StringValue("123"),
				Template: types.BoolValue(false),
				Configs:  testConfigsObjectWithNullIPReputation(t, true, "", nil, testOmittedIPListWrapper()),
			},
		},
		{
			name: "unknown status",
			config: resourceModel{
				EPID:     types.StringValue("123"),
				Template: types.BoolValue(false),
				Configs:  testConfigsObjectWithUnknownStatus(t, true, "", nil, testOmittedIPListWrapper()),
			},
		},
		{
			name: "unknown ip_reputation",
			config: resourceModel{
				EPID:     types.StringValue("123"),
				Template: types.BoolValue(false),
				Configs:  testConfigsObjectWithUnknownIPReputation(t, true, "", nil, testOmittedIPListWrapper()),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			service := &fakeIPProtectionService{
				gets:   []fakeGetResult{{document: testDocumentFromJSON(t, ipGetFalse)}},
				exists: true,
			}
			implementation := &ipProtectionResource{service: service, locks: locking.NewRegistry()}
			resourceSchema := testResourceSchema(t, ctx, implementation)

			response := resource.CreateResponse{State: testNullState(ctx, resourceSchema)}
			implementation.Create(ctx, resource.CreateRequest{
				Config: testConfigFor(t, ctx, resourceSchema, &tc.config),
				Plan:   testPlanFor(t, ctx, resourceSchema, &tc.config),
			}, &response)
			if !response.Diagnostics.HasError() {
				t.Fatal("Create() with a null required scalar did not error")
			}
			if len(service.putDocuments()) != 0 {
				t.Fatal("Create() sent a PUT despite a null required scalar")
			}
		})
	}
}

func TestResourceConfigureRejectsUnexpectedProviderData(t *testing.T) {
	t.Parallel()

	implementation := &ipProtectionResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

type fakeGetResult struct {
	document client.IPProtectionDocument
	err      error
}

type fakeIPProtectionService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	existsErr error
	calls     []string
	puts      []client.WAFModuleResult
}

func (s *fakeIPProtectionService) GetIPProtection(_ context.Context, epID string) (client.IPProtectionDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.IPProtectionDocument{}, errors.New("unexpected GetIPProtection call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeIPProtectionService) PutIPProtection(_ context.Context, epID string, result client.WAFModuleResult) error {
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

func (s *fakeIPProtectionService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, s.existsErr
}

func (s *fakeIPProtectionService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeIPProtectionService) putDocuments() []client.WAFModuleResult {
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

func testDocumentFromJSON(t *testing.T, payload string) client.IPProtectionDocument {
	t.Helper()
	var document client.IPProtectionDocument
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

func ipEntry(ipType, ip string) ipEntryModel {
	if ipType == "" {
		return ipEntryModel{IP: types.StringValue(ip)}
	}
	return ipEntryModel{Type: types.StringValue(ipType), IP: types.StringValue(ip)}
}

func testIPList(t *testing.T, entries ...ipEntryModel) types.List {
	t.Helper()
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		attributes := map[string]attr.Value{"ip": entry.IP}
		if !entry.Type.IsNull() {
			attributes["type"] = entry.Type
		} else {
			attributes["type"] = types.StringNull()
		}
		object, diagnostics := types.ObjectValue(ipEntryObjectTypes().AttrTypes, attributes)
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

func testConfigsObject(t *testing.T, status, ipReputation bool, geoIPMode string, countries []string, ipList types.Object) types.Object {
	t.Helper()
	var geoMode types.String
	if geoIPMode == "" {
		geoMode = types.StringNull()
	} else {
		geoMode = types.StringValue(geoIPMode)
	}
	var countryList types.List
	if countries == nil {
		countryList = types.ListNull(types.StringType)
	} else {
		values := make([]attr.Value, 0, len(countries))
		for _, c := range countries {
			values = append(values, types.StringValue(c))
		}
		list, _ := types.ListValue(types.StringType, values)
		countryList = list
	}
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":             types.BoolValue(status),
		"ip_reputation":      types.BoolValue(ipReputation),
		"geo_ip_mode":        geoMode,
		"block_country_list": countryList,
		"ip_list":            ipList,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return configs
}

// testConfigsObjectWithNullStatus builds a configs object with a null status
// (simulating the user omitting the required status field).
func testConfigsObjectWithNullStatus(t *testing.T, ipReputation bool, geoIPMode string, countries []string, ipList types.Object) types.Object {
	t.Helper()
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":             types.BoolNull(),
		"ip_reputation":      types.BoolValue(ipReputation),
		"geo_ip_mode":        types.StringNull(),
		"block_country_list": types.ListNull(types.StringType),
		"ip_list":            ipList,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return configs
}

// testConfigsObjectWithNullIPReputation builds a configs object with a null
// ip_reputation (simulating the user omitting the required ip_reputation field).
func testConfigsObjectWithNullIPReputation(t *testing.T, status bool, geoIPMode string, countries []string, ipList types.Object) types.Object {
	t.Helper()
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":             types.BoolValue(status),
		"ip_reputation":      types.BoolNull(),
		"geo_ip_mode":        types.StringNull(),
		"block_country_list": types.ListNull(types.StringType),
		"ip_list":            ipList,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return configs
}

// testConfigsObjectWithUnknownStatus builds a configs object with an unknown
// status (simulating a computed-but-not-yet-resolved required field).
func testConfigsObjectWithUnknownStatus(t *testing.T, ipReputation bool, geoIPMode string, countries []string, ipList types.Object) types.Object {
	t.Helper()
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":             types.BoolUnknown(),
		"ip_reputation":      types.BoolValue(ipReputation),
		"geo_ip_mode":        types.StringNull(),
		"block_country_list": types.ListNull(types.StringType),
		"ip_list":            ipList,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return configs
}

// testConfigsObjectWithUnknownIPReputation builds a configs object with an
// unknown ip_reputation.
func testConfigsObjectWithUnknownIPReputation(t *testing.T, status bool, geoIPMode string, countries []string, ipList types.Object) types.Object {
	t.Helper()
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, map[string]attr.Value{
		"status":             types.BoolValue(status),
		"ip_reputation":      types.BoolUnknown(),
		"geo_ip_mode":        types.StringNull(),
		"block_country_list": types.ListNull(types.StringType),
		"ip_list":            ipList,
	})
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
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

var _ ipProtectionService = (*fakeIPProtectionService)(nil)
