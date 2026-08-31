package corsprotection

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

const corsGetFalse = `{"result":{"configs":{"status":false,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"old","port":0,"include_sub_domains":false},"allowed_methods":{"status":false,"methods":["GET"]},"allowed_headers":{"status":false,"headers":["X-Old"]},"exposed_headers":{"status":false,"headers":[]},"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`

// corsGetTrueTemplate is the normalized GET after a template=true apply: the
// remote keeps template=true and replays the effective (carried-forward) config.
const corsGetTrueTemplate = `{"result":{"configs":{"status":false,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"old","port":0,"include_sub_domains":false},"allowed_methods":{"status":false,"methods":["GET"]},"allowed_headers":{"status":false,"headers":["X-Old"]},"exposed_headers":{"status":false,"headers":[]},"future_config":{"keep":true}},"template":true,"future_envelope":"keep"}}`

const corsGetTrue = `{"result":{"configs":{"status":true,"block_cors_traffic":true,"allowed_origins":{"protocol":"HTTPS","origin_name":"new","port":8443,"include_sub_domains":true},"allowed_methods":{"status":true,"methods":["GET","POST"]},"allowed_headers":{"status":true,"headers":["X-New"]},"exposed_headers":{"status":true,"headers":["X-Exp"]},"url_pattern":"/secure","allowed_credentials":"TRUE","allowed_maximum_age":60,"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`

func TestNewResourceLoadsReviewedDestroyPromotion(t *testing.T) {
	t.Parallel()

	implementation := NewResource(locking.NewRegistry()).(*corsProtectionResource)
	if implementation.destroy.Module != "cors_protection" ||
		string(implementation.destroy.DestroyPolicy) != "disable" ||
		implementation.destroy.DestroyField != "status" ||
		!implementation.destroy.DestroyVerified {
		t.Fatalf("reviewed destroy policy = %#v", implementation.destroy)
	}
}

func TestCreateGetMergePutGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCorsProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, corsGetFalse)},
			{document: testDocumentFromJSON(t, corsGetTrue)},
		},
		exists: true,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new", 8443, true, true, []string{"GET", "POST"}, true, []string{"X-New"}, true, []string{"X-Exp"}, "/secure", "TRUE", 60),
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
	assertConfigBool(t, puts[0].Configs, "block_cors_traffic", true)
	var origins map[string]any
	if err := json.Unmarshal(puts[0].Configs["allowed_origins"], &origins); err != nil {
		t.Fatalf("decode allowed_origins: %v", err)
	}
	if origins["protocol"] != "HTTPS" || origins["origin_name"] != "new" || origins["port"] != float64(8443) {
		t.Fatalf("PUT allowed_origins = %#v", origins)
	}
	if _, ok := puts[0].Configs["future_config"]; !ok {
		t.Fatal("PUT document lost future_config")
	}

	state := testStateModelValue(t, ctx, response.State)
	if state.EPID.ValueString() != "123" || state.Template.ValueBool() {
		t.Fatalf("state = %#v", state)
	}
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if !configs.Status.ValueBool() || !configs.BlockCorsTraffic.ValueBool() {
		t.Fatalf("normalized configs = %#v", configs)
	}
	originsObj := decodeOrigins(t, ctx, configs.AllowedOrigins)
	if originsObj.Protocol.ValueString() != "HTTPS" || originsObj.OriginName.ValueString() != "new" {
		t.Fatalf("normalized allowed_origins = %#v", originsObj)
	}
}

func TestCreateTemplateTrueOmitsConfigs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCorsProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, corsGetFalse)},
			{document: testDocumentFromJSON(t, corsGetTrueTemplate)},
		},
		exists: true,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
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

func TestDeleteForgetsWithWarning(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCorsProtectionService{exists: true}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new", 8443, true, true, nil, true, nil, true, nil, "", "None", 0),
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
	service := &fakeCorsProtectionService{
		gets:   []fakeGetResult{{err: &client.APIError{Operation: "get cors protection", StatusCode: http.StatusNotFound}}},
		exists: false,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	priorModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new", 8443, true, true, nil, true, nil, true, nil, "", "None", 0),
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
	implementation := &corsProtectionResource{locks: locking.NewRegistry()}
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

	configs := testConfigsObject(t, true, true, "HTTPS", "new", 8443, true, true, nil, true, nil, true, nil, "", "None", 0)
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

// TestValidateConfigRequiresPolicyBlocks proves the four policy blocks are
// required when template is false (SingleNestedBlock cannot be Required in the
// schema, so ValidateConfig enforces it). A full control passes.
func TestValidateConfigRequiresPolicyBlocks(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	implementation := &corsProtectionResource{locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)

	// Controls: the wire schema requires all four policy objects for both block
	// modes. The official guide says the restriction settings are inactive while
	// block_cors_traffic is true, but neither source defines them as forbidden.
	// Accept both complete forms rather than inventing a destructive omission.
	for _, blockCorsTraffic := range []bool{false, true} {
		planModel := resourceModel{
			EPID:     types.StringValue("123"),
			Template: types.BoolValue(false),
			Configs:  testConfigsObject(t, true, blockCorsTraffic, "HTTPS", "new", 8443, true, true, nil, true, nil, true, nil, "", "None", 0),
		}
		resp := resource.ValidateConfigResponse{}
		implementation.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: testConfigFor(t, ctx, resourceSchema, &planModel)}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("ValidateConfig(block_cors_traffic=%t) diagnostics = %v", blockCorsTraffic, resp.Diagnostics)
		}
	}

	// Negative: missing allowed_origins.
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
	}
	planModel.Configs = testConfigsObjectMissingOrigins(t, true, true, true, nil, true, nil, true, nil)
	negResp := resource.ValidateConfigResponse{}
	implementation.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: testConfigFor(t, ctx, resourceSchema, &planModel)}, &negResp)
	if !negResp.Diagnostics.HasError() {
		t.Fatal("ValidateConfig accepted a missing allowed_origins block")
	}
}

func TestResourceConfigureRejectsUnexpectedProviderData(t *testing.T) {
	t.Parallel()

	implementation := &corsProtectionResource{locks: locking.NewRegistry()}
	var response resource.ConfigureResponse
	implementation.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}
}

// TestUpdateOmittedOptionalPreservesFreshGET proves an omitted optional in
// config does NOT overwrite a changed fresh-GET value with prior-state: config
// omits port, the plan carries the prior state port (9999), and the fresh GET
// has port 8443 — the PUT must carry 8443 (the fresh-GET value), not 9999.
func TestUpdateOmittedOptionalPreservesFreshGET(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const getWithPort = `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"HTTPS","origin_name":"new.example","port":8443,"include_sub_domains":true},"allowed_methods":{"status":true,"methods":["GET","POST"]},"allowed_headers":{"status":true,"headers":["X-New"]},"exposed_headers":{"status":true,"headers":["X-Exp"]},"url_pattern":"/secure","allowed_credentials":"TRUE","allowed_maximum_age":60,"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	service := &fakeCorsProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithPort)},
			{document: testDocumentFromJSON(t, getWithPort)},
		},
		exists: true,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	// Config omits port (null); plan carries prior-state port. The fresh GET
	// has port 8443, which must survive the PUT.
	configModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new.example", 0, true, true, []string{"GET", "POST"}, true, []string{"X-New"}, true, []string{"X-Exp"}, "/secure", "TRUE", 60),
	}
	// Set the config's port to null (omitted) by rebuilding configs with a null port.
	configModel.Configs = testConfigsObjectNullPort(t, true, true, "HTTPS", "new.example", true, true, []string{"GET", "POST"}, true, []string{"X-New"}, true, []string{"X-Exp"}, "/secure", "TRUE", 60)
	// Plan has port from prior state (9999) — must NOT be written.
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new.example", 9999, true, true, []string{"GET", "POST"}, true, []string{"X-New"}, true, []string{"X-Exp"}, "/secure", "TRUE", 60),
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
	var origins map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["allowed_origins"], &origins); err != nil {
		t.Fatalf("decode allowed_origins: %v", err)
	}
	var port int
	if err := json.Unmarshal(origins["port"], &port); err != nil {
		t.Fatalf("decode port: %v", err)
	}
	if port != 8443 {
		t.Fatalf("PUT port = %d, want 8443 (fresh-GET value preserved, not prior-state 9999)", port)
	}
}

// TestCreatePreservesNestedUnknownKey proves the raw-level deep merge
// preserves an unknown nested key inside allowed_origins (a future field)
// rather than dropping it when overlaying configured fields.
func TestCreatePreservesNestedUnknownKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const getWithFuture = `{"result":{"configs":{"status":false,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"old","port":0,"include_sub_domains":false,"future_origin_key":"keep"},"allowed_methods":{"status":false,"future_methods_key":"keep"},"allowed_headers":{"status":false,"future_headers_key":"keep"},"exposed_headers":{"status":false,"future_exposed_key":"keep"},"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	service := &fakeCorsProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithFuture)},
			{document: testDocumentFromJSON(t, getWithFuture)},
		},
		exists: true,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	// Configure the policy objects so the deep-merge overlays configured fields
	// while preserving the remote future_* nested keys.
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new.example", 8443, true, true, []string{"GET", "POST"}, true, []string{"X-New"}, true, []string{"X-Exp"}, "/secure", "TRUE", 60),
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
	// Unknown nested keys must survive in each policy object.
	var origins map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["allowed_origins"], &origins); err != nil {
		t.Fatalf("decode allowed_origins: %v", err)
	}
	if _, ok := origins["future_origin_key"]; !ok {
		t.Fatal("PUT allowed_origins lost future_origin_key")
	}
	var protocol string
	if err := json.Unmarshal(origins["protocol"], &protocol); err != nil || protocol != "HTTPS" {
		t.Fatalf("PUT allowed_origins protocol = %s, want HTTPS", origins["protocol"])
	}
	var methods map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["allowed_methods"], &methods); err != nil {
		t.Fatalf("decode allowed_methods: %v", err)
	}
	if _, ok := methods["future_methods_key"]; !ok {
		t.Fatal("PUT allowed_methods lost future_methods_key")
	}
	var headers map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["allowed_headers"], &headers); err != nil {
		t.Fatalf("decode allowed_headers: %v", err)
	}
	if _, ok := headers["future_headers_key"]; !ok {
		t.Fatal("PUT allowed_headers lost future_headers_key")
	}
}

func TestCreatePreservesAllowedOriginsSingletonArrayShape(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const getWithArray = `{"result":{"configs":{"status":false,"block_cors_traffic":false,"allowed_origins":[{"protocol":"ANY","origin_name":"old","port":0,"include_sub_domains":false,"future_origin_key":"keep"}],"allowed_methods":{"status":false,"methods":["GET"]},"allowed_headers":{"status":false,"headers":[]},"exposed_headers":{"status":false,"headers":[]},"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	const normalizedArray = `{"result":{"configs":{"status":true,"block_cors_traffic":true,"allowed_origins":[{"protocol":"HTTPS","origin_name":"new.example","port":8443,"include_sub_domains":true,"future_origin_key":"keep"}],"allowed_methods":{"status":true,"methods":["GET","POST"]},"allowed_headers":{"status":true,"headers":["X-New"]},"exposed_headers":{"status":true,"headers":["X-Exp"]},"url_pattern":"/secure","allowed_credentials":"TRUE","allowed_maximum_age":60,"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	service := &fakeCorsProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithArray)},
			{document: testDocumentFromJSON(t, normalizedArray)},
		},
		exists: true,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new.example", 8443, true, true, []string{"GET", "POST"}, true, []string{"X-New"}, true, []string{"X-Exp"}, "/secure", "TRUE", 60),
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
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["allowed_origins"], &items); err != nil {
		t.Fatalf("PUT allowed_origins did not retain singleton-array shape: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("PUT allowed_origins items = %d, want 1", len(items))
	}
	if _, ok := items[0]["future_origin_key"]; !ok {
		t.Fatal("PUT allowed_origins lost future_origin_key")
	}
	var protocol, originName string
	if err := json.Unmarshal(items[0]["protocol"], &protocol); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(items[0]["origin_name"], &originName); err != nil {
		t.Fatal(err)
	}
	if protocol != "HTTPS" || originName != "new.example" {
		t.Fatalf("PUT allowed_origins = protocol:%q origin_name:%q", protocol, originName)
	}
}

func TestCreateExpandsEmptyAllowedOriginsArrayToOwnedSingleton(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const getWithEmptyArray = `{"result":{"configs":{"status":false,"block_cors_traffic":false,"allowed_origins":[],"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	const normalizedArray = `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":[{"protocol":"HTTPS","origin_name":"new.example","port":443,"include_sub_domains":false}],"allowed_methods":{"status":true,"methods":["GET"]},"allowed_headers":{"status":true,"headers":["Content-Type"]},"exposed_headers":{"status":true,"headers":[]},"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`
	service := &fakeCorsProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, getWithEmptyArray)},
			{document: testDocumentFromJSON(t, normalizedArray)},
		},
		exists: true,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, false, "HTTPS", "new.example", 443, false, true, []string{"GET"}, true, []string{"Content-Type"}, true, []string{}, "", "", 0),
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
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(puts[0].Configs["allowed_origins"], &items); err != nil {
		t.Fatalf("PUT allowed_origins did not retain array shape: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("PUT allowed_origins items = %d, want 1", len(items))
	}
	var originName string
	if err := json.Unmarshal(items[0]["origin_name"], &originName); err != nil {
		t.Fatal(err)
	}
	if originName != "new.example" {
		t.Fatalf("PUT allowed_origins origin_name = %q", originName)
	}
}

func TestUpdateRefreshesAfterConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeCorsProtectionService{
		gets: []fakeGetResult{
			{document: testDocumentFromJSON(t, corsGetFalse)},
			{document: testDocumentFromJSON(t, corsGetFalse)},
			{document: testDocumentFromJSON(t, corsGetTrue)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put cors protection", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := &corsProtectionResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)
	planModel := resourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, true, true, "HTTPS", "new", 8443, true, true, []string{"GET", "POST"}, true, []string{"X-New"}, true, []string{"X-Exp"}, "/secure", "TRUE", 60),
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

type fakeGetResult struct {
	document client.CorsProtectionDocument
	err      error
}

type fakeCorsProtectionService struct {
	mu        sync.Mutex
	gets      []fakeGetResult
	putErrors []error
	exists    bool
	existsErr error
	calls     []string
	puts      []client.WAFModuleResult
}

func (s *fakeCorsProtectionService) GetCorsProtection(_ context.Context, epID string) (client.CorsProtectionDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		return client.CorsProtectionDocument{}, errors.New("unexpected GetCorsProtection call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	return result.document, result.err
}

func (s *fakeCorsProtectionService) PutCorsProtection(_ context.Context, epID string, result client.WAFModuleResult) error {
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

func (s *fakeCorsProtectionService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, s.existsErr
}

func (s *fakeCorsProtectionService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeCorsProtectionService) putDocuments() []client.WAFModuleResult {
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

func testDocumentFromJSON(t *testing.T, payload string) client.CorsProtectionDocument {
	t.Helper()
	var document client.CorsProtectionDocument
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

func stringList(elems []string) types.List {
	if elems == nil {
		return types.ListNull(types.StringType)
	}
	values := make([]attr.Value, 0, len(elems))
	for _, e := range elems {
		values = append(values, types.StringValue(e))
	}
	list, _ := types.ListValue(types.StringType, values)
	return list
}

func policyObject(status bool, elems []string, statusKey string, listKey string, objTypes basetypes.ObjectType) types.Object {
	attributes := map[string]attr.Value{statusKey: types.BoolValue(status), listKey: stringList(elems)}
	obj, _ := types.ObjectValue(objTypes.AttrTypes, attributes)
	return obj
}

func originsObject(protocol, originName string, port int64, includeSub bool) types.Object {
	attributes := map[string]attr.Value{
		"protocol":            types.StringValue(protocol),
		"origin_name":         types.StringValue(originName),
		"port":                types.Int64Value(port),
		"include_sub_domains": types.BoolValue(includeSub),
	}
	obj, _ := types.ObjectValue(allowedOriginsObjectTypes().AttrTypes, attributes)
	return obj
}

// testConfigsObject builds a full configs object. Pass empty/zero for optional
// scalars; methods/headers as nil for absent lists.
func testConfigsObject(t *testing.T, status, block bool, protocol, originName string, port int64, includeSub bool,
	methodsStatus bool, methods []string, allowedHeadersStatus bool, allowedHeaders []string,
	exposedHeadersStatus bool, exposedHeaders []string, urlPattern, allowedCredentials string, allowedMaximumAge int64) types.Object {
	t.Helper()
	attributes := map[string]attr.Value{
		"status":              types.BoolValue(status),
		"block_cors_traffic":  types.BoolValue(block),
		"allowed_origins":     originsObject(protocol, originName, port, includeSub),
		"allowed_methods":     policyObject(methodsStatus, methods, "status", "methods", methodPolicyObjectTypes()),
		"allowed_headers":     policyObject(allowedHeadersStatus, allowedHeaders, "status", "headers", headerPolicyObjectTypes()),
		"exposed_headers":     policyObject(exposedHeadersStatus, exposedHeaders, "status", "headers", headerPolicyObjectTypes()),
		"url_pattern":         types.StringValue(urlPattern),
		"allowed_credentials": types.StringValue(allowedCredentials),
		"allowed_maximum_age": types.Int64Value(allowedMaximumAge),
	}
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, attributes)
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return configs
}

// testConfigsObjectNullPort builds a configs object with a null port (simulating
// the user omitting port in config while other fields are configured).
func testConfigsObjectNullPort(t *testing.T, status, block bool, protocol, originName string, includeSub bool,
	methodsStatus bool, methods []string, allowedHeadersStatus bool, allowedHeaders []string,
	exposedHeadersStatus bool, exposedHeaders []string, urlPattern, allowedCredentials string, allowedMaximumAge int64) types.Object {
	t.Helper()
	originsAttrs := map[string]attr.Value{
		"protocol":            types.StringValue(protocol),
		"origin_name":         types.StringValue(originName),
		"port":                types.Int64Null(),
		"include_sub_domains": types.BoolValue(includeSub),
	}
	originsObj, diagnostics := types.ObjectValue(allowedOriginsObjectTypes().AttrTypes, originsAttrs)
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(origins) diagnostics = %v", diagnostics)
	}
	attributes := map[string]attr.Value{
		"status":              types.BoolValue(status),
		"block_cors_traffic":  types.BoolValue(block),
		"allowed_origins":     originsObj,
		"allowed_methods":     policyObject(methodsStatus, methods, "status", "methods", methodPolicyObjectTypes()),
		"allowed_headers":     policyObject(allowedHeadersStatus, allowedHeaders, "status", "headers", headerPolicyObjectTypes()),
		"exposed_headers":     policyObject(exposedHeadersStatus, exposedHeaders, "status", "headers", headerPolicyObjectTypes()),
		"url_pattern":         types.StringValue(urlPattern),
		"allowed_credentials": types.StringValue(allowedCredentials),
		"allowed_maximum_age": types.Int64Value(allowedMaximumAge),
	}
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, attributes)
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return configs
}

// testConfigsObjectMissingOrigins builds a configs object with a null
// allowed_origins block (to exercise the required-block validator).
func testConfigsObjectMissingOrigins(t *testing.T, status, block, methodsStatus bool, methods []string, allowedHeadersStatus bool, allowedHeaders []string, exposedHeadersStatus bool, exposedHeaders []string) types.Object {
	t.Helper()
	attributes := map[string]attr.Value{
		"status":              types.BoolValue(status),
		"block_cors_traffic":  types.BoolValue(block),
		"allowed_origins":     types.ObjectNull(allowedOriginsObjectTypes().AttrTypes),
		"allowed_methods":     policyObject(methodsStatus, methods, "status", "methods", methodPolicyObjectTypes()),
		"allowed_headers":     policyObject(allowedHeadersStatus, allowedHeaders, "status", "headers", headerPolicyObjectTypes()),
		"exposed_headers":     policyObject(exposedHeadersStatus, exposedHeaders, "status", "headers", headerPolicyObjectTypes()),
		"url_pattern":         types.StringNull(),
		"allowed_credentials": types.StringNull(),
		"allowed_maximum_age": types.Int64Null(),
	}
	configs, diagnostics := types.ObjectValue(configsAttributeTypes, attributes)
	if diagnostics.HasError() {
		t.Fatalf("ObjectValue(configs) diagnostics = %v", diagnostics)
	}
	return configs
}

func decodeOrigins(t *testing.T, ctx context.Context, object types.Object) allowedOriginsModel {
	t.Helper()
	if object.IsNull() || object.IsUnknown() {
		t.Fatalf("allowed_origins object = %#v", object)
	}
	var origins allowedOriginsModel
	if diagnostics := object.As(ctx, &origins, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("allowed_origins.As() diagnostics = %v", diagnostics)
	}
	return origins
}

var _ corsProtectionService = (*fakeCorsProtectionService)(nil)
