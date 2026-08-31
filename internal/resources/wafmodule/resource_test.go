package wafmodule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var testConfigAttributeTypes = map[string]attr.Type{
	"label":  types.StringType,
	"status": types.BoolType,
}

type testResourceModel struct {
	EPID     types.String `tfsdk:"ep_id"`
	Template types.Bool   `tfsdk:"template"`
	Configs  types.Object `tfsdk:"configs"`
}

type testConfigsModel struct {
	Label  types.String `tfsdk:"label"`
	Status types.Bool   `tfsdk:"status"`
}

func TestDescriptorMetadataSchemaAndConfigure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := &fakeCodec{}
	descriptor := testDescriptor(codec)
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("Descriptor.Validate() error = %v", err)
	}
	implementation := NewResource(descriptor, nil).(*moduleResource)

	var metadata resource.MetadataResponse
	implementation.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &metadata)
	if metadata.TypeName != "fortiappseccloud_waf_test_module" {
		t.Fatalf("type name = %q", metadata.TypeName)
	}
	resourceSchema := testModuleSchema(t, ctx, implementation)
	if _, ok := resourceSchema.Attributes["ep_id"]; !ok {
		t.Fatal("schema is missing ep_id")
	}
	if _, ok := resourceSchema.Blocks["configs"]; !ok {
		t.Fatal("schema is missing configs")
	}

	var configure resource.ConfigureResponse
	implementation.Configure(ctx, resource.ConfigureRequest{ProviderData: "wrong"}, &configure)
	if !configure.Diagnostics.HasError() {
		t.Fatal("Configure() accepted unexpected provider data")
	}

	invalid := descriptor
	invalid.Endpoint.Path = "/waf/apps/{ep_id}/nested/path"
	invalidResource := NewResource(invalid, nil).(*moduleResource)
	var schemaResponse resource.SchemaResponse
	invalidResource.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if !schemaResponse.Diagnostics.HasError() {
		t.Fatal("Schema() accepted an unsafe descriptor endpoint")
	}

	verifiedForget := descriptor
	verifiedForget.Destroy.Verified = true
	if err := verifiedForget.Validate(); err == nil {
		t.Fatal("Descriptor.Validate() accepted a verified forget policy")
	}
	candidateForget := descriptor
	candidateForget.Destroy.Field = "status"
	if err := candidateForget.Validate(); err != nil {
		t.Fatalf("Descriptor.Validate() rejected a safe unverified disable candidate: %v", err)
	}
	invalidCandidate := descriptor
	invalidCandidate.Destroy.Field = "label"
	if err := invalidCandidate.Validate(); err == nil {
		t.Fatal("Descriptor.Validate() accepted a non-status disable candidate")
	}
	unsupported := descriptor
	unsupported.Destroy.Mode = DestroyMode("disable")
	if err := unsupported.Validate(); err == nil {
		t.Fatal("Descriptor.Validate() accepted an unimplemented destroy policy")
	}
}

func TestValidateConfigChecksBaseInvariantAndCodec(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := &fakeCodec{configError: errors.New("codec rejected config")}
	implementation := NewResource(testDescriptor(codec), nil).(*moduleResource)
	resourceSchema := testModuleSchema(t, ctx, implementation)

	tests := map[string]testResourceModel{
		"empty id": {
			EPID:     types.StringValue("   "),
			Template: types.BoolValue(true),
			Configs:  types.ObjectNull(testConfigAttributeTypes),
		},
		"configs with template": {
			EPID:     types.StringValue("123"),
			Template: types.BoolValue(true),
			Configs:  testConfigsObject(t, types.BoolValue(true), types.StringNull()),
		},
		"missing local configs": {
			EPID:     types.StringValue("123"),
			Template: types.BoolValue(false),
			Configs:  types.ObjectNull(testConfigAttributeTypes),
		},
	}
	for name, model := range tests {
		model := model
		t.Run(name, func(t *testing.T) {
			var response resource.ValidateConfigResponse
			implementation.ValidateConfig(ctx, resource.ValidateConfigRequest{
				Config: testModuleConfigFor(t, ctx, resourceSchema, &model),
			}, &response)
			if !response.Diagnostics.HasError() {
				t.Fatal("ValidateConfig() diagnostics did not report an error")
			}
		})
	}
	if codec.validateConfigCalls() != len(tests) {
		t.Fatalf("codec ValidateConfig calls = %d, want %d", codec.validateConfigCalls(), len(tests))
	}
}

func TestCreateGetMergePutGetPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := &fakeCodec{}
	service := &fakeModuleService{
		gets: []fakeModuleGet{
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"label":"old","future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":false,"label":"","future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	implementation := testModuleResource(codec, service, locking.NewRegistry())
	resourceSchema := testModuleSchema(t, ctx, implementation)
	model := testResourceModel{
		EPID:     types.StringValue(" 123 "),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, types.BoolValue(false), types.StringValue("")),
	}
	request := resource.CreateRequest{
		Config: testModuleConfigFor(t, ctx, resourceSchema, &model),
		Plan:   testModulePlanFor(t, ctx, resourceSchema, &model),
	}
	response := resource.CreateResponse{State: testModuleNullState(ctx, resourceSchema)}
	implementation.Create(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}

	wantCalls := []string{"get:123", "put:123", "get:123"}
	if calls := service.callLog(); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	puts := service.putResults()
	if len(puts) != 1 {
		t.Fatalf("PUT results = %d, want 1", len(puts))
	}
	assertRawBool(t, puts[0].Configs["status"], false)
	assertRawString(t, puts[0].Configs["label"], "")
	if _, ok := puts[0].Configs["future_config"]; !ok {
		t.Fatal("PUT result lost future_config")
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
		t.Fatal("PUT result lost future_envelope")
	}

	state := testModuleStateValue(t, ctx, response.State)
	if state.EPID.ValueString() != "123" || state.Template.ValueBool() {
		t.Fatalf("state = %#v", state)
	}
	configs := testDecodeConfigs(t, ctx, state.Configs)
	if configs.Status.ValueBool() || configs.Label.ValueString() != "" {
		t.Fatalf("normalized configs = %#v", configs)
	}
	if !codec.sawNullCurrentState() {
		t.Fatal("Create codec did not receive a real null current state")
	}
}

func TestUpdateConflictRefreshesAndRemerges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := &fakeCodec{}
	service := &fakeModuleService{
		gets: []fakeModuleGet{
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"label":"first","generation":1},"template":false}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"label":"fresh","generation":2},"template":false}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":false,"label":"fresh","generation":2},"template":false}}`)},
		},
		putErrors: []error{
			&client.APIError{Operation: "put CSRF protection", StatusCode: http.StatusConflict},
			nil,
		},
		exists: true,
	}
	implementation := testModuleResource(codec, service, locking.NewRegistry())
	resourceSchema := testModuleSchema(t, ctx, implementation)
	priorModel := testResourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, types.BoolValue(true), types.StringValue("first")),
	}
	configModel := testResourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, types.BoolValue(false), types.StringNull()),
	}
	planModel := testResourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, types.BoolValue(false), types.StringValue("first")),
	}
	prior := testModuleStateFor(t, ctx, resourceSchema, &priorModel)
	response := resource.UpdateResponse{State: testCopyModuleState(prior)}
	implementation.Update(ctx, resource.UpdateRequest{
		Config: testModuleConfigFor(t, ctx, resourceSchema, &configModel),
		Plan:   testModulePlanFor(t, ctx, resourceSchema, &planModel),
		State:  prior,
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	wantCalls := []string{"get:123", "put:123", "get:123", "put:123", "get:123"}
	if calls := service.callLog(); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	puts := service.putResults()
	if len(puts) != 2 {
		t.Fatalf("PUT results = %d, want 2", len(puts))
	}
	assertRawString(t, puts[0].Configs["label"], "first")
	assertRawString(t, puts[1].Configs["label"], "fresh")
	assertRawNumber(t, puts[1].Configs["generation"], 2)
	assertRawBool(t, puts[1].Configs["status"], false)
}

func TestUpdateStopsAfterThreeConflictAttempts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := &fakeCodec{}
	conflict := &client.APIError{Operation: "put test module", StatusCode: http.StatusConflict}
	service := &fakeModuleService{
		gets: []fakeModuleGet{
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true},"template":false}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true},"template":false}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true},"template":false}}`)},
		},
		putErrors: []error{conflict, conflict, conflict},
		exists:    true,
	}
	implementation := testModuleResource(codec, service, locking.NewRegistry())
	resourceSchema := testModuleSchema(t, ctx, implementation)
	model := testResourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(false),
		Configs:  testConfigsObject(t, types.BoolValue(false), types.StringNull()),
	}
	prior := testModuleStateFor(t, ctx, resourceSchema, &model)
	response := resource.UpdateResponse{State: testCopyModuleState(prior)}
	implementation.Update(ctx, resource.UpdateRequest{
		Config: testModuleConfigFor(t, ctx, resourceSchema, &model),
		Plan:   testModulePlanFor(t, ctx, resourceSchema, &model),
		State:  prior,
	}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Update() did not report the final conflict")
	}
	wantCalls := []string{"get:123", "put:123", "get:123", "put:123", "get:123", "put:123"}
	if calls := service.callLog(); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if len(service.putResults()) != maxConflictAttempts {
		t.Fatalf("PUT attempts = %d, want %d", len(service.putResults()), maxConflictAttempts)
	}
	if !response.State.Raw.Equal(prior.Raw) {
		t.Fatal("Update() changed state after conflict exhaustion")
	}
}

func TestTemplateInheritanceSkipsPatchAndSuppressesState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := &fakeCodec{}
	service := &fakeModuleService{
		gets: []fakeModuleGet{
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"label":"effective"},"template":false}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"label":"effective"},"template":true}}`)},
		},
		exists: true,
	}
	implementation := testModuleResource(codec, service, locking.NewRegistry())
	resourceSchema := testModuleSchema(t, ctx, implementation)
	model := testResourceModel{
		EPID:     types.StringValue("123"),
		Template: types.BoolValue(true),
		Configs:  types.ObjectNull(testConfigAttributeTypes),
	}
	response := resource.CreateResponse{State: testModuleNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{
		Config: testModuleConfigFor(t, ctx, resourceSchema, &model),
		Plan:   testModulePlanFor(t, ctx, resourceSchema, &model),
	}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	if codec.patchCalls() != 0 {
		t.Fatalf("patch Apply calls = %d, want 0", codec.patchCalls())
	}
	puts := service.putResults()
	if len(puts) != 1 || !puts[0].Template {
		t.Fatalf("PUT results = %#v", puts)
	}
	assertRawString(t, puts[0].Configs["label"], "effective")
	state := testModuleStateValue(t, ctx, response.State)
	if !state.Template.ValueBool() || !state.Configs.IsNull() {
		t.Fatalf("template state = %#v", state)
	}
}

func TestReadDriftOwnershipImportAndParentAbsence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tests := map[string]struct {
		prior          testResourceModel
		get            fakeModuleGet
		exists         bool
		wantError      bool
		wantRemoved    bool
		wantConfigsNil bool
		wantStatus     bool
		wantSource     OwnershipSource
	}{
		"owned drift refreshes": {
			prior:      testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: testConfigsObject(t, types.BoolValue(true), types.StringNull())},
			get:        fakeModuleGet{document: testModuleDocument(t, `{"result":{"configs":{"status":false},"template":false}}`)},
			exists:     true,
			wantStatus: false,
			wantSource: OwnershipPriorState,
		},
		"unowned remains null": {
			prior:          testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: types.ObjectNull(testConfigAttributeTypes)},
			get:            fakeModuleGet{document: testModuleDocument(t, `{"result":{"configs":{"status":false},"template":false}}`)},
			exists:         true,
			wantConfigsNil: true,
			wantSource:     OwnershipPriorState,
		},
		"import hydrates": {
			prior:      testResourceModel{EPID: types.StringValue("123"), Template: types.BoolNull(), Configs: types.ObjectNull(testConfigAttributeTypes)},
			get:        fakeModuleGet{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"label":"imported"},"template":false}}`)},
			exists:     true,
			wantStatus: true,
			wantSource: OwnershipImported,
		},
		"absent parent removes state": {
			prior:       testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: testConfigsObject(t, types.BoolValue(true), types.StringNull())},
			get:         fakeModuleGet{err: &client.APIError{Operation: "get CSRF protection", StatusCode: http.StatusNotFound}},
			exists:      false,
			wantRemoved: true,
		},
		"present parent retains state": {
			prior:     testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: testConfigsObject(t, types.BoolValue(true), types.StringNull())},
			get:       fakeModuleGet{err: &client.APIError{Operation: "get CSRF protection", StatusCode: http.StatusBadRequest}},
			exists:    true,
			wantError: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			codec := &fakeCodec{}
			service := &fakeModuleService{gets: []fakeModuleGet{test.get}, exists: test.exists}
			implementation := testModuleResource(codec, service, locking.NewRegistry())
			resourceSchema := testModuleSchema(t, ctx, implementation)
			prior := testModuleStateFor(t, ctx, resourceSchema, &test.prior)
			response := resource.ReadResponse{State: testCopyModuleState(prior)}
			implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
			if response.Diagnostics.HasError() != test.wantError {
				t.Fatalf("Read() diagnostics = %v, wantError %t", response.Diagnostics, test.wantError)
			}
			if test.wantRemoved {
				if !response.State.Raw.Equal(testModuleNullState(ctx, resourceSchema).Raw) {
					t.Fatal("Read() did not remove state")
				}
				return
			}
			if test.wantError {
				if !response.State.Raw.Equal(prior.Raw) {
					t.Fatal("Read() changed state after unresolved module error")
				}
				return
			}
			state := testModuleStateValue(t, ctx, response.State)
			if state.Configs.IsNull() != test.wantConfigsNil {
				t.Fatalf("configs null = %t, want %t", state.Configs.IsNull(), test.wantConfigsNil)
			}
			if !test.wantConfigsNil {
				configs := testDecodeConfigs(t, ctx, state.Configs)
				if configs.Status.ValueBool() != test.wantStatus {
					t.Fatalf("status = %t, want %t", configs.Status.ValueBool(), test.wantStatus)
				}
			}
			if sources := codec.ownershipLog(); len(sources) == 0 || sources[len(sources)-1] != test.wantSource {
				t.Fatalf("ownership sources = %#v, want final %v", sources, test.wantSource)
			}
		})
	}
}

func TestMalformedSuccessfulResultRetainsState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := &fakeCodec{}
	service := &fakeModuleService{
		gets:   []fakeModuleGet{{document: testModuleDocument(t, `{"result":{"configs":{"status":"secret-invalid-value"},"template":false}}`)}},
		exists: true,
	}
	implementation := testModuleResource(codec, service, locking.NewRegistry())
	resourceSchema := testModuleSchema(t, ctx, implementation)
	model := testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: testConfigsObject(t, types.BoolValue(true), types.StringNull())}
	prior := testModuleStateFor(t, ctx, resourceSchema, &model)
	response := resource.ReadResponse{State: testCopyModuleState(prior)}
	implementation.Read(ctx, resource.ReadRequest{State: prior}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Read() accepted a malformed successful API result")
	}
	if !response.State.Raw.Equal(prior.Raw) {
		t.Fatal("Read() changed state after malformed result")
	}
	diagnosticText := diagnosticsText(response.Diagnostics)
	if diagnosticText == "" {
		t.Fatal("Read() returned an empty diagnostic")
	}
	if strings.Contains(diagnosticText, "secret-invalid-value") {
		t.Fatal("Read() diagnostic exposed the malformed API value")
	}
}

func TestImportStateTrimsAndSetsOnlyEPID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	implementation := NewResource(testDescriptor(&fakeCodec{}), nil).(*moduleResource)
	resourceSchema := testModuleSchema(t, ctx, implementation)
	empty := testModuleStateFor(t, ctx, resourceSchema, &testResourceModel{
		EPID:     types.StringNull(),
		Template: types.BoolNull(),
		Configs:  types.ObjectNull(testConfigAttributeTypes),
	})
	response := resource.ImportStateResponse{State: testCopyModuleState(empty)}
	implementation.ImportState(ctx, resource.ImportStateRequest{ID: " 123 "}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("ImportState() diagnostics = %v", response.Diagnostics)
	}
	state := testModuleStateValue(t, ctx, response.State)
	if state.EPID.ValueString() != "123" || !state.Template.IsNull() || !state.Configs.IsNull() {
		t.Fatalf("imported state = %#v", state)
	}

	emptyResponse := resource.ImportStateResponse{State: testCopyModuleState(empty)}
	implementation.ImportState(ctx, resource.ImportStateRequest{ID: "   "}, &emptyResponse)
	if !emptyResponse.Diagnostics.HasError() {
		t.Fatal("ImportState() accepted an empty ID")
	}
}

func TestDeleteForgetPolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tests := map[string]struct {
		get         fakeModuleGet
		exists      bool
		existsErr   error
		wantError   bool
		wantWarning bool
	}{
		"present module warns without mutation": {
			get:         fakeModuleGet{document: testModuleDocument(t, `{"result":{"configs":{"status":true},"template":false}}`)},
			exists:      true,
			wantWarning: true,
		},
		"malformed module still warns without mutation": {
			get:         fakeModuleGet{document: testModuleDocument(t, `{"result":{"configs":{"status":"invalid"},"template":false}}`)},
			exists:      true,
			wantWarning: true,
		},
		"absent parent succeeds silently": {
			get:    fakeModuleGet{err: &client.APIError{Operation: "get CSRF protection", StatusCode: http.StatusNotFound}},
			exists: false,
		},
		"authentication failure retains state": {
			get:       fakeModuleGet{err: &client.APIError{Operation: "get CSRF protection", StatusCode: http.StatusUnauthorized}},
			wantError: true,
		},
		"parent check failure retains state": {
			get:       fakeModuleGet{err: &client.APIError{Operation: "get CSRF protection", StatusCode: http.StatusBadRequest}},
			existsErr: errors.New("inventory unavailable"),
			wantError: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			codec := &fakeCodec{}
			service := &fakeModuleService{gets: []fakeModuleGet{test.get}, exists: test.exists, existsErr: test.existsErr}
			implementation := testModuleResource(codec, service, locking.NewRegistry())
			resourceSchema := testModuleSchema(t, ctx, implementation)
			model := testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: testConfigsObject(t, types.BoolValue(true), types.StringNull())}
			prior := testModuleStateFor(t, ctx, resourceSchema, &model)
			response := resource.DeleteResponse{State: testCopyModuleState(prior)}
			implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
			if response.Diagnostics.HasError() != test.wantError {
				t.Fatalf("Delete() diagnostics = %v, wantError %t", response.Diagnostics, test.wantError)
			}
			if warningCount(response.Diagnostics) != boolInt(test.wantWarning) {
				t.Fatalf("warnings = %d, want %d", warningCount(response.Diagnostics), boolInt(test.wantWarning))
			}
			if len(service.putResults()) != 0 {
				t.Fatal("forget destroy issued a PUT")
			}
			if !response.State.Raw.Equal(prior.Raw) {
				t.Fatal("Delete() directly changed state")
			}
		})
	}
}

func TestDeleteDisablePolicyPreservesConfigurationAndVerifies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeModuleService{
		gets: []fakeModuleGet{
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"future":{"keep":true}},"template":true,"future_envelope":"keep"}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":false,"future":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
		},
		exists: true,
	}
	descriptor := testDescriptor(&fakeCodec{})
	descriptor.Destroy = DestroyPolicy{Mode: DestroyDisable, Verified: true, Field: "status", Reason: "live disable lifecycle verified"}
	implementation := NewResource(descriptor, locking.NewRegistry()).(*moduleResource)
	implementation.service = service
	resourceSchema := testModuleSchema(t, ctx, implementation)
	model := testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(true), Configs: types.ObjectNull(testConfigAttributeTypes)}
	prior := testModuleStateFor(t, ctx, resourceSchema, &model)
	response := resource.DeleteResponse{State: testCopyModuleState(prior)}
	implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
	if response.Diagnostics.HasError() || warningCount(response.Diagnostics) != 0 {
		t.Fatalf("Delete() diagnostics = %v", response.Diagnostics)
	}
	if calls := service.callLog(); !reflect.DeepEqual(calls, []string{"get:123", "put:123", "get:123"}) {
		t.Fatalf("calls = %#v", calls)
	}
	puts := service.putResults()
	if len(puts) != 1 || puts[0].Template {
		t.Fatalf("PUT = %#v", puts)
	}
	assertRawBool(t, puts[0].Configs["status"], false)
	if _, ok := puts[0].Configs["future"]; !ok {
		t.Fatal("disable dropped an unowned config field")
	}
}

func TestDeleteDisablePolicyFailsClosed(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		gets      []fakeModuleGet
		wantCalls []string
	}{
		"fresh status is missing": {
			gets: []fakeModuleGet{
				{document: testModuleDocument(t, `{"result":{"configs":{"future":true},"template":false}}`)},
			},
			wantCalls: []string{"get:123"},
		},
		"fresh status is not boolean": {
			gets: []fakeModuleGet{
				{document: testModuleDocument(t, `{"result":{"configs":{"status":"enable","future":true},"template":false}}`)},
			},
			wantCalls: []string{"get:123"},
		},
		"fresh status is null": {
			gets: []fakeModuleGet{
				{document: testModuleDocument(t, `{"result":{"configs":{"status":null,"future":true},"template":false}}`)},
			},
			wantCalls: []string{"get:123"},
		},
		"verification changes unowned config": {
			gets: []fakeModuleGet{
				{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"future":{"keep":true}},"template":false,"future_envelope":"keep"}}`)},
				{document: testModuleDocument(t, `{"result":{"configs":{"status":false,"future":{"keep":false}},"template":false,"future_envelope":"keep"}}`)},
			},
			wantCalls: []string{"get:123", "put:123", "get:123"},
		},
		"verification omits status": {
			gets: []fakeModuleGet{
				{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"future":true},"template":false}}`)},
				{document: testModuleDocument(t, `{"result":{"configs":{"future":true},"template":false}}`)},
			},
			wantCalls: []string{"get:123", "put:123", "get:123"},
		},
		"verification returns null status": {
			gets: []fakeModuleGet{
				{document: testModuleDocument(t, `{"result":{"configs":{"status":true,"future":true},"template":false}}`)},
				{document: testModuleDocument(t, `{"result":{"configs":{"status":null,"future":true},"template":false}}`)},
			},
			wantCalls: []string{"get:123", "put:123", "get:123"},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			service := &fakeModuleService{gets: test.gets, exists: true}
			descriptor := testDescriptor(&fakeCodec{})
			descriptor.Destroy = DestroyPolicy{Mode: DestroyDisable, Verified: true, Field: "status", Reason: "live disable lifecycle verified"}
			implementation := NewResource(descriptor, locking.NewRegistry()).(*moduleResource)
			implementation.service = service
			resourceSchema := testModuleSchema(t, ctx, implementation)
			model := testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: testConfigsObject(t, types.BoolValue(true), types.StringNull())}
			prior := testModuleStateFor(t, ctx, resourceSchema, &model)
			response := resource.DeleteResponse{State: testCopyModuleState(prior)}
			implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
			if !response.Diagnostics.HasError() {
				t.Fatal("Delete() accepted an unsafe or unverifiable disable")
			}
			if calls := service.callLog(); !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("calls = %#v, want %#v", calls, test.wantCalls)
			}
		})
	}
}

func TestDisableOnDestroyNormalizesGETShapeForPutAndVerification(t *testing.T) {
	t.Parallel()

	current := testModuleDocument(t, `{
		"result": {
			"configs": {
				"status": true,
				"ip_reputation": true,
				"future": {"keep": true},
				"ip_list": [
					{"idx": 1, "type": "trust-ip", "ip": "10.0.0.1"},
					{"idx": 2, "type": "block-ip", "ip": null}
				]
			},
			"template": true,
			"future_envelope": "keep"
		}
	}`)
	verified := testModuleDocument(t, `{
		"result": {
			"configs": {
				"status": false,
				"ip_reputation": true,
				"future": {"keep": true},
				"ip_list": [
					{"idx": 1, "type": "trust-ip", "ip": "10.0.0.1"},
					{"idx": 2, "type": "block-ip", "ip": null}
				]
			},
			"template": false,
			"future_envelope": "keep"
		}
	}`)

	var put client.WAFModuleResult
	var diagnostics diag.Diagnostics
	DisableOnDestroy(context.Background(), DisableRequest{
		ModuleName:      "IP protection",
		EPID:            "123",
		Field:           "status",
		Verified:        true,
		Current:         &current,
		NormalizeForPut: client.NormalizeIPProtectionResultForPut,
	}, DisableAccess{
		Get: func(context.Context) (client.WAFModuleDocument, error) {
			return verified, nil
		},
		Put: func(_ context.Context, result client.WAFModuleResult) error {
			put = result
			return nil
		},
		ApplicationExists: func(context.Context) (bool, error) {
			return true, nil
		},
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("DisableOnDestroy() diagnostics = %v", diagnostics)
	}
	if put.Template {
		t.Fatal("disable PUT retained template=true")
	}
	assertRawBool(t, put.Configs["status"], false)
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(put.Configs["ip_list"], &items); err != nil {
		t.Fatalf("decode PUT ip_list: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("PUT ip_list length = %d, want 1 active item", len(items))
	}
	if _, ok := items[0]["idx"]; ok {
		t.Fatal("disable PUT retained GET-only idx")
	}
	if _, ok := put.Configs["future"]; !ok {
		t.Fatal("disable PUT lost unowned config")
	}
}

func TestResourcesSharingRegistrySerializeSameEndpoint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	registry := locking.NewRegistry()
	service := &fakeModuleService{
		gets: []fakeModuleGet{
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true},"template":false}}`)},
			{document: testModuleDocument(t, `{"result":{"configs":{"status":true},"template":false}}`)},
		},
		getDelay: 25 * time.Millisecond,
		exists:   true,
	}
	first := testModuleResource(&fakeCodec{}, service, registry)
	second := testModuleResource(&fakeCodec{}, service, registry)
	resourceSchema := testModuleSchema(t, ctx, first)
	model := testResourceModel{EPID: types.StringValue("123"), Template: types.BoolValue(false), Configs: testConfigsObject(t, types.BoolValue(true), types.StringNull())}
	prior := testModuleStateFor(t, ctx, resourceSchema, &model)

	var wait sync.WaitGroup
	wait.Add(2)
	responses := make([]resource.ReadResponse, 2)
	for index, implementation := range []*moduleResource{first, second} {
		index, implementation := index, implementation
		go func() {
			defer wait.Done()
			responses[index].State = testCopyModuleState(prior)
			implementation.Read(ctx, resource.ReadRequest{State: prior}, &responses[index])
		}()
	}
	wait.Wait()
	for index := range responses {
		if responses[index].Diagnostics.HasError() {
			t.Fatalf("Read(%d) diagnostics = %v", index, responses[index].Diagnostics)
		}
	}
	if service.maximumActiveGets() != 1 {
		t.Fatalf("maximum concurrent GETs = %d, want 1", service.maximumActiveGets())
	}
}

func TestConfiguredScalarHelpers(t *testing.T) {
	t.Parallel()

	stringValue, stringDiagnostics := ConfiguredString(types.StringValue(""), types.StringValue("planned"), "label")
	if stringDiagnostics.HasError() || !stringValue.Set || stringValue.Value != "" {
		t.Fatalf("ConfiguredString(explicit empty) = %#v, %v", stringValue, stringDiagnostics)
	}
	omitted, omittedDiagnostics := ConfiguredBool(types.BoolNull(), types.BoolValue(true), "status")
	if omittedDiagnostics.HasError() || omitted.Set {
		t.Fatalf("ConfiguredBool(omitted) = %#v, %v", omitted, omittedDiagnostics)
	}
	resolved, resolvedDiagnostics := ConfiguredBool(types.BoolUnknown(), types.BoolValue(false), "status")
	if resolvedDiagnostics.HasError() || !resolved.Set || resolved.Value {
		t.Fatalf("ConfiguredBool(resolved false) = %#v, %v", resolved, resolvedDiagnostics)
	}
	_, unresolvedDiagnostics := ConfiguredString(types.StringUnknown(), types.StringUnknown(), "label")
	if !unresolvedDiagnostics.HasError() {
		t.Fatal("ConfiguredString() accepted an unresolved configured value")
	}
}

func testDescriptor(codec Codec) Descriptor {
	return Descriptor{
		TypeNameSuffix: "waf_test_module",
		Endpoint: client.WAFModuleEndpoint{
			Path:      "/waf/apps/{ep_id}/test_module",
			Operation: "test module",
		},
		Codec: codec,
		Destroy: DestroyPolicy{
			Mode:     DestroyForget,
			Verified: false,
			Reason:   "No DELETE operation exists and disable semantics have not been verified",
		},
	}
}

func testModuleResource(codec Codec, service moduleService, locks *locking.Registry) *moduleResource {
	implementation := NewResource(testDescriptor(codec), locks).(*moduleResource)
	implementation.service = service
	return implementation
}

type fakeCodec struct {
	mu                  sync.Mutex
	configError         error
	validateCalls       int
	applyCalls          int
	ownershipSources    []OwnershipSource
	createStateWasNull  bool
	createStateObserved bool
}

func (c *fakeCodec) Schema(context.Context) schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"ep_id":    schema.StringAttribute{Required: true},
			"template": schema.BoolAttribute{Required: true},
		},
		Blocks: map[string]schema.Block{
			"configs": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"label":  schema.StringAttribute{Optional: true, Computed: true},
					"status": schema.BoolAttribute{Optional: true, Computed: true},
				},
			},
		},
	}
}

func (c *fakeCodec) ValidateConfig(_ context.Context, _ tfsdk.Config) diag.Diagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validateCalls++
	var diagnostics diag.Diagnostics
	if c.configError != nil {
		diagnostics.AddError("Invalid test module configuration", c.configError.Error())
	}
	return diagnostics
}

func (c *fakeCodec) BuildPatch(ctx context.Context, config tfsdk.Config, plan tfsdk.Plan, state tfsdk.State) (Patch, diag.Diagnostics) {
	c.mu.Lock()
	if !c.createStateObserved && state.Raw.IsKnown() {
		c.createStateObserved = true
		c.createStateWasNull = state.Raw.IsNull()
	}
	c.mu.Unlock()

	var configModel, planModel testResourceModel
	var diagnostics diag.Diagnostics
	diagnostics.Append(config.Get(ctx, &configModel)...)
	diagnostics.Append(plan.Get(ctx, &planModel)...)
	if diagnostics.HasError() || configModel.Configs.IsNull() {
		return PatchFunc(func(context.Context, *client.WAFModuleResult) diag.Diagnostics { return nil }), diagnostics
	}
	if configModel.Configs.IsUnknown() || planModel.Configs.IsUnknown() || planModel.Configs.IsNull() {
		diagnostics.AddError("Unknown test module configuration", "configs must be known during apply")
		return nil, diagnostics
	}
	var configured, planned testConfigsModel
	diagnostics.Append(configModel.Configs.As(ctx, &configured, basetypes.ObjectAsOptions{})...)
	diagnostics.Append(planModel.Configs.As(ctx, &planned, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	status, statusDiagnostics := ConfiguredBool(configured.Status, planned.Status, "status")
	label, labelDiagnostics := ConfiguredString(configured.Label, planned.Label, "label")
	diagnostics.Append(statusDiagnostics...)
	diagnostics.Append(labelDiagnostics...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	return PatchFunc(func(_ context.Context, result *client.WAFModuleResult) diag.Diagnostics {
		c.mu.Lock()
		c.applyCalls++
		c.mu.Unlock()
		var applyDiagnostics diag.Diagnostics
		if status.Set {
			if err := result.SetConfig("status", status.Value); err != nil {
				applyDiagnostics.AddError("Unable to set test module status", err.Error())
			}
		}
		if label.Set {
			if err := result.SetConfig("label", label.Value); err != nil {
				applyDiagnostics.AddError("Unable to set test module label", err.Error())
			}
		}
		return applyDiagnostics
	}), diagnostics
}

func (c *fakeCodec) ValidateResult(_ context.Context, result client.WAFModuleResult, ownership OwnershipContext) diag.Diagnostics {
	c.mu.Lock()
	c.ownershipSources = append(c.ownershipSources, ownership.Source)
	c.mu.Unlock()
	var diagnostics diag.Diagnostics
	raw, ok := result.Configs["status"]
	if !ok {
		diagnostics.AddError("Malformed test module result", "The successful API result did not contain status.")
		return diagnostics
	}
	var status bool
	if err := json.Unmarshal(raw, &status); err != nil {
		diagnostics.AddError("Malformed test module result", "The successful API result contained an invalid status value.")
	}
	return diagnostics
}

func (c *fakeCodec) Flatten(ctx context.Context, epID string, result client.WAFModuleResult, ownership OwnershipContext) (any, diag.Diagnostics) {
	model := testResourceModel{
		EPID:     types.StringValue(epID),
		Template: types.BoolValue(result.Template),
		Configs:  types.ObjectNull(testConfigAttributeTypes),
	}
	if result.Template {
		return &model, nil
	}

	owned := ownership.Source == OwnershipImported
	var diagnostics diag.Diagnostics
	switch ownership.Source {
	case OwnershipConfigured:
		var configured testResourceModel
		diagnostics.Append(ownership.Config.Get(ctx, &configured)...)
		owned = !configured.Configs.IsNull()
	case OwnershipPriorState:
		var prior testResourceModel
		diagnostics.Append(ownership.State.Get(ctx, &prior)...)
		owned = !prior.Configs.IsNull()
	}
	if diagnostics.HasError() || !owned {
		return &model, diagnostics
	}

	var status bool
	if err := json.Unmarshal(result.Configs["status"], &status); err != nil {
		diagnostics.AddError("Malformed test module result", "Unable to decode status while flattening state.")
		return nil, diagnostics
	}
	attributes := map[string]attr.Value{
		"status": types.BoolValue(status),
		"label":  types.StringNull(),
	}
	if raw, ok := result.Configs["label"]; ok && string(raw) != "null" {
		var label string
		if err := json.Unmarshal(raw, &label); err != nil {
			diagnostics.AddError("Malformed test module result", "Unable to decode label while flattening state.")
			return nil, diagnostics
		}
		attributes["label"] = types.StringValue(label)
	}
	model.Configs, diagnostics = types.ObjectValue(testConfigAttributeTypes, attributes)
	return &model, diagnostics
}

func (c *fakeCodec) validateConfigCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.validateCalls
}

func (c *fakeCodec) patchCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyCalls
}

func (c *fakeCodec) ownershipLog() []OwnershipSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]OwnershipSource(nil), c.ownershipSources...)
}

func (c *fakeCodec) sawNullCurrentState() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.createStateObserved && c.createStateWasNull
}

type fakeModuleGet struct {
	document client.WAFModuleDocument
	err      error
}

type fakeModuleService struct {
	mu         sync.Mutex
	gets       []fakeModuleGet
	putErrors  []error
	exists     bool
	existsErr  error
	calls      []string
	puts       []client.WAFModuleResult
	getDelay   time.Duration
	activeGets int
	maxGets    int
}

func (s *fakeModuleService) GetWAFModule(_ context.Context, _ client.WAFModuleEndpoint, epID string) (client.WAFModuleDocument, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "get:"+epID)
	if len(s.gets) == 0 {
		s.mu.Unlock()
		return client.WAFModuleDocument{}, errors.New("unexpected GetWAFModule call")
	}
	result := s.gets[0]
	s.gets = s.gets[1:]
	s.activeGets++
	if s.activeGets > s.maxGets {
		s.maxGets = s.activeGets
	}
	delay := s.getDelay
	s.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	s.mu.Lock()
	s.activeGets--
	s.mu.Unlock()
	return result.document, result.err
}

func (s *fakeModuleService) PutWAFModule(_ context.Context, _ client.WAFModuleEndpoint, epID string, result client.WAFModuleResult) error {
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

func (s *fakeModuleService) ApplicationExists(_ context.Context, epID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "exists:"+epID)
	return s.exists, s.existsErr
}

func (s *fakeModuleService) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *fakeModuleService) putResults() []client.WAFModuleResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := make([]client.WAFModuleResult, len(s.puts))
	for index := range s.puts {
		results[index] = s.puts[index].Clone()
	}
	return results
}

func (s *fakeModuleService) maximumActiveGets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxGets
}

func testModuleSchema(t *testing.T, ctx context.Context, implementation resource.Resource) schema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	implementation.Schema(ctx, resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Schema() diagnostics = %v", response.Diagnostics)
	}
	return response.Schema
}

func testModuleStateFor(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.State {
	t.Helper()
	state := tfsdk.State{Schema: resourceSchema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("State.Set() diagnostics = %v", diagnostics)
	}
	return state
}

func testModulePlanFor(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Plan {
	t.Helper()
	plan := tfsdk.Plan{Schema: resourceSchema}
	if diagnostics := plan.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("Plan.Set() diagnostics = %v", diagnostics)
	}
	return plan
}

func testModuleConfigFor(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Config {
	t.Helper()
	state := testModuleStateFor(t, ctx, resourceSchema, model)
	return tfsdk.Config{Schema: resourceSchema, Raw: state.Raw.Copy()}
}

func testModuleNullState(ctx context.Context, resourceSchema schema.Schema) tfsdk.State {
	return tfsdk.State{
		Schema: resourceSchema,
		Raw:    tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil),
	}
}

func testCopyModuleState(state tfsdk.State) tfsdk.State {
	return tfsdk.State{Schema: state.Schema, Raw: state.Raw.Copy()}
}

func testModuleStateValue(t *testing.T, ctx context.Context, state tfsdk.State) testResourceModel {
	t.Helper()
	var model testResourceModel
	if diagnostics := state.Get(ctx, &model); diagnostics.HasError() {
		t.Fatalf("State.Get() diagnostics = %v", diagnostics)
	}
	return model
}

func testConfigsObject(t *testing.T, status types.Bool, label types.String) types.Object {
	t.Helper()
	object, diagnostics := types.ObjectValue(testConfigAttributeTypes, map[string]attr.Value{
		"label":  label,
		"status": status,
	})
	if diagnostics.HasError() {
		t.Fatalf("types.ObjectValue() diagnostics = %v", diagnostics)
	}
	return object
}

func testDecodeConfigs(t *testing.T, ctx context.Context, object types.Object) testConfigsModel {
	t.Helper()
	var configs testConfigsModel
	if diagnostics := object.As(ctx, &configs, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatalf("configs.As() diagnostics = %v", diagnostics)
	}
	return configs
}

func testModuleDocument(t *testing.T, payload string) client.WAFModuleDocument {
	t.Helper()
	var document client.WAFModuleDocument
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

func assertRawNumber(t *testing.T, raw json.RawMessage, want float64) {
	t.Helper()
	var got float64
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	if got != want {
		t.Fatalf("value = %v, want %v", got, want)
	}
}

func warningCount(diagnostics diag.Diagnostics) int {
	count := 0
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity() == diag.SeverityWarning {
			count++
		}
	}
	return count
}

func diagnosticsText(diagnostics diag.Diagnostics) string {
	text := ""
	for _, diagnostic := range diagnostics {
		text += fmt.Sprintf("%s: %s", diagnostic.Summary(), diagnostic.Detail())
	}
	return text
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

var (
	_ Codec         = (*fakeCodec)(nil)
	_ moduleService = (*fakeModuleService)(nil)
)
