package wafmodule

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

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

func TestTemplateModuleLifecycleUsesTemplateIdentityAndFalseEnvelope(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codec := templateTestCodec{}
	service := &fakeTemplateModuleService{
		current: templateTestDocument(t, `{"result":{"configs":{"status":true}}}`),
	}
	implementation := NewTemplateResource(TemplateDescriptor{
		TypeNameSuffix: "waf_template_test_module",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/test_module",
			Operation: "test module",
		},
		Codec: codec,
		Destroy: DestroyPolicy{
			Mode:     DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   "test template status disable is verified",
		},
	}, locking.NewRegistry()).(*templateModuleResource)
	implementation.service = service

	resourceSchema := testModuleSchema(t, ctx, implementation)
	if _, ok := resourceSchema.Attributes["template_id"]; !ok {
		t.Fatal("template schema is missing template_id")
	}
	if _, ok := resourceSchema.Attributes["ep_id"]; ok {
		t.Fatal("template schema retained ep_id")
	}
	if _, ok := resourceSchema.Attributes["template"]; ok {
		t.Fatal("template schema retained app inheritance flag")
	}

	configs := testConfigsObject(t, types.BoolValue(false), types.StringNull())
	model := TemplateModel{TemplateID: types.StringValue("template-1"), Configs: configs}
	config := templateModuleConfig(t, ctx, resourceSchema, &model)
	plan := templateModulePlan(t, ctx, resourceSchema, &model)
	create := resource.CreateResponse{State: tfsdk.State{
		Schema: resourceSchema,
		Raw:    tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil),
	}}
	implementation.Create(ctx, resource.CreateRequest{Config: config, Plan: plan}, &create)
	if create.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", create.Diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"get:template-1", "put:template-1", "get:template-1"}) {
		t.Fatalf("calls = %#v", service.calls)
	}
	if len(service.puts) != 1 || service.puts[0].Template {
		t.Fatalf("PUT results = %#v", service.puts)
	}
	var status bool
	if err := json.Unmarshal(service.puts[0].Configs["status"], &status); err != nil || status {
		t.Fatalf("PUT status = %s, error = %v", service.puts[0].Configs["status"], err)
	}

	var state TemplateModel
	if diagnostics := create.State.Get(ctx, &state); diagnostics.HasError() {
		t.Fatalf("State.Get() diagnostics = %v", diagnostics)
	}
	if state.TemplateID.ValueString() != "template-1" {
		t.Fatalf("state = %#v", state)
	}

	service.current = templateTestDocument(t, `{"result":{"configs":{"status":true,"cache":{"status":true},"compress":{"status":true},"future":{"keep":true}},"future_envelope":"keep"}}`)
	service.calls = nil
	deleteResponse := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: create.State}, &deleteResponse)
	if deleteResponse.Diagnostics.HasError() || len(deleteResponse.Diagnostics.Warnings()) != 0 {
		t.Fatalf("Delete() diagnostics = %v", deleteResponse.Diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"get:template-1", "put:template-1", "get:template-1"}) || len(service.puts) != 2 {
		t.Fatalf("delete calls = %#v, puts = %d", service.calls, len(service.puts))
	}
	assertRawBool(t, service.puts[1].Configs["status"], false)
	if _, ok := service.puts[1].Configs["future"]; !ok {
		t.Fatal("template disable dropped an unowned config field")
	}
	if string(service.puts[1].Configs["cache"]) != `{"status":true}` ||
		string(service.puts[1].Configs["compress"]) != `{"status":true}` {
		t.Fatal("template disable changed nested caching/compression statuses")
	}
}

func TestTemplateDescriptorDestroyPolicyValidation(t *testing.T) {
	t.Parallel()

	descriptor := TemplateDescriptor{
		TypeNameSuffix: "waf_template_test_module",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/test_module",
			Operation: "test module",
		},
		Codec: templateTestCodec{},
		Destroy: DestroyPolicy{
			Mode:     DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   "verified template disable",
		},
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("TemplateDescriptor.Validate() error = %v", err)
	}

	unverified := descriptor
	unverified.Destroy.Verified = false
	if err := unverified.Validate(); err == nil {
		t.Fatal("TemplateDescriptor.Validate() accepted an unverified disable")
	}
	invalidField := descriptor
	invalidField.Destroy.Field = "label"
	if err := invalidField.Validate(); err == nil {
		t.Fatal("TemplateDescriptor.Validate() accepted a non-status disable field")
	}
	verifiedForget := descriptor
	verifiedForget.Destroy = DestroyPolicy{Mode: DestroyForget, Verified: true, Reason: "invalid"}
	if err := verifiedForget.Validate(); err == nil {
		t.Fatal("TemplateDescriptor.Validate() accepted a verified forget policy")
	}
	coupled := descriptor
	coupled.Codec = coupledTemplateTestCodec{templateTestCodec{}}
	coupled.Destroy.CoupledFields = []string{"cache.status", "compress.status"}
	if err := coupled.Validate(); err != nil {
		t.Fatalf("TemplateDescriptor.Validate() rejected reviewed coupled fields: %v", err)
	}
	partialCoupling := coupled
	partialCoupling.Destroy.CoupledFields = []string{"cache.status"}
	if err := partialCoupling.Validate(); err == nil {
		t.Fatal("TemplateDescriptor.Validate() accepted a partial coupled disable policy")
	}
}

func TestDisableTemplateOnDestroySetsReviewedCoupledFields(t *testing.T) {
	t.Parallel()

	current := templateTestDocument(t, `{"result":{"configs":{"status":true,"cache":{"status":true,"future_cache":"keep"},"compress":{"status":true,"future_compress":"keep"},"future":{"keep":true}},"future_envelope":"keep"}}`)
	service := &fakeTemplateModuleService{current: current}
	var diagnostics diag.Diagnostics
	DisableTemplateOnDestroy(context.Background(), TemplateDisableRequest{
		ModuleName:    "caching and compression",
		TemplateID:    "template-1",
		Field:         "status",
		CoupledFields: []string{"cache.status", "compress.status"},
		Verified:      true,
		Current:       &current,
	}, TemplateDisableAccess{
		Get: func(ctx context.Context) (client.WAFTemplateModuleDocument, error) {
			return service.GetWAFTemplateModule(ctx, client.WAFTemplateModuleEndpoint{}, "template-1")
		},
		Put: func(ctx context.Context, result client.WAFModuleResult) error {
			return service.PutWAFTemplateModule(ctx, client.WAFTemplateModuleEndpoint{}, "template-1", result)
		},
		TemplateExists: func(ctx context.Context) (bool, error) {
			return service.TemplateExists(ctx, "template-1")
		},
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("DisableTemplateOnDestroy() diagnostics = %v", diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"put:template-1", "get:template-1"}) || len(service.puts) != 1 {
		t.Fatalf("calls = %#v, puts = %d", service.calls, len(service.puts))
	}
	put := service.puts[0]
	for _, field := range []string{"status", "cache.status", "compress.status"} {
		enabled, err := booleanConfigPath(put, field)
		if err != nil || enabled {
			t.Fatalf("PUT configs.%s = %t, error = %v", field, enabled, err)
		}
	}
	encoded, err := json.Marshal(put)
	if err != nil {
		t.Fatal(err)
	}
	for _, preserved := range []string{"future_envelope", "future_cache", "future_compress", `"future":{"keep":true}`} {
		if !strings.Contains(string(encoded), preserved) {
			t.Fatalf("coupled disable dropped %q from %s", preserved, encoded)
		}
	}
}

func TestDisableTemplateOnDestroyRejectsUnappliedCoupledField(t *testing.T) {
	t.Parallel()

	current := templateTestDocument(t, `{"result":{"configs":{"status":true,"cache":{"status":true},"compress":{"status":true}}}}`)
	verification := templateTestDocument(t, `{"result":{"configs":{"status":false,"cache":{"status":true},"compress":{"status":false}}}}`)
	service := &fakeTemplateModuleService{current: current, verification: &verification}
	var diagnostics diag.Diagnostics
	DisableTemplateOnDestroy(context.Background(), TemplateDisableRequest{
		ModuleName:    "caching and compression",
		TemplateID:    "template-1",
		Field:         "status",
		CoupledFields: []string{"cache.status", "compress.status"},
		Verified:      true,
		Current:       &current,
	}, TemplateDisableAccess{
		Get: func(ctx context.Context) (client.WAFTemplateModuleDocument, error) {
			return service.GetWAFTemplateModule(ctx, client.WAFTemplateModuleEndpoint{}, "template-1")
		},
		Put: func(ctx context.Context, result client.WAFModuleResult) error {
			return service.PutWAFTemplateModule(ctx, client.WAFTemplateModuleEndpoint{}, "template-1", result)
		},
		TemplateExists: func(ctx context.Context) (bool, error) {
			return service.TemplateExists(ctx, "template-1")
		},
	}, &diagnostics)
	if !diagnostics.HasError() || !strings.Contains(diagnostics.Errors()[0].Detail(), "configs.cache.status=false") {
		t.Fatalf("DisableTemplateOnDestroy() diagnostics = %v", diagnostics)
	}
}

func TestDisableTemplateOnDestroyResolvesAmbiguousMissingParent(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			var diagnostics diag.Diagnostics
			putCalled := false
			DisableTemplateOnDestroy(context.Background(), TemplateDisableRequest{
				ModuleName: "test module",
				TemplateID: "template-1",
				Field:      "status",
				Verified:   true,
			}, TemplateDisableAccess{
				Get: func(context.Context) (client.WAFTemplateModuleDocument, error) {
					return client.WAFTemplateModuleDocument{}, &client.APIError{Operation: "get template module", StatusCode: status}
				},
				Put: func(context.Context, client.WAFModuleResult) error {
					putCalled = true
					return nil
				},
				TemplateExists: func(context.Context) (bool, error) {
					return false, nil
				},
			}, &diagnostics)
			if diagnostics.HasError() {
				t.Fatalf("DisableTemplateOnDestroy() diagnostics = %v", diagnostics)
			}
			if putCalled {
				t.Fatal("DisableTemplateOnDestroy() issued PUT for an absent template")
			}
		})
	}
}

func TestTemplateDeleteVerificationFailureRetainsState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	verification := templateTestDocument(t, `{"result":{"configs":{"status":false,"future":{"keep":false}},"future_envelope":"keep"}}`)
	service := &fakeTemplateModuleService{
		current:      templateTestDocument(t, `{"result":{"configs":{"status":true,"future":{"keep":true}},"future_envelope":"keep"}}`),
		verification: &verification,
	}
	implementation := NewTemplateResource(TemplateDescriptor{
		TypeNameSuffix: "waf_template_test_module",
		Endpoint: client.WAFTemplateModuleEndpoint{
			Path:      "/waf/template/{template_id}/test_module",
			Operation: "test module",
		},
		Codec: templateTestCodec{},
		Destroy: DestroyPolicy{
			Mode:     DestroyDisable,
			Verified: true,
			Field:    "status",
			Reason:   "test template status disable is verified",
		},
	}, locking.NewRegistry()).(*templateModuleResource)
	implementation.service = service
	resourceSchema := testModuleSchema(t, ctx, implementation)
	model := TemplateModel{
		TemplateID: types.StringValue("template-1"),
		Configs:    testConfigsObject(t, types.BoolValue(true), types.StringNull()),
	}
	prior := testModuleStateFor(t, ctx, resourceSchema, &model)
	response := resource.DeleteResponse{State: testCopyModuleState(prior)}

	implementation.Delete(ctx, resource.DeleteRequest{State: prior}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Delete() accepted a verification response that changed unowned configuration")
	}
	if !response.State.Raw.Equal(prior.Raw) {
		t.Fatal("Delete() failure did not retain Terraform state")
	}
	if !reflect.DeepEqual(service.calls, []string{"get:template-1", "put:template-1", "get:template-1"}) {
		t.Fatalf("Delete() calls = %#v", service.calls)
	}
}

type templateTestCodec struct{}

type coupledTemplateTestCodec struct {
	templateTestCodec
}

func (coupledTemplateTestCodec) Schema(ctx context.Context) schema.Schema {
	resourceSchema := (templateTestCodec{}).Schema(ctx)
	configs := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	configs.Blocks = map[string]schema.Block{
		"cache": schema.SingleNestedBlock{Attributes: map[string]schema.Attribute{
			"status": schema.BoolAttribute{Optional: true, Computed: true},
		}},
		"compress": schema.SingleNestedBlock{Attributes: map[string]schema.Attribute{
			"status": schema.BoolAttribute{Optional: true, Computed: true},
		}},
	}
	resourceSchema.Blocks["configs"] = configs
	return resourceSchema
}

func (templateTestCodec) Schema(context.Context) schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"ep_id":    schema.StringAttribute{Required: true},
			"template": schema.BoolAttribute{Required: true},
		},
		Blocks: map[string]schema.Block{
			"configs": schema.SingleNestedBlock{Attributes: map[string]schema.Attribute{
				"label":  schema.StringAttribute{Optional: true, Computed: true},
				"status": schema.BoolAttribute{Required: true},
			}},
		},
	}
}

func (templateTestCodec) ValidateTemplateConfig(context.Context, tfsdk.Config) diag.Diagnostics {
	return nil
}

func (templateTestCodec) BuildTemplatePatch(ctx context.Context, _ tfsdk.Config, plan tfsdk.Plan, _ tfsdk.State) (Patch, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var model TemplateModel
	diagnostics.Append(plan.Get(ctx, &model)...)
	var configs testConfigsModel
	if !diagnostics.HasError() {
		diagnostics.Append(model.Configs.As(ctx, &configs, basetypes.ObjectAsOptions{})...)
	}
	return PatchFunc(func(_ context.Context, result *client.WAFModuleResult) diag.Diagnostics {
		var applyDiagnostics diag.Diagnostics
		if err := result.SetConfig("status", configs.Status.ValueBool()); err != nil {
			applyDiagnostics.AddError("Unable to set status", err.Error())
		}
		return applyDiagnostics
	}), diagnostics
}

func (templateTestCodec) ValidateResult(_ context.Context, result client.WAFModuleResult, _ OwnershipContext) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	var status bool
	if err := json.Unmarshal(result.Configs["status"], &status); err != nil {
		diagnostics.AddError("Malformed test template module result", "status was not boolean")
	}
	return diagnostics
}

func (templateTestCodec) FlattenTemplate(_ context.Context, templateID string, result client.WAFModuleResult, _ OwnershipContext) (any, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var status bool
	if err := json.Unmarshal(result.Configs["status"], &status); err != nil {
		diagnostics.AddError("Malformed test template module result", "status was not boolean")
		return nil, diagnostics
	}
	configs, objectDiagnostics := types.ObjectValue(testConfigAttributeTypes, map[string]attr.Value{
		"label":  types.StringNull(),
		"status": types.BoolValue(status),
	})
	diagnostics.Append(objectDiagnostics...)
	return &TemplateModel{TemplateID: types.StringValue(templateID), Configs: configs}, diagnostics
}

type fakeTemplateModuleService struct {
	current      client.WAFTemplateModuleDocument
	verification *client.WAFTemplateModuleDocument
	calls        []string
	puts         []client.WAFModuleResult
}

func (s *fakeTemplateModuleService) GetWAFTemplateModule(_ context.Context, _ client.WAFTemplateModuleEndpoint, templateID string) (client.WAFTemplateModuleDocument, error) {
	s.calls = append(s.calls, "get:"+templateID)
	return s.current, nil
}

func (s *fakeTemplateModuleService) PutWAFTemplateModule(_ context.Context, _ client.WAFTemplateModuleEndpoint, templateID string, result client.WAFModuleResult) error {
	s.calls = append(s.calls, "put:"+templateID)
	result.Template = false
	s.puts = append(s.puts, result.Clone())
	if s.verification != nil {
		s.current = *s.verification
	} else {
		s.current.Result = result.Clone()
	}
	return nil
}

func (s *fakeTemplateModuleService) TemplateExists(context.Context, string) (bool, error) {
	return true, nil
}

func templateTestDocument(t *testing.T, payload string) client.WAFTemplateModuleDocument {
	t.Helper()
	var document client.WAFTemplateModuleDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal(document) error = %v", err)
	}
	return document
}

func templateModuleConfig(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Config {
	t.Helper()
	state := testModuleStateFor(t, ctx, resourceSchema, model)
	return tfsdk.Config{Schema: resourceSchema, Raw: state.Raw.Copy()}
}

func templateModulePlan(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Plan {
	t.Helper()
	state := testModuleStateFor(t, ctx, resourceSchema, model)
	return tfsdk.Plan{Schema: resourceSchema, Raw: state.Raw.Copy()}
}
