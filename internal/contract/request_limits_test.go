package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestRequestLimitsScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/request_limits", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_request_limits", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/request_limits", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_request_limits", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/request_limits", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_request_limits", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/request_limits", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_request_limits", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(RequestLimitsScope, want) {
		t.Fatalf("RequestLimitsScope = %#v, want %#v", RequestLimitsScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range RequestLimitsScope {
		operation, ok := document.Find(classification.Method, classification.Path)
		if !ok {
			t.Errorf("classification missing from OpenAPI: %s %s", classification.Method, classification.Path)
			continue
		}
		if !operation.Public {
			t.Errorf("classification is non-public: %s %s", classification.Method, classification.Path)
		}
		if classification.Disposition != DispositionDeferred && classification.ClientMethod == "" {
			t.Errorf("managed classification lacks client method: %s %s", classification.Method, classification.Path)
		}
	}
}

func TestRequestLimitsResourceContract(t *testing.T) {
	t.Parallel()

	if RequestLimitsResource.TerraformName != "fortiappseccloud_waf_request_limits" {
		t.Fatalf("TerraformName = %q", RequestLimitsResource.TerraformName)
	}
	if RequestLimitsResource.GoName != "RequestLimits" || RequestLimitsResource.TypeNameSuffix != "waf_request_limits" {
		t.Fatalf("resource identity = %#v", RequestLimitsResource)
	}
	if RequestLimitsResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", RequestLimitsResource.ImplementationState)
	}
	if !reflect.DeepEqual(RequestLimitsResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", RequestLimitsResource.ExpectedMethods)
	}
	if RequestLimitsResource.Refs.GetResponse != "#/components/schemas/GetRequestLimits" ||
		RequestLimitsResource.Refs.PutRequest != "#/components/schemas/PutRequestLimits" ||
		RequestLimitsResource.Refs.Configs != "#/components/schemas/RequestLimits" ||
		RequestLimitsResource.Refs.CollectionItem != "" {
		t.Fatalf("Refs = %#v", RequestLimitsResource.Refs)
	}
	if len(RequestLimitsResource.Schema.ConfigFields) != 64 {
		t.Fatalf("ConfigFields = %d, want 64", len(RequestLimitsResource.Schema.ConfigFields))
	}
	if len(RequestLimitsResource.Schema.Collections) != 0 {
		t.Fatalf("Collections = %d, want 0", len(RequestLimitsResource.Schema.Collections))
	}
	if len(RequestLimitsResource.Schema.ItemFields) != 0 {
		t.Fatalf("ItemFields = %d, want 0", len(RequestLimitsResource.Schema.ItemFields))
	}
	if len(RequestLimitsResource.Schema.ScalarStringArrays) != 1 {
		t.Fatalf("ScalarStringArrays = %d, want 1", len(RequestLimitsResource.Schema.ScalarStringArrays))
	}
	allowMethods := RequestLimitsResource.Schema.ScalarStringArrays[0]
	if allowMethods.Name != "allow_methods" || allowMethods.ItemAttribute != "method" || allowMethods.MaxItems != 0 {
		t.Fatalf("allow_methods = %#v", allowMethods)
	}
	if !allowMethods.Required {
		t.Fatalf("allow_methods must be pinned required so a missing owned remote array fails closed, got %#v", allowMethods)
	}
	wantMethods := []string{"connect", "delete", "get", "head", "options", "others", "patch", "post", "put", "rpc", "trace", "webdav"}
	if !reflect.DeepEqual(allowMethods.Enum, wantMethods) {
		t.Fatalf("allow_methods enum = %#v, want %#v", allowMethods.Enum, wantMethods)
	}

	// Integer range bounds and defaults are pinned for every bounded integer.
	for _, field := range RequestLimitsResource.Schema.ConfigFields {
		if field.Kind == "integer" {
			if field.Minimum == nil || field.Maximum == nil {
				t.Errorf("integer %q missing range bound", field.Name)
			}
			if !field.HasDefault {
				t.Errorf("integer %q missing default", field.Name)
			}
		}
	}
	derived := findConfigField(RequestLimitsResource.Schema.ConfigFields, "max_setting_initial_window_size")
	if derived == nil || !derived.ReadOnly || derived.Required {
		t.Fatalf("max_setting_initial_window_size = %#v, want optional readOnly", derived)
	}
}

func TestRequestLimitsResourceClonesScalarStringArrays(t *testing.T) {
	t.Parallel()

	resources := ImplementedGeneratedResources()
	var requestLimits ReviewedCandidate
	for _, resource := range resources {
		if resource.TerraformName == RequestLimitsResource.TerraformName {
			requestLimits = resource
		}
	}
	if requestLimits.TerraformName == "" {
		t.Fatal("RequestLimitsResource not present")
	}
	array := requestLimits.Schema.ScalarStringArrays[0]
	array.Enum[0] = "mutated"
	array.MaxItems = 999
	if RequestLimitsResource.Schema.ScalarStringArrays[0].Enum[0] == "mutated" ||
		RequestLimitsResource.Schema.ScalarStringArrays[0].MaxItems == 999 {
		t.Fatal("ImplementedGeneratedResources exposed mutable scalar string array storage")
	}
}
