package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestInformationLeakageScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/information_leakage", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_information_leakage", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/information_leakage", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_information_leakage", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/information_leakage", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_information_leakage", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/information_leakage", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_information_leakage", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(InformationLeakageScope, want) {
		t.Fatalf("InformationLeakageScope = %#v, want %#v", InformationLeakageScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range InformationLeakageScope {
		operation, ok := document.Find(classification.Method, classification.Path)
		if !ok {
			t.Errorf("classification missing from OpenAPI: %s %s", classification.Method, classification.Path)
			continue
		}
		if !operation.Public {
			t.Errorf("classification is non-public: %s %s", classification.Method, classification.Path)
		}
	}
}

func TestInformationLeakageResourceContract(t *testing.T) {
	t.Parallel()

	if InformationLeakageResource.TerraformName != "fortiappseccloud_waf_information_leakage" {
		t.Fatalf("TerraformName = %q", InformationLeakageResource.TerraformName)
	}
	if InformationLeakageResource.GoName != "InformationLeakage" || InformationLeakageResource.TypeNameSuffix != "waf_information_leakage" {
		t.Fatalf("resource identity = %#v", InformationLeakageResource)
	}
	if !reflect.DeepEqual(InformationLeakageResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", InformationLeakageResource.ExpectedMethods)
	}
	if InformationLeakageResource.Refs.CollectionItem != "#/components/schemas/SignatureBasedExceptionRule" {
		t.Fatalf("Refs = %#v", InformationLeakageResource.Refs)
	}
	// Config scalars.
	if len(InformationLeakageResource.Schema.ConfigFields) != 6 {
		t.Fatalf("ConfigFields = %d, want 6", len(InformationLeakageResource.Schema.ConfigFields))
	}
	// action enum.
	action := InformationLeakageResource.Schema.ConfigFields[0]
	if action.Name != "action" || !action.Required || len(action.Enum) != 3 {
		t.Fatalf("action = %#v, want required enum of 3", action)
	}
	// One object-item collection + one scalar-string-array.
	if len(InformationLeakageResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(InformationLeakageResource.Schema.Collections))
	}
	if InformationLeakageResource.Schema.Collections[0].Name != "sig_except_rules" || InformationLeakageResource.Schema.Collections[0].MaxItems != 100 {
		t.Fatalf("sig_except_rules = %#v", InformationLeakageResource.Schema.Collections[0])
	}
	// CollectionItemFields (per-collection, reusing SignatureBasedExceptionRule).
	sigFields, ok := InformationLeakageResource.Schema.CollectionItemFields["sig_except_rules"]
	if !ok {
		t.Fatal("missing sig_except_rules CollectionItemFields")
	}
	if len(sigFields) != 9 {
		t.Fatalf("sig_except_rules item fields = %d, want 9", len(sigFields))
	}
	// sig_id pins nine-character minimum.
	for _, f := range sigFields {
		if f.Name == "sig_id" {
			if f.MinLength != 9 || f.MaxLength != 9 {
				t.Fatalf("sig_id = %#v, want min 9 max 9", f)
			}
		}
	}
	// Scalar-string-array: http_headers, free-form (no enum), max 26, optional.
	if len(InformationLeakageResource.Schema.ScalarStringArrays) != 1 {
		t.Fatalf("ScalarStringArrays = %d, want 1", len(InformationLeakageResource.Schema.ScalarStringArrays))
	}
	hh := InformationLeakageResource.Schema.ScalarStringArrays[0]
	if hh.Name != "http_headers" || hh.ItemAttribute != "header" || len(hh.Enum) != 0 || hh.MaxItems != 26 || hh.Required {
		t.Fatalf("http_headers = %#v, want free-form max 26 optional", hh)
	}
}
