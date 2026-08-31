package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestJsonProtectionScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/json_protection", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_json_protection", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/json_protection", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_json_protection", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/json_protection", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_json_protection", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/json_protection", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_json_protection", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(JsonProtectionScope, want) {
		t.Fatalf("JsonProtectionScope = %#v, want %#v", JsonProtectionScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range JsonProtectionScope {
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

func TestJsonProtectionResourceContract(t *testing.T) {
	t.Parallel()

	if JsonProtectionResource.TerraformName != "fortiappseccloud_waf_json_protection" {
		t.Fatalf("TerraformName = %q", JsonProtectionResource.TerraformName)
	}
	if JsonProtectionResource.GoName != "JSONProtection" || JsonProtectionResource.TypeNameSuffix != "waf_json_protection" {
		t.Fatalf("resource identity = %#v", JsonProtectionResource)
	}
	if JsonProtectionResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", JsonProtectionResource.ImplementationState)
	}
	if !reflect.DeepEqual(JsonProtectionResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", JsonProtectionResource.ExpectedMethods)
	}
	if JsonProtectionResource.Refs.GetResponse != "#/components/schemas/GetJsonProtection" ||
		JsonProtectionResource.Refs.PutRequest != "#/components/schemas/PutJsonProtection" ||
		JsonProtectionResource.Refs.Configs != "#/components/schemas/JsonProtection" ||
		JsonProtectionResource.Refs.CollectionItem != "#/components/schemas/JsonFile" {
		t.Fatalf("Refs = %#v", JsonProtectionResource.Refs)
	}
	if len(JsonProtectionResource.Schema.ConfigFields) != 4 {
		t.Fatalf("ConfigFields = %d, want 4", len(JsonProtectionResource.Schema.ConfigFields))
	}
	if len(JsonProtectionResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(JsonProtectionResource.Schema.Collections))
	}
	if JsonProtectionResource.Schema.Collections[0].Name != "file_list" || JsonProtectionResource.Schema.Collections[0].MaxItems != 10 {
		t.Fatalf("file_list = %#v", JsonProtectionResource.Schema.Collections[0])
	}
	if len(JsonProtectionResource.Schema.ItemFields) != 6 {
		t.Fatalf("ItemFields = %d, want 6", len(JsonProtectionResource.Schema.ItemFields))
	}

	fields := make(map[string]CandidateFieldConstraint, len(JsonProtectionResource.Schema.ItemFields))
	for _, field := range JsonProtectionResource.Schema.ItemFields {
		fields[field.Name] = field
	}

	// filename, limit_check, name, schema_valid, url are required; md5 is optional.
	for _, required := range []string{"filename", "limit_check", "name", "schema_valid", "url"} {
		field, ok := fields[required]
		if !ok {
			t.Fatalf("missing required item field %q", required)
		}
		if !field.Required {
			t.Errorf("item field %q = %#v, want required", required, field)
		}
	}
	md5, ok := fields["md5"]
	if !ok {
		t.Fatal("missing md5 item field")
	}
	if md5.Required {
		t.Fatalf("md5 = %#v, want optional", md5)
	}
	// name and URL constraints are pinned by OpenAPI 26.3.a.
	name, ok := fields["name"]
	if !ok {
		t.Fatal("missing name item field")
	}
	if name.MaxLength != 40 {
		t.Fatalf("name MaxLength = %d, want 40", name.MaxLength)
	}
	if fields["url"].MaxLength != 255 {
		t.Fatalf("url MaxLength = %d, want 255", fields["url"].MaxLength)
	}
}
