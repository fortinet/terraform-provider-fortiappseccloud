package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestHttpHeaderSecurityScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/http_header_security", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_http_header_security", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/http_header_security", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_http_header_security", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/http_header_security", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_http_header_security", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/http_header_security", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_http_header_security", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(HttpHeaderSecurityScope, want) {
		t.Fatalf("HttpHeaderSecurityScope = %#v, want %#v", HttpHeaderSecurityScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range HttpHeaderSecurityScope {
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

func TestHttpHeaderSecurityResourceContract(t *testing.T) {
	t.Parallel()

	if HttpHeaderSecurityResource.TerraformName != "fortiappseccloud_waf_http_header_security" {
		t.Fatalf("TerraformName = %q", HttpHeaderSecurityResource.TerraformName)
	}
	if HttpHeaderSecurityResource.GoName != "HttpHeaderSecurity" || HttpHeaderSecurityResource.TypeNameSuffix != "waf_http_header_security" {
		t.Fatalf("resource identity = %#v", HttpHeaderSecurityResource)
	}
	if HttpHeaderSecurityResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", HttpHeaderSecurityResource.ImplementationState)
	}
	if !reflect.DeepEqual(HttpHeaderSecurityResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", HttpHeaderSecurityResource.ExpectedMethods)
	}
	if HttpHeaderSecurityResource.Refs.GetResponse != "#/components/schemas/GetHttpHeaderSecurity" ||
		HttpHeaderSecurityResource.Refs.PutRequest != "#/components/schemas/PutHttpHeaderSecurity" ||
		HttpHeaderSecurityResource.Refs.Configs != "#/components/schemas/HttpHeaderSecurity" ||
		HttpHeaderSecurityResource.Refs.CollectionItem != "" {
		t.Fatalf("Refs = %#v", HttpHeaderSecurityResource.Refs)
	}
	if len(HttpHeaderSecurityResource.Schema.ConfigFields) != 8 {
		t.Fatalf("ConfigFields = %d, want 8", len(HttpHeaderSecurityResource.Schema.ConfigFields))
	}
	if len(HttpHeaderSecurityResource.Schema.Collections) != 0 {
		t.Fatalf("Collections = %d, want 0", len(HttpHeaderSecurityResource.Schema.Collections))
	}

	fields := make(map[string]CandidateFieldConstraint, len(HttpHeaderSecurityResource.Schema.ConfigFields))
	for _, field := range HttpHeaderSecurityResource.Schema.ConfigFields {
		fields[field.Name] = field
	}

	// header_value: optional string, no default, maxLength 1023, not nullable.
	headerValue, ok := fields["header_value"]
	if !ok {
		t.Fatal("missing header_value config field")
	}
	if headerValue.Kind != "string" || headerValue.Required || headerValue.HasDefault || headerValue.MaxLength != 1023 || headerValue.AllowNull {
		t.Fatalf("header_value = %#v, want optional non-default string maxLength 1023 not nullable", headerValue)
	}

	// referrer_policy_header_value: optional string, default, enum, maxLength 64, nullable.
	referrer, ok := fields["referrer_policy_header_value"]
	if !ok {
		t.Fatal("missing referrer_policy_header_value config field")
	}
	if referrer.Kind != "string" || referrer.Required || !referrer.HasDefault || referrer.MaxLength != 64 || !referrer.AllowNull {
		t.Fatalf("referrer_policy_header_value = %#v, want optional default enum string maxLength 64 nullable", referrer)
	}
	if len(referrer.Enum) != 8 {
		t.Fatalf("referrer_policy_header_value enum = %d, want 8", len(referrer.Enum))
	}
}
