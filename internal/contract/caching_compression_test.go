package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestCachingCompressionScopeClassification(t *testing.T) {
	t.Parallel()
	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/caching_compression", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_caching_compression", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/caching_compression", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_caching_compression", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/caching_compression", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_caching_compression", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/caching_compression", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_caching_compression", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(CachingCompressionScope, want) {
		t.Fatalf("CachingCompressionScope = %#v, want %#v", CachingCompressionScope, want)
	}
	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range CachingCompressionScope {
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

func TestCachingCompressionResourceContract(t *testing.T) {
	t.Parallel()
	if CachingCompressionResource.TerraformName != "fortiappseccloud_waf_caching_compression" {
		t.Fatalf("TerraformName = %q", CachingCompressionResource.TerraformName)
	}
	if CachingCompressionResource.GoName != "CachingCompression" || CachingCompressionResource.TypeNameSuffix != "waf_caching_compression" {
		t.Fatalf("resource identity = %#v", CachingCompressionResource)
	}
	if CachingCompressionResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", CachingCompressionResource.ImplementationState)
	}
	if len(CachingCompressionResource.Schema.ConfigFields) != 3 {
		t.Fatalf("ConfigFields = %d, want 3", len(CachingCompressionResource.Schema.ConfigFields))
	}
	if len(CachingCompressionResource.Schema.Collections) != 3 {
		t.Fatalf("Collections = %d, want 3", len(CachingCompressionResource.Schema.Collections))
	}
	if len(CachingCompressionResource.Schema.ScalarStringArrays) != 2 {
		t.Fatalf("ScalarStringArrays = %d, want 2", len(CachingCompressionResource.Schema.ScalarStringArrays))
	}
	// Verify the cache nested object has ObjectFields.
	for _, field := range CachingCompressionResource.Schema.ConfigFields {
		if field.Name == "cache" && field.Kind == "object" {
			if len(field.ObjectFields) != 5 {
				t.Fatalf("cache ObjectFields = %d, want 5", len(field.ObjectFields))
			}
		}
		if field.Name == "compress" && field.Kind == "object" {
			if len(field.ObjectFields) != 1 {
				t.Fatalf("compress ObjectFields = %d, want 1", len(field.ObjectFields))
			}
		}
	}
}
