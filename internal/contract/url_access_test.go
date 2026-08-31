package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestURLAccessScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/url_access", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_url_access", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/url_access", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_url_access", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/url_access", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_url_access", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/url_access", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_url_access", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(URLAccessScope, want) {
		t.Fatalf("URLAccessScope = %#v, want %#v", URLAccessScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range URLAccessScope {
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
