package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestCookieSecurityScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/cookie_security", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_cookie_security", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/cookie_security", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_cookie_security", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/cookie_security", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_cookie_security", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/cookie_security", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_cookie_security", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(CookieSecurityScope, want) {
		t.Fatalf("CookieSecurityScope = %#v, want %#v", CookieSecurityScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range CookieSecurityScope {
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

func TestCookieSecurityResourceContract(t *testing.T) {
	t.Parallel()

	if CookieSecurityResource.TerraformName != "fortiappseccloud_waf_cookie_security" {
		t.Fatalf("TerraformName = %q", CookieSecurityResource.TerraformName)
	}
	if CookieSecurityResource.GoName != "CookieSecurity" || CookieSecurityResource.TypeNameSuffix != "waf_cookie_security" {
		t.Fatalf("resource identity = %#v", CookieSecurityResource)
	}
	if !reflect.DeepEqual(CookieSecurityResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", CookieSecurityResource.ExpectedMethods)
	}
	if CookieSecurityResource.Refs.CollectionItem != "#/components/schemas/CookieSecurityEexception" {
		t.Fatalf("Refs = %#v", CookieSecurityResource.Refs)
	}
	// Nine config scalars: eight required plus the optional samesite_value.
	if len(CookieSecurityResource.Schema.ConfigFields) != 9 {
		t.Fatalf("ConfigFields = %d, want 9", len(CookieSecurityResource.Schema.ConfigFields))
	}
	// One object-item collection, max 64.
	if len(CookieSecurityResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(CookieSecurityResource.Schema.Collections))
	}
	if CookieSecurityResource.Schema.Collections[0].Name != "cookie_except_list" || CookieSecurityResource.Schema.Collections[0].MaxItems != 64 {
		t.Fatalf("cookie_except_list = %#v, want max 64", CookieSecurityResource.Schema.Collections[0])
	}
	// action enum of four values, required, default alert_deny.
	action := CookieSecurityResource.findConfig("action")
	if action == nil || !action.Required || !action.HasDefault || action.Default != "alert_deny" || len(action.Enum) != 4 {
		t.Fatalf("action = %#v, want required 4-value enum default alert_deny", action)
	}
	// mode enum of three values, required, default signed.
	mode := CookieSecurityResource.findConfig("mode")
	if mode == nil || !mode.Required || !mode.HasDefault || mode.Default != "signed" || len(mode.Enum) != 3 {
		t.Fatalf("mode = %#v, want required 3-value enum default signed", mode)
	}
	// samesite_value is the only optional config scalar: enum of three, default Lax.
	samesiteValue := CookieSecurityResource.findConfig("samesite_value")
	if samesiteValue == nil {
		t.Fatal("missing samesite_value config field")
	}
	if samesiteValue.Required {
		t.Fatalf("samesite_value required = true, want false (optional)")
	}
	if !samesiteValue.HasDefault || samesiteValue.Default != "Lax" || len(samesiteValue.Enum) != 3 {
		t.Fatalf("samesite_value = %#v, want optional 3-value enum default Lax", samesiteValue)
	}
	// max_age bounded integer default 0 range 0..65535.
	maxAge := CookieSecurityResource.findConfig("max_age")
	if maxAge == nil || !maxAge.Required || !maxAge.HasDefault || maxAge.Default != 0 ||
		maxAge.Minimum == nil || *maxAge.Minimum != 0 || maxAge.Maximum == nil || *maxAge.Maximum != 65535 {
		t.Fatalf("max_age = %#v, want required default 0 range 0..65535", maxAge)
	}
	// Item fields: idx default 1, name required max 127, wildcard optional default false.
	if len(CookieSecurityResource.Schema.ItemFields) != 3 {
		t.Fatalf("ItemFields = %d, want 3", len(CookieSecurityResource.Schema.ItemFields))
	}
	idx := CookieSecurityResource.findItem("idx")
	if idx == nil || idx.HasDefault != true || idx.Default != 1 {
		t.Fatalf("idx = %#v, want default 1", idx)
	}
	name := CookieSecurityResource.findItem("name")
	if name == nil || !name.Required || name.MaxLength != 127 {
		t.Fatalf("name = %#v, want required max 127", name)
	}
	wildcard := CookieSecurityResource.findItem("wildcard")
	if wildcard == nil || wildcard.Required || !wildcard.HasDefault || wildcard.Default != false {
		t.Fatalf("wildcard = %#v, want optional default false", wildcard)
	}
}

func (r ReviewedCandidate) findItem(name string) *CandidateFieldConstraint {
	for i := range r.Schema.ItemFields {
		if r.Schema.ItemFields[i].Name == name {
			return &r.Schema.ItemFields[i]
		}
	}
	return nil
}
