package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestKnownAttacksScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/known_attacks", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_known_attacks", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/known_attacks", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_known_attacks", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/known_attacks", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_known_attacks", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/known_attacks", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_known_attacks", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(KnownAttacksScope, want) {
		t.Fatalf("KnownAttacksScope = %#v, want %#v", KnownAttacksScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range KnownAttacksScope {
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

func TestKnownAttacksResourceContract(t *testing.T) {
	t.Parallel()

	if KnownAttacksResource.TerraformName != "fortiappseccloud_waf_known_attacks" {
		t.Fatalf("TerraformName = %q", KnownAttacksResource.TerraformName)
	}
	if KnownAttacksResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", KnownAttacksResource.ImplementationState)
	}
	if KnownAttacksResource.Refs.GetResponse != "#/components/schemas/GetKnownAttacks" ||
		KnownAttacksResource.Refs.PutRequest != "#/components/schemas/PutKnownAttacks" ||
		KnownAttacksResource.Refs.Configs != "#/components/schemas/KnownAttacks" {
		t.Fatalf("Refs = %#v", KnownAttacksResource.Refs)
	}
	if len(KnownAttacksResource.Schema.ConfigFields) != 22 {
		t.Fatalf("ConfigFields = %d, want 22", len(KnownAttacksResource.Schema.ConfigFields))
	}
	if len(KnownAttacksResource.Schema.Collections) != 2 {
		t.Fatalf("Collections = %d, want 2", len(KnownAttacksResource.Schema.Collections))
	}
	for _, collection := range KnownAttacksResource.Schema.Collections {
		if collection.MaxItems != 100 {
			t.Errorf("collection %q MaxItems = %d, want 100", collection.Name, collection.MaxItems)
		}
	}
	if len(KnownAttacksResource.Schema.CollectionItemFields) != 2 {
		t.Fatalf("CollectionItemFields = %d, want 2", len(KnownAttacksResource.Schema.CollectionItemFields))
	}

	// sensitivity_level is an integer enum.
	var sensitivity *CandidateFieldConstraint
	for _, field := range KnownAttacksResource.Schema.ConfigFields {
		if field.Name == "sensitivity_level" {
			f := field
			sensitivity = &f
		}
	}
	if sensitivity == nil {
		t.Fatal("sensitivity_level config field missing")
	}
	if sensitivity.Kind != "integer" || !sensitivity.HasDefault || !reflect.DeepEqual(sensitivity.IntEnum, []int64{1, 2, 3, 4}) {
		t.Fatalf("sensitivity_level = %#v", sensitivity)
	}

	// sig_except_rules item has nested objects; stx_except_rules item has a different shape.
	sig := KnownAttacksResource.Schema.CollectionItemFields["sig_except_rules"]
	stx := KnownAttacksResource.Schema.CollectionItemFields["stx_except_rules"]
	if len(sig) == 0 || len(stx) == 0 {
		t.Fatalf("sig/stx item fields empty: sig=%d stx=%d", len(sig), len(stx))
	}
	// sig_except_rules requires cookie/host/http_header/json/param/sig_id/sig_name/url.
	sigNames := map[string]bool{}
	for _, f := range sig {
		sigNames[f.Name] = true
		if f.Kind == "object" && len(f.ObjectFields) == 0 {
			t.Errorf("sig item object field %q has no ObjectFields", f.Name)
		}
	}
	for _, required := range []string{"cookie", "host", "http_header", "json", "param", "sig_id", "sig_name", "url"} {
		if !sigNames[required] {
			t.Errorf("sig_except_rules item missing %q", required)
		}
	}
	// stx_except_rules requires attack_cat/attack_name/cookie/param/url (no host/http_header/json).
	stxNames := map[string]bool{}
	for _, f := range stx {
		stxNames[f.Name] = true
	}
	for _, required := range []string{"attack_cat", "attack_name", "cookie", "param", "url"} {
		if !stxNames[required] {
			t.Errorf("stx_except_rules item missing %q", required)
		}
	}
	if stxNames["host"] || stxNames["http_header"] || stxNames["json"] {
		t.Error("stx_except_rules item unexpectedly contains host/http_header/json")
	}
}
