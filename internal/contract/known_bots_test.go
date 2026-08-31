package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestKnownBotsScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/known_bots", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_known_bots", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/known_bots", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_known_bots", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/known_bots", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_known_bots", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/known_bots", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_known_bots", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(KnownBotsScope, want) {
		t.Fatalf("KnownBotsScope = %#v, want %#v", KnownBotsScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range KnownBotsScope {
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

func TestKnownBotsResourceContract(t *testing.T) {
	t.Parallel()

	if KnownBotsResource.TerraformName != "fortiappseccloud_waf_known_bots" {
		t.Fatalf("TerraformName = %q", KnownBotsResource.TerraformName)
	}
	if KnownBotsResource.GoName != "KnownBots" || KnownBotsResource.TypeNameSuffix != "waf_known_bots" {
		t.Fatalf("resource identity = %#v", KnownBotsResource)
	}
	if !reflect.DeepEqual(KnownBotsResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", KnownBotsResource.ExpectedMethods)
	}
	// Four config scalars.
	if len(KnownBotsResource.Schema.ConfigFields) != 4 {
		t.Fatalf("ConfigFields = %d, want 4", len(KnownBotsResource.Schema.ConfigFields))
	}
	// Three collections.
	if len(KnownBotsResource.Schema.Collections) != 3 {
		t.Fatalf("Collections = %d, want 3", len(KnownBotsResource.Schema.Collections))
	}
	// bad_bots_list and good_bots_list are unbounded (MaxItems 0) and unindexed.
	badBots := KnownBotsResource.findCollection("bad_bots_list")
	if badBots == nil || badBots.MaxItems != 0 || !badBots.Unindexed {
		t.Fatalf("bad_bots_list = %#v, want MaxItems 0 Unindexed true", badBots)
	}
	goodBots := KnownBotsResource.findCollection("good_bots_list")
	if goodBots == nil || goodBots.MaxItems != 0 || !goodBots.Unindexed {
		t.Fatalf("good_bots_list = %#v, want MaxItems 0 Unindexed true", goodBots)
	}
	// exception_list is bounded (128) and indexed.
	exceptionList := KnownBotsResource.findCollection("exception_list")
	if exceptionList == nil || exceptionList.MaxItems != 128 || exceptionList.Unindexed {
		t.Fatalf("exception_list = %#v, want MaxItems 128 Unindexed false", exceptionList)
	}
	// Per-collection item fields.
	badBotsItemFields := KnownBotsResource.Schema.CollectionItemFields["bad_bots_list"]
	if badBotsItemFields == nil {
		t.Fatal("missing bad_bots_list CollectionItemFields")
	}
	allowList := findStringArrayItemField(badBotsItemFields, "allow_list")
	if allowList == nil || allowList.StringArray == nil || allowList.StringArray.MaxItems != 0 || allowList.StringArray.ItemAttribute != "value" {
		t.Fatalf("allow_list = %#v, want item-level scalar-string-array unbounded", allowList)
	}
	goodBotsItemFields := KnownBotsResource.Schema.CollectionItemFields["good_bots_list"]
	denyList := findStringArrayItemField(goodBotsItemFields, "deny_list")
	if denyList == nil || denyList.StringArray == nil || denyList.StringArray.MaxItems != 0 || denyList.StringArray.ItemAttribute != "value" {
		t.Fatalf("deny_list = %#v, want item-level scalar-string-array unbounded", denyList)
	}
	// exception_list item has idx default 1.
	exceptionItemFields := KnownBotsResource.Schema.CollectionItemFields["exception_list"]
	idx := findItemFieldByName(exceptionItemFields, "idx")
	if idx == nil || !idx.HasDefault || idx.Default != 1 {
		t.Fatalf("exception_list idx = %#v, want default 1", idx)
	}
}

func (r ReviewedCandidate) findCollection(name string) *CandidateCollectionConstraint {
	for i := range r.Schema.Collections {
		if r.Schema.Collections[i].Name == name {
			return &r.Schema.Collections[i]
		}
	}
	return nil
}

func findStringArrayItemField(fields []CandidateFieldConstraint, name string) *CandidateFieldConstraint {
	for i := range fields {
		if fields[i].Name == name {
			return &fields[i]
		}
	}
	return nil
}

func findItemFieldByName(fields []CandidateFieldConstraint, name string) *CandidateFieldConstraint {
	return findStringArrayItemField(fields, name)
}
