package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestBotDeceptionScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/bot_deception", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_bot_deception", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/bot_deception", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_bot_deception", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/bot_deception", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_bot_deception", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/bot_deception", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_bot_deception", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(BotDeceptionScope, want) {
		t.Fatalf("BotDeceptionScope = %#v, want %#v", BotDeceptionScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range BotDeceptionScope {
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

func TestBotDeceptionResourceContract(t *testing.T) {
	t.Parallel()

	if BotDeceptionResource.TerraformName != "fortiappseccloud_waf_bot_deception" {
		t.Fatalf("TerraformName = %q", BotDeceptionResource.TerraformName)
	}
	if BotDeceptionResource.GoName != "BotDeception" || BotDeceptionResource.TypeNameSuffix != "waf_bot_deception" {
		t.Fatalf("resource identity = %#v", BotDeceptionResource)
	}
	if !reflect.DeepEqual(BotDeceptionResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", BotDeceptionResource.ExpectedMethods)
	}
	// Three config scalars.
	if len(BotDeceptionResource.Schema.ConfigFields) != 3 {
		t.Fatalf("ConfigFields = %d, want 3", len(BotDeceptionResource.Schema.ConfigFields))
	}
	// Two collections, both indexed and bounded.
	if len(BotDeceptionResource.Schema.Collections) != 2 {
		t.Fatalf("Collections = %d, want 2", len(BotDeceptionResource.Schema.Collections))
	}
	urlList := BotDeceptionResource.findCollection("url_list")
	if urlList == nil || urlList.MaxItems != 12 || urlList.Unindexed {
		t.Fatalf("url_list = %#v, want MaxItems 12 Unindexed false", urlList)
	}
	exceptionList := BotDeceptionResource.findCollection("exception_list")
	if exceptionList == nil || exceptionList.MaxItems != 128 || exceptionList.Unindexed {
		t.Fatalf("exception_list = %#v, want MaxItems 128 Unindexed false", exceptionList)
	}
	// Per-collection item schemas.
	urlItemFields := BotDeceptionResource.Schema.CollectionItemFields["url_list"]
	if urlItemFields == nil {
		t.Fatal("missing url_list CollectionItemFields")
	}
	urlField := findItemFieldByName(urlItemFields, "url")
	if urlField == nil || !urlField.Required || urlField.MaxLength != 255 {
		t.Fatalf("url_list url = %#v, want required max 255", urlField)
	}
	urlIdx := findItemFieldByName(urlItemFields, "idx")
	if urlIdx == nil || !urlIdx.HasDefault || urlIdx.Default != 1 {
		t.Fatalf("url_list idx = %#v, want default 1", urlIdx)
	}
	exceptionItemFields := BotDeceptionResource.Schema.CollectionItemFields["exception_list"]
	if exceptionItemFields == nil {
		t.Fatal("missing exception_list CollectionItemFields")
	}
	for _, name := range []string{"concatenate_type", "match_target", "operator"} {
		f := findItemFieldByName(exceptionItemFields, name)
		if f == nil || !f.Required {
			t.Fatalf("exception_list %s = %#v, want required", name, f)
		}
	}
	valueCheck := findItemFieldByName(exceptionItemFields, "value_check")
	if valueCheck == nil || !valueCheck.HasDefault || valueCheck.Default != false {
		t.Fatalf("exception_list value_check = %#v, want default false", valueCheck)
	}
	exceptionIdx := findItemFieldByName(exceptionItemFields, "idx")
	if exceptionIdx == nil || !exceptionIdx.HasDefault || exceptionIdx.Default != 1 {
		t.Fatalf("exception_list idx = %#v, want default 1", exceptionIdx)
	}
}
