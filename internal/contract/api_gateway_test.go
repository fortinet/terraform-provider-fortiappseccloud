package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestAPIGatewayScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/api_gateway", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_api_gateway", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/api_gateway", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_api_gateway", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/api_gateway", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_api_gateway", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/api_gateway", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_api_gateway", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(APIGatewayScope, want) {
		t.Fatalf("APIGatewayScope = %#v, want %#v", APIGatewayScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range APIGatewayScope {
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

func TestAPIGatewayResourceContract(t *testing.T) {
	t.Parallel()

	if APIGatewayResource.TerraformName != "fortiappseccloud_waf_api_gateway" {
		t.Fatalf("TerraformName = %q", APIGatewayResource.TerraformName)
	}
	if APIGatewayResource.GoName != "APIGateway" || APIGatewayResource.TypeNameSuffix != "waf_api_gateway" {
		t.Fatalf("resource identity = %#v", APIGatewayResource)
	}
	if APIGatewayResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", APIGatewayResource.ImplementationState)
	}
	if len(APIGatewayResource.Schema.ConfigFields) != 2 {
		t.Fatalf("ConfigFields = %d, want 2", len(APIGatewayResource.Schema.ConfigFields))
	}
	if len(APIGatewayResource.Schema.Collections) != 2 {
		t.Fatalf("Collections = %d, want 2", len(APIGatewayResource.Schema.Collections))
	}
	if len(APIGatewayResource.Schema.CollectionItemFields) != 2 {
		t.Fatalf("CollectionItemFields = %d, want 2", len(APIGatewayResource.Schema.CollectionItemFields))
	}
	if len(APIGatewayResource.Schema.ComputedOnlyItemFields) != 3 {
		t.Fatalf("ComputedOnlyItemFields = %d, want 3", len(APIGatewayResource.Schema.ComputedOnlyItemFields))
	}

	// The three computed-only fields: uuid, api_key, create_time.
	computedPaths := make(map[string]bool)
	for _, c := range APIGatewayResource.Schema.ComputedOnlyItemFields {
		computedPaths[c.Path] = true
		if !c.ReadOnly || !c.PreserveFromGet {
			t.Fatalf("computed-only field %q missing ReadOnly or PreserveFromGet", c.Path)
		}
	}
	for _, p := range []string{"configs.user_list.item.uuid", "configs.user_list.item.api_key", "configs.user_list.item.create_time"} {
		if !computedPaths[p] {
			t.Fatalf("missing computed-only field %q", p)
		}
	}
	// api_key is Sensitive.
	for _, c := range APIGatewayResource.Schema.ComputedOnlyItemFields {
		if c.Path == "configs.user_list.item.api_key" && !c.Sensitive {
			t.Fatal("api_key computed-only field must be Sensitive")
		}
	}

	// rule_list has url_list sub-item array AND user_list item string-array.
	ruleFields := APIGatewayResource.Schema.CollectionItemFields["rule_list"]
	hasURLList := false
	hasUserListArray := false
	for _, f := range ruleFields {
		if f.Name == "url_list" && f.Kind == "array" && f.SubItemArray != nil {
			hasURLList = true
		}
		if f.Name == "user_list" && f.Kind == "string_array" {
			hasUserListArray = true
		}
	}
	if !hasURLList {
		t.Fatal("rule_list missing url_list sub-item array")
	}
	if !hasUserListArray {
		t.Fatal("rule_list missing user_list item string-array")
	}

	// user_list has TWO sibling sub-item arrays: ip_list + referer_list.
	userFields := APIGatewayResource.Schema.CollectionItemFields["user_list"]
	subItemCount := 0
	for _, f := range userFields {
		if f.Kind == "array" && f.SubItemArray != nil {
			subItemCount++
		}
	}
	if subItemCount != 2 {
		t.Fatalf("user_list sub-item array count = %d, want 2 (ip_list + referer_list)", subItemCount)
	}
}
