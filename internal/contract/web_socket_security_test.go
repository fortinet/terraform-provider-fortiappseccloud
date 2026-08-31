package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestWebSocketSecurityScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/web_socket_security", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_web_socket_security", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/web_socket_security", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_web_socket_security", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/web_socket_security", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_web_socket_security", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/web_socket_security", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_web_socket_security", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(WebSocketSecurityScope, want) {
		t.Fatalf("WebSocketSecurityScope = %#v, want %#v", WebSocketSecurityScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range WebSocketSecurityScope {
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

func TestWebSocketSecurityResourceContract(t *testing.T) {
	t.Parallel()

	if WebSocketSecurityResource.TerraformName != "fortiappseccloud_waf_web_socket_security" {
		t.Fatalf("TerraformName = %q", WebSocketSecurityResource.TerraformName)
	}
	if WebSocketSecurityResource.GoName != "WebSocketSecurity" || WebSocketSecurityResource.TypeNameSuffix != "waf_web_socket_security" {
		t.Fatalf("resource identity = %#v", WebSocketSecurityResource)
	}
	if !reflect.DeepEqual(WebSocketSecurityResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", WebSocketSecurityResource.ExpectedMethods)
	}
	if WebSocketSecurityResource.Refs.CollectionItem != "#/components/schemas/WebSocketRule" {
		t.Fatalf("Refs = %#v", WebSocketSecurityResource.Refs)
	}
	if len(WebSocketSecurityResource.Schema.ConfigFields) != 2 {
		t.Fatalf("ConfigFields = %d, want 2", len(WebSocketSecurityResource.Schema.ConfigFields))
	}
	if WebSocketSecurityResource.Schema.Collections[0].Name != "rule_list" || WebSocketSecurityResource.Schema.Collections[0].MaxItems != 12 {
		t.Fatalf("rule_list = %#v", WebSocketSecurityResource.Schema.Collections[0])
	}

	fields := make(map[string]CandidateFieldConstraint, len(WebSocketSecurityResource.Schema.ItemFields))
	for _, field := range WebSocketSecurityResource.Schema.ItemFields {
		fields[field.Name] = field
	}
	// Required boolean item fields.
	for _, required := range []string{"allow_binary_text", "allow_plain_text", "allow_websocket", "block_attacks", "block_extensions"} {
		if f, ok := fields[required]; !ok || !f.Required {
			t.Errorf("required boolean %q missing or not required", required)
		}
	}
	// Required integer item fields with ranges.
	maxFrm, ok := fields["max_frm_size"]
	if !ok || !maxFrm.Required || maxFrm.Minimum == nil || maxFrm.Maximum == nil {
		t.Fatalf("max_frm_size = %#v, want required with range", maxFrm)
	}
	// name maxLength 39, url maxLength 255 with pattern.
	name, ok := fields["name"]
	if !ok || !name.Required || name.MaxLength != 39 {
		t.Fatalf("name = %#v, want required maxLength 39", name)
	}
	urlField, ok := fields["url"]
	if !ok || !urlField.Required || urlField.MaxLength != 255 || urlField.Pattern != `^/.*$` {
		t.Fatalf("url = %#v, want required maxLength 255 pattern ^/.*$", urlField)
	}
	// origin_list nested array with AllowedOrigin sub-item.
	originList, ok := fields["origin_list"]
	if !ok || originList.Kind != "array" || originList.SubItemArray == nil {
		t.Fatalf("origin_list = %#v, want array with SubItemArray", originList)
	}
	if originList.SubItemArray.MaxItems != 256 {
		t.Fatalf("origin_list MaxItems = %d, want 256", originList.SubItemArray.MaxItems)
	}
	if len(originList.SubItemArray.ItemFields) != 1 {
		t.Fatalf("origin_list item fields = %d, want 1", len(originList.SubItemArray.ItemFields))
	}
	origin, ok := originList.SubItemArray.ItemFields[0], originList.SubItemArray.ItemFields[0].Name == "origin"
	if !ok || origin.MaxLength != 255 {
		t.Fatalf("origin sub-item = %#v, want name origin maxLength 255", originList.SubItemArray.ItemFields[0])
	}
}
