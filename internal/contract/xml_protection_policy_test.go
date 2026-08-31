package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestXMLProtectionPolicyScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/xml_protection_policy", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_xml_protection_policy", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/xml_protection_policy", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_xml_protection_policy", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/xml_protection_policy", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_xml_protection_policy", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/xml_protection_policy", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_xml_protection_policy", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(XMLProtectionPolicyScope, want) {
		t.Fatalf("XMLProtectionPolicyScope = %#v, want %#v", XMLProtectionPolicyScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range XMLProtectionPolicyScope {
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

func TestXMLProtectionPolicyResourceContract(t *testing.T) {
	t.Parallel()

	if XMLProtectionPolicyResource.TerraformName != "fortiappseccloud_waf_xml_protection_policy" {
		t.Fatalf("TerraformName = %q", XMLProtectionPolicyResource.TerraformName)
	}
	if XMLProtectionPolicyResource.GoName != "XMLProtectionPolicy" || XMLProtectionPolicyResource.TypeNameSuffix != "waf_xml_protection_policy" {
		t.Fatalf("resource identity = %#v", XMLProtectionPolicyResource)
	}
	if XMLProtectionPolicyResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", XMLProtectionPolicyResource.ImplementationState)
	}
	if !reflect.DeepEqual(XMLProtectionPolicyResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", XMLProtectionPolicyResource.ExpectedMethods)
	}
	if XMLProtectionPolicyResource.Refs.GetResponse != "#/components/schemas/GetXMLProtection" ||
		XMLProtectionPolicyResource.Refs.PutRequest != "#/components/schemas/PutXMLProtection" ||
		XMLProtectionPolicyResource.Refs.Configs != "#/components/schemas/XMLProtection" ||
		XMLProtectionPolicyResource.Refs.CollectionItem != "#/components/schemas/XMLFile" {
		t.Fatalf("Refs = %#v", XMLProtectionPolicyResource.Refs)
	}
	if len(XMLProtectionPolicyResource.Schema.ConfigFields) != 4 {
		t.Fatalf("ConfigFields = %d, want 4", len(XMLProtectionPolicyResource.Schema.ConfigFields))
	}
	if len(XMLProtectionPolicyResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(XMLProtectionPolicyResource.Schema.Collections))
	}
	if XMLProtectionPolicyResource.Schema.Collections[0].Name != "file_list" || XMLProtectionPolicyResource.Schema.Collections[0].MaxItems != 10 {
		t.Fatalf("file_list = %#v", XMLProtectionPolicyResource.Schema.Collections[0])
	}

	configFields := make(map[string]CandidateFieldConstraint, len(XMLProtectionPolicyResource.Schema.ConfigFields))
	for _, field := range XMLProtectionPolicyResource.Schema.ConfigFields {
		configFields[field.Name] = field
	}
	action, ok := configFields["action"]
	if !ok {
		t.Fatal("missing action config field")
	}
	if !action.Required || len(action.Enum) != 3 || action.Default != "alert_deny" {
		t.Fatalf("action = %#v, want required enum of 3 default alert_deny", action)
	}
	status, ok := configFields["status"]
	if !ok {
		t.Fatal("missing status config field")
	}
	if !status.Required || status.Default != false {
		t.Fatalf("status = %#v, want required default false", status)
	}

	fields := make(map[string]CandidateFieldConstraint, len(XMLProtectionPolicyResource.Schema.ItemFields))
	for _, field := range XMLProtectionPolicyResource.Schema.ItemFields {
		fields[field.Name] = field
	}
	if len(XMLProtectionPolicyResource.Schema.ItemFields) != 7 {
		t.Fatalf("ItemFields = %d, want 7 (excluding idx)", len(XMLProtectionPolicyResource.Schema.ItemFields))
	}
	// name is required with maxLength 32.
	name, ok := fields["name"]
	if !ok {
		t.Fatal("missing name item field")
	}
	if !name.Required || name.MaxLength != 32 {
		t.Fatalf("name = %#v, want required maxLength 32", name)
	}
	// filename is required with maxLength 58.
	filename, ok := fields["filename"]
	if !ok {
		t.Fatal("missing filename item field")
	}
	if !filename.Required || filename.MaxLength != 58 {
		t.Fatalf("filename = %#v, want required maxLength 58", filename)
	}
	// entity_check is required boolean default false (XMLFile-specific).
	entityCheck, ok := fields["entity_check"]
	if !ok {
		t.Fatal("missing entity_check item field")
	}
	if !entityCheck.Required || entityCheck.Kind != "boolean" || entityCheck.Default != false {
		t.Fatalf("entity_check = %#v, want required boolean default false", entityCheck)
	}
	// md5 is optional (no default).
	md5, ok := fields["md5"]
	if !ok {
		t.Fatal("missing md5 item field")
	}
	if md5.Required {
		t.Fatalf("md5 = %#v, want optional", md5)
	}
}
