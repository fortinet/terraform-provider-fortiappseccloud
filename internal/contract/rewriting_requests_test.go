package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestRewritingRequestsScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/rewriting_requests", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_rewriting_requests", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/rewriting_requests", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_rewriting_requests", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/rewriting_requests", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_rewriting_requests", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/rewriting_requests", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_rewriting_requests", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(RewritingRequestsScope, want) {
		t.Fatalf("RewritingRequestsScope = %#v, want %#v", RewritingRequestsScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range RewritingRequestsScope {
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

func TestRewritingRequestsResourceContract(t *testing.T) {
	t.Parallel()

	if RewritingRequestsResource.TerraformName != "fortiappseccloud_waf_rewriting_requests" {
		t.Fatalf("TerraformName = %q", RewritingRequestsResource.TerraformName)
	}
	if RewritingRequestsResource.GoName != "RewritingRequests" || RewritingRequestsResource.TypeNameSuffix != "waf_rewriting_requests" {
		t.Fatalf("resource identity = %#v", RewritingRequestsResource)
	}
	if RewritingRequestsResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", RewritingRequestsResource.ImplementationState)
	}
	if !reflect.DeepEqual(RewritingRequestsResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", RewritingRequestsResource.ExpectedMethods)
	}
	if RewritingRequestsResource.Refs.GetResponse != "#/components/schemas/GetRewritingRequests" ||
		RewritingRequestsResource.Refs.PutRequest != "#/components/schemas/PutRewritingRequests" ||
		RewritingRequestsResource.Refs.Configs != "#/components/schemas/RewritingRequests" ||
		RewritingRequestsResource.Refs.CollectionItem != "#/components/schemas/RewritingRule" {
		t.Fatalf("Refs = %#v", RewritingRequestsResource.Refs)
	}
	if len(RewritingRequestsResource.Schema.ConfigFields) != 7 {
		t.Fatalf("ConfigFields = %d, want 7", len(RewritingRequestsResource.Schema.ConfigFields))
	}
	if len(RewritingRequestsResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(RewritingRequestsResource.Schema.Collections))
	}
	if RewritingRequestsResource.Schema.Collections[0].Name != "rule_list" || RewritingRequestsResource.Schema.Collections[0].MaxItems != 12 {
		t.Fatalf("rule_list = %#v", RewritingRequestsResource.Schema.Collections[0])
	}

	configFields := make(map[string]CandidateFieldConstraint, len(RewritingRequestsResource.Schema.ConfigFields))
	for _, field := range RewritingRequestsResource.Schema.ConfigFields {
		configFields[field.Name] = field
	}
	status, ok := configFields["status"]
	if !ok || !status.Required || status.Default != false {
		t.Fatalf("status = %#v, want required default false", status)
	}
	xForwardedFor, ok := configFields["x_forwarded_for"]
	if !ok || xForwardedFor.Default != true {
		t.Fatalf("x_forwarded_for = %#v, want default true", xForwardedFor)
	}
	identifyOriginalIP, ok := configFields["identify_original_ip"]
	if !ok || identifyOriginalIP.Default != true {
		t.Fatalf("identify_original_ip = %#v, want default true", identifyOriginalIP)
	}
	xHeader, ok := configFields["x_header"]
	if !ok || xHeader.Default != "X-Forwarded-For" {
		t.Fatalf("x_header = %#v, want default X-Forwarded-For", xHeader)
	}

	fields := make(map[string]CandidateFieldConstraint, len(RewritingRequestsResource.Schema.ItemFields))
	for _, field := range RewritingRequestsResource.Schema.ItemFields {
		fields[field.Name] = field
	}
	// idx is the first reviewed item field whose wire kind is string.
	idx, ok := fields["idx"]
	if !ok {
		t.Fatal("missing idx item field")
	}
	if idx.Kind != "string" || idx.Default != "1" {
		t.Fatalf("idx = %#v, want string kind default \"1\"", idx)
	}
	// name is optional with maxLength 39.
	name, ok := fields["name"]
	if !ok {
		t.Fatal("missing name item field")
	}
	if name.Required || name.MaxLength != 39 {
		t.Fatalf("name = %#v, want optional maxLength 39", name)
	}
	// action is optional with an enum of 8.
	action, ok := fields["action"]
	if !ok {
		t.Fatal("missing action item field")
	}
	if action.Required || len(action.Enum) != 8 {
		t.Fatalf("action = %#v, want optional enum of 8", action)
	}
	// protocol is optional enum HTTP|HTTPS default HTTP.
	protocol, ok := fields["protocol"]
	if !ok {
		t.Fatal("missing protocol item field")
	}
	if protocol.Default != "HTTP" || len(protocol.Enum) != 2 {
		t.Fatalf("protocol = %#v, want default HTTP enum of 2", protocol)
	}
	// rewrite_from/rewrite_to are maxLength 255 in OpenAPI 26.3.a.
	rewriteFrom, ok := fields["rewrite_from"]
	if !ok || rewriteFrom.MaxLength != 255 || fields["rewrite_to"].MaxLength != 255 {
		t.Fatalf("rewrite fields = %#v / %#v, want maxLength 255", rewriteFrom, fields["rewrite_to"])
	}
	if fields["insert_header_value"].MaxLength != 1023 {
		t.Fatalf("insert_header_value = %#v, want maxLength 1023", fields["insert_header_value"])
	}
	// remove_header is the item-level scalar-string-array (max 10).
	removeHeader, ok := fields["remove_header"]
	if !ok {
		t.Fatal("missing remove_header item field")
	}
	if removeHeader.Kind != "string_array" || removeHeader.StringArray == nil || removeHeader.StringArray.MaxItems != 10 {
		t.Fatalf("remove_header = %#v, want string_array max 10", removeHeader)
	}
	if removeHeader.StringArray.ItemAttribute != "header" {
		t.Fatalf("remove_header item attribute = %q, want header", removeHeader.StringArray.ItemAttribute)
	}
}
