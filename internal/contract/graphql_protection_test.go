package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestGraphQLProtectionScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/graphql_protection", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_graphql_protection", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/graphql_protection", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_graphql_protection", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/graphql_protection", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_graphql_protection", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/graphql_protection", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_graphql_protection", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(GraphQLProtectionScope, want) {
		t.Fatalf("GraphQLProtectionScope = %#v, want %#v", GraphQLProtectionScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range GraphQLProtectionScope {
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

func TestGraphQLProtectionResourceContract(t *testing.T) {
	t.Parallel()

	if GraphQLProtectionResource.TerraformName != "fortiappseccloud_waf_graphql_protection" {
		t.Fatalf("TerraformName = %q", GraphQLProtectionResource.TerraformName)
	}
	if GraphQLProtectionResource.GoName != "GraphQLProtection" || GraphQLProtectionResource.TypeNameSuffix != "waf_graphql_protection" {
		t.Fatalf("resource identity = %#v", GraphQLProtectionResource)
	}
	if GraphQLProtectionResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", GraphQLProtectionResource.ImplementationState)
	}
	if !reflect.DeepEqual(GraphQLProtectionResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", GraphQLProtectionResource.ExpectedMethods)
	}
	if GraphQLProtectionResource.Refs.GetResponse != "#/components/schemas/GetGraphQLProtection" ||
		GraphQLProtectionResource.Refs.PutRequest != "#/components/schemas/PutGraphQLProtection" ||
		GraphQLProtectionResource.Refs.Configs != "#/components/schemas/GraphQLProtection" ||
		GraphQLProtectionResource.Refs.CollectionItem != "#/components/schemas/GraphQLProtectionRule" {
		t.Fatalf("Refs = %#v", GraphQLProtectionResource.Refs)
	}
	if len(GraphQLProtectionResource.Schema.ConfigFields) != 2 {
		t.Fatalf("ConfigFields = %d, want 2", len(GraphQLProtectionResource.Schema.ConfigFields))
	}
	if len(GraphQLProtectionResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(GraphQLProtectionResource.Schema.Collections))
	}
	if GraphQLProtectionResource.Schema.Collections[0].Name != "rule_list" || GraphQLProtectionResource.Schema.Collections[0].MaxItems != 10 {
		t.Fatalf("rule_list = %#v", GraphQLProtectionResource.Schema.Collections[0])
	}
	if len(GraphQLProtectionResource.Schema.ItemFields) != 12 {
		t.Fatalf("ItemFields = %d, want 12", len(GraphQLProtectionResource.Schema.ItemFields))
	}

	fields := make(map[string]CandidateFieldConstraint, len(GraphQLProtectionResource.Schema.ItemFields))
	for _, field := range GraphQLProtectionResource.Schema.ItemFields {
		fields[field.Name] = field
	}

	// Required string item fields.
	name, ok := fields["name"]
	if !ok {
		t.Fatal("missing name item field")
	}
	if !name.Required || name.MaxLength != 40 {
		t.Fatalf("name = %#v, want required with MaxLength 40", name)
	}
	requestURL, ok := fields["request_url"]
	if !ok {
		t.Fatal("missing request_url item field")
	}
	if !requestURL.Required {
		t.Fatalf("request_url = %#v, want required", requestURL)
	}

	// Every optional integer item field pins a reviewed default and a range.
	intFields := map[string]struct {
		min, max float64
	}{
		"alias_batch_query_number": {0, 2147483647},
		"array_batch_query_number": {0, 2147483647},
		"field_number":             {0, 2147483647},
		"graphql_data_size":        {0, 10240},
		"object_depth":             {0, 2147483647},
		"value_size":               {0, 10240},
	}
	for fieldName, want := range intFields {
		field, ok := fields[fieldName]
		if !ok {
			t.Fatalf("missing integer item field %q", fieldName)
		}
		if field.Kind != "integer" || field.Required {
			t.Fatalf("%s = %#v, want optional integer", fieldName, field)
		}
		if !field.HasDefault {
			t.Errorf("integer %q missing reviewed default", fieldName)
		}
		if field.Minimum == nil || *field.Minimum != want.min || field.Maximum == nil || *field.Maximum != want.max {
			t.Errorf("integer %q range = %#v, want min %v max %v", fieldName, field, want.min, want.max)
		}
	}
}
