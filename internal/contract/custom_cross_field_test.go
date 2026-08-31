package contract

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type describedObjectSchema struct {
	Properties map[string]describedProperty `json:"properties"`
	Required   []string                     `json:"required"`
}

type describedProperty struct {
	Description string `json:"description"`
	Enum        []any  `json:"enum"`
}

func TestCustomRuleDiscriminatorDescriptionEvidence(t *testing.T) {
	t.Parallel()

	var schema describedObjectSchema
	if err := json.Unmarshal(schemaByName(t, "CustomRuleFilter"), &schema); err != nil {
		t.Fatalf("decode CustomRuleFilter: %v", err)
	}
	wantTypes := []string{
		"source-ip-filter", "user-filter", "url-filter", "parameter",
		"http-header-filter", "content-type", "response-code", "security-rules",
		"access-limit-filter", "packet-interval", "http-transaction",
		"occurrence", "time-range-filter", "geo-filter",
	}
	gotTypes := make([]string, 0, len(schema.Properties["type"].Enum))
	for _, value := range schema.Properties["type"].Enum {
		stringValue, ok := value.(string)
		if !ok {
			t.Fatalf("CustomRuleFilter.type enum contains non-string value %#v", value)
		}
		gotTypes = append(gotTypes, stringValue)
	}
	if !reflect.DeepEqual(gotTypes, wantTypes) {
		t.Fatalf("CustomRuleFilter.type enum = %#v, want %#v", gotTypes, wantTypes)
	}

	dependencies := map[string][]string{
		"reverse_match":            {"source-ip-filter", "user-filter", "url-filter"},
		"ip":                       {"source-ip-filter"},
		"username":                 {"user-filter"},
		"url":                      {"url-filter"},
		"name":                     {"parameter"},
		"value":                    {"parameter"},
		"header_check":             {"http-header-filter"},
		"header_type":              {"http-header-filter"},
		"header_name":              {"http-header-filter"},
		"header_value":             {"http-header-filter"},
		"header_reverse_match":     {"http-header-filter"},
		"method_check":             {"http-header-filter"},
		"method_value":             {"http-header-filter"},
		"method_reverse_match":     {"http-header-filter"},
		"http_hline_missing_check": {"http-header-filter"},
		"http_hline_empty_check":   {"http-header-filter"},
		"content_types":            {"content-type"},
		"code":                     {"response-code"},
		"cross_site_scripting":     {"security-rules"},
		"sql_injection":            {"security-rules"},
		"generic_attacks":          {"security-rules"},
		"known_exploits":           {"security-rules"},
		"trojans":                  {"security-rules"},
		"limit":                    {"access-limit-filter"},
		"timeout":                  {"packet-interval", "http-transaction"},
		"occurrence":               {"occurrence"},
		"within":                   {"occurrence"},
		"time_type":                {"time-range-filter"},
		"start":                    {"time-range-filter"},
		"end":                      {"time-range-filter"},
		"country_list":             {"geo-filter"},
		"match_exclusively":        {"geo-filter"},
	}
	for field, types := range dependencies {
		property, ok := schema.Properties[field]
		if !ok {
			t.Errorf("CustomRuleFilter is missing %q", field)
			continue
		}
		for _, filterType := range types {
			if !strings.Contains(property.Description, "'"+filterType+"'") {
				t.Errorf("CustomRuleFilter.%s description %q does not bind type %q", field, property.Description, filterType)
			}
		}
	}
	for _, field := range []string{"start", "end"} {
		description := schema.Properties[field].Description
		for _, format := range []string{"%H:%M", "%H:%M %Y/%m/%d"} {
			if !strings.Contains(description, format) {
				t.Errorf("CustomRuleFilter.%s description %q is missing format %q", field, description, format)
			}
		}
	}
}

func TestCorsRequiredObjectCrossFieldEvidence(t *testing.T) {
	t.Parallel()

	var schema describedObjectSchema
	if err := json.Unmarshal(schemaByName(t, "CorsProtection"), &schema); err != nil {
		t.Fatalf("decode CorsProtection: %v", err)
	}
	sort.Strings(schema.Required)
	wantRequired := []string{
		"allowed_headers", "allowed_methods", "allowed_origins",
		"block_cors_traffic", "exposed_headers", "status",
	}
	if !reflect.DeepEqual(schema.Required, wantRequired) {
		t.Fatalf("CorsProtection.required = %#v, want %#v", schema.Required, wantRequired)
	}
	if description := schema.Properties["block_cors_traffic"].Description; !strings.Contains(description, "block all") {
		t.Fatalf("block_cors_traffic description = %q, want block-all semantics", description)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(schemaByName(t, "CorsProtection"), &raw); err != nil {
		t.Fatalf("decode raw CorsProtection: %v", err)
	}
	for _, unsupported := range []string{"oneOf", "anyOf", "dependentRequired"} {
		if _, ok := raw[unsupported]; ok {
			t.Errorf("CorsProtection now declares %s; review the both-complete-modes decision", unsupported)
		}
	}
}
