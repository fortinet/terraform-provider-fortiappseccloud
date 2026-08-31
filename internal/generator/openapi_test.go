package generator

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"terraform-provider-fortiappseccloud/internal/contract"
	profile "terraform-provider-fortiappseccloud/internal/generator/profile/waf"
)

func TestSchemaResolverLocalReferencesAndPointerEscapes(t *testing.T) {
	t.Parallel()

	resolver := newSchemaResolver(map[string]json.RawMessage{
		"Root":        json.RawMessage(`{"type":"object","properties":{"value":{"$ref":"#/components/schemas/Foo~1Bar~0Baz"}},"required":["value"]}`),
		"Foo/Bar~Baz": json.RawMessage(`{"type":"string","maxLength":7}`),
	})
	resolved, err := resolver.Resolve("#/components/schemas/Root")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	field, err := requiredField(resolved, "value", "string")
	if err != nil {
		t.Fatal(err)
	}
	if field.SourceRef != "#/components/schemas/Foo~1Bar~0Baz" || field.MaxLength == nil || *field.MaxLength != 7 {
		t.Fatalf("resolved escaped ref = %#v", field)
	}
	again, err := resolver.Resolve("#/components/schemas/Root")
	if err != nil || again.SourceRef != resolved.SourceRef {
		t.Fatalf("memoized Resolve() = %#v, %v", again, err)
	}
}

func TestSchemaResolverCrossFieldExtensionV1(t *testing.T) {
	t.Parallel()

	resolver := newSchemaResolver(map[string]json.RawMessage{
		"Root": json.RawMessage(`{
			"type":"object",
			"properties":{
				"enabled":{"type":"boolean"},
				"minimum":{"type":"integer"},
				"maximum":{"type":"integer"}
			},
			"x-fortinet-cross-field-v1":[
				{"kind":"conditional_range","field":"minimum","minimum":1,"maximum":10,"when":{"field":"enabled","equals":true}},
				{"kind":"compare","left":"minimum","operator":"less_than","right":"maximum","when":{"all_of":[{"field":"enabled","equals":true}]}}
			]
		}`),
	})
	resolved, err := resolver.Resolve("#/components/schemas/Root")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(resolved.CrossFieldRules) != 2 {
		t.Fatalf("CrossFieldRules = %#v, want 2 rules", resolved.CrossFieldRules)
	}
	rangeRule := resolved.CrossFieldRules[0]
	if rangeRule.Kind != "conditional_range" || rangeRule.Field != "minimum" ||
		rangeRule.Minimum == nil || *rangeRule.Minimum != 1 || rangeRule.Maximum == nil || *rangeRule.Maximum != 10 ||
		rangeRule.When == nil || rangeRule.When.Field != "enabled" || rangeRule.When.Equals == nil || !*rangeRule.When.Equals {
		t.Fatalf("conditional range = %#v", rangeRule)
	}
	compareRule := resolved.CrossFieldRules[1]
	if compareRule.Kind != "compare" || compareRule.Left != "minimum" || compareRule.Operator != "less_than" || compareRule.Right != "maximum" ||
		compareRule.When == nil || len(compareRule.When.AllOf) != 1 {
		t.Fatalf("compare = %#v", compareRule)
	}
}

func TestSchemaResolverRejectsInvalidCrossFieldExtensionV1(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		schema string
		want   string
	}{
		"unknown rule field": {
			schema: `{"type":"object","properties":{"value":{"type":"integer"}},"x-fortinet-cross-field-v1":[{"kind":"compare","left":"value","operator":"less_than","right":"missing"}]}`,
			want:   "unknown right field",
		},
		"unknown extension key": {
			schema: `{"type":"object","properties":{"value":{"type":"integer"}},"x-fortinet-cross-field-v1":[{"kind":"compare","left":"value","operator":"less_than","right":"value","future":true}]}`,
			want:   "unknown field",
		},
		"conditional and unconditional bounds": {
			schema: `{"type":"object","properties":{"enabled":{"type":"boolean"},"value":{"type":"integer","minimum":1}},"x-fortinet-cross-field-v1":[{"kind":"conditional_range","field":"value","minimum":1,"maximum":10,"when":{"field":"enabled","equals":true}}]}`,
			want:   "must not also declare unconditional",
		},
		"non-boolean guard": {
			schema: `{"type":"object","properties":{"guard":{"type":"string"},"value":{"type":"integer"}},"x-fortinet-cross-field-v1":[{"kind":"conditional_range","field":"value","minimum":1,"maximum":10,"when":{"field":"guard","equals":true}}]}`,
			want:   "must be boolean",
		},
		"empty all_of": {
			schema: `{"type":"object","properties":{"value":{"type":"integer"}},"x-fortinet-cross-field-v1":[{"kind":"compare","left":"value","operator":"less_than","right":"value","when":{"all_of":[]}}]}`,
			want:   "exactly one boolean equality or one non-empty all_of",
		},
		"property placement": {
			schema: `{"type":"integer","x-fortinet-cross-field-v1":[{"kind":"compare","left":"a","operator":"less_than","right":"b"}]}`,
			want:   "supported only on object schemas",
		},
		"unsupported extension version": {
			schema: `{"type":"object","properties":{},"x-fortinet-cross-field-v2":[]}`,
			want:   "unsupported cross-field extension",
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := newSchemaResolver(map[string]json.RawMessage{"Root": json.RawMessage(test.schema)}).Resolve("#/components/schemas/Root")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Resolve() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestSchemaResolverRejectsUnsupportedReferencesAndSchemas(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		schemas map[string]json.RawMessage
		ref     string
		want    string
	}{
		"missing ref": {
			schemas: map[string]json.RawMessage{},
			ref:     "#/components/schemas/Missing",
			want:    "does not exist",
		},
		"external ref": {
			schemas: map[string]json.RawMessage{"Root": json.RawMessage(`{"$ref":"https://example.test/schema.json"}`)},
			ref:     "#/components/schemas/Root",
			want:    "external schema reference",
		},
		"cycle": {
			schemas: map[string]json.RawMessage{
				"A": json.RawMessage(`{"$ref":"#/components/schemas/B"}`),
				"B": json.RawMessage(`{"$ref":"#/components/schemas/A"}`),
			},
			ref:  "#/components/schemas/A",
			want: "cyclic schema reference",
		},
		"ref siblings": {
			schemas: map[string]json.RawMessage{
				"Root":  json.RawMessage(`{"$ref":"#/components/schemas/Value","description":"unsupported"}`),
				"Value": json.RawMessage(`{"type":"string"}`),
			},
			ref:  "#/components/schemas/Root",
			want: "unsupported sibling",
		},
		"oneOf": {
			schemas: map[string]json.RawMessage{"Root": json.RawMessage(`{"oneOf":[{"type":"string"}]}`)},
			ref:     "#/components/schemas/Root",
			want:    "unsupported oneOf",
		},
		"anyOf": {
			schemas: map[string]json.RawMessage{"Root": json.RawMessage(`{"anyOf":[{"type":"string"}]}`)},
			ref:     "#/components/schemas/Root",
			want:    "unsupported anyOf",
		},
		"allOf": {
			schemas: map[string]json.RawMessage{"Root": json.RawMessage(`{"allOf":[{"type":"string"}]}`)},
			ref:     "#/components/schemas/Root",
			want:    "unsupported allOf",
		},
		"not": {
			schemas: map[string]json.RawMessage{"Root": json.RawMessage(`{"not":{"type":"string"}}`)},
			ref:     "#/components/schemas/Root",
			want:    "unsupported not",
		},
		"nullable type array": {
			schemas: map[string]json.RawMessage{"Root": json.RawMessage(`{"type":["string","null"]}`)},
			ref:     "#/components/schemas/Root",
			want:    "supported string type",
		},
		"unknown type": {
			schemas: map[string]json.RawMessage{"Root": json.RawMessage(`{"type":"mystery"}`)},
			ref:     "#/components/schemas/Root",
			want:    "unknown schema type",
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := newSchemaResolver(test.schemas).Resolve(test.ref)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Resolve() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeSingleJSONRejectsAllTrailingData(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"second value":  `{} {}`,
		"invalid token": `{} x`,
		"truncated":     `{} {`,
	} {
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var value map[string]any
			if err := decodeSingleJSON([]byte(input), &value); err == nil {
				t.Fatalf("decodeSingleJSON(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestPinnedCSRFManifestNormalization(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("BuildManifest() error = %v", err)
	}
	if manifest.OpenAPI.Version != "26.3.a" || manifest.OpenAPI.SHA256 != "463015364e7d4d7cbd8f346a2e238928d1c7c741271656fec06bd8ed87e58e63" {
		t.Fatalf("OpenAPI source = %#v", manifest.OpenAPI)
	}
	if !manifest.Scope.FullWAFClassification || manifest.Scope.PublicOperationCount != 256 ||
		manifest.Scope.NonPublicOperationCount != 6 || manifest.Scope.SelectedResourceCount != 25 ||
		len(manifest.Scope.Operations) != 256 || len(manifest.Resources) != 25 {
		t.Fatalf("scope/resources = %#v / %#v", manifest.Scope, manifest.Resources)
	}
	if manifest.Scope.NextGeneratedResource != nil {
		t.Fatalf("next generated resource = %#v, want nil", manifest.Scope.NextGeneratedResource)
	}
	resource := findManifestResource(t, manifest, contract.CSRFProtectionResource.TerraformName)
	if resource.Source.GetResponseRef != contract.CSRFProtectionResource.Refs.GetResponse ||
		resource.Source.GetResultRef != contract.CSRFProtectionResource.Refs.PutRequest ||
		resource.Source.PutRequestRef != contract.CSRFProtectionResource.Refs.PutRequest {
		t.Fatalf("source refs = %#v", resource.Source)
	}
	configs, err := requiredField(resource.WireSchema, "configs", "object")
	if err != nil {
		t.Fatal(err)
	}
	action, err := requiredField(configs, "action", "string")
	if err != nil {
		t.Fatal(err)
	}
	if action.Default != "alert" || len(action.Enum) != 3 {
		t.Fatalf("action = %#v", action)
	}
	status, err := requiredField(configs, "status", "boolean")
	if err != nil || status.Default != false {
		t.Fatalf("status = %#v, error = %v", status, err)
	}
	if _, err := requiredField(resource.WireSchema, "template", "boolean"); err != nil {
		t.Fatal(err)
	}
	if !resource.WireSchema.Required || resource.Reviewed.TypeNameSuffix != "waf_csrf_protection" || resource.Reviewed.OperationName != "CSRF protection" {
		t.Fatalf("normalized resource metadata = %#v", resource)
	}
	for _, name := range []string{"page_list", "url_list"} {
		list, err := optionalField(configs, name, "array")
		if err != nil {
			t.Fatal(err)
		}
		if list.MaxItems == nil || *list.MaxItems != 256 || list.Items == nil {
			t.Fatalf("%s = %#v", name, list)
		}
		url, err := requiredField(*list.Items, "url", "string")
		if err != nil {
			t.Fatal(err)
		}
		if url.MaxLength == nil || *url.MaxLength != 255 || url.Pattern != `^/.*$` {
			t.Fatalf("%s url = %#v", name, url)
		}
		filter, err := requiredField(*list.Items, "filter", "boolean")
		if err != nil || filter.Default != false {
			t.Fatalf("%s filter = %#v, error = %v", name, filter, err)
		}
		parameterName, err := optionalField(*list.Items, "name", "string")
		if err != nil || parameterName.MaxLength == nil || *parameterName.MaxLength != 63 {
			t.Fatalf("%s name = %#v, error = %v", name, parameterName, err)
		}
		value, err := optionalField(*list.Items, "value", "string")
		if err != nil || value.MaxLength == nil || *value.MaxLength != 255 {
			t.Fatalf("%s value = %#v, error = %v", name, value, err)
		}
		idx, err := optionalField(*list.Items, "idx", "integer")
		if err != nil || fmt.Sprint(idx.Default) != "1" || idx.Minimum != nil || idx.Maximum != nil || idx.ReadOnly != nil {
			t.Fatalf("%s idx = %#v, error = %v", name, idx, err)
		}
	}
}

func TestPinnedURLAccessManifestNormalization(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("BuildManifest() error = %v", err)
	}
	if len(manifest.Resources) != 25 {
		t.Fatalf("resources = %d, want 25", len(manifest.Resources))
	}
	resource := findManifestResource(t, manifest, contract.URLAccessCandidate.TerraformName)
	if resource.TerraformName != contract.URLAccessCandidate.TerraformName ||
		resource.Source.GetResponseRef != contract.URLAccessCandidate.Refs.GetResponse ||
		resource.Source.GetResultRef != contract.URLAccessCandidate.Refs.PutRequest ||
		resource.Source.PutRequestRef != contract.URLAccessCandidate.Refs.PutRequest {
		t.Fatalf("URL access source = %#v", resource.Source)
	}
	configs, err := requiredField(resource.WireSchema, "configs", "object")
	if err != nil {
		t.Fatal(err)
	}
	status, err := requiredField(configs, "status", "boolean")
	if err != nil || status.Default != false {
		t.Fatalf("status = %#v, error = %v", status, err)
	}
	ruleList, err := optionalField(configs, "rule_list", "array")
	if err != nil {
		t.Fatal(err)
	}
	if ruleList.MaxItems == nil || *ruleList.MaxItems != 12 || ruleList.Items == nil ||
		ruleList.Items.SourceRef != contract.URLAccessCandidate.Refs.CollectionItem {
		t.Fatalf("rule_list = %#v", ruleList)
	}
	item := *ruleList.Items
	action, err := requiredField(item, "action", "string")
	if err != nil || fmt.Sprint(action.Default) != "pass" ||
		!reflect.DeepEqual(action.Enum, []any{"alert_deny", "continue", "deny_no_log", "pass"}) {
		t.Fatalf("action = %#v, error = %v", action, err)
	}
	name, err := requiredField(item, "name", "string")
	if err != nil || name.MaxLength == nil || *name.MaxLength != 39 {
		t.Fatalf("name = %#v, error = %v", name, err)
	}
	url, err := requiredField(item, "url", "string")
	if err != nil || url.MaxLength == nil || *url.MaxLength != 255 || url.Pattern != "" {
		t.Fatalf("url = %#v, error = %v", url, err)
	}
	idx, err := optionalField(item, "idx", "integer")
	if err != nil || fmt.Sprint(idx.Default) != "1" || idx.Minimum != nil || idx.Maximum != nil || idx.ReadOnly != nil {
		t.Fatalf("idx = %#v, error = %v", idx, err)
	}
	// url_type is native in OpenAPI 26.3.a; no backend-only enrichment remains.
	urlType, err := requiredField(item, "url_type", "string")
	if err != nil {
		t.Fatalf("url_type = %#v, error = %v", urlType, err)
	}
	if urlType.BackendEnriched || urlType.BackendProvenance != "" || urlType.Default != "string" {
		t.Fatalf("url_type native source markers/default = %#v", urlType)
	}
	if urlType.MaxLength != nil || urlType.Pattern != "" {
		t.Fatalf("url_type constraints = %#v, want no max length and no invented pattern", urlType)
	}
	if !reflect.DeepEqual(stringEnumValues(urlType.Enum), []string{"regex", "string"}) {
		t.Fatalf("url_type enum = %#v", urlType.Enum)
	}
}

// TestBackendFieldInjectionRejectsFailures covers the generic path-driven
// injection failure cases: unsupported path shape, unsupported kind, collision
// with a pure OpenAPI item field, duplicate additions, missing provenance, and
// contract mismatch. Each case builds a minimal schema and reviewed policy and
// asserts the injection rejects the drift.
func TestBackendFieldInjectionRejectsFailures(t *testing.T) {
	t.Parallel()

	pureItem := SchemaIR{
		Name: "Item", Kind: "object",
		Fields: []SchemaIR{
			{Name: "idx", Kind: "integer"},
			{Name: "url", Kind: "string", Required: true, MaxLength: intPtr(255)},
		},
	}
	root := SchemaIR{
		Name: "Put", Kind: "object", Required: true,
		Fields: []SchemaIR{
			{Name: "configs", Kind: "object", Required: true, Fields: []SchemaIR{
				{Name: "rule_list", Kind: "array", Items: &pureItem},
			}},
		},
	}

	contractResource := contract.ReviewedCandidate{
		TerraformName: "fortiappseccloud_waf_url_access",
		Schema: contract.CandidateSchemaContract{
			BackendEnrichedItemFields: []contract.CandidateFieldConstraint{
				{Name: "url_type", Kind: "string", Required: true, Enum: []string{"regex", "string"}},
			},
		},
	}

	tests := map[string]struct {
		addition profile.BackendFieldAddition
		want     string
	}{
		"unsupported path shape": {
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.url_type", Kind: "string", Provenance: "p"},
			want:     "is not a configs",
		},
		"unsupported kind": {
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.item.url_type", Kind: "integer", Provenance: "p"},
			want:     "kind",
		},
		"collision with pure OpenAPI field": {
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.item.url", Kind: "string", Provenance: "p"},
			want:     "collides with existing pure OpenAPI item field",
		},
		"missing provenance": {
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.item.url_type", Kind: "string"},
			want:     "missing provenance",
		},
		"contract kind mismatch": {
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.item.url_type", Kind: "boolean", Provenance: "p"},
			want:     "kind =",
		},
		"contract required mismatch": {
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.item.url_type", Kind: "string", Required: false, Provenance: "p"},
			want:     "required =",
		},
		"contract enum mismatch": {
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.item.url_type", Kind: "string", Required: true, Enum: []string{"regex"}, Provenance: "p"},
			want:     "enum =",
		},
		"unexpected pattern": {
			// The reviewed backend contract pins no pattern; an invented
			// pattern in the addition must be rejected as drift.
			addition: profile.BackendFieldAddition{Path: "configs.rule_list.item.url_type", Kind: "string", Required: true, Enum: []string{"regex", "string"}, Pattern: "^(regex|string)$", Provenance: "p"},
			want:     "pattern =",
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reviewed := profile.ResourceOverride{BackendFieldAdditions: []profile.BackendFieldAddition{test.addition}}
			err := injectBackendAdditions(cloneSchemaIRPtr(root), reviewed, contractResource)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("injectBackendAdditions() error = %v, want substring %q", err, test.want)
			}
		})
	}

	t.Run("contract default unsupported", func(t *testing.T) {
		withDefault := contractResource
		withDefault.Schema.BackendEnrichedItemFields = append([]contract.CandidateFieldConstraint(nil), contractResource.Schema.BackendEnrichedItemFields...)
		withDefault.Schema.BackendEnrichedItemFields[0].HasDefault = true
		withDefault.Schema.BackendEnrichedItemFields[0].Default = "string"
		reviewed := profile.ResourceOverride{BackendFieldAdditions: []profile.BackendFieldAddition{{
			Path: "configs.rule_list.item.url_type", Kind: "string", Required: true,
			Enum: []string{"regex", "string"}, Provenance: "p",
		}}}
		err := injectBackendAdditions(cloneSchemaIRPtr(root), reviewed, withDefault)
		if err == nil || !strings.Contains(err.Error(), "defaults are unsupported") {
			t.Fatalf("injectBackendAdditions() error = %v, want unsupported default", err)
		}
	})
}

func intPtr(value int) *int { return &value }

// cloneSchemaIRPtr deep-copies a SchemaIR via JSON round-trip and returns a
// pointer so each test case mutates an isolated schema.
func cloneSchemaIRPtr(root SchemaIR) *SchemaIR {
	encoded, err := json.Marshal(root)
	if err != nil {
		panic(err)
	}
	var cloned SchemaIR
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		panic(err)
	}
	return &cloned
}

func TestReviewedSchemaConstraintsRejectDrift(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("BuildManifest() error = %v", err)
	}

	tests := map[string]func(*contract.ReviewedCandidate){
		"enum": func(candidate *contract.ReviewedCandidate) {
			candidate.Schema.ConfigFields[0].Enum[0] = "block"
		},
		"max items": func(candidate *contract.ReviewedCandidate) {
			candidate.Schema.Collections[0].MaxItems++
		},
		"item max length": func(candidate *contract.ReviewedCandidate) {
			candidate.Schema.ItemFields[1].MaxLength++
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate, ok := contract.FindImplementedGeneratedResource(contract.CSRFProtectionResource.TerraformName)
			if !ok {
				t.Fatal("CSRF generated-resource contract is missing")
			}
			mutate(&candidate)
			if err := validateGeneratedResourceSchema(manifest.Resources[0].WireSchema, candidate); err == nil {
				t.Fatal("validateGeneratedResourceSchema() unexpectedly accepted reviewed constraint drift")
			}
		})
	}
}

func TestPinnedOpenAPIRejectsChecksumMismatch(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	openAPI = append(append([]byte(nil), openAPI...), ' ')
	if _, err := BuildManifest(openAPI, profile.DefaultOverridesJSON); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("BuildManifest() error = %v", err)
	}
}

// findManifestResource returns the manifest resource with the given Terraform
// name, so tests do not depend on the alphabetical ResourceIR ordering.
func findManifestResource(t *testing.T, manifest Manifest, name string) ResourceIR {
	t.Helper()
	for _, resource := range manifest.Resources {
		if resource.TerraformName == name {
			return resource
		}
	}
	t.Fatalf("manifest resource %q not found", name)
	return ResourceIR{}
}

// TestSchemaResolverNormalizesDuplicateEnums verifies the resolver sorts and
// deduplicates enum values when constructing SchemaIR.Enum. The pinned
// OpenAPI carries duplicate enum values (e.g. FileType.type), and the
// generated map literals, validators, docs, and manifest cannot represent
// duplicates, so the in-memory IR is normalized to a sorted, duplicate-free
// set. A contract-only duplicate (one the source lacks) is still rejected
// because validation compares the normalized source against the undeduplicated
// reviewed contract with slices.Equal.
func TestSchemaResolverNormalizesDuplicateEnums(t *testing.T) {
	t.Parallel()

	t.Run("string enum deduped and sorted", func(t *testing.T) {
		t.Parallel()
		resolver := newSchemaResolver(map[string]json.RawMessage{
			"Root": json.RawMessage(`{"type":"string","enum":["beta","alpha","beta"]}`),
		})
		resolved, err := resolver.Resolve("#/components/schemas/Root")
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if got := stringEnumValues(resolved.Enum); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
			t.Fatalf("normalized string enum = %v, want [alpha beta]", got)
		}
	})

	t.Run("integer enum deduped and sorted", func(t *testing.T) {
		t.Parallel()
		resolver := newSchemaResolver(map[string]json.RawMessage{
			"Root": json.RawMessage(`{"type":"integer","enum":[2,1,2]}`),
		})
		resolved, err := resolver.Resolve("#/components/schemas/Root")
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if !intEnumEqual(resolved.Enum, []int64{1, 2}) {
			t.Fatalf("normalized integer enum = %#v, want [1 2]", resolved.Enum)
		}
		// A contract-only duplicate (one the source lacks) is still rejected
		// because the normalized source has fewer entries than the contract.
		if intEnumEqual(resolved.Enum, []int64{1, 1, 2}) {
			t.Fatalf("contract-only duplicate unexpectedly matched normalized source")
		}
	})
}

// TestReviewedStringEnumRejectsContractOnlyDuplicate verifies that a contract
// enum containing a duplicate the normalized source lacks is rejected. The
// source is normalized to ["alpha","beta"]; a contract with ["alpha","alpha",
// "beta"] is longer and fails the slices.Equal comparison.
func TestReviewedStringEnumRejectsContractOnlyDuplicate(t *testing.T) {
	t.Parallel()

	field := SchemaIR{Kind: "string", Enum: []any{"alpha", "beta"}}
	expected := contract.CandidateFieldConstraint{
		Name: "type", Kind: "string", Enum: []string{"alpha", "alpha", "beta"},
	}
	err := validateCandidateFieldConstraint("configs.type", field, expected, nil, "fortiappseccloud_waf_test")
	if err == nil || !strings.Contains(err.Error(), "enum changed") {
		t.Fatalf("validateCandidateFieldConstraint() err = %v, want an enum changed error", err)
	}
}
