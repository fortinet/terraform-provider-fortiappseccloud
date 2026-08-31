package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestURLAccessCandidateRecord pins the reviewed URL access metadata.
func TestURLAccessCandidateRecord(t *testing.T) {
	t.Parallel()

	if got := URLAccessCandidate.TerraformName; got != "fortiappseccloud_waf_url_access" {
		t.Fatalf("TerraformName = %q, want fortiappseccloud_waf_url_access", got)
	}
	if got := URLAccessCandidate.GoName; got != "URLAccess" {
		t.Fatalf("GoName = %q, want URLAccess", got)
	}
	if got := URLAccessCandidate.TypeNameSuffix; got != "waf_url_access" {
		t.Fatalf("TypeNameSuffix = %q, want waf_url_access", got)
	}
	if got := URLAccessCandidate.OperationName; got != "URL access" {
		t.Fatalf("OperationName = %q, want \"URL access\"", got)
	}
	if got := URLAccessCandidate.Path; got != "/waf/apps/{ep_id}/url_access" {
		t.Fatalf("Path = %q, want /waf/apps/{ep_id}/url_access", got)
	}
	if got := URLAccessCandidate.ExpectedMethods; !reflect.DeepEqual(got, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v, want [GET PUT]", got)
	}
	if got := URLAccessCandidate.ImplementationState; got != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q, want %q", got, ImplementationStateImplemented)
	}

	wantRefs := CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetUrlAccess",
		PutRequest:     "#/components/schemas/PutUrlAccess",
		Configs:        "#/components/schemas/UrlAccess",
		CollectionItem: "#/components/schemas/UrlAccessRule",
	}
	if !reflect.DeepEqual(URLAccessCandidate.Refs, wantRefs) {
		t.Fatalf("Refs = %#v, want %#v", URLAccessCandidate.Refs, wantRefs)
	}
	for label, ref := range map[string]string{
		"GetResponse":    URLAccessCandidate.Refs.GetResponse,
		"PutRequest":     URLAccessCandidate.Refs.PutRequest,
		"Configs":        URLAccessCandidate.Refs.Configs,
		"CollectionItem": URLAccessCandidate.Refs.CollectionItem,
	} {
		if !strings.HasPrefix(ref, "#/components/schemas/") {
			t.Errorf("%s ref = %q, must be a full #/components/schemas/... string", label, ref)
		}
	}

	if strings.TrimSpace(URLAccessCandidate.Provenance) == "" {
		t.Fatal("Provenance must not be empty")
	}
	for _, phrase := range []string{"CSRF", "structural neighbor", "shared runtime", "locally tested"} {
		if !strings.Contains(URLAccessCandidate.Provenance, phrase) {
			t.Errorf("Provenance missing expected phrase %q: %q", phrase, URLAccessCandidate.Provenance)
		}
	}
}

func TestImplementedGeneratedResources(t *testing.T) {
	t.Parallel()

	resources := ImplementedGeneratedResources()
	if len(resources) != 25 {
		t.Fatalf("implemented generated resources = %d, want 25", len(resources))
	}
	if resources[0].TerraformName != CSRFProtectionResource.TerraformName ||
		resources[1].TerraformName != URLAccessCandidate.TerraformName ||
		resources[2].TerraformName != RequestLimitsResource.TerraformName ||
		resources[3].TerraformName != KnownAttacksResource.TerraformName ||
		resources[4].TerraformName != HttpHeaderSecurityResource.TerraformName ||
		resources[5].TerraformName != GraphQLProtectionResource.TerraformName ||
		resources[6].TerraformName != JsonProtectionResource.TerraformName {
		t.Fatalf("implemented generated resources = %#v", resources)
	}
	for _, resource := range resources {
		if resource.ImplementationState != ImplementationStateImplemented {
			t.Errorf("resource %q state = %q", resource.TerraformName, resource.ImplementationState)
		}
		found, ok := FindImplementedGeneratedResource(resource.TerraformName)
		if !ok || !reflect.DeepEqual(found, resource) {
			t.Errorf("FindImplementedGeneratedResource(%q) = %#v, %t", resource.TerraformName, found, ok)
		}
	}
	resources[0].ExpectedMethods[0] = "POST"
	resources[0].Schema.ConfigFields[0].Enum[0] = "block"
	resources[0].Schema.Collections[0].MaxItems = 1
	if CSRFProtectionResource.ExpectedMethods[0] != "GET" {
		t.Fatal("ImplementedGeneratedResources exposed mutable method storage")
	}
	if CSRFProtectionResource.Schema.ConfigFields[0].Enum[0] != "alert" || CSRFProtectionResource.Schema.Collections[0].MaxItems != 256 {
		t.Fatal("ImplementedGeneratedResources exposed mutable schema contract storage")
	}
	if _, ok := FindImplementedGeneratedResource("fortiappseccloud_waf_missing"); ok {
		t.Fatal("FindImplementedGeneratedResource found an unknown resource")
	}
}

// TestURLAccessCandidatePinnedContract validates the URL access contract
// against the pinned OpenAPI document using the package test helpers. It
// proves the public GET/PUT operations exist, no POST/DELETE is present, the
// selected schema graph matches the candidate refs, and the
// UrlAccessRule/UrlAccess field constraints match the reviewed policy.
func TestURLAccessCandidatePinnedContract(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}

	var document struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode OpenAPI baseline: %v", err)
	}

	pathItem := document.Paths[URLAccessCandidate.Path]
	if pathItem == nil {
		t.Fatalf("url access path %q is absent", URLAccessCandidate.Path)
	}

	// Public GET and PUT exist; no POST/DELETE.
	if _, ok := pathItem["get"]; !ok {
		t.Fatal("public GET operation is absent")
	}
	if _, ok := pathItem["put"]; !ok {
		t.Fatal("public PUT operation is absent")
	}
	if _, ok := pathItem["post"]; ok {
		t.Fatal("POST operation unexpectedly present")
	}
	if _, ok := pathItem["delete"]; ok {
		t.Fatal("DELETE operation unexpectedly present")
	}

	// GET 200 response ref is GetUrlAccess.
	if got := responseSchemaRef(t, pathItem["get"], "200"); got != URLAccessCandidate.Refs.GetResponse {
		t.Fatalf("GET 200 response ref = %q, want %q", got, URLAccessCandidate.Refs.GetResponse)
	}

	// PUT request body ref is PutUrlAccess.
	if got := requestSchemaRef(t, pathItem["put"]); got != URLAccessCandidate.Refs.PutRequest {
		t.Fatalf("PUT request ref = %q, want %q", got, URLAccessCandidate.Refs.PutRequest)
	}

	// GET result ref and PUT request ref both resolve to PutUrlAccess.
	var getWrapper objectSchema
	if err := json.Unmarshal(document.Components.Schemas["GetUrlAccess"], &getWrapper); err != nil {
		t.Fatalf("decode GetUrlAccess: %v", err)
	}
	if got := getWrapper.Properties["result"].Ref; got != URLAccessCandidate.Refs.PutRequest {
		t.Fatalf("GetUrlAccess.result ref = %q, want %q", got, URLAccessCandidate.Refs.PutRequest)
	}

	// PutUrlAccess requires configs and template, and configs/template have
	// the expected refs/types.
	var envelope objectSchema
	if err := json.Unmarshal(document.Components.Schemas["PutUrlAccess"], &envelope); err != nil {
		t.Fatalf("decode PutUrlAccess: %v", err)
	}
	sort.Strings(envelope.Required)
	if !reflect.DeepEqual(envelope.Required, []string{"configs", "template"}) {
		t.Fatalf("PutUrlAccess required = %#v, want [configs template]", envelope.Required)
	}
	if got := envelope.Properties["configs"].Ref; got != URLAccessCandidate.Refs.Configs {
		t.Fatalf("PutUrlAccess.configs ref = %q, want %q", got, URLAccessCandidate.Refs.Configs)
	}
	if got := envelope.Properties["template"].Type; got != "boolean" {
		t.Fatalf("PutUrlAccess.template type = %q, want boolean", got)
	}

	// UrlAccess requires status and has an optional rule_list with
	// maxItems 12 whose items resolve to UrlAccessRule.
	var configs objectSchema
	if err := json.Unmarshal(document.Components.Schemas["UrlAccess"], &configs); err != nil {
		t.Fatalf("decode UrlAccess: %v", err)
	}
	sort.Strings(configs.Required)
	if !reflect.DeepEqual(configs.Required, []string{"status"}) {
		t.Fatalf("UrlAccess required = %#v, want [status]", configs.Required)
	}
	ruleList := configs.Properties["rule_list"]
	if ruleList.Type != "array" {
		t.Fatalf("UrlAccess.rule_list type = %q, want array", ruleList.Type)
	}
	if ruleList.MaxItems != 12 {
		t.Fatalf("UrlAccess.rule_list maxItems = %d, want 12", ruleList.MaxItems)
	}
	if ruleList.Items == nil {
		t.Fatal("UrlAccess.rule_list items are absent")
	} else if got := ruleList.Items.Ref; got != URLAccessCandidate.Refs.CollectionItem {
		t.Fatalf("UrlAccess.rule_list item ref = %q, want %q", got, URLAccessCandidate.Refs.CollectionItem)
	}

	// UrlAccessRule requires action/name/url/url_type; action has default pass and the
	// reviewed enum; name max 39; url max 255; idx is optional with default 1
	// and is not readOnly or numerically bounded.
	var rule objectSchema
	if err := json.Unmarshal(document.Components.Schemas["UrlAccessRule"], &rule); err != nil {
		t.Fatalf("decode UrlAccessRule: %v", err)
	}
	sort.Strings(rule.Required)
	if !reflect.DeepEqual(rule.Required, []string{"action", "name", "url", "url_type"}) {
		t.Fatalf("UrlAccessRule required = %#v, want [action name url url_type]", rule.Required)
	}

	action := rule.Properties["action"]
	if got := action.Default; got != "pass" {
		t.Fatalf("UrlAccessRule.action default = %#v, want pass", got)
	}
	if !reflect.DeepEqual(action.Enum, []any{"pass", "alert_deny", "deny_no_log", "continue"}) {
		t.Fatalf("UrlAccessRule.action enum = %#v, want [pass alert_deny deny_no_log continue]", action.Enum)
	}

	if got := rule.Properties["name"].MaxLength; got != 39 {
		t.Errorf("UrlAccessRule.name maxLength = %d, want 39", got)
	}
	if got := rule.Properties["url"].MaxLength; got != 255 {
		t.Errorf("UrlAccessRule.url maxLength = %d, want 255", got)
	}

	idx := rule.Properties["idx"]
	if got := idx.Default; !reflect.DeepEqual(got, float64(1)) {
		t.Errorf("UrlAccessRule.idx default = %#v, want 1", got)
	}
	if idx.Minimum != nil {
		t.Errorf("UrlAccessRule.idx minimum = %v, want absent", *idx.Minimum)
	}
	if idx.Maximum != nil {
		t.Errorf("UrlAccessRule.idx maximum = %v, want absent", *idx.Maximum)
	}
	if idx.ReadOnly != nil {
		t.Errorf("UrlAccessRule.idx readOnly = %v, want absent", *idx.ReadOnly)
	}

	// The selected graph contains no oneOf/anyOf/allOf/not or nullable=true.
	for _, name := range []string{
		"GetUrlAccess",
		"PutUrlAccess",
		"UrlAccess",
		"UrlAccessRule",
	} {
		blob := document.Components.Schemas[name]
		for _, keyword := range []string{`"oneOf"`, `"anyOf"`, `"allOf"`, `"not"`} {
			if strings.Contains(string(blob), keyword) {
				t.Errorf("schema %q contains forbidden keyword %s", name, keyword)
			}
		}
		if strings.Contains(string(blob), `"nullable":true`) || strings.Contains(string(blob), `"nullable": true`) {
			t.Errorf("schema %q contains nullable=true", name)
		}
	}
}

// TestURLAccessCandidatePublicOperations confirms the public GET/PUT
// operations are classified as public by the contract parser, complementing
// the raw path-item checks above.
func TestURLAccessCandidatePublicOperations(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}

	for _, method := range []string{"GET", "PUT"} {
		operation, ok := document.Find(method, URLAccessCandidate.Path)
		if !ok {
			t.Fatalf("%s %s is absent from the parsed contract", method, URLAccessCandidate.Path)
		}
		if !operation.Public {
			t.Fatalf("%s %s is tagged non-public", method, URLAccessCandidate.Path)
		}
	}
}
