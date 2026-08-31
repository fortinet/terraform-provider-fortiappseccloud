package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestAccountTakeoverContract(t *testing.T) {
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

	pathItem := document.Paths["/waf/apps/{ep_id}/account_takeover"]
	if pathItem == nil {
		t.Fatal("account takeover app path is absent")
	}
	if got := responseSchemaRef(t, pathItem["get"], "200"); got != "#/components/schemas/GetAccountTakeover" {
		t.Fatalf("GET response ref = %q", got)
	}
	if got := requestSchemaRef(t, pathItem["put"]); got != "#/components/schemas/PutAccountTakeover" {
		t.Fatalf("PUT request ref = %q", got)
	}

	var envelope objectSchema
	if err := json.Unmarshal(document.Components.Schemas["PutAccountTakeover"], &envelope); err != nil {
		t.Fatalf("decode PutAccountTakeover: %v", err)
	}
	sort.Strings(envelope.Required)
	if !reflect.DeepEqual(envelope.Required, []string{"configs", "template"}) {
		t.Fatalf("PutAccountTakeover required = %#v", envelope.Required)
	}
	if envelope.Properties["configs"].Ref != "#/components/schemas/AccountTakeover" {
		t.Fatalf("configs ref = %q", envelope.Properties["configs"].Ref)
	}

	var accountTakeover objectSchema
	if err := json.Unmarshal(document.Components.Schemas["AccountTakeover"], &accountTakeover); err != nil {
		t.Fatalf("decode AccountTakeover: %v", err)
	}
	if len(accountTakeover.Properties) != 12 {
		t.Fatalf("AccountTakeover property count = %d, want 12", len(accountTakeover.Properties))
	}
	sort.Strings(accountTakeover.Required)
	if !reflect.DeepEqual(accountTakeover.Required, []string{"action", "status"}) {
		t.Fatalf("AccountTakeover required = %#v", accountTakeover.Required)
	}
	if !reflect.DeepEqual(accountTakeover.Properties["action"].Enum, []any{"alert", "alert_deny", "deny_no_log"}) {
		t.Fatalf("action enum = %#v", accountTakeover.Properties["action"].Enum)
	}
	for _, field := range []string{"password", "sess_id_name", "username"} {
		if accountTakeover.Properties[field].MaxLength != 63 {
			t.Errorf("%s maxLength = %d, want 63", field, accountTakeover.Properties[field].MaxLength)
		}
	}
}

func TestAccountTakeoverScopeClassification(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}

	for _, classification := range AccountTakeoverScope {
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

type objectSchema struct {
	Properties map[string]schemaProperty `json:"properties"`
	Required   []string                  `json:"required"`
}

type schemaProperty struct {
	Ref       string          `json:"$ref"`
	Type      string          `json:"type"`
	Items     *schemaProperty `json:"items"`
	Enum      []any           `json:"enum"`
	Default   any             `json:"default"`
	MaxItems  int             `json:"maxItems"`
	MaxLength int             `json:"maxLength"`
	Pattern   string          `json:"pattern"`
	Minimum   *float64        `json:"minimum"`
	Maximum   *float64        `json:"maximum"`
	ReadOnly  *bool           `json:"readOnly"`
}

func responseSchemaRef(t *testing.T, operationRaw json.RawMessage, status string) string {
	t.Helper()
	var operation struct {
		Responses map[string]struct {
			Content map[string]struct {
				Schema schemaProperty `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(operationRaw, &operation); err != nil {
		t.Fatalf("decode operation response: %v", err)
	}
	return operation.Responses[status].Content["application/json"].Schema.Ref
}

func requestSchemaRef(t *testing.T, operationRaw json.RawMessage) string {
	t.Helper()
	var operation struct {
		RequestBody struct {
			Content map[string]struct {
				Schema schemaProperty `json:"schema"`
			} `json:"content"`
		} `json:"requestBody"`
	}
	if err := json.Unmarshal(operationRaw, &operation); err != nil {
		t.Fatalf("decode operation request: %v", err)
	}
	return operation.RequestBody.Content["application/json"].Schema.Ref
}
