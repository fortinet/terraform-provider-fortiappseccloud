package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestCustomTemplateModulePairsReuseReviewedAppSchemas(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode OpenAPI baseline: %v", err)
	}

	modules := []string{
		"account_takeover",
		"anomaly_detection",
		"cors_protection",
		"custom_rule",
		"ip_protection",
		"ml_api_protection",
	}
	for _, module := range modules {
		module := module
		t.Run(module, func(t *testing.T) {
			t.Parallel()
			app := document.Paths["/waf/apps/{ep_id}/"+module]
			template := document.Paths["/waf/template/{template_id}/"+module]
			if app == nil || template == nil {
				t.Fatalf("app/template path presence = %t/%t", app != nil, template != nil)
			}
			appRefs := []string{
				responseSchemaRef(t, app["get"], "200"),
				requestSchemaRef(t, app["put"]),
			}
			templateRefs := []string{
				responseSchemaRef(t, template["get"], "200"),
				requestSchemaRef(t, template["put"]),
			}
			if !reflect.DeepEqual(templateRefs, appRefs) {
				t.Fatalf("template refs = %#v, want app refs %#v", templateRefs, appRefs)
			}
			if _, ok := template["delete"]; ok {
				t.Fatal("template module unexpectedly exposes DELETE")
			}
		})
	}
}

func TestImplementedTemplateModuleSet(t *testing.T) {
	t.Parallel()

	want := []string{
		"account_takeover",
		"anomaly_detection",
		"api_gateway",
		"biometrics_based_detection",
		"bot_deception",
		"caching_compression",
		"cookie_security",
		"cors_protection",
		"csrf_protection",
		"custom_rule",
		"ddos_prevention",
		"file_protection",
		"graphql_protection",
		"http_header_security",
		"information_leakage",
		"ip_protection",
		"json_protection",
		"known_attacks",
		"known_bots",
		"mitb_protection",
		"ml_api_protection",
		"ml_bot_detection",
		"mobile_api_protection",
		"parameter_validation",
		"request_limits",
		"rewriting_requests",
		"threshold_detection",
		"url_access",
		"waiting_room",
		"web_socket_security",
		"xml_protection_policy",
	}
	if got := sortedKeys(implementedTemplateModules); !reflect.DeepEqual(got, want) {
		t.Fatalf("implemented template modules = %#v, want %#v", got, want)
	}
}
