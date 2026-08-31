package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

// TestCustomModuleLedgerFreeze pins the Slice 0 custom-module contract ledger
// (plan/2026-07-22-waf-custom-module-contract-ledger.md). It guards three
// things a future OpenAPI change must not silently break:
//
//  1. the 16 remaining custom pairs (plus the two already-owned segments
//     `endpoint` and `servers`) are exactly the reviewed custom union;
//  2. each module's intended Terraform owner resolves through appModuleOwner
//     to the documented resource name;
//  3. the explicit unsupported decisions retain their source evidence:
//     log_settings, ca_certificate, and crl_certificate stay SingleJsonObject
//     on both GET and PUT, and signature_exception keeps its GET/PUT
//     asymmetry (GET
//     returns only a template identifier while PUT accepts exception rules).
//
// A future scope or schema change must update this test and the ledger together.
func TestCustomModuleLedgerFreeze(t *testing.T) {
	t.Parallel()

	custom := unionSets(designCustomAppModules, schemaCustomAppModules)
	wantCustom := []string{
		"anomaly_detection", "ca_certificate", "cors_protection", "crl_certificate",
		"custom_rule", "endpoint", "global_trust_list_parameter",
		"inter_certificate", "ip_protection",
		"log_settings", "ml_api_protection", "modules", "routings", "server_ca",
		"server_crl", "servers", "signature_exception", "sni_certificate",
	}
	if got := sortedKeys(custom); !reflect.DeepEqual(got, wantCustom) {
		t.Fatalf("custom union = %#v, want %#v", got, wantCustom)
	}

	// The 16 remaining custom pairs exclude endpoint (owned by waf_app) and
	// servers (owned by waf_origin_servers), which are already live-verified.
	remaining := []string{
		"global_trust_list_parameter", "anomaly_detection", "cors_protection",
		"ip_protection", "routings", "custom_rule", "ml_api_protection",
		"signature_exception", "log_settings", "modules", "inter_certificate",
		"sni_certificate", "server_ca", "server_crl", "ca_certificate",
		"crl_certificate",
	}
	if len(remaining) != 16 {
		t.Fatalf("remaining custom count = %d, want 16", len(remaining))
	}
	for _, module := range remaining {
		if !has(custom, module) {
			t.Errorf("remaining custom module %q is not in the custom union", module)
		}
	}

	owners := map[string]string{
		"global_trust_list_parameter": "fortiappseccloud_waf_global_trust_list_parameter",
		"anomaly_detection":           "fortiappseccloud_waf_anomaly_detection",
		"cors_protection":             "fortiappseccloud_waf_cors_protection",
		"ip_protection":               "fortiappseccloud_waf_ip_protection",
		"routings":                    "fortiappseccloud_waf_content_routing",
		"custom_rule":                 "fortiappseccloud_waf_custom_rule",
		"ml_api_protection":           "fortiappseccloud_waf_ml_api_protection",
		"inter_certificate":           "fortiappseccloud_waf_inter_certificate",
		"sni_certificate":             "fortiappseccloud_waf_sni_certificate",
		"server_ca":                   "fortiappseccloud_waf_server_ca",
		"server_crl":                  "fortiappseccloud_waf_server_crl",
		// endpoint and servers are owned by existing resources, not new custom ones.
		"endpoint": "fortiappseccloud_waf_app",
		"servers":  "fortiappseccloud_waf_origin_servers",
		// The non-resource modules have no served resource; their
		// appModuleOwner placeholder names are pinned so a future reclassification
		// or owner change is detected. The ledger records the appropriate data
		// source or explicit unsupported outcome.
		"signature_exception": "fortiappseccloud_waf_signature_exception",
		"log_settings":        "fortiappseccloud_waf_log_settings",
		"modules":             "fortiappseccloud_waf_modules",
		"ca_certificate":      "fortiappseccloud_waf_ca_certificate",
		"crl_certificate":     "fortiappseccloud_waf_crl_certificate",
	}
	for module, wantOwner := range owners {
		if got := appModuleOwner(module); got != wantOwner {
			t.Errorf("appModuleOwner(%q) = %q, want %q", module, got, wantOwner)
		}
	}

	// No remaining custom module may collide with a generated resource name or
	// the existing OpenAPI-validation / origin / app owners.
	for _, module := range remaining {
		owner := appModuleOwner(module)
		if has(generatedAppModules, module) {
			t.Errorf("remaining custom module %q is also classified generated", module)
		}
		switch owner {
		case "fortiappseccloud_waf_app", "fortiappseccloud_waf_origin_servers", "fortiappseccloud_waf_openapi_validation":
			t.Errorf("remaining custom module %q owner %q overlaps an existing resource", module, owner)
		}
	}
}

// TestCustomModuleDecisionEvidence pins schema evidence behind the reviewed
// unsupported and asymmetric-module decisions.
func TestCustomModuleDecisionEvidence(t *testing.T) {
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

	singleObject := "#/components/schemas/SingleJsonObject"
	for _, module := range []string{"log_settings", "ca_certificate", "crl_certificate"} {
		pathItem := document.Paths["/waf/apps/{ep_id}/"+module]
		if pathItem == nil {
			t.Fatalf("%s app path is absent", module)
		}
		if got := requestSchemaRef(t, pathItem["put"]); got != singleObject {
			t.Errorf("%s PUT request ref = %q, want SingleJsonObject", module, got)
		}
		if got := responseSchemaRef(t, pathItem["get"], "200"); got != singleObject {
			t.Errorf("%s GET response ref = %q, want SingleJsonObject", module, got)
		}
	}

	// signature_exception: GET returns a template identifier, PUT accepts the
	// exception-rule array. The asymmetry is the blocker.
	sigPath := document.Paths["/waf/apps/{ep_id}/signature_exception"]
	if sigPath == nil {
		t.Fatal("signature_exception app path is absent")
	}
	if got := responseSchemaRef(t, sigPath["get"], "200"); got != "#/components/schemas/GetSignatureException" {
		t.Fatalf("signature_exception GET response ref = %q", got)
	}
	if got := requestSchemaRef(t, sigPath["put"]); got != "#/components/schemas/PutSignatureException" {
		t.Fatalf("signature_exception PUT request ref = %q", got)
	}

	var getSig objectSchema
	if err := json.Unmarshal(schemaByName(t, "GetSignatureException"), &getSig); err != nil {
		t.Fatalf("decode GetSignatureException: %v", err)
	}
	// GetSignatureException.result must reference the template-only schema, not a
	// rule-bearing schema. If result ever points at a rule array, the GET/PUT
	// asymmetry blocker no longer holds.
	resultRef := getSig.Properties["result"].Ref
	if resultRef != "#/components/schemas/SignatureExceptionTemplate" {
		t.Fatalf("GetSignatureException.result ref = %q, want SignatureExceptionTemplate", resultRef)
	}
	if _, ok := getSig.Properties["exception_rule"]; ok {
		t.Error("GetSignatureException declares exception_rule; the GET/PUT asymmetry blocker no longer holds")
	}
	var templateSchema objectSchema
	if err := json.Unmarshal(schemaByName(t, "SignatureExceptionTemplate"), &templateSchema); err != nil {
		t.Fatalf("decode SignatureExceptionTemplate: %v", err)
	}
	// Pin the complete property-key set of SignatureExceptionTemplate to exactly
	// ["template"] (string). If a rule-bearing property (e.g. "exception rule"
	// or exception_rule) ever appears, the GET/PUT asymmetry blocker no longer
	// holds.
	templateKeys := make([]string, 0, len(templateSchema.Properties))
	for key := range templateSchema.Properties {
		templateKeys = append(templateKeys, key)
	}
	sort.Strings(templateKeys)
	if !reflect.DeepEqual(templateKeys, []string{"template"}) {
		t.Fatalf("SignatureExceptionTemplate properties = %#v, want exactly [template]", templateKeys)
	}
	if templateSchema.Properties["template"].Type != "string" {
		t.Fatalf("SignatureExceptionTemplate.template type = %q, want string", templateSchema.Properties["template"].Type)
	}

	var putSig objectSchema
	if err := json.Unmarshal(schemaByName(t, "PutSignatureException"), &putSig); err != nil {
		t.Fatalf("decode PutSignatureException: %v", err)
	}
	// The pinned schema requires the space-separated wire key "exception rule"
	// (marshmallow data_key). The OpenAPI-required name carries the space; this
	// pins the asymmetry against PUT-accepts-rules / GET-returns-template.
	sort.Strings(putSig.Required)
	if !reflect.DeepEqual(putSig.Required, []string{"exception rule"}) {
		t.Fatalf("PutSignatureException required = %#v, want [exception rule]", putSig.Required)
	}
	ruleProp, ok := putSig.Properties["exception rule"]
	if !ok {
		t.Fatal("PutSignatureException missing the \"exception rule\" property")
	}
	if ruleProp.Type != "array" || ruleProp.Items == nil ||
		ruleProp.Items.Ref != "#/components/schemas/SignatureExceptionItem" {
		t.Fatalf("PutSignatureException \"exception rule\" = %+v, want array of SignatureExceptionItem", ruleProp)
	}
}

// TestCustomModuleModulesBulkStatus pins that /modules is a bulk
// ApplicationModuleStatus array on both GET and PUT, which is the
// overlapping-ownership disqualifier for the Slice 10 decision.
func TestCustomModuleModulesBulkStatus(t *testing.T) {
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

	pathItem := document.Paths["/waf/apps/{ep_id}/modules"]
	if pathItem == nil {
		t.Fatal("modules app path is absent")
	}
	for _, op := range []json.RawMessage{pathItem["get"], pathItem["put"]} {
		var opd struct {
			RequestBody struct {
				Content map[string]struct {
					Schema schemaProperty `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema schemaProperty `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		}
		if err := json.Unmarshal(op, &opd); err != nil {
			t.Fatalf("decode modules operation: %v", err)
		}
		var schema schemaProperty
		if opd.RequestBody.Content != nil {
			schema = opd.RequestBody.Content["application/json"].Schema
		} else {
			schema = opd.Responses["200"].Content["application/json"].Schema
		}
		if schema.Type != "array" {
			t.Errorf("modules operation is not an array (type=%q)", schema.Type)
		}
		if schema.Items == nil || schema.Items.Ref != "#/components/schemas/ApplicationModuleStatus" {
			t.Errorf("modules array items = %+v, want $ref ApplicationModuleStatus", schema.Items)
		}
	}
}

// TestCustomModuleModulesEnumReconciliation pins the Slice 10 reconciliation of
// the 35 ApplicationModuleStatus.id enum values against the public app-module
// inventory. advanced_bot_protection appears in the enum but has NO public
// /waf/apps/{ep_id}/advanced_bot_protection GET/PUT path and is not in the
// app-module inventory, so it is a /modules-only status id with no individual
// owner resource and no public GET/PUT pair. This does NOT violate the
// "every public app-module GET/PUT pair has an owner" invariant, because
// advanced_bot_protection has no public pair. Every enum id that DOES have a
// public GET/PUT pair must resolve to an app-module-set member.
func TestCustomModuleModulesEnumReconciliation(t *testing.T) {
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

	// Decode the ApplicationModuleStatus.id enum.
	var status struct {
		Properties struct {
			ID struct {
				Enum []string `json:"enum"`
			} `json:"id"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(document.Components.Schemas["ApplicationModuleStatus"], &status); err != nil {
		t.Fatalf("decode ApplicationModuleStatus: %v", err)
	}
	if len(status.Properties.ID.Enum) != 35 {
		t.Fatalf("ApplicationModuleStatus.id enum length = %d, want 35", len(status.Properties.ID.Enum))
	}

	// advanced_bot_protection is in the enum but must NOT have a public
	// app-module GET/PUT path and must not be in the app-module inventory.
	const advancedBot = "advanced_bot_protection"
	if !contains(status.Properties.ID.Enum, advancedBot) {
		t.Fatalf("ApplicationModuleStatus.id enum is missing %q", advancedBot)
	}
	if has(allAppModuleSet, advancedBot) {
		t.Errorf("%q is in the app-module inventory; it should be a /modules-only status id", advancedBot)
	}
	for _, method := range []string{"get", "put"} {
		if pathItem := document.Paths["/waf/apps/{ep_id}/"+advancedBot]; pathItem != nil && pathItem[method] != nil {
			t.Errorf("%q has a public %s operation; it should have no public GET/PUT path", advancedBot, method)
		}
	}

	// Every enum id that DOES have a public app-module GET/PUT path must be in
	// the app-module inventory (every public pair has an owner).
	for _, id := range status.Properties.ID.Enum {
		if id == advancedBot {
			continue
		}
		// content_routing is the module-status id; its public path is routings.
		publicID := id
		if id == "content_routing" {
			publicID = "routings"
		}
		pathItem := document.Paths["/waf/apps/{ep_id}/"+publicID]
		if pathItem == nil || pathItem["get"] == nil || pathItem["put"] == nil {
			// No public GET/PUT pair for this enum id; it is /modules-only and
			// not required to be in the inventory.
			continue
		}
		if !has(allAppModuleSet, publicID) {
			t.Errorf("enum id %q has a public GET/PUT path but is not in the app-module inventory", id)
		}
	}
}

func schemaByName(t *testing.T, name string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode OpenAPI baseline: %v", err)
	}
	schema, ok := document.Components.Schemas[name]
	if !ok {
		t.Fatalf("schema %q is absent", name)
	}
	return schema
}
