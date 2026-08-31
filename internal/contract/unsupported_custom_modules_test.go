package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestReviewedUnsupportedCustomModuleContracts(t *testing.T) {
	t.Parallel()

	contracts := ReviewedUnsupportedCustomModuleContracts()
	if len(contracts) != 7 {
		t.Fatalf("unsupported custom module contracts = %d, want 7", len(contracts))
	}
	wantModules := []string{
		"ca_certificate", "crl_certificate", "inter_certificate",
		"log_settings", "server_ca", "server_crl", "sni_certificate",
	}
	gotModules := make([]string, 0, len(contracts))
	owners := make(map[string]struct{}, len(contracts))
	for _, contract := range contracts {
		gotModules = append(gotModules, contract.Module)
		if contract.TerraformName != appModuleOwner(contract.Module) {
			t.Errorf("%s owner = %q, inventory owner = %q", contract.Module, contract.TerraformName, appModuleOwner(contract.Module))
		}
		if _, duplicate := owners[contract.TerraformName]; duplicate {
			t.Errorf("duplicate unsupported owner %q", contract.TerraformName)
		}
		owners[contract.TerraformName] = struct{}{}
		if contract.PublicPath != "/waf/apps/{ep_id}/"+contract.Module {
			t.Errorf("%s public path = %q", contract.Module, contract.PublicPath)
		}
		if strings.TrimSpace(contract.ReviewedEvidence) == "" ||
			strings.TrimSpace(contract.Reason) == "" ||
			strings.TrimSpace(contract.ScopeDecision) == "" {
			t.Errorf("%s has incomplete exclusion evidence: %+v", contract.Module, contract)
		}
	}
	sort.Strings(gotModules)
	if !reflect.DeepEqual(gotModules, wantModules) {
		t.Fatalf("unsupported modules = %#v, want %#v", gotModules, wantModules)
	}
}

func TestUnsupportedCustomModuleClassification(t *testing.T) {
	t.Parallel()

	classifications, err := ClassifyPublicWAF(loadPinnedWAFDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	byKey := make(map[string]OperationClassification, len(classifications))
	for _, classification := range classifications {
		byKey[operationKey(classification.Method, classification.Path)] = classification
	}
	for _, contract := range ReviewedUnsupportedCustomModuleContracts() {
		for _, method := range []string{"GET", "PUT"} {
			classification, ok := byKey[operationKey(method, contract.PublicPath)]
			if !ok {
				t.Errorf("%s %s is absent from the public inventory", method, contract.PublicPath)
				continue
			}
			if classification.Disposition != DispositionExplicitExclusion ||
				classification.Mode != ModeNone ||
				classification.Coverage != CoverageExcluded ||
				classification.ClientMethod != "" {
				t.Errorf("%s %s classification = %+v", method, contract.PublicPath, classification)
			}
		}
	}
}

func TestUnsupportedCustomModuleOpenAPIEvidence(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "openapi_spec", "openapi.json"))
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode OpenAPI baseline: %v", err)
	}
	const singleObject = "#/components/schemas/SingleJsonObject"

	for _, module := range []string{"log_settings", "ca_certificate", "crl_certificate"} {
		pathItem := document.Paths["/waf/apps/{ep_id}/"+module]
		if pathItem == nil {
			t.Fatalf("%s public path is absent", module)
		}
		if got := requestSchemaRef(t, pathItem["put"]); got != singleObject {
			t.Errorf("%s PUT schema = %q, want SingleJsonObject", module, got)
		}
		if got := responseSchemaRef(t, pathItem["get"], "200"); got != singleObject {
			t.Errorf("%s GET schema = %q, want SingleJsonObject", module, got)
		}
	}
}

func TestUnsupportedCustomModuleSecretFieldEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		schema string
		fields []string
	}{
		{"PutInterCertificate", []string{"certificate"}},
		{"PutSniCertificate", []string{"certificate", "passwd", "private_key"}},
		{"PutServerCaRequestScheme", []string{"certificate"}},
		{"PutServerCrlRequestScheme", []string{"certificate"}},
	}
	for _, testCase := range tests {
		var schema objectSchema
		if err := json.Unmarshal(schemaByName(t, testCase.schema), &schema); err != nil {
			t.Fatalf("decode %s: %v", testCase.schema, err)
		}
		for _, field := range testCase.fields {
			property, ok := schema.Properties[field]
			if !ok || property.Type != "string" {
				t.Errorf("%s.%s = %+v, want string content field", testCase.schema, field, property)
			}
		}
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "openapi_spec", "openapi.json"))
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode OpenAPI baseline: %v", err)
	}
	logSettings, err := json.Marshal(document.Paths["/waf/apps/{ep_id}/log_settings"])
	if err != nil {
		t.Fatalf("encode log_settings path evidence: %v", err)
	}
	if !containsJSONKey(logSettings, "user_secret_key") {
		t.Fatal("OpenAPI no longer contains the log_settings user_secret_key evidence")
	}
}

func containsJSONKey(data []byte, key string) bool {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	return walkJSONKey(value, key)
}

func walkJSONKey(value any, key string) bool {
	switch value := value.(type) {
	case map[string]any:
		for name, child := range value {
			if name == key || walkJSONKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if walkJSONKey(child, key) {
				return true
			}
		}
	}
	return false
}
