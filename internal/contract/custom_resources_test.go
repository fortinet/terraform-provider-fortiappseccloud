package contract

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestReviewedCustomResourceContracts(t *testing.T) {
	t.Parallel()

	contracts := ReviewedCustomResourceContracts()
	if len(contracts) != 7 {
		t.Fatalf("reviewed custom resource contracts = %d, want 7", len(contracts))
	}
	wantModules := []string{
		"anomaly_detection", "cors_protection", "custom_rule",
		"global_trust_list_parameter", "ip_protection",
		"ml_api_protection", "routings",
	}
	var gotModules []string
	terraformNames := make(map[string]struct{}, len(contracts))
	paths := make(map[string]struct{}, len(contracts))
	lifecycleTests := make(map[string]struct{}, len(contracts))
	disableCandidates := 0
	activeDisables := 0
	ineligible := 0
	for _, contract := range contracts {
		gotModules = append(gotModules, contract.Module)
		if contract.GetMethod != http.MethodGet || contract.PutMethod != http.MethodPut {
			t.Errorf("%s methods = %s/%s, want GET/PUT", contract.Module, contract.GetMethod, contract.PutMethod)
		}
		wantPath := "/waf/apps/{ep_id}/" + contract.Module
		if contract.PublicPath != wantPath {
			t.Errorf("%s public path = %q, want %q", contract.Module, contract.PublicPath, wantPath)
		}
		if contract.GetResponseSchema == "" || contract.PutRequestSchema == "" ||
			contract.Ownership == "" || contract.Identity == "" || contract.ImportFormat == "" ||
			contract.DocumentationFile == "" || contract.ExampleFile == "" {
			t.Errorf("%s has an incomplete reviewed contract: %+v", contract.Module, contract)
		}
		if got := appModuleOwner(contract.Module); got != contract.TerraformName {
			t.Errorf("%s Terraform owner = %q, inventory owner = %q", contract.Module, contract.TerraformName, got)
		}
		if _, duplicate := terraformNames[contract.TerraformName]; duplicate {
			t.Errorf("duplicate Terraform owner %q", contract.TerraformName)
		}
		terraformNames[contract.TerraformName] = struct{}{}
		if _, duplicate := paths[contract.PublicPath]; duplicate {
			t.Errorf("duplicate public path %q", contract.PublicPath)
		}
		paths[contract.PublicPath] = struct{}{}
		if _, duplicate := lifecycleTests[contract.LocalLifecycleTest]; duplicate {
			t.Errorf("duplicate lifecycle test %q", contract.LocalLifecycleTest)
		}
		lifecycleTests[contract.LocalLifecycleTest] = struct{}{}
		switch contract.DestroyPolicy {
		case CustomDestroyForget:
			if contract.DestroyVerified {
				t.Errorf("%s forget policy must not be verified", contract.Module)
			}
		case CustomDestroyDisable:
			activeDisables++
			if !contract.DestroyVerified {
				t.Errorf("%s active disable must be individually live verified", contract.Module)
			}
			if contract.DestroyReason == customDestroyCandidateReason {
				t.Errorf("%s active disable still has unverified candidate provenance", contract.Module)
			}
		default:
			t.Errorf("%s destroy policy = %q", contract.Module, contract.DestroyPolicy)
		}
		if contract.DestroyReason == "" {
			t.Errorf("%s destroy policy has no reason/provenance", contract.Module)
		}
		switch contract.DestroyField {
		case "status":
			disableCandidates++
		case "":
			ineligible++
			if contract.DestroyPolicy == CustomDestroyDisable {
				t.Errorf("%s active disable has no field", contract.Module)
			}
		default:
			t.Errorf("%s destroy field = %q, want status or empty", contract.Module, contract.DestroyField)
		}
	}
	sort.Strings(gotModules)
	if !reflect.DeepEqual(gotModules, wantModules) {
		t.Fatalf("reviewed custom modules = %#v, want %#v", gotModules, wantModules)
	}
	if disableCandidates != 5 || activeDisables != 5 || ineligible != 2 {
		t.Fatalf("custom destroy policies = %d candidates/%d active/%d ineligible, want 5/5/2", disableCandidates, activeDisables, ineligible)
	}
	if contract, ok := ReviewedCustomResourceContract("ip_protection"); !ok || contract.Module != "ip_protection" {
		t.Fatalf("ReviewedCustomResourceContract(ip_protection) = %#v, %t", contract, ok)
	}
	if contract, ok := ReviewedCustomResourceContract("unknown"); ok || contract != (CustomResourceContract{}) {
		t.Fatalf("ReviewedCustomResourceContract(unknown) = %#v, %t", contract, ok)
	}
}

func TestReviewedCustomResourceDocumentationEvidence(t *testing.T) {
	t.Parallel()

	for _, contract := range ReviewedCustomResourceContracts() {
		documentation := readRepositoryFile(t, contract.DocumentationFile)
		for _, required := range []string{
			"# " + contract.TerraformName,
			"## Example Usage",
			"## Import",
			"## Destroy Behavior",
		} {
			if !strings.Contains(documentation, required) {
				t.Errorf("%s documentation %q is missing %q", contract.Module, contract.DocumentationFile, required)
			}
		}

		example := readRepositoryFile(t, contract.ExampleFile)
		declaration := `resource "` + contract.TerraformName + `"`
		if !strings.Contains(example, declaration) {
			t.Errorf("%s example %q is missing %q", contract.Module, contract.ExampleFile, declaration)
		}

		for file, contents := range map[string]string{
			contract.DocumentationFile: documentation,
			contract.ExampleFile:       example,
		} {
			if strings.Contains(contents, "BEGIN CERTIFICATE") || strings.Contains(contents, "PRIVATE KEY") {
				t.Errorf("%s contains certificate/key material instead of a path-only example", file)
			}
		}
	}
}

func TestReviewedCustomResourceOpenAPIAndLifecycleEvidence(t *testing.T) {
	t.Parallel()

	openAPIData, err := os.ReadFile(filepath.Join("..", "..", "openapi_spec", "openapi.json"))
	if err != nil {
		t.Fatalf("read pinned OpenAPI: %v", err)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPIData, &document); err != nil {
		t.Fatalf("decode pinned OpenAPI: %v", err)
	}
	cliTestData, err := os.ReadFile(filepath.Join("..", "..", "main_terraform_cli_test.go"))
	if err != nil {
		t.Fatalf("read Terraform CLI tests: %v", err)
	}

	for _, contract := range ReviewedCustomResourceContracts() {
		pathItem := document.Paths[contract.PublicPath]
		if pathItem == nil {
			t.Errorf("%s path %q missing from pinned OpenAPI", contract.Module, contract.PublicPath)
			continue
		}
		wantGetRef := "#/components/schemas/" + contract.GetResponseSchema
		if got := responseSchemaRef(t, pathItem["get"], "200"); got != wantGetRef {
			t.Errorf("%s GET schema = %q, want %q", contract.Module, got, wantGetRef)
		}
		wantPutRef := "#/components/schemas/" + contract.PutRequestSchema
		if got := requestSchemaRef(t, pathItem["put"]); got != wantPutRef {
			t.Errorf("%s PUT schema = %q, want %q", contract.Module, got, wantPutRef)
		}
		testDeclaration := "func " + contract.LocalLifecycleTest + "("
		if !strings.Contains(string(cliTestData), testDeclaration) {
			t.Errorf("%s lifecycle evidence %q is absent", contract.Module, contract.LocalLifecycleTest)
		}
	}
}

func readRepositoryFile(t *testing.T, repositoryPath string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(repositoryPath)))
	if err != nil {
		t.Fatalf("read %s: %v", repositoryPath, err)
	}
	return string(data)
}
