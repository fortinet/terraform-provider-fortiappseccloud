package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewedDataSourceContracts(t *testing.T) {
	t.Parallel()

	contracts := ReviewedDataSourceContracts()
	if len(contracts) != 2 {
		t.Fatalf("reviewed data source contracts = %d, want 2", len(contracts))
	}

	classifications, err := ClassifyPublicWAF(loadPinnedWAFDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]struct{}, len(contracts))
	for _, contract := range contracts {
		if contract.TerraformName == "" || contract.PublicPath == "" ||
			contract.ClientMethod == "" || contract.ResponseSchema == "" ||
			contract.Identity == "" || contract.StateProjection == "" ||
			contract.LocalLifecycleTest == "" || contract.DocumentationFile == "" ||
			contract.ExampleFile == "" {
			t.Errorf("incomplete data source contract = %+v", contract)
		}
		if _, duplicate := names[contract.TerraformName]; duplicate {
			t.Errorf("duplicate data source contract %q", contract.TerraformName)
		}
		names[contract.TerraformName] = struct{}{}

		var get, put *OperationClassification
		for index := range classifications {
			classification := &classifications[index]
			if classification.Path != contract.PublicPath {
				continue
			}
			switch classification.Method {
			case "GET":
				get = classification
			case "PUT":
				put = classification
			}
		}
		if get == nil || get.Owner != contract.TerraformName ||
			get.ClientMethod != contract.ClientMethod ||
			get.Disposition != DispositionDataSource ||
			get.Mode != ModeDataSource ||
			get.Coverage != CoverageLocallyImplemented {
			t.Errorf("%s GET classification = %#v", contract.TerraformName, get)
		}
		if put == nil || put.Disposition != DispositionExplicitExclusion ||
			put.Mode != ModeNone || put.Coverage != CoverageExcluded ||
			put.ClientMethod != "" {
			t.Errorf("%s PUT classification = %#v", contract.TerraformName, put)
		}
	}
}

func TestReviewedDataSourceOpenAPIAndLifecycleEvidence(t *testing.T) {
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
	type operationSchema struct {
		Responses map[string]struct {
			Content map[string]struct {
				Schema struct {
					Ref   string `json:"$ref"`
					Type  string `json:"type"`
					Items *struct {
						Ref string `json:"$ref"`
					} `json:"items"`
				} `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	}

	cliTests := readRepositoryFile(t, "main_terraform_cli_test.go")
	for _, contract := range ReviewedDataSourceContracts() {
		var operation operationSchema
		if err := json.Unmarshal(document.Paths[contract.PublicPath]["get"], &operation); err != nil {
			t.Errorf("decode %s GET: %v", contract.TerraformName, err)
			continue
		}
		schema := operation.Responses["200"].Content["application/json"].Schema
		switch contract.TerraformName {
		case "fortiappseccloud_waf_modules":
			if schema.Type != "array" || schema.Items == nil ||
				schema.Items.Ref != "#/components/schemas/ApplicationModuleStatus" {
				t.Errorf("modules GET response schema = %+v", schema)
			}
		case "fortiappseccloud_waf_signature_exception":
			if schema.Ref != "#/components/schemas/GetSignatureException" {
				t.Errorf("signature exception GET response schema = %+v", schema)
			}
		default:
			t.Errorf("unreviewed data source contract %q", contract.TerraformName)
		}
		if declaration := "func " + contract.LocalLifecycleTest + "("; !strings.Contains(cliTests, declaration) {
			t.Errorf("%s lifecycle evidence %q is absent", contract.TerraformName, contract.LocalLifecycleTest)
		}
	}
}

func TestReviewedDataSourceDocumentationEvidence(t *testing.T) {
	t.Parallel()

	for _, contract := range ReviewedDataSourceContracts() {
		documentation := readRepositoryFile(t, contract.DocumentationFile)
		for _, required := range []string{
			"# " + contract.TerraformName,
			"## Example Usage",
			"## Argument Reference",
			"## Attribute Reference",
			"never changes",
		} {
			if !strings.Contains(documentation, required) {
				t.Errorf("documentation %q is missing %q", contract.DocumentationFile, required)
			}
		}
		example := readRepositoryFile(t, contract.ExampleFile)
		if declaration := `data "` + contract.TerraformName + `"`; !strings.Contains(example, declaration) {
			t.Errorf("example %q is missing %q", contract.ExampleFile, declaration)
		}
	}
}
