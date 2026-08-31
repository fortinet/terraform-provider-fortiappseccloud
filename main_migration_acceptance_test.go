package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const capturedV105MigrationGate = "captured_v1_0_5_refresh_noop_v1"

// TestAccCapturedV105StateMigration verifies the migration gate against an
// untouched full Terraform state captured from provider v1.0.5. The command is
// deliberately plan-only: it refreshes through the current Framework provider
// and requires an empty plan, but it cannot apply or write to the WAF API.
func TestAccCapturedV105StateMigration(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	requireExactMigrationEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	requireExactMigrationEnvironment(t, "FORTIAPPSECCLOUD_ACC_V1_MIGRATION_READ", capturedV105MigrationGate)
	requireNonEmptyMigrationEnvironment(t, "FORTIAPPSECCLOUD_HOSTNAME")
	requireNonEmptyMigrationEnvironment(t, "FORTIAPPSECCLOUD_API_TOKEN")
	statePath := requireNonEmptyMigrationEnvironment(t, "FORTIAPPSECCLOUD_ACC_V1_STATE_PATH")
	configPath := requireNonEmptyMigrationEnvironment(t, "FORTIAPPSECCLOUD_ACC_V2_CONFIG_PATH")

	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read captured v1.0.5 state: %v", err)
	}
	requireCapturedV105State(t, state)
	configuration, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read v2 migration configuration: %v", err)
	}
	configurationText := string(configuration)
	if !strings.Contains(configurationText, "fortinet/fortiappseccloud") || !strings.Contains(configurationText, "fortiappseccloud_waf_app") || !strings.Contains(configurationText, "fortiappseccloud_waf_openapi_validation") {
		t.Fatal("v2 migration configuration must select fortinet/fortiappseccloud and declare both legacy resource addresses")
	}

	temporaryRoot := t.TempDir()
	workDir := filepath.Join(temporaryRoot, "captured-v1-migration")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatalf("create migration directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "terraform.tfstate"), state, 0o600); err != nil {
		t.Fatalf("copy captured state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "main.tf"), configuration, 0o600); err != nil {
		t.Fatalf("copy v2 migration configuration: %v", err)
	}
	copyMigrationAssets(t, workDir, os.Getenv("FORTIAPPSECCLOUD_ACC_V2_ASSET_PATHS"))

	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)
	result := cli.runLiveReadOnly(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false")
	if result.ExitCode != 0 {
		// Do not print plan or diagnostics: captured state and live refresh output
		// can contain application, origin, or validation-file details.
		t.Fatalf("captured v1.0.5 migration plan exit code = %d, want 0", result.ExitCode)
	}
}

func copyMigrationAssets(t *testing.T, workDir, pathList string) {
	t.Helper()
	for _, sourcePath := range filepath.SplitList(strings.TrimSpace(pathList)) {
		sourcePath = strings.TrimSpace(sourcePath)
		if sourcePath == "" {
			continue
		}
		name := filepath.Base(sourcePath)
		if name == "." || name == string(filepath.Separator) || name == "main.tf" || name == "terraform.tfstate" {
			t.Fatalf("migration asset %q has a reserved filename", sourcePath)
		}
		contents, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatalf("read migration asset %q: %v", sourcePath, err)
		}
		destination := filepath.Join(workDir, name)
		if err := os.WriteFile(destination, contents, 0o600); err != nil {
			t.Fatalf("copy migration asset %q: %v", sourcePath, err)
		}
	}
}

type capturedTerraformState struct {
	Version   int                     `json:"version"`
	Resources []capturedStateResource `json:"resources"`
}

type capturedStateResource struct {
	Mode      string                  `json:"mode"`
	Type      string                  `json:"type"`
	Provider  string                  `json:"provider"`
	Instances []capturedStateInstance `json:"instances"`
}

type capturedStateInstance struct {
	SchemaVersion int             `json:"schema_version"`
	Attributes    json.RawMessage `json:"attributes"`
}

func requireCapturedV105State(t *testing.T, raw []byte) {
	t.Helper()
	var state capturedTerraformState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("decode captured Terraform state: %v", err)
	}
	if state.Version != 4 {
		t.Fatalf("captured Terraform state version = %d, want 4", state.Version)
	}
	want := map[string][]string{
		"fortiappseccloud_waf_app":                {"app_name", "app_service", "origin_server_ip"},
		"fortiappseccloud_waf_openapi_validation": {"app_name", "action", "enable"},
	}
	found := map[string]bool{}
	for _, resource := range state.Resources {
		required, relevant := want[resource.Type]
		if resource.Mode != "managed" || !relevant {
			continue
		}
		if !strings.Contains(resource.Provider, "registry.terraform.io/fortinet/fortiappseccloud") {
			t.Fatalf("captured %s state has an unexpected provider address", resource.Type)
		}
		if len(resource.Instances) != 1 || resource.Instances[0].SchemaVersion != 0 {
			t.Fatalf("captured %s state must contain exactly one schema-version-0 instance", resource.Type)
		}
		var attributes map[string]json.RawMessage
		if err := json.Unmarshal(resource.Instances[0].Attributes, &attributes); err != nil {
			t.Fatalf("decode captured %s attributes: %v", resource.Type, err)
		}
		for _, name := range required {
			if _, ok := attributes[name]; !ok {
				t.Fatalf("captured %s state is missing legacy attribute %s", resource.Type, name)
			}
		}
		found[resource.Type] = true
	}
	for resourceType := range want {
		if !found[resourceType] {
			t.Fatalf("captured state is missing %s", resourceType)
		}
	}
}

func requireExactMigrationEnvironment(t *testing.T, name, expected string) {
	t.Helper()
	if os.Getenv(name) != expected {
		t.Skipf("set %s to the exact reviewed value to run captured-state migration acceptance", name)
	}
}

func requireNonEmptyMigrationEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Skipf("set %s to run captured-state migration acceptance", name)
	}
	return value
}

func TestCapturedV105StateShape(t *testing.T) {
	t.Parallel()
	requireCapturedV105State(t, []byte(`{
  "version": 4,
  "resources": [
    {
      "mode": "managed",
      "type": "fortiappseccloud_waf_app",
      "provider": "provider[\"registry.terraform.io/fortinet/fortiappseccloud\"]",
      "instances": [{
        "schema_version": 0,
        "attributes": {"app_name":"captured","app_service":{"https":443},"origin_server_ip":"192.0.2.10"}
      }]
    },
    {
      "mode": "managed",
      "type": "fortiappseccloud_waf_openapi_validation",
      "provider": "provider[\"registry.terraform.io/fortinet/fortiappseccloud\"]",
      "instances": [{
        "schema_version": 0,
        "attributes": {"app_name":"captured","action":"alert","enable":true}
      }]
    }
  ]
}`))
}
