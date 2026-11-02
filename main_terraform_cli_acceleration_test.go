package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTerraformCLIAccelerationLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	for _, scope := range []struct {
		name, resourceType, identity, path, template string
	}{
		{"app", "fortiappseccloud_waf_acceleration", "ep_id", "/v2/waf/apps/123/acceleration", "template = false"},
		{"template", "fortiappseccloud_waf_template_acceleration", "template_id", "/v2/waf/template/123/acceleration", ""},
	} {
		t.Run(scope.name, func(t *testing.T) {
			mock := newTerraformCLIMock(t, scope.path, terraformCLITestToken, map[string]any{
				"template": false,
				"configs": map[string]any{
					"status": false, "css_minify": false, "html_minify": true,
					"html_combine_heads": false, "html_css2head": false, "js_minify": true,
					"exception_list": []any{}, "future_config": map[string]any{"keep": true},
				},
				"future_envelope": map[string]any{"keep": true},
			}, func(body []byte) error {
				var result map[string]any
				return json.Unmarshal(body, &result)
			})
			server := httptest.NewServer(mock)
			defer server.Close()
			workDir := filepath.Join(temporaryRoot, scope.name)
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				t.Fatal(err)
			}
			configuration := func(cssMinify bool, exceptions string) string {
				return fmt.Sprintf(`
terraform {
  required_providers {
    fortiappseccloud = {
      source = "fortinet/fortiappseccloud"
    }
  }
}
provider "fortiappseccloud" {
  hostname = %q
  api_token = %q
}
resource %q "test" {
  %s = "123"
  %s
  configs {
    status = true
    css_minify = %t
    %s
  }
}
`, server.URL, terraformCLITestToken, scope.resourceType, scope.identity, scope.template, cssMinify, exceptions)
			}
			populated := `exception_list {
  item {
    host_status = true
    host = "static.example.com"
    url_pattern = "^/assets/"
    url_type = "regex"
  }
  item {
    host_status = false
    url_pattern = "/health-check"
    url_type = "string"
  }
}`
			initial := mock.remoteResult()
			initialHCL := configuration(true, populated)
			writeTerraformCLIConfig(t, workDir, initialHCL)
			requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
			put := requireTerraformCLISinglePUT(t, mock.recordedRequests())
			requireTerraformCLIConfigScalar(t, put.Body, "css_minify", true)
			requireTerraformCLIConfigScalar(t, put.Body, "html_minify", true)
			requireTerraformCLIConfigScalar(t, put.Body, "js_minify", true)
			requireTerraformCLIUnknownFields(t, initial, put.Body)
			exceptions := requireTerraformCLIConfigRaw(t, put.Body, "exception_list")
			requireTerraformCLIJSONEqual(t, exceptions, []byte(`[
  {"idx":1,"host_status":true,"host":"static.example.com","url_pattern":"^/assets/","url_type":"regex"},
  {"idx":2,"host_status":false,"url_pattern":"/health-check","url_type":"string"}
]`), "acceleration exceptions changed order or lost their configured fields")
			mock.resetRequests()
			requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
			requireTerraformCLINoPUT(t, mock.recordedRequests())
			requireTerraformCLIBoolDrift(t, cli, workDir, mock, "css_minify")

			importDir := filepath.Join(workDir, "import")
			if err := os.MkdirAll(importDir, 0o755); err != nil {
				t.Fatal(err)
			}
			writeTerraformCLIConfig(t, importDir, initialHCL)
			mock.resetRequests()
			requireTerraformCLIExit(t, cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", scope.resourceType+".test", "123"), 0)
			requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
			requireTerraformCLINoPUT(t, mock.recordedRequests())

			writeTerraformCLIConfig(t, workDir, configuration(false, ""))
			mock.resetRequests()
			requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
			put = requireTerraformCLISinglePUT(t, mock.recordedRequests())
			requireTerraformCLIJSONEqual(t, requireTerraformCLIConfigRaw(t, put.Body, "exception_list"), exceptions, "omitting acceleration exceptions changed the remote array")
			requireTerraformCLIConfigScalar(t, put.Body, "css_minify", false)
			requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))

			writeTerraformCLIConfig(t, workDir, configuration(false, "exception_list {}"))
			mock.resetRequests()
			requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
			put = requireTerraformCLISinglePUT(t, mock.recordedRequests())
			requireTerraformCLIEmptyArray(t, put.Body, "exception_list")
			requireTerraformCLIUnknownFields(t, initial, put.Body)
			requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
			requireTerraformCLIDisableOnDestroy(t, cli, workDir, mock)
			mock.requireNoHandlerFailures(t)
		})
	}
}
