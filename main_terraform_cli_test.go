package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	terraformCLITestToken      = "dummy-local-api-token"
	terraformCLITestAddress    = "fortiappseccloud_waf_csrf_protection.test"
	terraformCLIURLTestAddress = "fortiappseccloud_waf_url_access.test"
)

func TestTerraformCLIGeneratedCSRFLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/id with spaces"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/csrf_protection"
	mock := newTerraformCLICSRFMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"action": "alert",
			"status": false,
			"page_list": []any{
				map[string]any{"idx": 1, "filter": false, "url": "/remote-page", "name": "remote", "value": "page"},
			},
			"url_list": []any{
				map[string]any{"idx": 1, "filter": true, "url": "/remote-url", "name": "remote", "value": "url"},
			},
			"future_config": map[string]any{"keep": true, "revision": 7},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"alpha", float64(2)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIHCL(server.URL, epID, initialCSRFBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIArray(t, initialPut.Body, "page_list", []string{"/checkout", "/payment"})
	requireTerraformCLIArray(t, initialPut.Body, "url_list", []string{"/api/orders"})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	beforeOmittedUpdate := mock.remoteResult()
	beforeURLList := requireTerraformCLIConfigRaw(t, beforeOmittedUpdate, "url_list")
	writeTerraformCLIConfig(t, workDir, terraformCLIHCL(server.URL, epID, scalarUpdateCSRFBody()))
	mock.resetRequests()
	updateResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, updateResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	omittedPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, omittedPut.Body, "action", "deny_no_log")
	requireTerraformCLIConfigScalar(t, omittedPut.Body, "status", false)
	requireTerraformCLIManagedItemDefaults(t, omittedPut.Body, "page_list", 0)
	afterOmittedURLList := requireTerraformCLIConfigRaw(t, omittedPut.Body, "url_list")
	requireTerraformCLIJSONEqual(t, afterOmittedURLList, beforeURLList, "omitted url_list was not preserved")
	requireTerraformCLIUnknownFields(t, initialUnknown, omittedPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	beforeEmptyUpdate := mock.remoteResult()
	beforePageList := requireTerraformCLIConfigRaw(t, beforeEmptyUpdate, "page_list")
	writeTerraformCLIConfig(t, workDir, terraformCLIHCL(server.URL, epID, emptyWrapperCSRFBody()))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "url_list")
	afterEmptyPageList := requireTerraformCLIConfigRaw(t, emptyPut.Body, "page_list")
	requireTerraformCLIJSONEqual(t, afterEmptyPageList, beforePageList, "omitted page_list was not preserved while url_list was cleared")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	finalHCL := terraformCLIHCL(server.URL, epID, reorderedCSRFBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	reorderResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, reorderResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	reorderedPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIArray(t, reorderedPut.Body, "page_list", []string{"/page-second", "/page-first"})
	requireTerraformCLIArray(t, reorderedPut.Body, "url_list", []string{"/url-second", "/url-first"})
	requireTerraformCLIUnknownFields(t, initialUnknown, reorderedPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	writeTerraformCLIConfig(t, workDir, terraformCLIHCL(server.URL, epID, templateOnlyCSRFBody()))
	mock.resetRequests()
	templateResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, templateResult, 0)
	templateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, templateRequests)
	templatePut := requireTerraformCLISinglePUT(t, templateRequests)
	requireTerraformCLITemplate(t, templatePut.Body, true)
	requireTerraformCLIUnknownFields(t, initialUnknown, templatePut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	localResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, localResult, 0)
	localRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, localRequests)
	localPut := requireTerraformCLISinglePUT(t, localRequests)
	requireTerraformCLITemplate(t, localPut.Body, false)
	requireTerraformCLIArray(t, localPut.Body, "page_list", []string{"/page-second", "/page-first"})
	requireTerraformCLIArray(t, localPut.Body, "url_list", []string{"/url-second", "/url-first"})
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLITestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	validationCases := []struct {
		name string
		body string
	}{
		{name: "invalid action", body: invalidActionCSRFBody()},
		{name: "invalid URL", body: invalidURLCSRFBody()},
		{name: "missing configs when template is false", body: "  template = false\n"},
		{name: "configs present when template is true", body: templateWithConfigsCSRFBody()},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != 1 {
				t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

func TestTerraformCLIGeneratedURLAccessLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/id with spaces"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/url_access"
	mock := newTerraformCLIURLAccessMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status": true,
			"rule_list": []any{
				map[string]any{"idx": 1, "action": "pass", "name": "remote-allow", "url": "/remote/allow", "url_type": "string"},
				map[string]any{"idx": 2, "action": "deny_no_log", "name": "remote-deny", "url": "/remote/deny", "url_type": "string"},
			},
			"cache":         map[string]any{"status": true},
			"compress":      map[string]any{"status": true},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIURLAccessHCL(server.URL, epID, initialURLAccessBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIURLAccessArray(t, initialPut.Body, "rule_list", []terraformCLIURLAccessItem{
		{Index: 1, Action: "pass", Name: "allow-application-api", URL: "/api/application/", URLType: "string"},
		{Index: 2, Action: "alert_deny", Name: "deny-admin-area", URL: "^/admin/(login|setup)$", URLType: "regex"},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	beforeOmittedUpdate := mock.remoteResult()
	beforeRuleList := requireTerraformCLIConfigRaw(t, beforeOmittedUpdate, "rule_list")
	writeTerraformCLIConfig(t, workDir, terraformCLIURLAccessHCL(server.URL, epID, scalarUpdateURLAccessBody()))
	mock.resetRequests()
	updateResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, updateResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	omittedPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, omittedPut.Body, "status", false)
	afterOmittedRuleList := requireTerraformCLIConfigRaw(t, omittedPut.Body, "rule_list")
	requireTerraformCLIJSONEqual(t, afterOmittedRuleList, beforeRuleList, "omitted rule_list was not preserved")
	requireTerraformCLIUnknownFields(t, initialUnknown, omittedPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	writeTerraformCLIConfig(t, workDir, terraformCLIURLAccessHCL(server.URL, epID, emptyWrapperURLAccessBody()))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "rule_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	finalHCL := terraformCLIURLAccessHCL(server.URL, epID, reorderedURLAccessBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	reorderResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, reorderResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	reorderedPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIURLAccessArray(t, reorderedPut.Body, "rule_list", []terraformCLIURLAccessItem{
		{Index: 1, Action: "deny_no_log", Name: "rule-second", URL: "/url-second", URLType: "string"},
		{Index: 2, Action: "continue", Name: "rule-first", URL: "/url-first", URLType: "string"},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, reorderedPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	writeTerraformCLIConfig(t, workDir, terraformCLIURLAccessHCL(server.URL, epID, templateOnlyURLAccessBody()))
	mock.resetRequests()
	templateResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, templateResult, 0)
	templateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, templateRequests)
	templatePut := requireTerraformCLISinglePUT(t, templateRequests)
	requireTerraformCLITemplate(t, templatePut.Body, true)
	requireTerraformCLIUnknownFields(t, initialUnknown, templatePut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	localResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, localResult, 0)
	localRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, localRequests)
	localPut := requireTerraformCLISinglePUT(t, localRequests)
	requireTerraformCLITemplate(t, localPut.Body, false)
	requireTerraformCLIURLAccessArray(t, localPut.Body, "rule_list", []terraformCLIURLAccessItem{
		{Index: 1, Action: "deny_no_log", Name: "rule-second", URL: "/url-second", URLType: "string"},
		{Index: 2, Action: "continue", Name: "rule-first", URL: "/url-first", URLType: "string"},
	})
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIURLTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	validationCases := []struct {
		name string
		body string
	}{
		{name: "invalid action", body: invalidActionURLAccessBody()},
		{name: "missing name", body: missingNameURLAccessBody()},
		{name: "missing url", body: missingURLURLAccessBody()},
		{name: "name too long", body: nameTooLongURLAccessBody()},
		{name: "url too long", body: urlTooLongURLAccessBody()},
		{name: "too many items", body: tooManyItemsURLAccessBody()},
		{name: "missing url_type", body: missingURLTypeURLAccessBody()},
		{name: "invalid url_type", body: invalidURLTypeURLAccessBody()},
		{name: "configs missing when template is false", body: "  template = false\n"},
		{name: "configs present when template is true", body: templateWithConfigsURLAccessBody()},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-url", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIURLAccessHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != 1 {
				t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

type terraformCLI struct {
	path       string
	configFile string
	tempRoot   string
}

type terraformCLIResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func (r terraformCLIResult) output() string {
	return r.Stdout + r.Stderr
}

func buildTerraformCLIProvider(t *testing.T, terraformPath, repositoryRoot, temporaryRoot string) terraformCLI {
	t.Helper()
	pluginDir := filepath.Join(temporaryRoot, "plugins")
	for _, directory := range []string{
		pluginDir,
		filepath.Join(temporaryRoot, "home"),
		filepath.Join(temporaryRoot, "tmp"),
		filepath.Join(temporaryRoot, "plugin-cache"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("create temporary Terraform directory: %v", err)
		}
	}
	binaryName := "terraform-provider-fortiappseccloud"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	providerBinary := filepath.Join(pluginDir, binaryName)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", providerBinary, ".")
	command.Dir = repositoryRoot
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("build provider binary: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("build provider binary: %v\n%s", err, output)
	}

	cliConfig := filepath.Join(temporaryRoot, "terraform.rc")
	contents := fmt.Sprintf(`provider_installation {
  dev_overrides {
    %s = %s
  }

  direct {
    exclude = [%s]
  }
}
`, strconv.Quote(providerAddress), strconv.Quote(pluginDir), strconv.Quote(providerAddress))
	if err := os.WriteFile(cliConfig, []byte(contents), 0o600); err != nil {
		t.Fatalf("write Terraform CLI configuration: %v", err)
	}
	return terraformCLI{path: terraformPath, configFile: cliConfig, tempRoot: temporaryRoot}
}

func (c terraformCLI) run(t *testing.T, directory string, arguments ...string) terraformCLIResult {
	return c.runWithCredentialPolicy(t, directory, false, arguments...)
}

// runLiveReadOnly preserves environment-provided provider credentials for the
// separately gated captured-state migration plan. Callers must ensure the
// Terraform command cannot apply or mutate remote state.
func (c terraformCLI) runLiveReadOnly(t *testing.T, directory string, arguments ...string) terraformCLIResult {
	return c.runWithCredentialPolicy(t, directory, true, arguments...)
}

func (c terraformCLI) runWithCredentialPolicy(t *testing.T, directory string, preserveLiveCredentials bool, arguments ...string) terraformCLIResult {
	t.Helper()
	dataDir := filepath.Join(directory, ".terraform-data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("create Terraform data directory: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, c.path, arguments...)
	command.Dir = directory
	replacements := map[string]string{
		"ALL_PROXY":                  "",
		"CHECKPOINT_DISABLE":         "1",
		"HOME":                       filepath.Join(c.tempRoot, "home"),
		"HTTP_PROXY":                 "",
		"HTTPS_PROXY":                "",
		"NO_PROXY":                   "*",
		"TF_CLI_CONFIG_FILE":         c.configFile,
		"TF_DATA_DIR":                dataDir,
		"TF_IN_AUTOMATION":           "1",
		"TF_INPUT":                   "0",
		"TF_PLUGIN_CACHE_DIR":        filepath.Join(c.tempRoot, "plugin-cache"),
		"TF_REGISTRY_CLIENT_TIMEOUT": "1",
		"TMPDIR":                     filepath.Join(c.tempRoot, "tmp"),
		"all_proxy":                  "",
		"http_proxy":                 "",
		"https_proxy":                "",
		"no_proxy":                   "*",
	}
	if !preserveLiveCredentials {
		replacements["FORTIAPPSECCLOUD_API_TOKEN"] = ""
		replacements["FORTIAPPSECCLOUD_HOSTNAME"] = ""
		replacements["FORTIAPPSECCLOUD_PASSWORD"] = ""
		replacements["FORTIAPPSECCLOUD_USERNAME"] = ""
	}
	command.Env = terraformCLIEnvironment(os.Environ(), replacements)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		if preserveLiveCredentials {
			t.Fatalf("terraform %s timed out during live read-only verification", strings.Join(arguments, " "))
		}
		t.Fatalf("terraform %s timed out: %v\n%s%s", strings.Join(arguments, " "), ctx.Err(), stdout.String(), stderr.String())
	}
	result := terraformCLIResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return result
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result
	}
	t.Fatalf("start terraform %s: %v", strings.Join(arguments, " "), err)
	return terraformCLIResult{}
}

func terraformCLIEnvironment(environment []string, replacements map[string]string) []string {
	result := make([]string, 0, len(environment)+len(replacements))
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, replaced := replacements[key]; replaced {
				continue
			}
		}
		result = append(result, entry)
	}
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+replacements[key])
	}
	return result
}

func terraformCLIHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_csrf_protection", "test", epID, resourceBody)
}

func terraformCLIResourceHCL(apiURL, resourceType, resourceName, epID, resourceBody string) string {
	return fmt.Sprintf(`terraform {
  required_providers {
    fortiappseccloud = {
      source = "fortinet/fortiappseccloud"
    }
  }
}

provider "fortiappseccloud" {
  hostname  = %s
  api_token = %s
}

resource %q %q {
  ep_id = %s
%s}
`, strconv.Quote(apiURL), strconv.Quote(terraformCLITestToken), resourceType, resourceName, strconv.Quote(epID), resourceBody)
}

func initialCSRFBody() string {
	return `  template = false

  configs {
    action = "alert_deny"
    status = true

    page_list {
      item {
        filter = true
        url    = "/checkout"
        name   = "csrf_token"
        value  = "expected"
      }
      item {
        filter = false
        url    = "/payment"
        name   = "csrf_token"
        value  = "payment"
      }
    }

    url_list {
      item {
        filter = false
        url    = "/api/orders"
        name   = "csrf_token"
        value  = "orders"
      }
    }
  }
`
}

func scalarUpdateCSRFBody() string {
	return `  template = false

  configs {
    action = "deny_no_log"
    status = false

    page_list {
      item {
        url = "/checkout"
      }
      item {
        filter = false
        url    = "/payment"
        name   = "csrf_token"
        value  = "payment"
      }
    }
  }
`
}

func emptyWrapperCSRFBody() string {
	return `  template = false

  configs {
    action = "deny_no_log"
    status = false

    url_list {}
  }
`
}

func reorderedCSRFBody() string {
	return `  template = false

  configs {
    action = "alert"
    status = true

    page_list {
      item {
        filter = true
        url    = "/page-second"
        name   = "page_two"
        value  = "second"
      }
      item {
        filter = false
        url    = "/page-first"
        name   = "page_one"
        value  = "first"
      }
    }

    url_list {
      item {
        filter = false
        url    = "/url-second"
        name   = "url_two"
        value  = "second"
      }
      item {
        filter = true
        url    = "/url-first"
        name   = "url_one"
        value  = "first"
      }
    }
  }
`
}

func templateOnlyCSRFBody() string {
	return `  template = true
`
}

func invalidActionCSRFBody() string {
	return `  template = false

  configs {
    action = "block"
    status = true
  }
`
}

func invalidURLCSRFBody() string {
	return `  template = false

  configs {
    action = "alert"
    status = true

    page_list {
      item {
        filter = false
        url    = "relative/path"
      }
    }
  }
`
}

func templateWithConfigsCSRFBody() string {
	return `  template = true

  configs {
    action = "alert"
    status = false
  }
`
}

func terraformCLIURLAccessHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_url_access", "test", epID, resourceBody)
}

func initialURLAccessBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "pass"
        name     = "allow-application-api"
        url      = "/api/application/"
        url_type = "string"
      }
      item {
        action   = "alert_deny"
        name     = "deny-admin-area"
        url      = "^/admin/(login|setup)$"
        url_type = "regex"
      }
    }
  }
`
}

func scalarUpdateURLAccessBody() string {
	return `  template = false

  configs {
    status = false
  }
`
}

func emptyWrapperURLAccessBody() string {
	return `  template = false

  configs {
    status = false

    rule_list {}
  }
`
}

func reorderedURLAccessBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "deny_no_log"
        name     = "rule-second"
        url      = "/url-second"
        url_type = "string"
      }
      item {
        action   = "continue"
        name     = "rule-first"
        url      = "/url-first"
        url_type = "string"
      }
    }
  }
`
}

func templateOnlyURLAccessBody() string {
	return `  template = true
`
}

func invalidActionURLAccessBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "alert"
        name     = "bad-action"
        url      = "/ok"
        url_type = "string"
      }
    }
  }
`
}

func missingNameURLAccessBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "pass"
        url      = "/ok"
        url_type = "string"
      }
    }
  }
`
}

func missingURLURLAccessBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "pass"
        name     = "missing-url"
        url_type = "string"
      }
    }
  }
`
}

func nameTooLongURLAccessBody() string {
	return fmt.Sprintf(`  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "pass"
        name     = "%s"
        url      = "/ok"
        url_type = "string"
      }
    }
  }
`, strings.Repeat("n", 40))
}

func urlTooLongURLAccessBody() string {
	return fmt.Sprintf(`  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "pass"
        name     = "url-too-long"
        url      = "/%s"
        url_type = "string"
      }
    }
  }
`, strings.Repeat("x", 255))
}

func missingURLTypeURLAccessBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        action = "pass"
        name   = "missing-url-type"
        url    = "/ok"
      }
    }
  }
`
}

func invalidURLTypeURLAccessBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        action   = "pass"
        name     = "invalid-url-type"
        url      = "/ok"
        url_type = "glob"
      }
    }
  }
`
}

func tooManyItemsURLAccessBody() string {
	var builder strings.Builder
	builder.WriteString(`  template = false

  configs {
    status = true

    rule_list {
`)
	for index := 0; index < terraformCLIURLAccessMaxItems+1; index++ {
		fmt.Fprintf(&builder, "      item {\n        action   = \"pass\"\n        name     = \"rule-%d\"\n        url      = \"/%d\"\n        url_type = \"string\"\n      }\n", index, index)
	}
	builder.WriteString("    }\n  }\n")
	return builder.String()
}

func templateWithConfigsURLAccessBody() string {
	return `  template = true

  configs {
    status = false
  }
`
}

func writeTerraformCLIConfig(t *testing.T, directory, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "main.tf"), []byte(contents), 0o600); err != nil {
		t.Fatalf("write Terraform configuration: %v", err)
	}
}

type terraformCLISchemaBlock struct {
	Attributes map[string]json.RawMessage               `json:"attributes"`
	BlockTypes map[string]terraformCLISchemaNestedBlock `json:"block_types"`
}

type terraformCLISchemaNestedBlock struct {
	NestingMode string                  `json:"nesting_mode"`
	Block       terraformCLISchemaBlock `json:"block"`
}

func requireTerraformCLISchema(t *testing.T, data []byte) {
	t.Helper()
	var document struct {
		ProviderSchemas map[string]struct {
			ResourceSchemas map[string]struct {
				Block terraformCLISchemaBlock `json:"block"`
			} `json:"resource_schemas"`
			DataSourceSchemas map[string]struct {
				Block terraformCLISchemaBlock `json:"block"`
			} `json:"data_source_schemas"`
		} `json:"provider_schemas"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode terraform providers schema JSON: %v\n%s", err, data)
	}
	providerSchema, ok := document.ProviderSchemas[providerAddress]
	if !ok {
		t.Fatalf("provider schema %q is missing", providerAddress)
	}
	gotResources := make([]string, 0, len(providerSchema.ResourceSchemas))
	for name := range providerSchema.ResourceSchemas {
		gotResources = append(gotResources, name)
	}
	sort.Strings(gotResources)
	wantResources := []string{
		"fortiappseccloud_waf_account_takeover",
		"fortiappseccloud_waf_anomaly_detection",
		"fortiappseccloud_waf_api_gateway",
		"fortiappseccloud_waf_app",
		"fortiappseccloud_waf_biometrics_based_detection",
		"fortiappseccloud_waf_bot_deception",
		"fortiappseccloud_waf_caching_compression",
		"fortiappseccloud_waf_content_routing",
		"fortiappseccloud_waf_cookie_security",
		"fortiappseccloud_waf_cors_protection",
		"fortiappseccloud_waf_csrf_protection",
		"fortiappseccloud_waf_custom_rule",
		"fortiappseccloud_waf_ddos_prevention",
		"fortiappseccloud_waf_file_protection",
		"fortiappseccloud_waf_global_trust_list_parameter",
		"fortiappseccloud_waf_graphql_protection",
		"fortiappseccloud_waf_http_header_security",
		"fortiappseccloud_waf_information_leakage",
		"fortiappseccloud_waf_ip_protection",
		"fortiappseccloud_waf_json_protection",
		"fortiappseccloud_waf_known_attacks",
		"fortiappseccloud_waf_known_bots",
		"fortiappseccloud_waf_mitb_protection",
		"fortiappseccloud_waf_ml_api_protection",
		"fortiappseccloud_waf_ml_bot_detection",
		"fortiappseccloud_waf_mobile_api_protection",
		"fortiappseccloud_waf_openapi_validation",
		"fortiappseccloud_waf_origin_servers",
		"fortiappseccloud_waf_parameter_validation",
		"fortiappseccloud_waf_request_limits",
		"fortiappseccloud_waf_rewriting_requests",
		"fortiappseccloud_waf_template",
		"fortiappseccloud_waf_template_account_takeover",
		"fortiappseccloud_waf_template_anomaly_detection",
		"fortiappseccloud_waf_template_api_gateway",
		"fortiappseccloud_waf_template_attachment",
		"fortiappseccloud_waf_template_biometrics_based_detection",
		"fortiappseccloud_waf_template_bot_deception",
		"fortiappseccloud_waf_template_caching_compression",
		"fortiappseccloud_waf_template_cookie_security",
		"fortiappseccloud_waf_template_cors_protection",
		"fortiappseccloud_waf_template_csrf_protection",
		"fortiappseccloud_waf_template_custom_rule",
		"fortiappseccloud_waf_template_ddos_prevention",
		"fortiappseccloud_waf_template_file_protection",
		"fortiappseccloud_waf_template_graphql_protection",
		"fortiappseccloud_waf_template_http_header_security",
		"fortiappseccloud_waf_template_information_leakage",
		"fortiappseccloud_waf_template_ip_protection",
		"fortiappseccloud_waf_template_json_protection",
		"fortiappseccloud_waf_template_known_attacks",
		"fortiappseccloud_waf_template_known_bots",
		"fortiappseccloud_waf_template_mitb_protection",
		"fortiappseccloud_waf_template_ml_api_protection",
		"fortiappseccloud_waf_template_ml_bot_detection",
		"fortiappseccloud_waf_template_mobile_api_protection",
		"fortiappseccloud_waf_template_parameter_validation",
		"fortiappseccloud_waf_template_request_limits",
		"fortiappseccloud_waf_template_rewriting_requests",
		"fortiappseccloud_waf_template_threshold_detection",
		"fortiappseccloud_waf_template_url_access",
		"fortiappseccloud_waf_template_waiting_room",
		"fortiappseccloud_waf_template_web_socket_security",
		"fortiappseccloud_waf_template_xml_protection_policy",
		"fortiappseccloud_waf_threshold_detection",
		"fortiappseccloud_waf_url_access",
		"fortiappseccloud_waf_waiting_room",
		"fortiappseccloud_waf_web_socket_security",
		"fortiappseccloud_waf_xml_protection_policy",
	}
	if !reflect.DeepEqual(gotResources, wantResources) {
		t.Fatalf("Terraform CLI resource schemas = %#v, want %#v", gotResources, wantResources)
	}
	template := providerSchema.ResourceSchemas["fortiappseccloud_waf_template"].Block
	for _, attribute := range []string{"template_id", "name", "predefined", "features"} {
		if _, ok := template.Attributes[attribute]; !ok {
			t.Fatalf("template root attribute %q is missing", attribute)
		}
	}
	templateCSRF := providerSchema.ResourceSchemas["fortiappseccloud_waf_template_csrf_protection"].Block
	if _, ok := templateCSRF.Attributes["template_id"]; !ok {
		t.Fatal("template CSRF root attribute template_id is missing")
	}
	for _, absent := range []string{"ep_id", "template"} {
		if _, ok := templateCSRF.Attributes[absent]; ok {
			t.Fatalf("template CSRF unexpectedly exposes app-only attribute %q", absent)
		}
	}
	requireTerraformCLINestedBlock(t, templateCSRF, "configs", "single")

	gotDataSources := make([]string, 0, len(providerSchema.DataSourceSchemas))
	for name := range providerSchema.DataSourceSchemas {
		gotDataSources = append(gotDataSources, name)
	}
	sort.Strings(gotDataSources)
	if want := []string{
		"fortiappseccloud_waf_modules",
		"fortiappseccloud_waf_signature_exception",
	}; !reflect.DeepEqual(gotDataSources, want) {
		t.Fatalf("Terraform CLI data source schemas = %#v, want %#v", gotDataSources, want)
	}
	modules := providerSchema.DataSourceSchemas["fortiappseccloud_waf_modules"].Block
	var epIDAttribute, modulesAttribute struct {
		Required bool `json:"required"`
		Computed bool `json:"computed"`
	}
	if err := json.Unmarshal(modules.Attributes["ep_id"], &epIDAttribute); err != nil {
		t.Fatalf("decode modules data source ep_id schema: %v", err)
	}
	if err := json.Unmarshal(modules.Attributes["modules"], &modulesAttribute); err != nil {
		t.Fatalf("decode modules data source modules schema: %v", err)
	}
	if !epIDAttribute.Required || !modulesAttribute.Computed {
		t.Fatalf("modules data source attributes = ep_id:%#v modules:%#v", epIDAttribute, modulesAttribute)
	}
	signatureException := providerSchema.DataSourceSchemas["fortiappseccloud_waf_signature_exception"].Block
	var signatureEPID, signatureID, templateID struct {
		Required bool `json:"required"`
		Computed bool `json:"computed"`
	}
	for name, target := range map[string]any{
		"ep_id": &signatureEPID, "signature_id": &signatureID, "template_id": &templateID,
	} {
		if err := json.Unmarshal(signatureException.Attributes[name], target); err != nil {
			t.Fatalf("decode signature exception data source %s schema: %v", name, err)
		}
	}
	if !signatureEPID.Required || !signatureID.Required || !templateID.Computed {
		t.Fatalf("signature exception data source attributes = ep_id:%#v signature_id:%#v template_id:%#v", signatureEPID, signatureID, templateID)
	}
	csrf := providerSchema.ResourceSchemas["fortiappseccloud_waf_csrf_protection"].Block
	for _, attribute := range []string{"ep_id", "template"} {
		if _, ok := csrf.Attributes[attribute]; !ok {
			t.Fatalf("CSRF root attribute %q is missing", attribute)
		}
	}
	configs := requireTerraformCLINestedBlock(t, csrf, "configs", "single")
	for _, attribute := range []string{"action", "status"} {
		if _, ok := configs.Attributes[attribute]; !ok {
			t.Fatalf("CSRF configs attribute %q is missing", attribute)
		}
	}
	for _, listName := range []string{"page_list", "url_list"} {
		wrapper := requireTerraformCLINestedBlock(t, configs, listName, "single")
		item := requireTerraformCLINestedBlock(t, wrapper, "item", "list")
		if _, ok := item.Attributes["idx"]; ok {
			t.Fatalf("CSRF %s.item unexpectedly exposes idx", listName)
		}
		gotAttributes := make([]string, 0, len(item.Attributes))
		for name := range item.Attributes {
			gotAttributes = append(gotAttributes, name)
		}
		sort.Strings(gotAttributes)
		wantAttributes := []string{"filter", "name", "url", "value"}
		if !reflect.DeepEqual(gotAttributes, wantAttributes) {
			t.Fatalf("CSRF %s.item attributes = %#v, want %#v", listName, gotAttributes, wantAttributes)
		}
	}

	urlAccess := providerSchema.ResourceSchemas["fortiappseccloud_waf_url_access"].Block
	for _, attribute := range []string{"ep_id", "template"} {
		if _, ok := urlAccess.Attributes[attribute]; !ok {
			t.Fatalf("URL access root attribute %q is missing", attribute)
		}
	}
	urlConfigs := requireTerraformCLINestedBlock(t, urlAccess, "configs", "single")
	if _, ok := urlConfigs.Attributes["status"]; !ok {
		t.Fatalf("URL access configs attribute %q is missing", "status")
	}
	if _, ok := urlConfigs.Attributes["action"]; ok {
		t.Fatalf("URL access configs unexpectedly exposes a top-level action attribute")
	}
	ruleList := requireTerraformCLINestedBlock(t, urlConfigs, "rule_list", "single")
	ruleItem := requireTerraformCLINestedBlock(t, ruleList, "item", "list")
	if _, ok := ruleItem.Attributes["idx"]; ok {
		t.Fatalf("URL access rule_list.item unexpectedly exposes idx")
	}
	gotURLItemAttributes := make([]string, 0, len(ruleItem.Attributes))
	for name := range ruleItem.Attributes {
		gotURLItemAttributes = append(gotURLItemAttributes, name)
	}
	sort.Strings(gotURLItemAttributes)
	wantURLItemAttributes := []string{"action", "name", "url", "url_type"}
	if !reflect.DeepEqual(gotURLItemAttributes, wantURLItemAttributes) {
		t.Fatalf("URL access rule_list.item attributes = %#v, want %#v", gotURLItemAttributes, wantURLItemAttributes)
	}
}

func requireTerraformCLINestedBlock(t *testing.T, block terraformCLISchemaBlock, name, nestingMode string) terraformCLISchemaBlock {
	t.Helper()
	nested, ok := block.BlockTypes[name]
	if !ok {
		t.Fatalf("nested block %q is missing", name)
	}
	if nested.NestingMode != nestingMode {
		t.Fatalf("nested block %q mode = %q, want %q", name, nested.NestingMode, nestingMode)
	}
	return nested.Block
}

func requireTerraformCLIExit(t *testing.T, result terraformCLIResult, want int) {
	t.Helper()
	if result.ExitCode != want {
		t.Fatalf("Terraform exit code = %d, want %d\n%s", result.ExitCode, want, result.output())
	}
}

func requireTerraformCLINoOpPlan(t *testing.T, result terraformCLIResult) {
	t.Helper()
	if result.ExitCode != 0 {
		t.Fatalf("Terraform no-op plan exit code = %d, want 0\n%s", result.ExitCode, result.output())
	}
}

type terraformCLIRecordedRequest struct {
	Method     string
	RequestURI string
	Host       string
	Proto      string
	Header     http.Header
	Body       []byte
}

// terraformCLIMock is the shared httptest backend for the local Terraform CLI
// lifecycle tests. It records every request, enforces the expected path and
// dummy Basic token, serves the remote result on GET, and validates then
// stores PUT bodies using the resource-specific validator supplied at
// construction time.
type terraformCLIMock struct {
	mu            sync.Mutex
	expectedPath  string
	expectedToken string
	remote        json.RawMessage
	putValidator  func([]byte) error
	// putRemoteShaper, when set, transforms a validated PUT body into the
	// GET-shaped remote result stored for subsequent GETs. This models
	// resources whose GET and PUT item shapes differ (e.g. ip_protection,
	// where GET includes wire-only idx but the pinned PUT schema omits it).
	// When nil, the PUT body is stored verbatim (GET and PUT shapes match).
	putRemoteShaper func([]byte) (json.RawMessage, error)
	requests        []terraformCLIRecordedRequest
	handlerFailure  []string
}

// terraformCLICSRFMock is an alias kept for the CSRF lifecycle test so the
// existing helper names remain readable; it shares the generic implementation.
type terraformCLICSRFMock = terraformCLIMock

func newTerraformCLICSRFMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLICSRFMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLICSRFResult)
}

func newTerraformCLIURLAccessMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIURLAccessResult)
}

func newTerraformCLIMock(t *testing.T, expectedPath, expectedToken string, initial any, putValidator func([]byte) error) *terraformCLIMock {
	t.Helper()
	encoded, err := json.Marshal(initial)
	if err != nil {
		t.Fatalf("encode initial mock result: %v", err)
	}
	if err := putValidator(encoded); err != nil {
		t.Fatalf("validate initial mock result: %v", err)
	}
	return &terraformCLIMock{
		expectedPath:  expectedPath,
		expectedToken: expectedToken,
		remote:        encoded,
		putValidator:  putValidator,
	}
}

func (m *terraformCLIMock) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	body, readErr := io.ReadAll(request.Body)
	if readErr != nil {
		m.fail(response, http.StatusUnprocessableEntity, "read request body: %v", readErr)
		return
	}
	m.mu.Lock()
	m.requests = append(m.requests, terraformCLIRecordedRequest{
		Method:     request.Method,
		RequestURI: request.RequestURI,
		Host:       request.Host,
		Proto:      request.Proto,
		Header:     request.Header.Clone(),
		Body:       append([]byte(nil), body...),
	})
	m.mu.Unlock()

	if request.URL.EscapedPath() != m.expectedPath || request.URL.RawQuery != "" {
		m.fail(response, http.StatusUnprocessableEntity, "request path = %q, want %q", request.URL.EscapedPath(), m.expectedPath)
		return
	}
	if request.Header.Get("Authorization") != "Basic "+m.expectedToken {
		m.fail(response, http.StatusUnauthorized, "authorization header was not the dummy local token")
		return
	}

	switch request.Method {
	case http.MethodGet:
		if len(bytes.TrimSpace(body)) != 0 {
			m.fail(response, http.StatusUnprocessableEntity, "GET request contained a body")
			return
		}
		m.mu.Lock()
		remote := append(json.RawMessage(nil), m.remote...)
		m.mu.Unlock()
		payload, err := json.Marshal(map[string]json.RawMessage{
			"result":        remote,
			"mock_metadata": json.RawMessage(`{"source":"local-httptest"}`),
		})
		if err != nil {
			m.fail(response, http.StatusInternalServerError, "encode GET response: %v", err)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(payload)
	case http.MethodPut:
		if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
			m.fail(response, http.StatusUnsupportedMediaType, "PUT content type was not application/json")
			return
		}
		if err := m.putValidator(body); err != nil {
			m.fail(response, http.StatusUnprocessableEntity, "invalid PUT result: %v", err)
			return
		}
		stored := append(json.RawMessage(nil), body...)
		if m.putRemoteShaper != nil {
			shaped, err := m.putRemoteShaper(body)
			if err != nil {
				m.fail(response, http.StatusUnprocessableEntity, "shape PUT result for GET: %v", err)
				return
			}
			stored = shaped
		}
		m.mu.Lock()
		m.remote = stored
		m.mu.Unlock()
		response.WriteHeader(http.StatusNoContent)
	default:
		m.fail(response, http.StatusMethodNotAllowed, "method %s is not supported", request.Method)
	}
}

func (m *terraformCLICSRFMock) fail(response http.ResponseWriter, status int, format string, arguments ...any) {
	message := fmt.Sprintf(format, arguments...)
	m.mu.Lock()
	m.handlerFailure = append(m.handlerFailure, message)
	m.mu.Unlock()
	http.Error(response, message, status)
}

func (m *terraformCLICSRFMock) resetRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
}

func (m *terraformCLICSRFMock) recordedRequests() []terraformCLIRecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]terraformCLIRecordedRequest, len(m.requests))
	for index, request := range m.requests {
		result[index] = request
		result[index].Header = request.Header.Clone()
		result[index].Body = append([]byte(nil), request.Body...)
	}
	return result
}

func (m *terraformCLICSRFMock) remoteResult() json.RawMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append(json.RawMessage(nil), m.remote...)
}

// setRemoteResult replaces the mock's remote result, modeling an out-of-band
// change (drift) made outside Terraform. It runs the putValidator against the
// new value so a malformed drift body fails the test rather than the request.
func (m *terraformCLICSRFMock) setRemoteResult(t *testing.T, result any) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode drift remote result: %v", err)
	}
	m.mu.Lock()
	validator := m.putValidator
	m.mu.Unlock()
	if validator != nil {
		if err := validator(encoded); err != nil {
			t.Fatalf("drift remote result failed validator: %v", err)
		}
	}
	m.mu.Lock()
	m.remote = encoded
	m.mu.Unlock()
}

// requireTerraformCLIBoolDrift mutates one owned boolean scalar
// outside Terraform, proves refresh+plan detects the drift without issuing a
// PUT, then restores the exact remote result and proves no-op convergence.
// It is shared by the custom-module CLI lifecycles so every resource exercises
// the plan's explicit out-of-band drift phase. Most modules place the scalar
// under configs; non-standard envelopes such as content_routing place it at
// the result root.
func requireTerraformCLIBoolDrift(t *testing.T, cli terraformCLI, workDir string, mock *terraformCLIMock, field string) {
	t.Helper()

	original := mock.remoteResult()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(original, &result); err != nil {
		t.Fatalf("decode remote result before drift: %v", err)
	}
	owner := result
	ownerName := "result"
	if configsRaw, ok := result["configs"]; ok {
		var configs map[string]json.RawMessage
		if err := json.Unmarshal(configsRaw, &configs); err != nil {
			t.Fatalf("decode remote configs before drift: %v", err)
		}
		owner = configs
		ownerName = "configs"
	}
	var current bool
	raw, ok := owner[field]
	if !ok {
		t.Fatalf("remote %s missing drift field %q", ownerName, field)
	}
	if err := json.Unmarshal(raw, &current); err != nil {
		t.Fatalf("decode remote drift field %q as boolean: %v", field, err)
	}
	mutated, err := json.Marshal(!current)
	if err != nil {
		t.Fatalf("encode drift field %q: %v", field, err)
	}
	owner[field] = mutated
	if ownerName == "configs" {
		encodedConfigs, err := json.Marshal(owner)
		if err != nil {
			t.Fatalf("encode drifted configs: %v", err)
		}
		result["configs"] = encodedConfigs
	}
	mock.setRemoteResult(t, result)

	mock.resetRequests()
	driftResult := cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false")
	if driftResult.ExitCode != 2 {
		t.Fatalf("drift plan exit code = %d, want 2 (drift detected)\n%s", driftResult.ExitCode, driftResult.output())
	}
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())

	mock.setRemoteResult(t, original)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())
}

func (m *terraformCLICSRFMock) requireNoHandlerFailures(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.handlerFailure) != 0 {
		t.Fatalf("mock API handler failures: %s", strings.Join(m.handlerFailure, "; "))
	}
}

func validateTerraformCLICSRFResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var action string
	if err := json.Unmarshal(configs["action"], &action); err != nil {
		return fmt.Errorf("action must be a string: %w", err)
	}
	if action != "alert" && action != "alert_deny" && action != "deny_no_log" {
		return fmt.Errorf("action %q is invalid", action)
	}
	var status bool
	if err := json.Unmarshal(configs["status"], &status); err != nil {
		return fmt.Errorf("status must be a boolean: %w", err)
	}
	for _, name := range []string{"page_list", "url_list"} {
		var items []json.RawMessage
		if err := json.Unmarshal(configs[name], &items); err != nil {
			return fmt.Errorf("%s must be an array: %w", name, err)
		}
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	return nil
}

// validateTerraformCLIURLAccessResult enforces the generated strict wire
// decoder contract in the local mock: configs must carry a non-null status
// boolean and a bounded rule_list whose items contain idx/action/name/url/
// url_type with reviewed enum values. It additionally mirrors the backend v2
// relationship that url_type="string" requires a slash-prefixed URL; the
// generated provider leaves that cross-field rule to the backend. The mock does
// not attempt to emulate Python regex compilation. Unknown config and envelope
// fields remain tolerated so preserve-unknown-data behavior can be exercised.
func validateTerraformCLIURLAccessResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var status bool
	if err := json.Unmarshal(configs["status"], &status); err != nil {
		return fmt.Errorf("status must be a boolean: %w", err)
	}
	ruleListRaw, ok := configs["rule_list"]
	if !ok {
		return errors.New("rule_list must be present")
	}
	if bytes.Equal(bytes.TrimSpace(ruleListRaw), []byte("null")) {
		return errors.New("rule_list must not be null")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(ruleListRaw, &items); err != nil {
		return fmt.Errorf("rule_list must be an array: %w", err)
	}
	if len(items) > terraformCLIURLAccessMaxItems {
		return fmt.Errorf("rule_list has %d items, at most %d allowed", len(items), terraformCLIURLAccessMaxItems)
	}
	for index, rawItem := range items {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawItem, &object); err != nil {
			return fmt.Errorf("rule_list item %d was not an object: %w", index+1, err)
		}
		var action string
		if err := json.Unmarshal(object["action"], &action); err != nil {
			return fmt.Errorf("rule_list item %d action must be a string: %w", index+1, err)
		}
		if !terraformCLIURLAccessActionValid(action) {
			return fmt.Errorf("rule_list item %d action %q is invalid", index+1, action)
		}
		var name, url string
		if err := json.Unmarshal(object["name"], &name); err != nil {
			return fmt.Errorf("rule_list item %d name must be a string: %w", index+1, err)
		}
		if err := json.Unmarshal(object["url"], &url); err != nil {
			return fmt.Errorf("rule_list item %d url must be a string: %w", index+1, err)
		}
		urlTypeRaw, ok := object["url_type"]
		if !ok || bytes.Equal(bytes.TrimSpace(urlTypeRaw), []byte("null")) {
			return fmt.Errorf("rule_list item %d url_type is required", index+1)
		}
		var urlType string
		if err := json.Unmarshal(urlTypeRaw, &urlType); err != nil {
			return fmt.Errorf("rule_list item %d url_type must be a string: %w", index+1, err)
		}
		if !terraformCLIURLAccessURLTypeValid(urlType) {
			return fmt.Errorf("rule_list item %d url_type %q is invalid", index+1, urlType)
		}
		if urlType == "string" && !strings.HasPrefix(url, "/") {
			return fmt.Errorf("rule_list item %d url %q with url_type=string must start with /", index+1, url)
		}
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	return nil
}

const terraformCLIURLAccessMaxItems = 12

func terraformCLIURLAccessActionValid(value string) bool {
	switch value {
	case "pass", "alert_deny", "deny_no_log", "continue":
		return true
	}
	return false
}

func terraformCLIURLAccessURLTypeValid(value string) bool {
	switch value {
	case "regex", "string":
		return true
	}
	return false
}

func requireTerraformCLIMethods(t *testing.T, requests []terraformCLIRecordedRequest, want []string) {
	t.Helper()
	got := make([]string, len(requests))
	for index, request := range requests {
		got[index] = request.Method
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request methods = %#v, want %#v", got, want)
	}
}

func requireTerraformCLIGetPutGetSubsequence(t *testing.T, requests []terraformCLIRecordedRequest) {
	t.Helper()
	for index := 1; index+1 < len(requests); index++ {
		if requests[index-1].Method == http.MethodGet && requests[index].Method == http.MethodPut && requests[index+1].Method == http.MethodGet {
			return
		}
	}
	methods := make([]string, len(requests))
	for index, request := range requests {
		methods[index] = request.Method
	}
	t.Fatalf("requests did not contain GET -> PUT -> GET: %#v", methods)
}

func requireTerraformCLISinglePUT(t *testing.T, requests []terraformCLIRecordedRequest) terraformCLIRecordedRequest {
	t.Helper()
	var puts []terraformCLIRecordedRequest
	for _, request := range requests {
		if request.Method == http.MethodPut {
			puts = append(puts, request)
		}
	}
	if len(puts) != 1 {
		t.Fatalf("PUT request count = %d, want 1", len(puts))
	}
	return puts[0]
}

func requireTerraformCLINoPUT(t *testing.T, requests []terraformCLIRecordedRequest) {
	t.Helper()
	for _, request := range requests {
		if request.Method == http.MethodPut {
			t.Fatalf("unexpected PUT request body: %s", request.Body)
		}
	}
}

func requireTerraformCLIAtLeastOneGETAndNoPUT(t *testing.T, requests []terraformCLIRecordedRequest) {
	t.Helper()
	gets := 0
	for _, request := range requests {
		switch request.Method {
		case http.MethodGet:
			gets++
		case http.MethodPut:
			t.Fatalf("unexpected PUT request body: %s", request.Body)
		}
	}
	if gets == 0 {
		t.Fatal("expected at least one GET request")
	}
}

// requireTerraformCLIDisableOnDestroy exercises the real served Terraform
// Delete path for a promoted app module. It proves the provider performs a
// preserving GET/PUT/GET lifecycle, changes only template and configs.status,
// and removes the object from Terraform state.
func requireTerraformCLIDisableOnDestroy(
	t *testing.T,
	cli terraformCLI,
	workDir string,
	mock *terraformCLIMock,
) {
	t.Helper()

	before := mock.remoteResult()
	expected := terraformCLIDisabledResult(t, before)
	mock.resetRequests()

	destroyResult := cli.run(t, workDir, "destroy", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, destroyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	put := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLITemplate(t, put.Body, false)
	requireTerraformCLIConfigScalar(t, put.Body, "status", false)
	requireTerraformCLIJSONEqual(t, mock.remoteResult(), expected, "disable-on-destroy changed an unowned remote field")

	stateList := cli.run(t, workDir, "state", "list", "-no-color")
	requireTerraformCLIExit(t, stateList, 0)
	if strings.TrimSpace(stateList.Stdout) != "" {
		t.Fatalf("Terraform state still contains resources after destroy: %q", stateList.Stdout)
	}
}

func terraformCLIDisabledResult(t *testing.T, before json.RawMessage) json.RawMessage {
	t.Helper()

	var result map[string]json.RawMessage
	if err := json.Unmarshal(before, &result); err != nil {
		t.Fatalf("decode remote result before disable-on-destroy: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode remote configs before disable-on-destroy: %v", err)
	}
	result["template"] = json.RawMessage("false")
	configs["status"] = json.RawMessage("false")
	encodedConfigs, err := json.Marshal(configs)
	if err != nil {
		t.Fatalf("encode expected disabled configs: %v", err)
	}
	result["configs"] = encodedConfigs
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode expected disabled result: %v", err)
	}
	return encoded
}

func requireTerraformCLIConfigScalar(t *testing.T, resultJSON []byte, name string, want any) {
	t.Helper()
	raw := requireTerraformCLIConfigRaw(t, resultJSON, name)
	var got any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode config %s: %v", name, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config %s = %#v, want %#v", name, got, want)
	}
}

func requireTerraformCLITemplate(t *testing.T, resultJSON []byte, want bool) {
	t.Helper()
	var result struct {
		Template bool `json:"template"`
	}
	if err := json.Unmarshal(resultJSON, &result); err != nil {
		t.Fatalf("decode WAF module template: %v", err)
	}
	if result.Template != want {
		t.Fatalf("template = %t, want %t", result.Template, want)
	}
}

func requireTerraformCLIConfigRaw(t *testing.T, resultJSON []byte, name string) json.RawMessage {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(resultJSON, &result); err != nil {
		t.Fatalf("decode WAF module result: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode WAF module configs: %v", err)
	}
	raw, ok := configs[name]
	if !ok {
		t.Fatalf("WAF module configs are missing %q", name)
	}
	return append(json.RawMessage(nil), raw...)
}

func requireTerraformCLIArray(t *testing.T, resultJSON []byte, name string, wantURLs []string) {
	t.Helper()
	raw := requireTerraformCLIConfigRaw(t, resultJSON, name)
	var items []struct {
		Index int    `json:"idx"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if len(items) != len(wantURLs) {
		t.Fatalf("%s item count = %d, want %d", name, len(items), len(wantURLs))
	}
	for index, item := range items {
		if item.Index != index+1 {
			t.Fatalf("%s item %d idx = %d, want %d", name, index+1, item.Index, index+1)
		}
		if item.URL != wantURLs[index] {
			t.Fatalf("%s item %d url = %q, want %q", name, index+1, item.URL, wantURLs[index])
		}
	}
}

type terraformCLIURLAccessItem struct {
	Index   int    `json:"idx"`
	Action  string `json:"action"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	URLType string `json:"url_type"`
}

func requireTerraformCLIURLAccessArray(t *testing.T, resultJSON []byte, name string, want []terraformCLIURLAccessItem) {
	t.Helper()
	raw := requireTerraformCLIConfigRaw(t, resultJSON, name)
	var items []terraformCLIURLAccessItem
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if len(items) != len(want) {
		t.Fatalf("%s item count = %d, want %d", name, len(items), len(want))
	}
	for index, item := range items {
		if item.Index != index+1 {
			t.Fatalf("%s item %d idx = %d, want %d", name, index+1, item.Index, index+1)
		}
		if item.Action != want[index].Action {
			t.Fatalf("%s item %d action = %q, want %q", name, index+1, item.Action, want[index].Action)
		}
		if item.Name != want[index].Name {
			t.Fatalf("%s item %d name = %q, want %q", name, index+1, item.Name, want[index].Name)
		}
		if item.URL != want[index].URL {
			t.Fatalf("%s item %d url = %q, want %q", name, index+1, item.URL, want[index].URL)
		}
		if item.URLType != want[index].URLType {
			t.Fatalf("%s item %d url_type = %q, want %q", name, index+1, item.URLType, want[index].URLType)
		}
	}
}

func requireTerraformCLIManagedItemDefaults(t *testing.T, resultJSON []byte, name string, itemIndex int) {
	t.Helper()
	raw := requireTerraformCLIConfigRaw(t, resultJSON, name)
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if itemIndex < 0 || itemIndex >= len(items) {
		t.Fatalf("%s item index %d is outside %d items", name, itemIndex, len(items))
	}
	item := items[itemIndex]
	var filter bool
	if err := json.Unmarshal(item["filter"], &filter); err != nil {
		t.Fatalf("decode %s item %d filter: %v", name, itemIndex+1, err)
	}
	if filter {
		t.Fatalf("%s item %d filter = true, want default false", name, itemIndex+1)
	}
	for _, optional := range []string{"name", "value"} {
		if _, ok := item[optional]; ok {
			t.Fatalf("%s item %d retained omitted %s", name, itemIndex+1, optional)
		}
	}
}

func requireTerraformCLIEmptyArray(t *testing.T, resultJSON []byte, name string) {
	t.Helper()
	raw := requireTerraformCLIConfigRaw(t, resultJSON, name)
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if items == nil || len(items) != 0 {
		t.Fatalf("%s = %s, want []", name, raw)
	}
}

// requireTerraformCLIStringIdx asserts that every item in the named collection
// serializes its wire-only idx as a JSON string (e.g. "1"), not a number. This
// is the wire-encoding check for resources whose reviewed idx is string-typed.
func requireTerraformCLIStringIdx(t *testing.T, resultJSON []byte, name string) {
	t.Helper()
	raw := requireTerraformCLIConfigRaw(t, resultJSON, name)
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	for i, item := range items {
		idxRaw, ok := item["idx"]
		if !ok {
			t.Fatalf("%s item %d is missing idx", name, i)
		}
		trimmed := bytes.TrimSpace(idxRaw)
		if len(trimmed) == 0 || trimmed[0] != '"' {
			t.Fatalf("%s item %d idx = %s, want a JSON string", name, i, trimmed)
		}
		var idx string
		if err := json.Unmarshal(trimmed, &idx); err != nil {
			t.Fatalf("%s item %d idx is not a valid JSON string: %v", name, i, err)
		}
		if v, err := strconv.Atoi(idx); err != nil || v <= 0 {
			t.Fatalf("%s item %d idx = %q, want a string-encoded positive integer", name, i, idx)
		}
	}
}

func requireTerraformCLIUnknownFields(t *testing.T, original, updated []byte) {
	t.Helper()
	originalEnvelope := requireTerraformCLIRawField(t, original, "future_envelope")
	updatedEnvelope := requireTerraformCLIRawField(t, updated, "future_envelope")
	requireTerraformCLIJSONEqual(t, updatedEnvelope, originalEnvelope, "unknown result-envelope field was not preserved")
	originalConfig := requireTerraformCLIConfigRaw(t, original, "future_config")
	updatedConfig := requireTerraformCLIConfigRaw(t, updated, "future_config")
	requireTerraformCLIJSONEqual(t, updatedConfig, originalConfig, "unknown top-level config field was not preserved")
}

func requireTerraformCLIRawField(t *testing.T, data []byte, name string) json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("decode JSON object: %v", err)
	}
	raw, ok := object[name]
	if !ok {
		t.Fatalf("JSON object is missing %q", name)
	}
	return raw
}

func requireTerraformCLIJSONEqual(t *testing.T, got, want []byte, message string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode actual JSON for %s: %v", message, err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("decode expected JSON for %s: %v", message, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("%s: got %s, want %s", message, got, want)
	}
}

const terraformCLIRequestLimitsTestAddress = "fortiappseccloud_waf_request_limits.test"

func newTerraformCLIRequestLimitsMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIRequestLimitsResult)
}

func terraformCLIRequestLimitsHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_request_limits", "test", epID, resourceBody)
}

// initialRequestLimitsBody configures a representative subset of integer,
// boolean, and enum scalars plus a populated allow_methods wrapper.
func initialRequestLimitsBody() string {
	return `  template = false

  configs {
    status             = true
    body_param_len     = 4096
    cookie_num         = 64
    http_req_len       = 1024
    malformed_url_check = true
    range_num          = 5
    http_header_action = "alert"

    allow_methods {
      item { method = "get"  }
      item { method = "post" }
      item { method = "head" }
    }
  }
`
}

func scalarUpdateRequestLimitsBody() string {
	return `  template = false

  configs {
    status             = false
    body_param_len     = 8192
  }
`
}

func emptyAllowMethodsRequestLimitsBody() string {
	return `  template = false

  configs {
    status             = true
    body_param_len     = 4096

    allow_methods {}
  }
`
}

func outOfRangeRequestLimitsBody() string {
	return `  template = false

  configs {
    status         = true
    body_param_len = 999999
  }
`
}

func invalidMethodRequestLimitsBody() string {
	return `  template = false

  configs {
    status         = true
    body_param_len = 4096

    allow_methods {
      item { method = "get"     }
      item { method = "invalid" }
    }
  }
`
}

func invalidWindowRangeRequestLimitsBody() string {
	return `  template = false

  configs {
    status                                 = true
    rg_min_setting_initial_window_size     = 10
    rg_max_setting_initial_window_size     = 10
  }
`
}

func validateTerraformCLIRequestLimitsResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	allowRaw, ok := configs["allow_methods"]
	if !ok {
		return errors.New("allow_methods must be present")
	}
	if bytes.Equal(bytes.TrimSpace(allowRaw), []byte("null")) {
		return errors.New("allow_methods must not be null")
	}
	var methods []string
	if err := json.Unmarshal(allowRaw, &methods); err != nil {
		return fmt.Errorf("allow_methods must be a string array: %w", err)
	}
	for index, method := range methods {
		if !terraformCLIRequestLimitsMethodValid(method) {
			return fmt.Errorf("allow_methods item %d method %q is invalid", index+1, method)
		}
	}
	return nil
}

func terraformCLIRequestLimitsMethodValid(value string) bool {
	switch value {
	case "connect", "delete", "get", "head", "options", "others", "patch", "post", "put", "rpc", "trace", "webdav":
		return true
	}
	return false
}

func requireTerraformCLIAllowMethods(t *testing.T, resultJSON []byte, want []string) {
	t.Helper()
	raw := requireTerraformCLIConfigRaw(t, resultJSON, "allow_methods")
	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode allow_methods: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allow_methods = %#v, want %#v", got, want)
	}
}

func TestTerraformCLIGeneratedRequestLimitsLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/request-limits"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/request_limits"
	mock := newTerraformCLIRequestLimitsMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"allow_methods":                        []any{"get", "post", "head"},
			"body_param_len":                       8192,
			"chunk_size_check":                     false,
			"cl_te_coexist_check":                  false,
			"content_length_action":                "alert_deny",
			"content_length_num":                   0,
			"cookie_num":                           128,
			"duplicate_param_check":                false,
			"header_len":                           8192,
			"header_line_num":                      200,
			"header_line_num_action":               "alert_deny",
			"header_name_len":                      50,
			"header_value_len":                     4096,
			"http2_max_req_action":                 "block_period",
			"http2_max_requests_check":             true,
			"http2_max_requests_num":               1000,
			"http2_rst_action":                     "block_period",
			"http2_rst_stream_check":               true,
			"http2_rst_stream_frq_check":           true,
			"http2_rst_stream_frq_num":             20,
			"http2_rst_stream_num":                 50,
			"http_header_action":                   "alert_deny",
			"http_param_action":                    "alert_deny",
			"http_req_action":                      "alert_deny",
			"http_req_len":                         2048,
			"illegal_char_check":                   true,
			"illegal_cl_check":                     false,
			"illegal_ctype_check":                  false,
			"illegal_header_name_check":            false,
			"illegal_header_value_check":           false,
			"illegal_host_name_check":              false,
			"illegal_http_req_method_check":        false,
			"illegal_http_ver_check":               false,
			"illegal_param_name_check":             false,
			"illegal_param_value_check":            false,
			"illegal_res_code_check":               false,
			"inconsistent_cl_check":                false,
			"malformed_req_check":                  false,
			"malformed_url_check":                  true,
			"max_http_body_length":                 16384,
			"max_setting_current_streams_num":      1000,
			"max_setting_frame_size":               4194303,
			"max_setting_header_list_size":         65536,
			"max_setting_header_table_size":        65535,
			"max_setting_initial_window_size":      33554432,
			"multipart_formdata_bad_request_check": false,
			"null_char_check":                      true,
			"odd_and_even_space_attack_check":      false,
			"others_action":                        "alert_deny",
			"param_name_check":                     false,
			"param_value_check":                    false,
			"post_req_ctype_check":                 false,
			"range_num":                            5,
			"range_overlapping_check":              false,
			"redundant_header_check":               true,
			"req_filename_len":                     2048,
			"rg_max_setting_initial_window_size":   33554432,
			"rg_min_setting_initial_window_size":   0,
			"rpc_protocol_check":                   false,
			"status":                               true,
			"url_param_len":                        8192,
			"url_param_name_len":                   4096,
			"url_param_num":                        128,
			"url_param_value_len":                  4096,
			"web_socket_protocol_check":            false,
			"future_config":                        map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-request-limits")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIRequestLimitsHCL(server.URL, epID, initialRequestLimitsBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "body_param_len", float64(4096))
	requireTerraformCLIConfigScalar(t, initialPut.Body, "http_header_action", "alert")
	requireTerraformCLIAllowMethods(t, initialPut.Body, []string{"get", "post", "head"})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Omitting the allow_methods wrapper preserves the raw remote array while
	// the configured scalars are updated.
	beforeOmitted := mock.remoteResult()
	beforeAllow := requireTerraformCLIConfigRaw(t, beforeOmitted, "allow_methods")
	writeTerraformCLIConfig(t, workDir, terraformCLIRequestLimitsHCL(server.URL, epID, scalarUpdateRequestLimitsBody()))
	mock.resetRequests()
	updateResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, updateResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	omittedPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, omittedPut.Body, "status", false)
	requireTerraformCLIConfigScalar(t, omittedPut.Body, "body_param_len", float64(8192))
	afterAllow := requireTerraformCLIConfigRaw(t, omittedPut.Body, "allow_methods")
	requireTerraformCLIJSONEqual(t, afterAllow, beforeAllow, "omitted allow_methods was not preserved")
	requireTerraformCLIUnknownFields(t, initialUnknown, omittedPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// A present empty allow_methods wrapper replaces the array with [].
	writeTerraformCLIConfig(t, workDir, terraformCLIRequestLimitsHCL(server.URL, epID, emptyAllowMethodsRequestLimitsBody()))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "allow_methods")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply the populated configuration so the remote allow_methods array
	// matches the configuration used for import and the post-import no-op plan.
	finalHCL := terraformCLIRequestLimitsHCL(server.URL, epID, initialRequestLimitsBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-request-limits")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIRequestLimitsTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	validationCases := []struct {
		name string
		body string
	}{
		{name: "out of range integer", body: outOfRangeRequestLimitsBody()},
		{name: "invalid initial window comparison", body: invalidWindowRangeRequestLimitsBody()},
		{name: "invalid method", body: invalidMethodRequestLimitsBody()},
		{name: "configs missing when template is false", body: "  template = false\n"},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-request-limits", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIRequestLimitsHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != 1 {
				t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

const terraformCLIKnownAttacksTestAddress = "fortiappseccloud_waf_known_attacks.test"

func newTerraformCLIKnownAttacksMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIKnownAttacksResult)
}

func terraformCLIKnownAttacksHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_known_attacks", "test", epID, resourceBody)
}

func initialKnownAttacksBody() string {
	return `  template = false

  configs {
    status            = true
    sensitivity_level = 2
    action            = "alert_deny"

    sig_except_rules {
      item {
        sig_id   = "030000010"
        sig_name = "SQL Injection"
        cookie {
          check_status = false
          check_value  = ""
          status       = true
          type         = "string"
          value        = "sessionid"
        }
        host {
          status = true
          type   = "string"
          value  = "www.example.com"
        }
        http_header {
          check_status = false
          check_value  = ""
          status       = true
          type         = "string"
          value        = "x-custom"
        }
        json {
          check_status = false
          check_value  = ""
          status       = true
          type         = "string"
          value        = "field"
        }
        param {
          check_status = false
          check_value  = ""
          status       = true
          type         = "string"
          value        = "query"
        }
        url {
          status = true
          type   = "regex"
          value  = "^/admin"
        }
      }
    }

    stx_except_rules {
      item {
        attack_cat   = "SQL Injection (Syntax Based Detection)"
        attack_name  = "Stacked Queries SQL Injection"
        cookie {
          status = true
          type   = "string"
          value  = "sessionid"
        }
        param {
          status = true
          type   = "string"
          value  = "query"
        }
        url {
          status = true
          type   = "string"
          value  = "/admin"
        }
      }
    }
  }
`
}

func validateTerraformCLIKnownAttacksResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"sig_except_rules", "stx_except_rules"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s must be an array: %w", name, err)
		}
		if len(items) > 100 {
			return fmt.Errorf("%s has %d items, at most 100 allowed", name, len(items))
		}
	}
	return nil
}

func TestTerraformCLIGeneratedKnownAttacksLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/known-attacks"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/known_attacks"
	mock := newTerraformCLIKnownAttacksMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"action":                "alert_deny",
			"arithmetic_sql_inject": false,
			"condition_sql_inject":  false,
			"cross_site_script":     true,
			"cross_site_script_ext": false,
			"embed_sql_inject":      true,
			"future_config":         map[string]any{"keep": true, "revision": 9},
			"generic_attacks":       true,
			"generic_attacks_ext":   false,
			"html_attr_xss_inject":  true,
			"html_css_xss_inject":   true,
			"html_tag_xss_inject":   true,
			"js_func_xss_inject":    true,
			"js_var_xss_inject":     true,
			"known_exploits":        true,
			"line_comments":         false,
			"sensitivity_level":     1,
			"sig_except_rules":      []any{},
			"sql_func_inject":       false,
			"sql_inject":            true,
			"sql_inject_ext":        false,
			"stack_sql_inject":      true,
			"status":                true,
			"stx_except_rules":      []any{},
			"trojans":               true,
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-known-attacks")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIKnownAttacksHCL(server.URL, epID, initialKnownAttacksBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "sensitivity_level", float64(2))
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty sig_except_rules wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIKnownAttacksHCL(server.URL, epID, `  template = false

  configs {
    status            = true
    sensitivity_level = 2
    action            = "alert_deny"

    sig_except_rules {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "sig_except_rules")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIKnownAttacksHCL(server.URL, epID, initialKnownAttacksBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-known-attacks")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIKnownAttacksTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

const terraformCLIHttpHeaderSecurityTestAddress = "fortiappseccloud_waf_http_header_security.test"

func newTerraformCLIHttpHeaderSecurityMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIHttpHeaderSecurityResult)
}

func terraformCLIHttpHeaderSecurityHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_http_header_security", "test", epID, resourceBody)
}

func initialHttpHeaderSecurityBody() string {
	return `  template = false

  configs {
    status               = true
    content_security_policy = true
    referrer_policy        = true
    x_content_type_options = true
    x_frame_options       = true
    x_xss_protection      = true
  }
`
}

func validateTerraformCLIHttpHeaderSecurityResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	return nil
}

func TestTerraformCLIGeneratedHttpHeaderSecurityLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/http-header-security"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/http_header_security"
	mock := newTerraformCLIHttpHeaderSecurityMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":                       true,
			"content_security_policy":      true,
			"header_value":                 "",
			"referrer_policy":              true,
			"referrer_policy_header_value": "strict-origin-when-cross-origin",
			"x_content_type_options":       true,
			"x_frame_options":              true,
			"x_xss_protection":             true,
			"future_config":                map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-http-header-security")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIHttpHeaderSecurityHCL(server.URL, epID, initialHttpHeaderSecurityBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-http-header-security")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	finalHCL := terraformCLIHttpHeaderSecurityHCL(server.URL, epID, initialHttpHeaderSecurityBody())
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIHttpHeaderSecurityTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: header_value beyond 1023 characters and
	// referrer_policy_header_value beyond 64 characters must be rejected at
	// plan time without a PUT. These maximum lengths are pinned from OpenAPI.
	validationCases := []struct {
		name string
		body string
	}{
		{name: "header_value exceeds max length", body: tooLongHttpHeaderSecurityValueBody()},
		{name: "referrer_policy_header_value exceeds max length", body: tooLongHttpHeaderSecurityReferrerBody()},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-http-header-security", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIHttpHeaderSecurityHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != 1 {
				t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

func tooLongHttpHeaderSecurityValueBody() string {
	tooLong := strings.Repeat("a", 1024)
	return fmt.Sprintf(`  template = false

  configs {
    status                  = true
    content_security_policy = true
    header_value            = %q
    referrer_policy         = true
    x_content_type_options  = true
    x_frame_options         = true
    x_xss_protection        = true
  }
`, tooLong)
}

func tooLongHttpHeaderSecurityReferrerBody() string {
	tooLong := strings.Repeat("a", 65)
	return fmt.Sprintf(`  template = false

  configs {
    status                       = true
    content_security_policy      = true
    referrer_policy              = true
    referrer_policy_header_value = %q
    x_content_type_options       = true
    x_frame_options              = true
    x_xss_protection             = true
  }
`, tooLong)
}

const terraformCLIGraphQLProtectionTestAddress = "fortiappseccloud_waf_graphql_protection.test"

func newTerraformCLIGraphQLProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIGraphQLProtectionResult)
}

func terraformCLIGraphQLProtectionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_graphql_protection", "test", epID, resourceBody)
}

func initialGraphQLProtectionBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name        = "graphql-default"
        request_url = "/graphql"
      }
    }
  }
`
}

func validateTerraformCLIGraphQLProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	return nil
}

func TestTerraformCLIGeneratedGraphQLProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/graphql-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/graphql_protection"
	mock := newTerraformCLIGraphQLProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"action":        "alert_deny",
			"rule_list":     []any{},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-graphql-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIGraphQLProtectionHCL(server.URL, epID, initialGraphQLProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty rule_list wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIGraphQLProtectionHCL(server.URL, epID, `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "rule_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIGraphQLProtectionHCL(server.URL, epID, initialGraphQLProtectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-graphql-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIGraphQLProtectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: an out-of-range integer item field and a
	// too-long required name must both be rejected at plan time without a PUT.
	validationCases := []struct {
		name string
		body string
	}{
		{name: "out of range item integer", body: outOfRangeGraphQLProtectionBody()},
		{name: "name exceeds max length", body: tooLongGraphQLNameBody()},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-graphql-protection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIGraphQLProtectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != 1 {
				t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

func outOfRangeGraphQLProtectionBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name              = "graphql-range"
        request_url       = "/graphql"
        graphql_data_size = 999999
      }
    }
  }
`
}

func tooLongGraphQLNameBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name        = "this-rule-name-is-far-longer-than-the-reviewed-forty-character-limit"
        request_url = "/graphql"
      }
    }
  }
`
}

const terraformCLIJSONProtectionTestAddress = "fortiappseccloud_waf_json_protection.test"

func newTerraformCLIJSONProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIJSONProtectionResult)
}

func terraformCLIJSONProtectionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_json_protection", "test", epID, resourceBody)
}

func initialJSONProtectionBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    file_list {
      item {
        name         = "json-rule"
        url          = "/api/json"
        filename     = "data.json"
        limit_check  = true
        schema_valid = true
      }
    }
  }
`
}

func validateTerraformCLIJSONProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"file_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedJSONProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/json-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/json_protection"
	mock := newTerraformCLIJSONProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"action":        "alert_deny",
			"bucket":        "",
			"prefix":        "",
			"file_list":     []any{},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-json-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIJSONProtectionHCL(server.URL, epID, initialJSONProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty file_list wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIJSONProtectionHCL(server.URL, epID, `  template = false

  configs {
    status = true
    action = "alert_deny"

    file_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "file_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIJSONProtectionHCL(server.URL, epID, initialJSONProtectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-json-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIJSONProtectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

const terraformCLIXMLProtectionPolicyTestAddress = "fortiappseccloud_waf_xml_protection_policy.test"

func newTerraformCLIXMLProtectionPolicyMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIXMLProtectionPolicyResult)
}

func terraformCLIXMLProtectionPolicyHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_xml_protection_policy", "test", epID, resourceBody)
}

func initialXMLProtectionPolicyBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    file_list {
      item {
        name         = "xml-rule"
        url          = "/api/xml"
        filename     = "schema.xsd"
        limit_check  = true
        entity_check = true
        schema_valid = true
      }
    }
  }
`
}

func validateTerraformCLIXMLProtectionPolicyResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"file_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedXMLProtectionPolicyLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/xml-protection-policy"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/xml_protection_policy"
	mock := newTerraformCLIXMLProtectionPolicyMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"action":        "alert_deny",
			"bucket":        "",
			"prefix":        "",
			"file_list":     []any{},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-xml-protection-policy")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIXMLProtectionPolicyHCL(server.URL, epID, initialXMLProtectionPolicyBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty file_list wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIXMLProtectionPolicyHCL(server.URL, epID, `  template = false

  configs {
    status = true
    action = "alert_deny"

    file_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "file_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIXMLProtectionPolicyHCL(server.URL, epID, initialXMLProtectionPolicyBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-xml-protection-policy")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIXMLProtectionPolicyTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: a too-long name (max 32) and a too-long
	// filename (max 58) must both be rejected at plan time without a PUT.
	validationCases := []struct {
		name string
		body string
	}{
		{name: "name exceeds max length", body: tooLongXMLProtectionPolicyNameBody()},
		{name: "filename exceeds max length", body: tooLongXMLProtectionPolicyFilenameBody()},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-xml-protection-policy", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIXMLProtectionPolicyHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != 1 {
				t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

func tooLongXMLProtectionPolicyNameBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    file_list {
      item {
        name         = "x` + strings.Repeat("m", 33) + `"
        url          = "/api/xml"
        filename     = "schema.xsd"
        limit_check  = true
        entity_check = true
        schema_valid = true
      }
    }
  }
`
}

func tooLongXMLProtectionPolicyFilenameBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    file_list {
      item {
        name         = "xml-rule"
        url          = "/api/xml"
        filename     = "s` + strings.Repeat("x", 58) + `"
        limit_check  = true
        entity_check = true
        schema_valid = true
      }
    }
  }
`
}

const terraformCLIRewritingRequestsTestAddress = "fortiappseccloud_waf_rewriting_requests.test"

func newTerraformCLIRewritingRequestsMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIRewritingRequestsResult)
}

func terraformCLIRewritingRequestsHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_rewriting_requests", "test", epID, resourceBody)
}

func initialRewritingRequestsBody() string {
	return `  template = false

  configs {
    status               = true
    x_forwarded_for      = true
    identify_original_ip = true
    x_header             = "X-Forwarded-For"

    rule_list {
      item {
        name         = "rewrite-example"
        action       = "rewrite-url"
        rewrite_from = "/old"
        rewrite_to   = "/new"

        remove_header {
          item {
            header = "X-Old-Header"
          }
        }
      }
    }
  }
`
}

func validateTerraformCLIRewritingRequestsResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"rule_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedRewritingRequestsLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/rewriting-requests"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/rewriting_requests"
	// The remote GET returns a string-typed idx ("1") to exercise the string-idx
	// decode path; rule_list carries one populated rule.
	mock := newTerraformCLIRewritingRequestsMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":               true,
			"x_forwarded_for":      true,
			"identify_original_ip": true,
			"source_port":          false,
			"x_forwarded_port":     false,
			"x_header":             "X-Forwarded-For",
			"x_real_ip":            false,
			"rule_list":            []any{},
			"future_config":        map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-rewriting-requests")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIRewritingRequestsHCL(server.URL, epID, initialRewritingRequestsBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	// The PUT must serialize idx as a JSON string ("1"), not a number.
	requireTerraformCLIStringIdx(t, initialPut.Body, "rule_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty rule_list wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIRewritingRequestsHCL(server.URL, epID, `  template = false

  configs {
    status = true

    rule_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "rule_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIRewritingRequestsHCL(server.URL, epID, initialRewritingRequestsBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-rewriting-requests")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIRewritingRequestsTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: a too-long name (max 39) and a too-long
	// remove_header header (max 63) must both be rejected at plan time
	// without a PUT.
	validationCases := []struct {
		name string
		body string
	}{
		{name: "name exceeds max length", body: tooLongRewritingRequestsNameBody()},
		{name: "remove_header item exceeds max length", body: tooLongRewritingRequestsRemoveHeaderBody()},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-rewriting-requests", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIRewritingRequestsHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != 1 {
				t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

func tooLongRewritingRequestsNameBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        name = "x` + strings.Repeat("r", 39) + `"
        action = "rewrite-url"
      }
    }
  }
`
}

func tooLongRewritingRequestsRemoveHeaderBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        name = "rewrite-example"
        action = "rewrite-url"

        remove_header {
          item {
            header = "X-` + strings.Repeat("h", 62) + `"
          }
        }
      }
    }
  }
`
}

const terraformCLIAPIGatewayTestAddress = "fortiappseccloud_waf_api_gateway.test"

func newTerraformCLIAPIGatewayMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIAPIGatewayResult)
}

func terraformCLIAPIGatewayHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_api_gateway", "test", epID, resourceBody)
}

func initialAPIGatewayBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name              = "example-rule"
        api_key_verify    = true
        api_key_loc       = "http-header"
        field_name        = "X-API-Key"
        rate_limit_period = 60
        rate_limit_req    = 100

        url_list {
          item {
            frontend = "/api"
            backend  = "/backend"
          }
        }
      }
    }

    user_list {
      item {
        name     = "example-user"
        email    = "user@example.com"
        comments = "example user"
      }
    }
  }
`
}

func validateTerraformCLIAPIGatewayResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"rule_list", "user_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedAPIGatewayLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/api-gateway"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/api_gateway"
	// The remote GET returns computed-only fields (uuid, api_key, create_time)
	// on user_list items to exercise the computed-only decode + PUT graft.
	mock := newTerraformCLIAPIGatewayMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"action":        "alert_deny",
			"rule_list":     []any{},
			"user_list":     []any{map[string]any{"idx": 1, "name": "example-user", "email": "user@example.com", "comments": "example user", "uuid": "test-uuid", "api_key": "test-api-key", "create_time": "2022-03-24 21:27:07"}},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-api-gateway")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIAPIGatewayHCL(server.URL, epID, initialAPIGatewayBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty rule_list + user_list wrappers send [].
	writeTerraformCLIConfig(t, workDir, terraformCLIAPIGatewayHCL(server.URL, epID, `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {}
    user_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "rule_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "user_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIAPIGatewayHCL(server.URL, epID, initialAPIGatewayBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-api-gateway")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIAPIGatewayTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

const terraformCLIParameterValidationTestAddress = "fortiappseccloud_waf_parameter_validation.test"

func newTerraformCLIParameterValidationMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIParameterValidationResult)
}

func terraformCLIParameterValidationHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_parameter_validation", "test", epID, resourceBody)
}

func initialParameterValidationBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        name         = "param-rule"
        url          = "/api/params"
        action       = "alert_deny"
        block_period = 60

        sub_rule_list {
          item {
            name       = "username"
            arg_type   = "data-type"
            arg_val    = "string"
            max_len    = 128
            required   = true
            type_check = true
          }
        }
      }
    }
  }
`
}

func validateTerraformCLIParameterValidationResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"rule_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedParameterValidationLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/parameter-validation"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/parameter_validation"
	mock := newTerraformCLIParameterValidationMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"rule_list":     []any{},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-parameter-validation")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIParameterValidationHCL(server.URL, epID, initialParameterValidationBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIPopulatedRuleListWithSubRuleList(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty rule_list wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIParameterValidationHCL(server.URL, epID, `  template = false

  configs {
    status = true

    rule_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "rule_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIParameterValidationHCL(server.URL, epID, initialParameterValidationBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-parameter-validation")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIParameterValidationTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Regression: apply with sub_rule_list omitted, then refresh → no-op plan.
	omittedHCL := terraformCLIParameterValidationHCL(server.URL, epID, `  template = false

  configs {
    status = true

    rule_list {
      item {
        name         = "param-rule"
        url          = "/api/params"
        action       = "alert_deny"
        block_period = 60
      }
    }
  }
`)
	writeTerraformCLIConfig(t, workDir, omittedHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	omittedRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, omittedRequests)
	omittedPut := requireTerraformCLISinglePUT(t, omittedRequests)
	requireTerraformCLIOmittedSubRuleList(t, omittedPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

// requireTerraformCLIPopulatedRuleListWithSubRuleList asserts the PUT body's
// rule_list carries one item whose nested sub_rule_list carries one sub-item
// with the configured values and the reviewed idx, exercising the nested
// array-of-objects-in-item serialization.
func requireTerraformCLIPopulatedRuleListWithSubRuleList(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	configsRaw, ok := result["configs"]
	if !ok {
		t.Fatal("PUT body missing configs")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var ruleList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["rule_list"], &ruleList); err != nil || len(ruleList) != 1 {
		t.Fatalf("rule_list = %v, want one item", ruleList)
	}
	item := ruleList[0]
	if string(bytes.TrimSpace(item["name"])) != `"param-rule"` {
		t.Errorf("rule_list[0].name = %s, want %q", item["name"], `"param-rule"`)
	}
	subRaw, ok := item["sub_rule_list"]
	if !ok {
		t.Fatal("rule_list[0].sub_rule_list missing")
	}
	var subList []map[string]json.RawMessage
	if err := json.Unmarshal(subRaw, &subList); err != nil || len(subList) != 1 {
		t.Fatalf("sub_rule_list = %v, want one sub-item", subList)
	}
	sub := subList[0]
	if string(bytes.TrimSpace(sub["idx"])) != "1" {
		t.Errorf("sub_rule_list[0].idx = %s, want 1", sub["idx"])
	}
	if string(bytes.TrimSpace(sub["name"])) != `"username"` {
		t.Errorf("sub_rule_list[0].name = %s, want %q", sub["name"], `"username"`)
	}
}

// requireTerraformCLIOmittedSubRuleList asserts the PUT body's rule_list item
// preserves the sub_rule_list from the fresh GET (opaque preservation via merge).
func requireTerraformCLIOmittedSubRuleList(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var ruleList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["rule_list"], &ruleList); err != nil || len(ruleList) != 1 {
		t.Fatalf("rule_list = %v, want one item", ruleList)
	}
	// The provider must merge the prior GET sub_rule_list into the outgoing
	// item (opaque preservation), so sub_rule_list must be present.
	subRaw, hasSub := ruleList[0]["sub_rule_list"]
	if !hasSub {
		t.Fatal("rule_list[0] should contain sub_rule_list (preserved from GET), but it is absent")
	}
	var subItems []map[string]json.RawMessage
	if err := json.Unmarshal(subRaw, &subItems); err != nil || len(subItems) != 1 {
		t.Fatalf("sub_rule_list = %v, want one preserved sub-item", subItems)
	}
}

const terraformCLIWebSocketSecurityTestAddress = "fortiappseccloud_waf_web_socket_security.test"

func newTerraformCLIWebSocketSecurityMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIWebSocketSecurityResult)
}

func terraformCLIWebSocketSecurityHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_web_socket_security", "test", epID, resourceBody)
}

func initialWebSocketSecurityBody() string {
	return `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name              = "ws-rule"
        url               = "/ws"
        allow_binary_text = true
        allow_plain_text  = true
        allow_websocket   = true
        block_attacks     = true
        block_extensions  = false
        max_frm_size      = 64
        max_msg_size      = 1024

        origin_list {
          item {
            origin = "https://example.com"
          }
        }
      }
    }
  }
`
}

func validateTerraformCLIWebSocketSecurityResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"rule_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedWebSocketSecurityLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/web-socket-security"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/web_socket_security"
	mock := newTerraformCLIWebSocketSecurityMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"action":        "alert_deny",
			"rule_list":     []any{},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-web-socket-security")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIWebSocketSecurityHCL(server.URL, epID, initialWebSocketSecurityBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	// The populated rule_list item must serialize the nested origin_list.
	requireTerraformCLIPopulatedRuleListWithOriginList(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty rule_list wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIWebSocketSecurityHCL(server.URL, epID, `  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "rule_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIWebSocketSecurityHCL(server.URL, epID, initialWebSocketSecurityBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-web-socket-security")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIWebSocketSecurityTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

func requireTerraformCLIPopulatedRuleListWithOriginList(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var ruleList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["rule_list"], &ruleList); err != nil || len(ruleList) != 1 {
		t.Fatalf("rule_list = %v, want one item", ruleList)
	}
	item := ruleList[0]
	if string(bytes.TrimSpace(item["name"])) != `"ws-rule"` {
		t.Errorf("rule_list[0].name = %s, want %q", item["name"], `"ws-rule"`)
	}
	originRaw, ok := item["origin_list"]
	if !ok {
		t.Fatal("rule_list[0].origin_list missing")
	}
	var originList []map[string]json.RawMessage
	if err := json.Unmarshal(originRaw, &originList); err != nil || len(originList) != 1 {
		t.Fatalf("origin_list = %v, want one sub-item", originList)
	}
	if string(bytes.TrimSpace(originList[0]["origin"])) != `"https://example.com"` {
		t.Errorf("origin_list[0].origin = %s, want %q", originList[0]["origin"], `"https://example.com"`)
	}
}

const terraformCLIInformationLeakageTestAddress = "fortiappseccloud_waf_information_leakage.test"

func newTerraformCLIInformationLeakageMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIInformationLeakageResult)
}

func terraformCLIInformationLeakageHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_information_leakage",
		"test", epID, resourceBody)
}

func initialInformationLeakageBody() string {
	return `  template = false

  configs {
    status               = true
    action               = "deny_erase_no_log"
    cloak_error_pages    = true
    erase_http_headers   = true
    personal_info        = true
    server_info_disclose = true

    http_headers {
      item {
        header = "Server"
      }
    }

    sig_except_rules {
      item {
        sig_id   = "030000010"
        sig_name = "SQL Injection"
        cookie {
          status = true
          type   = "string"
          value  = "sessionid"
        }
        host {
          status = true
          type   = "string"
          value  = "www.example.com"
        }
        http_header {
          status = true
          type   = "string"
          value  = "X-Example"
        }
        json {
          status = true
          type   = "string"
          value  = "data"
        }
        param {
          status = true
          type   = "string"
          value  = "query"
        }
        url {
          status = true
          type   = "regex"
          value  = "^/admin"
        }
      }
    }
  }
`
}

func validateTerraformCLIInformationLeakageResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"sig_except_rules"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedInformationLeakageLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/information-leakage"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/information_leakage"
	mock := newTerraformCLIInformationLeakageMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":               true,
			"action":               "deny_erase_no_log",
			"cloak_error_pages":    false,
			"erase_http_headers":   true,
			"personal_info":        false,
			"server_info_disclose": true,
			"http_headers":         []any{},
			"sig_except_rules":     []any{},
			"future_config":        map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-information-leakage")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIInformationLeakageHCL(server.URL, epID, initialInformationLeakageBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	// The populated http_headers scalar-string-array and sig_except_rules
	// collection must both serialize correctly.
	requireTerraformCLIInformationLeakagePopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty sig_except_rules wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIInformationLeakageHCL(server.URL, epID, `  template = false

  configs {
    status = true
    action = "deny_erase_no_log"

    sig_except_rules {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "sig_except_rules")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIInformationLeakageHCL(server.URL, epID, initialInformationLeakageBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-information-leakage")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIInformationLeakageTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

func requireTerraformCLIInformationLeakagePopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	// http_headers scalar-string-array: one string "Server".
	var headers []string
	if err := json.Unmarshal(configs["http_headers"], &headers); err != nil || len(headers) != 1 || headers[0] != "Server" {
		t.Fatalf("http_headers = %v, want [\"Server\"]", headers)
	}
	// sig_except_rules: one item with sig_id.
	var sigRules []map[string]json.RawMessage
	if err := json.Unmarshal(configs["sig_except_rules"], &sigRules); err != nil || len(sigRules) != 1 {
		t.Fatalf("sig_except_rules = %v, want one item", sigRules)
	}
	if string(bytes.TrimSpace(sigRules[0]["sig_id"])) != `"030000010"` {
		t.Errorf("sig_except_rules[0].sig_id = %s, want %q", sigRules[0]["sig_id"], `"030000010"`)
	}
}

const terraformCLIDDoSPreventionTestAddress = "fortiappseccloud_waf_ddos_prevention.test"

func newTerraformCLIDDoSPreventionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIDDoSPreventionResult)
}

func terraformCLIDDoSPreventionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_ddos_prevention", "test", epID, resourceBody)
}

func initialDDoSPreventionBody() string {
	return `  template = false

  configs {
    status               = true
    action               = "block_period"
    challenge            = "real-browser-enforcement"
    http_access_limit    = true
    http_request_limit   = 1000
    conn_flood_check     = true
    conn_flood_limit     = 100
    http_flood_prevent   = true
    http_session_limit   = 500
    tcp_flood_prevent    = false
    tcp_conn_num_limit   = 255
    block_period         = 600

    ip_exception {
      item {
        ip = "1.1.1.1-1.1.1.2,1.1.1.4"
      }
    }
  }
`
}

func validateTerraformCLIDDoSPreventionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	raw, ok := configs["ip_exception"]
	if !ok {
		return errors.New("ip_exception must be present")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("ip_exception must not be null")
	}
	return nil
}

func TestTerraformCLIGeneratedDDoSPreventionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/ddos-prevention"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/ddos_prevention"
	mock := newTerraformCLIDDoSPreventionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":             true,
			"action":             "block_period",
			"challenge":          "real-browser-enforcement",
			"http_access_limit":  true,
			"http_request_limit": 1000,
			"conn_flood_check":   false,
			"conn_flood_limit":   100,
			"http_flood_prevent": true,
			"http_session_limit": 500,
			"tcp_flood_prevent":  false,
			"tcp_conn_num_limit": 255,
			"block_period":       600,
			"ip_exception":       []any{},
			"future_config":      map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-ddos-prevention")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIDDoSPreventionHCL(server.URL, epID, initialDDoSPreventionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIDDoSPreventionPopulatedArray(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty ip_exception wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIDDoSPreventionHCL(server.URL, epID, `  template = false

  configs {
    status               = true
    action               = "block_period"
    challenge            = "real-browser-enforcement"
    http_access_limit    = true
    http_request_limit   = 1000
    conn_flood_check     = true
    conn_flood_limit     = 100
    http_flood_prevent   = true
    http_session_limit   = 500
    tcp_flood_prevent    = false
    tcp_conn_num_limit   = 255
    block_period         = 600

    ip_exception {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "ip_exception")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIDDoSPreventionHCL(server.URL, epID, initialDDoSPreventionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-ddos-prevention")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIDDoSPreventionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

func requireTerraformCLIDDoSPreventionPopulatedArray(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var ips []string
	if err := json.Unmarshal(configs["ip_exception"], &ips); err != nil || len(ips) != 1 || ips[0] != "1.1.1.1-1.1.1.2,1.1.1.4" {
		t.Fatalf("ip_exception = %v, want [\"1.1.1.1-1.1.1.2,1.1.1.4\"]", ips)
	}
}

const terraformCLICookieSecurityTestAddress = "fortiappseccloud_waf_cookie_security.test"

func newTerraformCLICookieSecurityMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLICookieSecurityResult)
}

func terraformCLICookieSecurityHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_cookie_security", "test", epID, resourceBody)
}

func initialCookieSecurityBody() string {
	return `  template = false

  configs {
    status            = true
    action            = "alert_deny"
    mode              = "signed"
    replay_protection = true
    max_age           = 180
    secure_cookie     = true
    http_only         = true
    samesite          = false
    samesite_value    = "Lax"

    cookie_except_list {
      item {
        name     = "__utma"
        wildcard = false
      }
    }
  }
`
}

func validateTerraformCLICookieSecurityResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	raw, ok := configs["cookie_except_list"]
	if !ok {
		return errors.New("cookie_except_list must be present")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("cookie_except_list must not be null")
	}
	return nil
}

func TestTerraformCLIGeneratedCookieSecurityLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/cookie-security"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/cookie_security"
	mock := newTerraformCLICookieSecurityMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":             true,
			"action":             "alert_deny",
			"mode":               "signed",
			"replay_protection":  false,
			"max_age":            180,
			"secure_cookie":      true,
			"http_only":          true,
			"samesite":           false,
			"samesite_value":     "Lax",
			"cookie_except_list": []any{},
			"future_config":      map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-cookie-security")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLICookieSecurityHCL(server.URL, epID, initialCookieSecurityBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLICookieSecurityPopulatedArray(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty cookie_except_list wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLICookieSecurityHCL(server.URL, epID, `  template = false

  configs {
    status            = true
    action            = "alert_deny"
    mode              = "signed"
    replay_protection = true
    max_age           = 180
    secure_cookie     = true
    http_only         = true
    samesite          = false
    samesite_value    = "Lax"

    cookie_except_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "cookie_except_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLICookieSecurityHCL(server.URL, epID, initialCookieSecurityBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-cookie-security")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLICookieSecurityTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

func requireTerraformCLICookieSecurityPopulatedArray(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(configs["cookie_except_list"], &items); err != nil || len(items) != 1 {
		t.Fatalf("cookie_except_list = %v, want one item", items)
	}
	if string(bytes.TrimSpace(items[0]["name"])) != `"__utma"` {
		t.Errorf("cookie_except_list[0].name = %s, want %q", items[0]["name"], `"__utma"`)
	}
}

const terraformCLIKnownBotsTestAddress = "fortiappseccloud_waf_known_bots.test"

func newTerraformCLIKnownBotsMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIKnownBotsResult)
}

func terraformCLIKnownBotsHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_known_bots", "test", epID, resourceBody)
}

func initialKnownBotsBody() string {
	return `  template = false

  configs {
    status           = true
    bad_bots          = true
    bad_bots_action   = "block_period"
    good_bots_action  = "bypass"

    bad_bots_list {
      item {
        cat    = "DoS"
        status = true
        allow_list {
          item {
            value = "BadBot/1.0"
          }
        }
      }
    }

    good_bots_list {
      item {
        cat    = "Known Search Engines"
        status = true
        deny_list {
          item {
            value = "DenyThisBot"
          }
        }
      }
    }

    exception_list {
      item {
        concatenate_type = "AND"
        match_target      = "CLIENT_IP"
        operator         = "STRING_MATCH"
        value            = "10.0.0.0/8"
      }
    }
  }
`
}

func validateTerraformCLIKnownBotsResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"bad_bots_list", "good_bots_list", "exception_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func TestTerraformCLIGeneratedKnownBotsLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/known-bots"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/known_bots"
	mock := newTerraformCLIKnownBotsMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":           true,
			"bad_bots":         true,
			"bad_bots_action":  "block_period",
			"good_bots_action": "bypass",
			"bad_bots_list":    []any{},
			"good_bots_list":   []any{},
			"exception_list":   []any{},
			"future_config":    map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-known-bots")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIKnownBotsHCL(server.URL, epID, initialKnownBotsBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIKnownBotsPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty all three wrappers sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIKnownBotsHCL(server.URL, epID, `  template = false

  configs {
    status           = true
    bad_bots          = true
    bad_bots_action   = "block_period"
    good_bots_action  = "bypass"

    bad_bots_list {}
    good_bots_list {}
    exception_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "bad_bots_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "good_bots_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "exception_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIKnownBotsHCL(server.URL, epID, initialKnownBotsBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-known-bots")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIKnownBotsTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

func requireTerraformCLIKnownBotsPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	// bad_bots_list: one item with cat=DoS and allow_list=["BadBot/1.0"] (no idx).
	var badBots []map[string]json.RawMessage
	if err := json.Unmarshal(configs["bad_bots_list"], &badBots); err != nil || len(badBots) != 1 {
		t.Fatalf("bad_bots_list = %v, want one item", badBots)
	}
	if _, hasIdx := badBots[0]["idx"]; hasIdx {
		t.Error("bad_bots_list item unexpectedly carries an idx (unindexed collection)")
	}
	var allowList []string
	if err := json.Unmarshal(badBots[0]["allow_list"], &allowList); err != nil || len(allowList) != 1 || allowList[0] != "BadBot/1.0" {
		t.Fatalf("allow_list = %v, want [\"BadBot/1.0\"]", allowList)
	}
	// good_bots_list: one item with deny_list=["DenyThisBot"] (no idx).
	var goodBots []map[string]json.RawMessage
	if err := json.Unmarshal(configs["good_bots_list"], &goodBots); err != nil || len(goodBots) != 1 {
		t.Fatalf("good_bots_list = %v, want one item", goodBots)
	}
	if _, hasIdx := goodBots[0]["idx"]; hasIdx {
		t.Error("good_bots_list item unexpectedly carries an idx (unindexed collection)")
	}
	var denyList []string
	if err := json.Unmarshal(goodBots[0]["deny_list"], &denyList); err != nil || len(denyList) != 1 || denyList[0] != "DenyThisBot" {
		t.Fatalf("deny_list = %v, want [\"DenyThisBot\"]", denyList)
	}
	// exception_list: one item WITH idx (indexed collection).
	var exceptionList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["exception_list"], &exceptionList); err != nil || len(exceptionList) != 1 {
		t.Fatalf("exception_list = %v, want one item", exceptionList)
	}
	if _, hasIdx := exceptionList[0]["idx"]; !hasIdx {
		t.Error("exception_list item is missing the expected idx (indexed collection)")
	}
}

// TestTerraformCLIGeneratedKnownBotsOmissionPreservesItemStringArray verifies
// that omitting an item-level scalar-string-array wrapper (allow_list) on
// update preserves the fresh GET's remote nested array in the PUT, while the
// wrapper stays null in state. This pins the write-side omission-preserving
// semantics for item-level scalar-string-arrays.
func TestTerraformCLIGeneratedKnownBotsOmissionPreservesItemStringArray(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/known-bots-omit"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/known_bots"
	// Remote already has a bad_bots_list item with a populated allow_list.
	mock := newTerraformCLIKnownBotsMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":           true,
			"bad_bots":         true,
			"bad_bots_action":  "block_period",
			"good_bots_action": "bypass",
			"bad_bots_list": []any{
				map[string]any{"cat": "DoS", "status": true, "allow_list": []any{"RemoteBot"}},
			},
			"good_bots_list": []any{},
			"exception_list": []any{},
			"future_config":  map[string]any{"keep": true},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	workDir := filepath.Join(temporaryRoot, "lifecycle-known-bots-omit")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	// HCL sets bad_bots_list with one item that OMITS allow_list (only cat/status).
	writeTerraformCLIConfig(t, workDir, terraformCLIKnownBotsHCL(server.URL, epID, `  template = false

  configs {
    status           = true
    bad_bots          = true
    bad_bots_action   = "block_period"
    good_bots_action  = "bypass"

    bad_bots_list {
      item {
        cat    = "DoS"
        status = true
      }
    }

    good_bots_list {}
    exception_list {}
  }
`))

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	put := requireTerraformCLISinglePUT(t, requests)
	// The PUT must preserve the remote allow_list=["RemoteBot"] for the item
	// whose allow_list wrapper was omitted.
	var body map[string]json.RawMessage
	if err := json.Unmarshal(put.Body, &body); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(body["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var badBots []map[string]json.RawMessage
	if err := json.Unmarshal(configs["bad_bots_list"], &badBots); err != nil || len(badBots) != 1 {
		t.Fatalf("bad_bots_list = %v, want one item", badBots)
	}
	var allowList []string
	if err := json.Unmarshal(badBots[0]["allow_list"], &allowList); err != nil || len(allowList) != 1 || allowList[0] != "RemoteBot" {
		t.Fatalf("omitted allow_list was not preserved: %s, want [\"RemoteBot\"]", badBots[0]["allow_list"])
	}

	// State must keep the allow_list wrapper null (omission is not ownership).
	stateShow := cli.run(t, workDir, "show", "-no-color")
	requireTerraformCLIExit(t, stateShow, 0)
	if strings.Contains(stateShow.Stdout, "allow_list") {
		t.Fatalf("state unexpectedly materialized the omitted allow_list wrapper:\n%s", stateShow.Stdout)
	}
	mock.requireNoHandlerFailures(t)
}

// --- bot_deception lifecycle test support ---

const terraformCLIBotDeceptionTestAddress = "fortiappseccloud_waf_bot_deception.test"

func newTerraformCLIBotDeceptionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIBotDeceptionResult)
}

func terraformCLIBotDeceptionHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_bot_deception", "test", epID, resourceBody)
}

func initialBotDeceptionBody() string {
	return `  template = false

  configs {
    status        = true
    action        = "alert_deny"
    deception_url = "/url.html"

    url_list {
      item {
        url = "/login"
      }
    }

    exception_list {
      item {
        concatenate_type = "AND"
        match_target     = "CLIENT_IP"
        operator         = "STRING_MATCH"
        ip_range         = "10.0.0.0/8"
      }
    }
  }
`
}

func validateTerraformCLIBotDeceptionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"url_list", "exception_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func requireTerraformCLIBotDeceptionPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var urlList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["url_list"], &urlList); err != nil || len(urlList) != 1 {
		t.Fatalf("url_list = %v, want one item", urlList)
	}
	if string(bytes.TrimSpace(urlList[0]["url"])) != `"/login"` {
		t.Errorf("url_list[0].url = %s, want %q", urlList[0]["url"], `"/login"`)
	}
	var exceptionList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["exception_list"], &exceptionList); err != nil || len(exceptionList) != 1 {
		t.Fatalf("exception_list = %v, want one item", exceptionList)
	}
	if string(bytes.TrimSpace(exceptionList[0]["match_target"])) != `"CLIENT_IP"` {
		t.Errorf("exception_list[0].match_target = %s, want %q", exceptionList[0]["match_target"], `"CLIENT_IP"`)
	}
}

func TestTerraformCLIGeneratedBotDeceptionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/bot-deception"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/bot_deception"
	mock := newTerraformCLIBotDeceptionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":         true,
			"action":         "alert_deny",
			"deception_url":  "/url.html",
			"url_list":       []any{},
			"exception_list": []any{},
			"future_config":  map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-bot-deception")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIBotDeceptionHCL(server.URL, epID, initialBotDeceptionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIBotDeceptionPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty both wrappers sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIBotDeceptionHCL(server.URL, epID, `  template = false

  configs {
    status        = true
    action        = "alert_deny"
    deception_url = "/url.html"

    url_list {}
    exception_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "url_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "exception_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIBotDeceptionHCL(server.URL, epID, initialBotDeceptionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-bot-deception")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIBotDeceptionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

// --- biometrics_based_detection lifecycle test support ---

const terraformCLIBiometricsBasedDetectionTestAddress = "fortiappseccloud_waf_biometrics_based_detection.test"

func newTerraformCLIBiometricsBasedDetectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIBiometricsBasedDetectionResult)
}

func terraformCLIBiometricsBasedDetectionHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_biometrics_based_detection", "test", epID, resourceBody)
}

func initialBiometricsBasedDetectionBody() string {
	return `  template = false

  configs {
    status               = true
    action               = "alert_deny"
    click                = true
    keyboard             = true
    mouse_movement       = true
    screen_touch         = false
    scroll               = false
    bot_effect_time      = 5
    event_collect_time   = 15

    url_list {
      item {
        url = "/login"
      }
    }

    exception_list {
      item {
        concatenate_type = "AND"
        match_target     = "CLIENT_IP"
        operator         = "STRING_MATCH"
        ip_range         = "10.0.0.0/8"
      }
    }
  }
`
}

func validateTerraformCLIBiometricsBasedDetectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"url_list", "exception_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func requireTerraformCLIBiometricsBasedDetectionPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var urlList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["url_list"], &urlList); err != nil || len(urlList) != 1 {
		t.Fatalf("url_list = %v, want one item", urlList)
	}
	var exceptionList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["exception_list"], &exceptionList); err != nil || len(exceptionList) != 1 {
		t.Fatalf("exception_list = %v, want one item", exceptionList)
	}
	if string(bytes.TrimSpace(exceptionList[0]["operator"])) != `"STRING_MATCH"` {
		t.Errorf("exception_list[0].operator = %s, want %q", exceptionList[0]["operator"], `"STRING_MATCH"`)
	}
}

func TestTerraformCLIGeneratedBiometricsBasedDetectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/biometrics-based-detection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/biometrics_based_detection"
	mock := newTerraformCLIBiometricsBasedDetectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":             true,
			"action":             "alert_deny",
			"click":              true,
			"keyboard":           true,
			"mouse_movement":     true,
			"screen_touch":       false,
			"scroll":             false,
			"bot_effect_time":    5,
			"event_collect_time": 15,
			"url_list":           []any{},
			"exception_list":     []any{},
			"future_config":      map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-biometrics-based-detection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIBiometricsBasedDetectionHCL(server.URL, epID, initialBiometricsBasedDetectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIBiometricsBasedDetectionPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty both wrappers sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIBiometricsBasedDetectionHCL(server.URL, epID, `  template = false

  configs {
    status               = true
    action               = "alert_deny"
    click                = true
    keyboard             = true
    mouse_movement       = true
    screen_touch         = false
    scroll               = false
    bot_effect_time      = 5
    event_collect_time   = 15

    url_list {}
    exception_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "url_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "exception_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIBiometricsBasedDetectionHCL(server.URL, epID, initialBiometricsBasedDetectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-biometrics-based-detection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIBiometricsBasedDetectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	mock.requireNoHandlerFailures(t)
}

// --- waiting_room lifecycle test support ---

const terraformCLIWaitingRoomTestAddress = "fortiappseccloud_waf_waiting_room.test"

func newTerraformCLIWaitingRoomMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIWaitingRoomResult)
}

func terraformCLIWaitingRoomHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_waiting_room", "test", epID, resourceBody)
}

func initialWaitingRoomBody() string {
	return `  template = false

  configs {
    status                     = true
    path                       = "/.*"
    enable_total_active_users  = true
    total_active_users         = 1000
    enable_new_users_per_min   = false
    new_users_per_min          = 60
    session_duration           = 5
    custom_wt_page             = "Predefined"

    bypass_rules {
      item {
        rule_type  = "source-ip"
        rule_value = "192.0.2.10"
      }
    }
  }
`
}

func validateTerraformCLIWaitingRoomResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	raw, ok := configs["bypass_rules"]
	if !ok {
		return errors.New("bypass_rules must be present")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("bypass_rules must not be null")
	}
	return nil
}

func requireTerraformCLIWaitingRoomPopulatedArray(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(configs["bypass_rules"], &items); err != nil || len(items) != 1 {
		t.Fatalf("bypass_rules = %v, want one item", items)
	}
	if string(bytes.TrimSpace(items[0]["rule_type"])) != `"source-ip"` {
		t.Errorf("bypass_rules[0].rule_type = %s, want %q", items[0]["rule_type"], `"source-ip"`)
	}
	if string(bytes.TrimSpace(items[0]["rule_value"])) != `"192.0.2.10"` {
		t.Errorf("bypass_rules[0].rule_value = %s, want %q", items[0]["rule_value"], `"192.0.2.10"`)
	}
}

func TestTerraformCLIGeneratedWaitingRoomLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/waiting-room"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/waiting_room"
	mock := newTerraformCLIWaitingRoomMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":                    true,
			"path":                      "/.*",
			"enable_total_active_users": true,
			"total_active_users":        1000,
			"enable_new_users_per_min":  false,
			"new_users_per_min":         60,
			"session_duration":          5,
			"custom_wt_page":            "Predefined",
			"bypass_rules":              []any{},
			"future_config":             map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-waiting-room")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIWaitingRoomHCL(server.URL, epID, initialWaitingRoomBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIWaitingRoomPopulatedArray(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty bypass_rules wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIWaitingRoomHCL(server.URL, epID, `  template = false

  configs {
    status                     = true
    path                       = "/.*"
    enable_total_active_users  = true
    total_active_users         = 1000
    enable_new_users_per_min   = false
    new_users_per_min          = 60
    session_duration           = 5
    custom_wt_page             = "Predefined"

    bypass_rules {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "bypass_rules")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIWaitingRoomHCL(server.URL, epID, initialWaitingRoomBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-waiting-room")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIWaitingRoomTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: OpenAPI 26.3.a unconditional and
	// x-fortinet-cross-field-v1 conditional rules must be rejected at plan time
	// without a PUT.
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "total_active_users below minimum", body: outOfRangeWaitingRoomBody("total_active_users", 0), wantExitCode: 1},
		{name: "new users exceed total users", body: invalidWaitingRoomComparisonBody(), wantExitCode: 1},
		{name: "session_duration above maximum", body: outOfRangeWaitingRoomBody("session_duration", 999), wantExitCode: 1},
		// In-range control: the same body shape with a valid value must plan
		// cleanly (exit code 2 means changes to apply, NOT a parse/validator
		// error which is exit 1), proving the out-of-range failures come from
		// the generated Between validator rather than an HCL parse error.
		{name: "total_active_users in range", body: outOfRangeWaitingRoomBody("total_active_users", 1000), wantExitCode: 2},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-waiting-room", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIWaitingRoomHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

// outOfRangeWaitingRoomBody returns a waiting_room config body that sets the
// named integer field to the given out-of-range value (below minimum or above
// maximum) while keeping every other field at a valid value. The under-test
// field appears exactly once.
func outOfRangeWaitingRoomBody(field string, value int) string {
	defaults := map[string]int{
		"total_active_users": 1000,
		"new_users_per_min":  60,
		"session_duration":   5,
	}
	defaults[field] = value
	return fmt.Sprintf(`  template = false

  configs {
    status                    = true
    path                      = "/.*"
    enable_total_active_users = true
    total_active_users        = %d
    enable_new_users_per_min  = false
    new_users_per_min         = %d
    session_duration          = %d
    custom_wt_page            = "Predefined"
  }
`, defaults["total_active_users"], defaults["new_users_per_min"], defaults["session_duration"])
}

func invalidWaitingRoomComparisonBody() string {
	return `  template = false

  configs {
    status                      = true
    path                        = "/.*"
    enable_total_active_users   = true
    total_active_users          = 1000
    enable_new_users_per_min    = true
    new_users_per_min           = 1001
    session_duration            = 5
    custom_wt_page              = "Predefined"
  }
`
}

// --- mitb_protection lifecycle test support ---

const terraformCLIMITBProtectionTestAddress = "fortiappseccloud_waf_mitb_protection.test"

func newTerraformCLIMITBProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIMITBProtectionResult)
}

func terraformCLIMITBProtectionHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_mitb_protection",
		"test", epID, resourceBody)
}

func initialMITBProtectionBody() string {
	return `  template = false

  configs {
    status      = true
    action      = "alert_deny"
    request_url = "/login"
    post_url    = "/submit"

    param_list {
      item {
        type            = "regular-input"
        name            = "password"
        obfuscate       = true
        encrypt         = false
        anti_key_logger = false
      }
    }

    domain_list {
      item {
        domain = "https://maps.googleapis.com"
      }
    }
  }
`
}

func validateTerraformCLIMITBProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"param_list", "domain_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func requireTerraformCLIMITBProtectionPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var paramList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["param_list"], &paramList); err != nil || len(paramList) != 1 {
		t.Fatalf("param_list = %v, want one item", paramList)
	}
	if string(bytes.TrimSpace(paramList[0]["type"])) != `"regular-input"` {
		t.Errorf("param_list[0].type = %s, want %q", paramList[0]["type"], `"regular-input"`)
	}
	if string(bytes.TrimSpace(paramList[0]["name"])) != `"password"` {
		t.Errorf("param_list[0].name = %s, want %q", paramList[0]["name"], `"password"`)
	}
	var domainList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["domain_list"], &domainList); err != nil || len(domainList) != 1 {
		t.Fatalf("domain_list = %v, want one item", domainList)
	}
	if string(bytes.TrimSpace(domainList[0]["domain"])) != `"https://maps.googleapis.com"` {
		t.Errorf("domain_list[0].domain = %s, want %q", domainList[0]["domain"], `"https://maps.googleapis.com"`)
	}
}

func TestTerraformCLIGeneratedMITBProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/mitb-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/mitb_protection"
	mock := newTerraformCLIMITBProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"action":        "alert_deny",
			"request_url":   "/login",
			"post_url":      "/submit",
			"param_list":    []any{},
			"domain_list":   []any{},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-mitb-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIMITBProtectionHCL(server.URL, epID, initialMITBProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIMITBProtectionPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty both wrappers sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIMITBProtectionHCL(server.URL, epID, `  template = false

  configs {
    status      = true
    action      = "alert_deny"
    request_url = "/login"
    post_url    = "/submit"

    param_list {}
    domain_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "param_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "domain_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIMITBProtectionHCL(server.URL, epID, initialMITBProtectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-mitb-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIMITBProtectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: an optional config scalar URL that does not
	// match the ^/.*$ pattern, and a param_list item missing the required
	// `type` field, must both be rejected at plan time without a PUT. An
	// in-range control (a valid leading-slash URL) plans cleanly (exit 2),
	// proving the failure comes from the validator, not an HCL parse error.
	mitbValidationCases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "request_url does not match pattern", body: `  template = false

  configs {
    status      = true
    action      = "alert_deny"
    request_url = "no-leading-slash"

    param_list {
      item {
        type = "regular-input"
        name = "password"
      }
    }
    domain_list {
      item {
        domain = "https://example.com"
      }
    }
  }
`, wantErr: true},
		{name: "param_list item missing required type", body: `  template = false

  configs {
    status      = true
    action      = "alert_deny"
    request_url = "/login"

    param_list {
      item {
        name = "password"
      }
    }
    domain_list {
      item {
        domain = "https://example.com"
      }
    }
  }
`, wantErr: true},
		{name: "in-range control plans cleanly", body: `  template = false

  configs {
    status      = true
    action      = "alert_deny"
    request_url = "/login"

    param_list {
      item {
        type = "regular-input"
        name = "password"
      }
    }
    domain_list {
      item {
        domain = "https://example.com"
      }
    }
  }
`, wantErr: false},
	}
	for _, testCase := range mitbValidationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-mitb-protection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIMITBProtectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if testCase.wantErr {
				if result.ExitCode != 1 {
					t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
				}
			} else {
				if result.ExitCode != 2 {
					t.Fatalf("in-range control plan exit code = %d, want 2 (changes)\n%s", result.ExitCode, result.output())
				}
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

// --- threshold_detection lifecycle test support ---

const terraformCLIThresholdDetectionTestAddress = "fortiappseccloud_waf_threshold_detection.test"

func newTerraformCLIThresholdDetectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIThresholdDetectionResult)
}

func terraformCLIThresholdDetectionHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_threshold_detection", "test", epID, resourceBody)
}

func initialThresholdDetectionBody() string {
	return `  template = false

  configs {
    status                = true
    action                = "block_period"
    challenge             = "RBE"
    crawler               = false
    vulnerability_scan    = true
    slow_attack           = false
    content_scraping      = false
    credential_brute_force = true
    request_url           = "/login"
    occurrence            = 10
    range                 = 60

    exception_list {
      item {
        concatenate_type = "AND"
        match_target     = "CLIENT_IP"
        operator         = "STRING_MATCH"
        ip_range         = "10.0.0.0/8"
      }
    }
  }
`
}

func validateTerraformCLIThresholdDetectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	raw, ok := configs["exception_list"]
	if !ok {
		return errors.New("exception_list must be present")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("exception_list must not be null")
	}
	return nil
}

func requireTerraformCLIThresholdDetectionPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var exceptionList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["exception_list"], &exceptionList); err != nil || len(exceptionList) != 1 {
		t.Fatalf("exception_list = %v, want one item", exceptionList)
	}
	if string(bytes.TrimSpace(exceptionList[0]["match_target"])) != `"CLIENT_IP"` {
		t.Errorf("exception_list[0].match_target = %s, want %q", exceptionList[0]["match_target"], `"CLIENT_IP"`)
	}
}

func TestTerraformCLIGeneratedThresholdDetectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/threshold-detection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/threshold_detection"
	mock := newTerraformCLIThresholdDetectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":                 true,
			"action":                 "block_period",
			"challenge":              "RBE",
			"crawler":                false,
			"vulnerability_scan":     true,
			"slow_attack":            false,
			"content_scraping":       false,
			"credential_brute_force": true,
			"request_url":            "/login",
			"occurrence":             10,
			"range":                  60,
			"exception_list":         []any{},
			"future_config":          map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-threshold-detection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIThresholdDetectionHCL(server.URL, epID, initialThresholdDetectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIThresholdDetectionPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIThresholdDetectionHCL(server.URL, epID, `  template = false

  configs {
    status                = true
    action                = "block_period"
    challenge             = "RBE"
    crawler               = false
    vulnerability_scan    = true
    slow_attack           = false
    content_scraping      = false
    credential_brute_force = true
    request_url           = "/login"
    occurrence            = 10
    range                 = 60

    exception_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "exception_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIThresholdDetectionHCL(server.URL, epID, initialThresholdDetectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-threshold-detection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIThresholdDetectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: an out-of-range occurrence (101 > max 100)
	// is rejected at plan time without a PUT; an in-range control (10) plans
	// cleanly (exit 2), proving the failure comes from the Between validator.
	thresholdValidationCases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "occurrence out of range", body: `  template = false

  configs {
    status                 = true
    action                 = "block_period"
    challenge              = "RBE"
    crawler                = false
    vulnerability_scan     = true
    slow_attack            = false
    content_scraping       = false
    credential_brute_force = true
    request_url            = "/login"
    occurrence             = 101
    range                  = 60

    exception_list {}
  }
`, wantErr: true},
		{name: "in-range control plans cleanly", body: `  template = false

  configs {
    status                 = true
    action                 = "block_period"
    challenge              = "RBE"
    crawler                = false
    vulnerability_scan     = true
    slow_attack            = false
    content_scraping       = false
    credential_brute_force = true
    request_url            = "/login"
    occurrence             = 10
    range                  = 60

    exception_list {}
  }
`, wantErr: false},
	}
	for _, testCase := range thresholdValidationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-threshold-detection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIThresholdDetectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if testCase.wantErr {
				if result.ExitCode != 1 {
					t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
				}
			} else {
				if result.ExitCode != 2 {
					t.Fatalf("in-range control plan exit code = %d, want 2 (changes)\n%s", result.ExitCode, result.output())
				}
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

// --- ml_bot_detection lifecycle test support ---

const terraformCLIMLBotDetectionTestAddress = "fortiappseccloud_waf_ml_bot_detection.test"

func newTerraformCLIMLBotDetectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIMLBotDetectionResult)
}

func terraformCLIMLBotDetectionHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_ml_bot_detection", "test", epID, resourceBody)
}

func initialMLBotDetectionBody() string {
	return `  template = false

  configs {
    status                = true
    action                = "block_period"
    identification_method = "IP-and-User-Agent"
    model_type            = "Strict"
    anomaly_count         = 1
    challenge             = "Real-Browser-Enforcement"
    block_duration        = 600

    ip_list {
      item {
        ip = "10.0.0.0/8"
      }
    }

    url_list {
      item {
        url = "/login"
      }
    }

    exception_list {
      item {
        concatenate_type = "AND"
        match_target     = "CLIENT_IP"
        operator         = "STRING_MATCH"
        ip_range         = "10.0.0.0/8"
      }
    }
  }
`
}

func validateTerraformCLIMLBotDetectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"ip_list", "url_list", "exception_list"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func requireTerraformCLIMLBotDetectionPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var ipList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["ip_list"], &ipList); err != nil || len(ipList) != 1 {
		t.Fatalf("ip_list = %v, want one item", ipList)
	}
	if string(bytes.TrimSpace(ipList[0]["ip"])) != `"10.0.0.0/8"` {
		t.Errorf("ip_list[0].ip = %s, want %q", ipList[0]["ip"], `"10.0.0.0/8"`)
	}
	var urlList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["url_list"], &urlList); err != nil || len(urlList) != 1 {
		t.Fatalf("url_list = %v, want one item", urlList)
	}
	if string(bytes.TrimSpace(urlList[0]["url"])) != `"/login"` {
		t.Errorf("url_list[0].url = %s, want %q", urlList[0]["url"], `"/login"`)
	}
	var exceptionList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["exception_list"], &exceptionList); err != nil || len(exceptionList) != 1 {
		t.Fatalf("exception_list = %v, want one item", exceptionList)
	}
	if string(bytes.TrimSpace(exceptionList[0]["match_target"])) != `"CLIENT_IP"` {
		t.Errorf("exception_list[0].match_target = %s, want %q", exceptionList[0]["match_target"], `"CLIENT_IP"`)
	}
}

func TestTerraformCLIGeneratedMLBotDetectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/ml-bot-detection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/ml_bot_detection"
	mock := newTerraformCLIMLBotDetectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":                true,
			"action":                "block_period",
			"identification_method": "IP-and-User-Agent",
			"model_type":            "Strict",
			"anomaly_count":         1,
			"challenge":             "Real-Browser-Enforcement",
			"block_duration":        600,
			"ip_list":               []any{},
			"url_list":              []any{},
			"exception_list":        []any{},
			"future_config":         map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-ml-bot-detection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIMLBotDetectionHCL(server.URL, epID, initialMLBotDetectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIMLBotDetectionPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty all three wrappers sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIMLBotDetectionHCL(server.URL, epID, `  template = false

  configs {
    status                = true
    action                = "block_period"
    identification_method = "IP-and-User-Agent"
    model_type            = "Strict"
    anomaly_count         = 1
    challenge             = "Real-Browser-Enforcement"
    block_duration        = 600

    ip_list {}
    url_list {}
    exception_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "ip_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "url_list")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "exception_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIMLBotDetectionHCL(server.URL, epID, initialMLBotDetectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-ml-bot-detection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIMLBotDetectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: an out-of-range anomaly_count (4 > max 3)
	// and a url_list.item.url that does not match ^/.*$ are both rejected at
	// plan time without a PUT; an in-range control (anomaly_count=1, url=/login)
	// plans cleanly (exit 2), proving the failures come from the validators.
	mlValidationCases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "anomaly_count out of range", body: `  template = false

  configs {
    status                = true
    action                = "block_period"
    identification_method = "IP-and-User-Agent"
    model_type            = "Strict"
    anomaly_count         = 4
    challenge             = "Real-Browser-Enforcement"
    block_duration        = 600

    ip_list {}
    url_list {}
    exception_list {}
  }
`, wantErr: true},
		{name: "url_list item url does not match pattern", body: `  template = false

  configs {
    status                = true
    action                = "block_period"
    identification_method = "IP-and-User-Agent"
    model_type            = "Strict"
    anomaly_count         = 1
    challenge             = "Real-Browser-Enforcement"
    block_duration        = 600

    ip_list {}
    url_list {
      item {
        url = "no-leading-slash"
      }
    }
    exception_list {}
  }
`, wantErr: true},
		{name: "in-range control plans cleanly", body: `  template = false

  configs {
    status                = true
    action                = "block_period"
    identification_method = "IP-and-User-Agent"
    model_type            = "Strict"
    anomaly_count         = 1
    challenge             = "Real-Browser-Enforcement"
    block_duration        = 600

    ip_list {}
    url_list {
      item {
        url = "/login"
      }
    }
    exception_list {}
  }
`, wantErr: false},
	}
	for _, testCase := range mlValidationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-ml-bot-detection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIMLBotDetectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if testCase.wantErr {
				if result.ExitCode != 1 {
					t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
				}
			} else {
				if result.ExitCode != 2 {
					t.Fatalf("in-range control plan exit code = %d, want 2 (changes)\n%s", result.ExitCode, result.output())
				}
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

// --- file_protection lifecycle test support ---

const terraformCLIFileProtectionTestAddress = "fortiappseccloud_waf_file_protection.test"

func newTerraformCLIFileProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIFileProtectionResult)
}

func terraformCLIFileProtectionHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_file_protection", "test", epID, resourceBody)
}

func initialFileProtectionBody() string {
	return `  template = false

  configs {
    status            = true
    action            = "alert_deny"
    trojan            = false
    av_scan           = true
    file_action       = "Allow"
    file_size         = 10240
    url               = "/upload"
    json_file_support = false

    file_types {
      item {
        type = "PDF"
      }
    }

    custom_file_types {
      item {
        name           = "custom-archive"
        file_extension = "foo"

        file_content_match_rule {
          item {
            data_value       = "magic-bytes"
            offset_from      = "beginning"
            offset           = 0
            operation        = "equal"
            data_type        = "string"
            concatenate_type = "AND"
          }
        }
      }
    }
  }
`
}

func validateTerraformCLIFileProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	for _, name := range []string{"file_types", "custom_file_types"} {
		raw, ok := configs[name]
		if !ok {
			return fmt.Errorf("%s must be present", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must not be null", name)
		}
	}
	return nil
}

func requireTerraformCLIFileProtectionPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var fileTypes []map[string]json.RawMessage
	if err := json.Unmarshal(configs["file_types"], &fileTypes); err != nil || len(fileTypes) != 1 {
		t.Fatalf("file_types = %v, want one item", fileTypes)
	}
	if string(bytes.TrimSpace(fileTypes[0]["type"])) != `"PDF"` {
		t.Errorf("file_types[0].type = %s, want %q", fileTypes[0]["type"], `"PDF"`)
	}
	var customFileTypes []map[string]json.RawMessage
	if err := json.Unmarshal(configs["custom_file_types"], &customFileTypes); err != nil || len(customFileTypes) != 1 {
		t.Fatalf("custom_file_types = %v, want one item", customFileTypes)
	}
	if string(bytes.TrimSpace(customFileTypes[0]["name"])) != `"custom-archive"` {
		t.Errorf("custom_file_types[0].name = %s, want %q", customFileTypes[0]["name"], `"custom-archive"`)
	}
	var matchRules []map[string]json.RawMessage
	if err := json.Unmarshal(customFileTypes[0]["match_rules"], &matchRules); err != nil || len(matchRules) != 1 {
		t.Fatalf("match_rules = %v, want one item", matchRules)
	}
	if string(bytes.TrimSpace(matchRules[0]["data_value"])) != `"magic-bytes"` {
		t.Errorf("match_rules[0].data_value = %s, want %q", matchRules[0]["data_value"], `"magic-bytes"`)
	}
}

func TestTerraformCLIGeneratedFileProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/file-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/file_protection"
	mock := newTerraformCLIFileProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":            true,
			"action":            "alert_deny",
			"trojan":            false,
			"av_scan":           true,
			"file_action":       "Allow",
			"file_size":         10240,
			"url":               "/upload",
			"json_file_support": false,
			"file_types":        []any{},
			"custom_file_types": []any{},
			"future_config":     map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-file-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIFileProtectionHCL(server.URL, epID, initialFileProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIFileProtectionPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty both wrappers sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIFileProtectionHCL(server.URL, epID, `  template = false

  configs {
    status            = true
    action            = "alert_deny"
    trojan            = false
    av_scan           = true
    file_action       = "Allow"
    file_size         = 10240
    url               = "/upload"
    json_file_support = false

    file_types {}
    custom_file_types {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "file_types")
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "custom_file_types")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIFileProtectionHCL(server.URL, epID, initialFileProtectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-file-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIFileProtectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: a file_types.item.tid that does not match
	// ^\d{5}$ and a nested file_content_match_rule.item.offset above max 4096
	// are both rejected at plan time without a PUT; an in-range control (tid
	// 12345, offset 0) plans cleanly (exit 2), proving the failures come from
	// the validators.
	fileValidationCases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "file_types tid does not match pattern", body: `  template = false

  configs {
    status            = true
    action            = "alert_deny"
    trojan            = false
    av_scan           = true
    file_action       = "Allow"
    file_size         = 10240
    url               = "/upload"
    json_file_support = false

    file_types {
      item {
        type = "PDF"
        tid  = "abc"
      }
    }
    custom_file_types {}
  }
`, wantErr: true},
		{name: "nested offset out of range", body: `  template = false

  configs {
    status            = true
    action            = "alert_deny"
    trojan            = false
    av_scan           = true
    file_action       = "Allow"
    file_size         = 10240
    url               = "/upload"
    json_file_support = false

    file_types {}
    custom_file_types {
      item {
        name           = "custom-archive"
        file_extension = "foo"

        file_content_match_rule {
          item {
            data_value       = "magic-bytes"
            offset_from      = "beginning"
            offset           = 4097
            operation        = "equal"
            data_type        = "string"
            concatenate_type = "AND"
          }
        }
      }
    }
  }
`, wantErr: true},
		{name: "in-range control plans cleanly", body: `  template = false

  configs {
    status            = true
    action            = "alert_deny"
    trojan            = false
    av_scan           = true
    file_action       = "Allow"
    file_size         = 10240
    url               = "/upload"
    json_file_support = false

    file_types {
      item {
        type = "PDF"
        tid  = "12345"
      }
    }
    custom_file_types {
      item {
        name           = "custom-archive"
        file_extension = "foo"

        file_content_match_rule {
          item {
            data_value       = "magic-bytes"
            offset_from      = "beginning"
            offset           = 0
            operation        = "equal"
            data_type        = "string"
            concatenate_type = "AND"
          }
        }
      }
    }
  }
`, wantErr: false},
	}
	for _, testCase := range fileValidationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-file-protection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIFileProtectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if testCase.wantErr {
				if result.ExitCode != 1 {
					t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
				}
			} else {
				if result.ExitCode != 2 {
					t.Fatalf("in-range control plan exit code = %d, want 2 (changes)\n%s", result.ExitCode, result.output())
				}
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

// --- mobile_api_protection lifecycle test support ---

const terraformCLIMobileAPIProtectionTestAddress = "fortiappseccloud_waf_mobile_api_protection.test"

func newTerraformCLIMobileAPIProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIMobileAPIProtectionResult)
}

func terraformCLIMobileAPIProtectionHCL(apiUrl, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiUrl, "fortiappseccloud_waf_mobile_api_protection", "test", epID, resourceBody)
}

func initialMobileAPIProtectionBody() string {
	return `  template = false

  configs {
    status       = true
    action       = "alert_deny"
    token_header = "Jwt_Token"
    token_secret = "TOKEN_SECRET"

    url_list {
      item {
        url = "/login"
      }
    }
  }
`
}

func validateTerraformCLIMobileAPIProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	raw, ok := configs["url_list"]
	if !ok {
		return errors.New("url_list must be present")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("url_list must not be null")
	}
	return nil
}

func requireTerraformCLIMobileAPIProtectionPopulatedArrays(t *testing.T, body []byte) {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(result["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	var urlList []map[string]json.RawMessage
	if err := json.Unmarshal(configs["url_list"], &urlList); err != nil || len(urlList) != 1 {
		t.Fatalf("url_list = %v, want one item", urlList)
	}
	if string(bytes.TrimSpace(urlList[0]["url"])) != `"/login"` {
		t.Errorf("url_list[0].url = %s, want %q", urlList[0]["url"], `"/login"`)
	}
	// The sensitive token_secret is sent on the wire (the PUT body carries the
	// configured value); confirm it round-trips but never assert a real secret.
	if string(bytes.TrimSpace(configs["token_secret"])) != `"TOKEN_SECRET"` {
		t.Errorf("token_secret = %s, want %q", configs["token_secret"], `"TOKEN_SECRET"`)
	}
}

func TestTerraformCLIGeneratedMobileAPIProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/mobile-api-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/mobile_api_protection"
	mock := newTerraformCLIMobileAPIProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"action":        "alert_deny",
			"token_header":  "Jwt_Token",
			"token_secret":  "TOKEN_SECRET",
			"url_list":      []any{},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-mobile-api-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIMobileAPIProtectionHCL(server.URL, epID, initialMobileAPIProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	requireTerraformCLIMobileAPIProtectionPopulatedArrays(t, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Empty wrapper sends [].
	writeTerraformCLIConfig(t, workDir, terraformCLIMobileAPIProtectionHCL(server.URL, epID, `  template = false

  configs {
    status       = true
    action       = "alert_deny"
    token_header = "Jwt_Token"
    token_secret = "TOKEN_SECRET"

    url_list {}
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	emptyPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIEmptyArray(t, emptyPut.Body, "url_list")
	requireTerraformCLIUnknownFields(t, initialUnknown, emptyPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Re-apply populated config, then import.
	finalHCL := terraformCLIMobileAPIProtectionHCL(server.URL, epID, initialMobileAPIProtectionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-mobile-api-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIMobileAPIProtectionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: a token_secret exceeding the 127-character
	// maximum is rejected at plan time without a PUT; an in-range control
	// (a 16-character secret) plans cleanly (exit 2), proving the failure
	// comes from the length validator, not an HCL parse error.
	mobileValidationCases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "token_secret exceeds max length", body: fmt.Sprintf(`  template = false

  configs {
    status       = true
    action       = "alert_deny"
    token_header = "Jwt_Token"
    token_secret = "%s"

    url_list {}
  }
`, strings.Repeat("a", 128)), wantErr: true},
		{name: "in-range control plans cleanly", body: `  template = false

  configs {
    status       = true
    action       = "alert_deny"
    token_header = "Jwt_Token"
    token_secret = "0123456789abcdef"

    url_list {}
  }
`, wantErr: false},
	}
	for _, testCase := range mobileValidationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-mobile-api-protection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIMobileAPIProtectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if testCase.wantErr {
				if result.ExitCode != 1 {
					t.Fatalf("Terraform plan exit code = %d, want 1 for invalid configuration\n%s", result.ExitCode, result.output())
				}
			} else {
				if result.ExitCode != 2 {
					t.Fatalf("in-range control plan exit code = %d, want 2 (changes)\n%s", result.ExitCode, result.output())
				}
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}

	mock.requireNoHandlerFailures(t)
}

const terraformCLICachingCompressionTestAddress = "fortiappseccloud_waf_caching_compression.test"

func newTerraformCLICachingCompressionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLICachingCompressionResult)
}

func terraformCLICachingCompressionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_caching_compression",
		"test", epID, resourceBody)
}

func initialCachingCompressionBody() string {
	return `  template = false

  configs {
    status = true

    cache {
      status = true
    }

    compress {
      status = true
    }
  }
`
}

func validateTerraformCLICachingCompressionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	_ = configs
	return nil
}

func TestTerraformCLIGeneratedCachingCompressionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)
	epID := "application/caching-compression"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/caching_compression"
	mock := newTerraformCLICachingCompressionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":        true,
			"cache":         map[string]any{"status": true},
			"compress":      map[string]any{"status": true},
			"future_config": map[string]any{"keep": true, "revision": 9},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(3)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()
	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-caching-compression")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLICachingCompressionHCL(server.URL, epID, initialCachingCompressionBody()))
	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})
	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())
	// A locally managed cache/compress configuration can switch to template
	// mode with configs omitted, even though status is required in each wire
	// object. The Terraform-facing nested fields are optional/computed so stale
	// state does not trigger child-required errors while the parent disappears.
	writeTerraformCLIConfig(t, workDir, terraformCLICachingCompressionHCL(server.URL, epID, `  template = true
`))
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())
	writeTerraformCLIConfig(t, workDir, terraformCLICachingCompressionHCL(server.URL, epID, initialCachingCompressionBody()))
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())
	// Empty cache + compress wrappers.
	writeTerraformCLIConfig(t, workDir, terraformCLICachingCompressionHCL(server.URL, epID, `  template = false

  configs {
    status = true

    cache {
      status = false
    }

    compress {
      status = false
    }
  }
`))
	mock.resetRequests()
	emptyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, emptyResult, 0)
	requests = mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, requests)
	requireTerraformCLIUnknownFields(t, initialUnknown, requireTerraformCLISinglePUT(t, requests).Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())
	// Re-apply populated config, then import.
	finalHCL := terraformCLICachingCompressionHCL(server.URL, epID, initialCachingCompressionBody())
	writeTerraformCLIConfig(t, workDir, finalHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())
	importDir := filepath.Join(temporaryRoot, "import-caching-compression")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLICachingCompressionTestAddress, epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())
	// Forget-on-destroy.
	remoteBeforeDestroy := mock.remoteResult()
	mock.resetRequests()
	destroyResult := cli.run(t, importDir, "destroy", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, destroyResult, 0)
	if !strings.Contains(destroyResult.output(), "Remote caching and compression configuration remains") {
		t.Fatalf("destroy output did not contain the provider warning summary:\n%s", destroyResult.output())
	}
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	requireTerraformCLIJSONEqual(t, mock.remoteResult(), remoteBeforeDestroy, "destroy changed the remote caching and compression result")
	stateList := cli.run(t, importDir, "state", "list", "-no-color")
	requireTerraformCLIExit(t, stateList, 0)
	if strings.TrimSpace(stateList.Stdout) != "" {
		t.Fatalf("Terraform state still contains resources after destroy: %q", stateList.Stdout)
	}
	mock.requireNoHandlerFailures(t)
}

func TestTerraformCLIGlobalTrustListLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/global-trust-list"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/global_trust_list_parameter"
	mock := newTerraformCLIGlobalTrustListMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status": true,
			"trust_list": []any{
				map[string]any{"idx": 1, "name": "remote-one", "status": true, "url": "/remote-one"},
			},
			"future_config": map[string]any{"keep": true, "revision": 3},
		},
		"future_envelope": map[string]any{"keep": []any{"beta", float64(2)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-global-trust-list")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIGlobalTrustListHCL(server.URL, epID, initialGlobalTrustListBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIGlobalTrustListEntries(t, initialPut.Body, []globalTrustListExpectedEntry{
		{idx: 1, name: "one", status: true, url: "/one"},
		{idx: 2, name: "two", status: false, url: "/two"},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)
	// The global trust-list parameter envelope has NO template field.
	if hasTerraformCLITemplateField(t, initialPut.Body) {
		t.Fatal("PUT body emitted a template field; this endpoint has no template")
	}

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Assert wire-only idx is not persisted in Terraform state: the trust_list
	// item attributes in state are exactly name/status/url (no idx).
	requireTerraformCLIGlobalTrustListStateHasNoIdx(t, cli.run(t, workDir, "state", "pull", "-no-color"))

	// Update: change the trust_list to prove the GET-merge-PUT-GET update
	// path regenerates one-based idx in Terraform order and preserves unknown
	// envelope/config fields.
	updateHCL := terraformCLIGlobalTrustListHCL(server.URL, epID, updatedGlobalTrustListBody())
	writeTerraformCLIConfig(t, workDir, updateHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	updateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, updateRequests)
	updatePut := requireTerraformCLISinglePUT(t, updateRequests)
	requireTerraformCLIGlobalTrustListEntries(t, updatePut.Body, []globalTrustListExpectedEntry{
		{idx: 1, name: "alpha", status: true, url: "/alpha"},
		{idx: 2, name: "beta", status: false, url: "/beta"},
		{idx: 3, name: "gamma", status: true, url: "/gamma"},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, updatePut.Body)

	// Re-apply the same updated config: idempotent, so only a refresh GET.
	finalHCL := updateHCL
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-global-trust-list")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, finalHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_global_trust_list_parameter.test", epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Out-of-band drift in an owned scalar must be visible to Terraform.
	requireTerraformCLIBoolDrift(t, cli, importDir, mock, "status")

	// Forget-on-destroy: no remote mutation, warning emitted.
	remoteBeforeDestroy := mock.remoteResult()
	mock.resetRequests()
	destroyResult := cli.run(t, importDir, "destroy", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, destroyResult, 0)
	if !strings.Contains(destroyResult.output(), "forgotten, not destroyed") {
		t.Fatalf("destroy output did not contain the provider warning summary:\n%s", destroyResult.output())
	}
	destroyRequests := mock.recordedRequests()
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, destroyRequests)
	requireTerraformCLIJSONEqual(t, mock.remoteResult(), remoteBeforeDestroy, "destroy changed the remote global trust list result")
	stateList := cli.run(t, importDir, "state", "list", "-no-color")
	requireTerraformCLIExit(t, stateList, 0)
	if strings.TrimSpace(stateList.Stdout) != "" {
		t.Fatalf("Terraform state still contains resources after destroy: %q", stateList.Stdout)
	}

	// Focused negative validation: the reviewed trust_list 30-item bound and
	// name (63) / url (255) length bounds must be rejected at plan time without
	// a PUT. Each negative case pairs with an in-range control (exit code 2 =
	// a valid plan with changes, not a validator error which is exit 1).
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "trust_list within 30-item bound", body: boundedGlobalTrustListBody(30, "entry", "/u"), wantExitCode: 2},
		{name: "trust_list exceeds 30-item bound", body: boundedGlobalTrustListBody(31, "entry", "/u"), wantExitCode: 1},
		{name: "name within 63-char bound", body: singleGlobalTrustListBody(strings.Repeat("n", 63), "/u"), wantExitCode: 2},
		{name: "name exceeds 63-char bound", body: singleGlobalTrustListBody(strings.Repeat("n", 64), "/u"), wantExitCode: 1},
		{name: "url within 255-char bound", body: singleGlobalTrustListBody("n", "/"+strings.Repeat("u", 254)), wantExitCode: 2},
		{name: "url exceeds 255-char bound", body: singleGlobalTrustListBody("n", "/"+strings.Repeat("u", 255)), wantExitCode: 1},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-global-trust-list", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIGlobalTrustListHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}
	mock.requireNoHandlerFailures(t)
}

func newTerraformCLIGlobalTrustListMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIGlobalTrustListResult)
}

func terraformCLIGlobalTrustListHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_global_trust_list_parameter", "test", epID, resourceBody)
}

func initialGlobalTrustListBody() string {
	return `  configs {
    status = true

    trust_list {
      item {
        name   = "one"
        status = true
        url    = "/one"
      }
      item {
        name   = "two"
        status = false
        url    = "/two"
      }
    }
  }
`
}

func updatedGlobalTrustListBody() string {
	return `  configs {
    status = true

    trust_list {
      item {
        name   = "alpha"
        status = true
        url    = "/alpha"
      }
      item {
        name   = "beta"
        status = false
        url    = "/beta"
      }
      item {
        name   = "gamma"
        status = true
        url    = "/gamma"
      }
    }
  }
`
}

func singleGlobalTrustListBody(name, url string) string {
	return fmt.Sprintf(`  configs {
    status = true

    trust_list {
      item {
        name = %s
        url  = %s
      }
    }
  }
`, strconv.Quote(name), strconv.Quote(url))
}

func boundedGlobalTrustListBody(count int, name, url string) string {
	var builder strings.Builder
	builder.WriteString("  configs {\n    status = true\n\n    trust_list {\n")
	for i := 0; i < count; i++ {
		builder.WriteString("      item {\n")
		builder.WriteString(fmt.Sprintf("        name = %s\n        url  = %s\n", strconv.Quote(name), strconv.Quote(url)))
		builder.WriteString("      }\n")
	}
	builder.WriteString("    }\n  }\n")
	return builder.String()
}

func validateTerraformCLIGlobalTrustListResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	if _, ok := configs["status"]; !ok {
		return errors.New("status must be present")
	}
	// The global trust-list parameter envelope has NO template field; reject it
	// if a template ever appears so the mock stays faithful to the contract.
	if template, ok := result["template"]; ok && !bytes.Equal(bytes.TrimSpace(template), []byte("null")) {
		return errors.New("template must not be present on the global trust-list parameter envelope")
	}
	return nil
}

type globalTrustListExpectedEntry struct {
	idx    int
	name   string
	status bool
	url    string
}

func requireTerraformCLIGlobalTrustListEntries(t *testing.T, body []byte, want []globalTrustListExpectedEntry) {
	t.Helper()
	var envelope struct {
		Configs struct {
			TrustList []struct {
				IDX    int    `json:"idx"`
				Name   string `json:"name"`
				Status *bool  `json:"status"`
				URL    string `json:"url"`
			} `json:"trust_list"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode global trust list PUT body: %v", err)
	}
	if len(envelope.Configs.TrustList) != len(want) {
		t.Fatalf("trust_list length = %d, want %d", len(envelope.Configs.TrustList), len(want))
	}
	for index, entry := range envelope.Configs.TrustList {
		expected := want[index]
		if entry.IDX != expected.idx || entry.Name != expected.name || entry.URL != expected.url {
			t.Fatalf("trust_list[%d] = %+v, want %+v", index, entry, expected)
		}
		if entry.Status == nil || *entry.Status != expected.status {
			t.Fatalf("trust_list[%d] status = %#v, want %v", index, entry.Status, expected.status)
		}
	}
}

func hasTerraformCLITemplateField(t *testing.T, body []byte) bool {
	t.Helper()
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode PUT envelope: %v", err)
	}
	raw, ok := envelope["template"]
	return ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// requireTerraformCLIGlobalTrustListStateHasNoIdx asserts the wire-only idx is
// not persisted in Terraform state. `terraform state pull` returns the raw
// state JSON; the trust_list item objects must carry only name/status/url keys.
func requireTerraformCLIGlobalTrustListStateHasNoIdx(t *testing.T, result terraformCLIResult) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var state struct {
		Resources []struct {
			Instances []struct {
				Attributes struct {
					Configs struct {
						TrustList struct {
							Item []map[string]json.RawMessage `json:"item"`
						} `json:"trust_list"`
					} `json:"configs"`
				} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &state); err != nil {
		t.Fatalf("decode state pull JSON: %v", err)
	}
	if len(state.Resources) == 0 || len(state.Resources[0].Instances) == 0 {
		t.Fatalf("state pull has no resource instances:\n%s", result.Stdout)
	}
	entries := state.Resources[0].Instances[0].Attributes.Configs.TrustList.Item
	if len(entries) == 0 {
		t.Fatalf("state pull trust_list has no items:\n%s", result.Stdout)
	}
	for index, entry := range entries {
		if _, hasIdx := entry["idx"]; hasIdx {
			t.Fatalf("state trust_list item %d persists wire-only idx: %#v", index, entry)
		}
		gotKeys := make([]string, 0, len(entry))
		for key := range entry {
			gotKeys = append(gotKeys, key)
		}
		sort.Strings(gotKeys)
		if !reflect.DeepEqual(gotKeys, []string{"name", "status", "url"}) {
			t.Fatalf("state trust_list item %d keys = %#v, want exactly [name status url]", index, gotKeys)
		}
	}
}

func TestTerraformCLIAnomalyDetectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/anomaly-detection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/anomaly_detection"
	mock := newTerraformCLIAnomalyDetectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":       true,
			"action":       "alert_deny",
			"ip_list_type": "Block",
			"ip_list": []any{
				map[string]any{"idx": 1, "ip": "198.51.100.1"},
			},
			"future_config": map[string]any{"keep": true, "revision": 5},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(4)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-anomaly-detection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIAnomalyDetectionHCL(server.URL, epID, initialAnomalyDetectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLITemplate(t, initialPut.Body, false)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIConfigScalar(t, initialPut.Body, "ip_list_type", "Block")
	requireTerraformCLIAnomalyDetectionIPList(t, initialPut.Body, []anomalyDetectionExpectedIP{{idx: 1, ip: "198.51.100.1"}, {idx: 2, ip: "198.51.100.2"}})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())
	requireTerraformCLIAnomalyDetectionStateHasNoIdx(t, cli.run(t, workDir, "state", "pull", "-no-color"))

	// Update: change the ip_list to prove the GET-merge-PUT-GET update path
	// regenerates one-based idx in Terraform order and preserves unknown fields.
	updateHCL := terraformCLIAnomalyDetectionHCL(server.URL, epID, updatedAnomalyDetectionBody())
	writeTerraformCLIConfig(t, workDir, updateHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	updateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, updateRequests)
	updatePut := requireTerraformCLISinglePUT(t, updateRequests)
	requireTerraformCLIAnomalyDetectionIPList(t, updatePut.Body, []anomalyDetectionExpectedIP{{idx: 1, ip: "203.0.113.1"}, {idx: 2, ip: "203.0.113.2"}, {idx: 3, ip: "203.0.113.3"}})
	requireTerraformCLIUnknownFields(t, initialUnknown, updatePut.Body)

	// Idempotent re-apply: only a refresh GET.
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-anomaly-detection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, updateHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_anomaly_detection.test", epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Out-of-band drift in an owned scalar must be visible to Terraform.
	requireTerraformCLIBoolDrift(t, cli, importDir, mock, "status")

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: the reviewed ip_list 30-item bound must be
	// rejected at plan time without a PUT, with an in-range control.
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "ip_list within 30-item bound", body: boundedAnomalyDetectionIPList(30, "198.51.100.1"), wantExitCode: 2},
		{name: "ip_list exceeds 30-item bound", body: boundedAnomalyDetectionIPList(31, "198.51.100.1"), wantExitCode: 1},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-anomaly-detection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIAnomalyDetectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}
	mock.requireNoHandlerFailures(t)
}

func newTerraformCLIAnomalyDetectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIAnomalyDetectionResult)
}

func terraformCLIAnomalyDetectionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_anomaly_detection", "test", epID, resourceBody)
}

func initialAnomalyDetectionBody() string {
	return `  template = false

  configs {
    status       = true
    action       = "alert_deny"
    ip_list_type = "Block"

    ip_list {
      item {
        ip = "198.51.100.1"
      }
      item {
        ip = "198.51.100.2"
      }
    }
  }
`
}

func updatedAnomalyDetectionBody() string {
	return `  template = false

  configs {
    status       = true
    action       = "alert_deny"
    ip_list_type = "Block"

    ip_list {
      item {
        ip = "203.0.113.1"
      }
      item {
        ip = "203.0.113.2"
      }
      item {
        ip = "203.0.113.3"
      }
    }
  }
`
}

func boundedAnomalyDetectionIPList(count int, ip string) string {
	var builder strings.Builder
	builder.WriteString("  template = false\n\n  configs {\n    status       = true\n    action       = \"alert_deny\"\n    ip_list_type = \"Block\"\n\n    ip_list {\n")
	for i := 0; i < count; i++ {
		builder.WriteString("      item {\n")
		builder.WriteString(fmt.Sprintf("        ip = %s\n", strconv.Quote(ip)))
		builder.WriteString("      }\n")
	}
	builder.WriteString("    }\n  }\n")
	return builder.String()
}

func validateTerraformCLIAnomalyDetectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	for _, field := range []string{"status", "action", "ip_list_type"} {
		if _, ok := configs[field]; !ok {
			return fmt.Errorf("configs missing %s", field)
		}
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	return nil
}

type anomalyDetectionExpectedIP struct {
	idx int
	ip  string
}

func requireTerraformCLIAnomalyDetectionIPList(t *testing.T, body []byte, want []anomalyDetectionExpectedIP) {
	t.Helper()
	var envelope struct {
		Configs struct {
			IPList []struct {
				IDX int    `json:"idx"`
				IP  string `json:"ip"`
			} `json:"ip_list"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode anomaly detection PUT body: %v", err)
	}
	if len(envelope.Configs.IPList) != len(want) {
		t.Fatalf("ip_list length = %d, want %d", len(envelope.Configs.IPList), len(want))
	}
	for index, entry := range envelope.Configs.IPList {
		expected := want[index]
		if entry.IDX != expected.idx || entry.IP != expected.ip {
			t.Fatalf("ip_list[%d] = %+v, want %+v", index, entry, expected)
		}
	}
}

// requireTerraformCLIAnomalyDetectionStateHasNoIdx asserts the wire-only idx is
// not persisted in Terraform state and the ip_list item keys are exactly [ip].
func requireTerraformCLIAnomalyDetectionStateHasNoIdx(t *testing.T, result terraformCLIResult) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var state struct {
		Resources []struct {
			Instances []struct {
				Attributes struct {
					Configs struct {
						IPList struct {
							Item []map[string]json.RawMessage `json:"item"`
						} `json:"ip_list"`
					} `json:"configs"`
				} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &state); err != nil {
		t.Fatalf("decode state pull JSON: %v", err)
	}
	if len(state.Resources) == 0 || len(state.Resources[0].Instances) == 0 {
		t.Fatalf("state pull has no resource instances:\n%s", result.Stdout)
	}
	entries := state.Resources[0].Instances[0].Attributes.Configs.IPList.Item
	if len(entries) == 0 {
		t.Fatalf("state pull ip_list has no items:\n%s", result.Stdout)
	}
	for index, entry := range entries {
		if _, hasIdx := entry["idx"]; hasIdx {
			t.Fatalf("state ip_list item %d persists wire-only idx: %#v", index, entry)
		}
		gotKeys := make([]string, 0, len(entry))
		for key := range entry {
			gotKeys = append(gotKeys, key)
		}
		sort.Strings(gotKeys)
		if !reflect.DeepEqual(gotKeys, []string{"ip"}) {
			t.Fatalf("state ip_list item %d keys = %#v, want exactly [ip]", index, gotKeys)
		}
	}
}

func TestTerraformCLICorsProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/cors-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/cors_protection"
	mock := newTerraformCLICorsProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":             true,
			"block_cors_traffic": false,
			"allowed_origins": map[string]any{
				"protocol":            "ANY",
				"origin_name":         "remote.example",
				"port":                0,
				"include_sub_domains": false,
			},
			"allowed_methods": map[string]any{"status": true, "methods": []any{"GET"}},
			"allowed_headers": map[string]any{"status": true, "headers": []any{"X-Remote"}},
			"exposed_headers": map[string]any{"status": true, "headers": []any{}},
			"future_config":   map[string]any{"keep": true, "revision": 6},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(5)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-cors-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLICorsProtectionHCL(server.URL, epID, initialCorsProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLITemplate(t, initialPut.Body, false)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLICorsProtectionOrigins(t, initialPut.Body, "HTTPS", "new.example", 8443)
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Update: change allowed_origins to prove the GET-merge-PUT-GET update path.
	updateHCL := terraformCLICorsProtectionHCL(server.URL, epID, updatedCorsProtectionBody())
	writeTerraformCLIConfig(t, workDir, updateHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLIGetPutGetSubsequence(t, mock.recordedRequests())
	updatePut := requireTerraformCLISinglePUT(t, mock.recordedRequests())
	requireTerraformCLICorsProtectionOrigins(t, updatePut.Body, "HTTP", "updated.example", 8080)
	requireTerraformCLIUnknownFields(t, initialUnknown, updatePut.Body)

	// Idempotent re-apply: only a refresh GET.
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-cors-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, updateHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_cors_protection.test", epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Out-of-band drift in an owned scalar must be visible to Terraform.
	requireTerraformCLIBoolDrift(t, cli, importDir, mock, "status")

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: the reviewed port range (0..65535) and
	// allowed_maximum_age range (0..86400) must be rejected at plan time without
	// a PUT, with in-range controls.
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "port within range", body: corsProtectionPortBody(8443), wantExitCode: 2},
		{name: "port above maximum", body: corsProtectionPortBody(65536), wantExitCode: 1},
		{name: "allowed_maximum_age within range", body: corsProtectionMaximumAgeBody(86400), wantExitCode: 2},
		{name: "allowed_maximum_age above maximum", body: corsProtectionMaximumAgeBody(86401), wantExitCode: 1},
		{name: "allowed_credentials valid", body: corsProtectionCredentialsBody("TRUE"), wantExitCode: 2},
		{name: "allowed_credentials invalid", body: corsProtectionCredentialsBody("invalid"), wantExitCode: 1},
		{name: "protocol valid", body: corsProtectionProtocolBody("HTTPS"), wantExitCode: 2},
		{name: "protocol invalid", body: corsProtectionProtocolBody("FTP"), wantExitCode: 1},
		{name: "methods valid", body: corsProtectionMethodsBody([]string{"GET", "POST"}), wantExitCode: 2},
		{name: "methods invalid", body: corsProtectionMethodsBody([]string{"GET", "BOGUS"}), wantExitCode: 1},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-cors-protection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLICorsProtectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}
	mock.requireNoHandlerFailures(t)
}

func newTerraformCLICorsProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLICorsProtectionResult)
}

func terraformCLICorsProtectionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_cors_protection", "test", epID, resourceBody)
}

func initialCorsProtectionBody() string {
	return `  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol      = "HTTPS"
      origin_name   = "new.example"
      port          = 8443
    }
    allowed_methods {
      status  = true
      methods = ["GET", "POST"]
    }
    allowed_headers {
      status  = true
      headers = ["X-New"]
    }
    exposed_headers {
      status  = true
      headers = ["X-Exp"]
    }
    url_pattern         = "/secure"
    allowed_credentials = "TRUE"
    allowed_maximum_age = 60
  }
`
}

func updatedCorsProtectionBody() string {
	return `  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol      = "HTTP"
      origin_name   = "updated.example"
      port          = 8080
    }
    allowed_methods {
      status  = true
      methods = ["GET"]
    }
    allowed_headers {
      status  = true
      headers = ["X-New"]
    }
    exposed_headers {
      status  = true
      headers = ["X-Exp"]
    }
    url_pattern         = "/secure"
    allowed_credentials = "TRUE"
    allowed_maximum_age = 60
  }
`
}

func corsProtectionPortBody(port int) string {
	return fmt.Sprintf(`  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol      = "HTTPS"
      origin_name   = "new.example"
      port          = %d
    }
    allowed_methods {
      status  = true
      methods = ["GET"]
    }
    allowed_headers {
      status  = true
      headers = ["X-New"]
    }
    exposed_headers {
      status  = true
      headers = []
    }
  }
`, port)
}

func corsProtectionMaximumAgeBody(age int) string {
	return fmt.Sprintf(`  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol      = "HTTPS"
      origin_name   = "new.example"
    }
    allowed_methods {
      status  = true
      methods = ["GET"]
    }
    allowed_headers {
      status  = true
      headers = ["X-New"]
    }
    exposed_headers {
      status  = true
      headers = []
    }
    allowed_maximum_age = %d
  }
`, age)
}

func corsProtectionCredentialsBody(value string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol      = "HTTPS"
      origin_name   = "new.example"
    }
    allowed_methods {
      status  = true
      methods = ["GET"]
    }
    allowed_headers {
      status  = true
      headers = ["X-New"]
    }
    exposed_headers {
      status  = true
      headers = []
    }
    allowed_credentials = %s
  }
`, strconv.Quote(value))
}

func corsProtectionProtocolBody(protocol string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol      = %s
      origin_name   = "new.example"
    }
    allowed_methods {
      status  = true
      methods = ["GET"]
    }
    allowed_headers {
      status  = true
      headers = ["X-New"]
    }
    exposed_headers {
      status  = true
      headers = []
    }
  }
`, strconv.Quote(protocol))
}

func corsProtectionMethodsBody(methods []string) string {
	quoted := make([]string, 0, len(methods))
	for _, m := range methods {
		quoted = append(quoted, strconv.Quote(m))
	}
	return fmt.Sprintf(`  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol      = "HTTPS"
      origin_name   = "new.example"
    }
    allowed_methods {
      status  = true
      methods = [%s]
    }
    allowed_headers {
      status  = true
      headers = ["X-New"]
    }
    exposed_headers {
      status  = true
      headers = []
    }
  }
`, strings.Join(quoted, ", "))
}

func validateTerraformCLICorsProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	for _, field := range []string{"status", "block_cors_traffic", "allowed_origins", "allowed_methods", "allowed_headers", "exposed_headers"} {
		if _, ok := configs[field]; !ok {
			return fmt.Errorf("configs missing %s", field)
		}
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	return nil
}

func requireTerraformCLICorsProtectionOrigins(t *testing.T, body []byte, protocol, originName string, port int) {
	t.Helper()
	var envelope struct {
		Configs struct {
			AllowedOrigins struct {
				Protocol   string `json:"protocol"`
				OriginName string `json:"origin_name"`
				Port       int    `json:"port"`
			} `json:"allowed_origins"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode cors protection PUT body: %v", err)
	}
	if envelope.Configs.AllowedOrigins.Protocol != protocol ||
		envelope.Configs.AllowedOrigins.OriginName != originName ||
		envelope.Configs.AllowedOrigins.Port != port {
		t.Fatalf("allowed_origins = %+v, want protocol=%s origin_name=%s port=%d",
			envelope.Configs.AllowedOrigins, protocol, originName, port)
	}
}

func TestTerraformCLIIPProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/ip-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/ip_protection"
	mock := newTerraformCLIIPProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"status":             true,
			"ip_reputation":      true,
			"geo_ip_mode":        "block",
			"block_country_list": []any{"United States"},
			"ip_list": []any{
				map[string]any{"idx": 1, "type": "trust-ip", "ip": "198.51.100.1"},
				map[string]any{"idx": 2, "type": "block-ip", "ip": nil},
				map[string]any{"idx": 3, "type": "allow-only-ip", "ip": nil},
			},
			"future_config": map[string]any{"keep": true, "revision": 7},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": []any{"beta", float64(6)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-ip-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIIPProtectionHCL(server.URL, epID, initialIPProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLITemplate(t, initialPut.Body, false)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)
	requireTerraformCLIIPProtectionIPList(t, initialPut.Body, []ipProtectionExpectedIP{{idx: 1, ipType: "block-ip", ip: "198.51.100.1"}})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())
	requireTerraformCLIIPProtectionStateHasNoIdx(t, cli.run(t, workDir, "state", "pull", "-no-color"))

	// Update: change geo_ip_mode and ip_list.
	updateHCL := terraformCLIIPProtectionHCL(server.URL, epID, updatedIPProtectionBody())
	writeTerraformCLIConfig(t, workDir, updateHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	updateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, updateRequests)
	updatePut := requireTerraformCLISinglePUT(t, updateRequests)
	requireTerraformCLIConfigScalar(t, updatePut.Body, "geo_ip_mode", "allow")
	requireTerraformCLIIPProtectionIPList(t, updatePut.Body, []ipProtectionExpectedIP{{idx: 1, ipType: "trust-ip", ip: "203.0.113.1"}})
	requireTerraformCLIUnknownFields(t, initialUnknown, updatePut.Body)
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-ip-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, updateHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_ip_protection.test", epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Out-of-band drift in an owned scalar must be visible to Terraform.
	requireTerraformCLIBoolDrift(t, cli, importDir, mock, "status")

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: the reviewed ip_list 256-item bound must be
	// rejected at plan time without a PUT, with an in-range control.
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "ip_list within 256-item bound", body: boundedIPProtectionIPList(256, "198.51.100.1"), wantExitCode: 2},
		{name: "ip_list exceeds 256-item bound", body: boundedIPProtectionIPList(257, "198.51.100.1"), wantExitCode: 1},
		{name: "geo_ip_mode valid", body: geoIPModeIPProtectionBody("allow"), wantExitCode: 2},
		{name: "geo_ip_mode invalid", body: geoIPModeIPProtectionBody("invalid"), wantExitCode: 1},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-ip-protection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIIPProtectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}
	mock.requireNoHandlerFailures(t)
}

func TestTerraformCLIContentRoutingLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/content-routing"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/routings"
	mock := newTerraformCLIContentRoutingMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"status": false,
		"policy_list": []any{
			map[string]any{
				"idx":         1,
				"name":        "remote-policy",
				"server_pool": "remote-pool",
				"is_default":  true,
				"rule_list": []any{
					map[string]any{
						"idx":              1,
						"match_object":     "http-host",
						"match_condition":  "match-reg",
						"match_expression": "remote\\.example\\.com",
						"concatenate":      "or",
						"reverse":          false,
					},
				},
			},
		},
		"future_envelope": map[string]any{"keep": []any{"beta", float64(6)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-content-routing")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIContentRoutingHCL(server.URL, epID, initialContentRoutingBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLIContentRoutingStatus(t, initialPut.Body, true)
	requireTerraformCLIContentRoutingPolicyList(t, initialPut.Body, []contentRoutingExpectedPolicy{
		{name: "policy-one", serverPool: "pool-one", isDefault: false, rules: []contentRoutingExpectedRule{
			{matchObject: "http-request", matchCondition: "match-end", matchExpression: ".html", concatenate: "and", reverse: false},
			{matchObject: "url-parameter", name: "debug", value: "1", nameMatchCond: "equal", valueMatchCond: "equal", concatenate: "or", reverse: false},
		}},
	})
	requireTerraformCLIContentRoutingUnknownFields(t, initialUnknown, initialPut.Body)
	// The content-routing envelope is flat {status, policy_list}; no template field.
	if hasTerraformCLITemplateField(t, initialPut.Body) {
		t.Fatal("PUT body emitted a template field; this endpoint has no template")
	}

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Wire-only idx is never persisted in Terraform state: policy/rule item
	// attributes carry no idx.
	requireTerraformCLIContentRoutingStateHasNoIdx(t, cli.run(t, workDir, "state", "pull", "-no-color"))

	// Update: change status and the policy_list to prove the GET-merge-PUT-GET
	// update path regenerates one-based idx in Terraform order and preserves the
	// unknown envelope field.
	updateHCL := terraformCLIContentRoutingHCL(server.URL, epID, updatedContentRoutingBody())
	writeTerraformCLIConfig(t, workDir, updateHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	updateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, updateRequests)
	updatePut := requireTerraformCLISinglePUT(t, updateRequests)
	requireTerraformCLIContentRoutingStatus(t, updatePut.Body, false)
	requireTerraformCLIContentRoutingPolicyList(t, updatePut.Body, []contentRoutingExpectedPolicy{
		{name: "policy-alpha", serverPool: "pool-alpha", isDefault: true, rules: []contentRoutingExpectedRule{
			{matchObject: "source-ip", matchCondition: "ip-range", startIP: "10.0.0.0", endIP: "10.0.0.255", concatenate: "or", reverse: false},
		}},
		{name: "policy-beta", serverPool: "pool-beta", isDefault: false, rules: []contentRoutingExpectedRule{}},
	})
	requireTerraformCLIContentRoutingUnknownFields(t, initialUnknown, updatePut.Body)

	// Re-apply the same updated config: idempotent, so only a refresh GET.
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-content-routing")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, updateHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_content_routing.test", epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Out-of-band drift in an owned scalar must be visible to Terraform.
	requireTerraformCLIBoolDrift(t, cli, importDir, mock, "status")

	// Forget-on-destroy: no remote mutation, warning emitted.
	remoteBeforeDestroy := mock.remoteResult()
	mock.resetRequests()
	destroyResult := cli.run(t, importDir, "destroy", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, destroyResult, 0)
	if !strings.Contains(destroyResult.output(), "forgotten, not destroyed") {
		t.Fatalf("destroy output did not contain the provider warning summary:\n%s", destroyResult.output())
	}
	destroyRequests := mock.recordedRequests()
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, destroyRequests)
	requireTerraformCLIJSONEqual(t, mock.remoteResult(), remoteBeforeDestroy, "destroy changed the remote content routing result")
	stateList := cli.run(t, importDir, "state", "list", "-no-color")
	requireTerraformCLIExit(t, stateList, 0)
	if strings.TrimSpace(stateList.Stdout) != "" {
		t.Fatalf("Terraform state still contains resources after destroy: %q", stateList.Stdout)
	}

	// Focused negative validation: match_object / match_condition / concatenate
	// enum values are enforced at plan time without a PUT. Each negative case
	// pairs with an in-range control (exit code 2 = a valid plan with changes,
	// not a validator error which is exit 1).
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "match_object valid", body: contentRoutingBodyWithMatchObject("http-host"), wantExitCode: 2},
		{name: "match_object invalid", body: contentRoutingBodyWithMatchObject("not-a-real-object"), wantExitCode: 1},
		{name: "match_condition valid", body: contentRoutingBodyWithMatchCondition("match-reg"), wantExitCode: 2},
		{name: "match_condition invalid", body: contentRoutingBodyWithMatchCondition("not-a-real-condition"), wantExitCode: 1},
		{name: "concatenate valid", body: contentRoutingBodyWithConcatenate("or"), wantExitCode: 2},
		{name: "concatenate invalid", body: contentRoutingBodyWithConcatenate("xor"), wantExitCode: 1},
		{name: "source ip range variant valid", body: contentRoutingBodyWithSourceRange(false), wantExitCode: 2},
		{name: "source ip range missing end", body: contentRoutingBodyWithSourceRange(true), wantExitCode: 1},
		{name: "contradictory variant field", body: contentRoutingBodyWithContradictoryField(), wantExitCode: 1},
		{name: "multiple default policies", body: contentRoutingBodyWithMultipleDefaults(), wantExitCode: 1},
		{name: "policy_list within 32-item bound", body: boundedContentRoutingPolicies(32), wantExitCode: 2},
		{name: "policy_list exceeds 32-item bound", body: boundedContentRoutingPolicies(33), wantExitCode: 1},
		{name: "rule_list within 32-item bound", body: boundedContentRoutingRules(32), wantExitCode: 2},
		{name: "rule_list exceeds 32-item bound", body: boundedContentRoutingRules(33), wantExitCode: 1},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-content-routing", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIContentRoutingHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}
	mock.requireNoHandlerFailures(t)
}

func newTerraformCLIIPProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	mock := newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIIPProtectionResult)
	// Production GET canonicalizes ip_list into three fixed ordered rule-type
	// slots, with explicit-null ip placeholders for inactive types. The pinned
	// PUT shape contains active type/ip entries only and omits idx.
	mock.putRemoteShaper = shapeTerraformCLIIPProtectionPutForGet
	return mock
}

// shapeTerraformCLIIPProtectionPutForGet transforms a validated ip_protection
// PUT body (active ip_list items without idx) into the live-observed GET shape:
// fixed trust/block/allow slots with canonical one-based idx and ip:null for
// inactive slots.
func shapeTerraformCLIIPProtectionPutForGet(body []byte) (json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode ip protection PUT envelope: %w", err)
	}
	configsRaw, ok := envelope["configs"]
	if !ok {
		return nil, errors.New("ip protection PUT envelope missing configs")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return nil, fmt.Errorf("decode ip protection PUT configs: %w", err)
	}
	ipListRaw, hasIPList := configs["ip_list"]
	if !hasIPList {
		return append(json.RawMessage(nil), body...), nil
	}
	if bytes.Equal(bytes.TrimSpace(ipListRaw), []byte("null")) {
		return append(json.RawMessage(nil), body...), nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(ipListRaw, &items); err != nil {
		return nil, fmt.Errorf("decode ip protection PUT ip_list items: %w", err)
	}
	activeByType := make(map[string]map[string]json.RawMessage, len(items))
	for index, item := range items {
		ruleType := "trust-ip"
		if rawType, ok := item["type"]; ok {
			if err := json.Unmarshal(rawType, &ruleType); err != nil {
				return nil, fmt.Errorf("decode ip protection PUT ip_list item %d type: %w", index, err)
			}
		}
		if ruleType != "trust-ip" && ruleType != "block-ip" && ruleType != "allow-only-ip" {
			return nil, fmt.Errorf("ip protection PUT ip_list item %d has unsupported type %q", index, ruleType)
		}
		if _, duplicate := activeByType[ruleType]; duplicate {
			return nil, fmt.Errorf("ip protection production-shaped mock supports one active %s slot", ruleType)
		}
		activeByType[ruleType] = item
	}
	ruleTypes := []string{"trust-ip", "block-ip", "allow-only-ip"}
	shapedItems := make([]map[string]json.RawMessage, 0, len(ruleTypes))
	for index, ruleType := range ruleTypes {
		item, active := activeByType[ruleType]
		if !active {
			item = map[string]json.RawMessage{"ip": json.RawMessage("null")}
		}
		idxValue, err := json.Marshal(index + 1)
		if err != nil {
			return nil, fmt.Errorf("encode canonical idx: %w", err)
		}
		typeValue, err := json.Marshal(ruleType)
		if err != nil {
			return nil, fmt.Errorf("encode canonical type: %w", err)
		}
		item["idx"] = idxValue
		item["type"] = typeValue
		shapedItems = append(shapedItems, item)
	}
	shapedItemsJSON, err := json.Marshal(shapedItems)
	if err != nil {
		return nil, fmt.Errorf("encode GET-shaped ip_list: %w", err)
	}
	configs["ip_list"] = shapedItemsJSON
	shapedConfigs, err := json.Marshal(configs)
	if err != nil {
		return nil, fmt.Errorf("encode GET-shaped configs: %w", err)
	}
	envelope["configs"] = shapedConfigs
	return json.Marshal(envelope)
}

func TestShapeTerraformCLIIPProtectionPutForGetUsesProductionNullPlaceholders(t *testing.T) {
	t.Parallel()

	shaped, err := shapeTerraformCLIIPProtectionPutForGet([]byte(`{"template":false,"configs":{"status":false,"ip_reputation":false,"ip_list":[{"type":"block-ip","ip":"1.1.1.1"}]}}`))
	if err != nil {
		t.Fatalf("shape IP Protection PUT: %v", err)
	}
	var result struct {
		Configs struct {
			IPList []struct {
				IDX  int     `json:"idx"`
				Type string  `json:"type"`
				IP   *string `json:"ip"`
			} `json:"ip_list"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(shaped, &result); err != nil {
		t.Fatalf("decode shaped IP Protection GET: %v", err)
	}
	items := result.Configs.IPList
	if len(items) != 3 {
		t.Fatalf("shaped ip_list length = %d, want 3", len(items))
	}
	for index, ruleType := range []string{"trust-ip", "block-ip", "allow-only-ip"} {
		if items[index].IDX != index+1 || items[index].Type != ruleType {
			t.Fatalf("shaped ip_list[%d] = %#v", index, items[index])
		}
	}
	if items[0].IP != nil || items[2].IP != nil || items[1].IP == nil || *items[1].IP != "1.1.1.1" {
		t.Fatalf("shaped active/placeholders = %#v", items)
	}
}

func terraformCLIIPProtectionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_ip_protection", "test", epID, resourceBody)
}

func initialIPProtectionBody() string {
	return `  template = false

  configs {
    status        = true
    ip_reputation = true
    geo_ip_mode   = "block"
    block_country_list = ["United States"]

    ip_list {
      item {
        type = "block-ip"
        ip   = "198.51.100.1"
      }
    }
  }
`
}

func updatedIPProtectionBody() string {
	return `  template = false

  configs {
    status        = true
    ip_reputation = true
    geo_ip_mode   = "allow"
    block_country_list = ["United States", "Canada"]

    ip_list {
      item {
        type = "trust-ip"
        ip   = "203.0.113.1"
      }
    }
  }
`
}

func boundedIPProtectionIPList(count int, ip string) string {
	var builder strings.Builder
	builder.WriteString("  template = false\n\n  configs {\n    status        = true\n    ip_reputation = true\n\n    ip_list {\n")
	for i := 0; i < count; i++ {
		builder.WriteString("      item {\n")
		builder.WriteString(fmt.Sprintf("        ip = %s\n", strconv.Quote(ip)))
		builder.WriteString("      }\n")
	}
	builder.WriteString("    }\n  }\n")
	return builder.String()
}

func geoIPModeIPProtectionBody(mode string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status        = true
    ip_reputation = true
    geo_ip_mode   = %s
  }
`, strconv.Quote(mode))
}

func validateTerraformCLIIPProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	for _, field := range []string{"status", "ip_reputation"} {
		if _, ok := configs[field]; !ok {
			return fmt.Errorf("configs missing %s", field)
		}
	}
	var template bool
	if err := json.Unmarshal(result["template"], &template); err != nil {
		return fmt.Errorf("template must be a boolean: %w", err)
	}
	return nil
}

// ipProtectionExpectedIP describes one reviewed PUT ip_list item. The pinned
// PutIPProtection schema omits wire-only idx, so the PUT body carries only
// type and ip; expectIdx is unused for PUT assertions and is retained only so
// the call sites read in Terraform (source) order.
type ipProtectionExpectedIP struct {
	idx    int
	ipType string
	ip     string
}

func requireTerraformCLIIPProtectionIPList(t *testing.T, body []byte, want []ipProtectionExpectedIP) {
	t.Helper()
	var envelope struct {
		Configs struct {
			IPList []struct {
				Type string `json:"type"`
				IP   string `json:"ip"`
			} `json:"ip_list"`
			IPListRaw []map[string]json.RawMessage `json:"-"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode ip protection PUT body: %v", err)
	}
	if len(envelope.Configs.IPList) != len(want) {
		t.Fatalf("ip_list length = %d, want %d", len(envelope.Configs.IPList), len(want))
	}
	for index, entry := range envelope.Configs.IPList {
		expected := want[index]
		if entry.IP != expected.ip || entry.Type != expected.ipType {
			t.Fatalf("ip_list[%d] = %+v, want type=%q ip=%q", index, entry, expected.ipType, expected.ip)
		}
	}
	// The PUT shape must omit wire-only idx per the pinned PutIPProtection
	// schema. Assert no idx key appears on any PUT ip_list item.
	var rawEnvelope struct {
		Configs struct {
			IPList []map[string]json.RawMessage `json:"ip_list"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(body, &rawEnvelope); err != nil {
		t.Fatalf("decode raw ip protection PUT body: %v", err)
	}
	for i, item := range rawEnvelope.Configs.IPList {
		if _, hasIdx := item["idx"]; hasIdx {
			t.Fatalf("PUT ip_list item %d carries wire-only idx; the PUT shape must omit it", i)
		}
	}
}

func requireTerraformCLIIPProtectionStateHasNoIdx(t *testing.T, result terraformCLIResult) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var state struct {
		Resources []struct {
			Instances []struct {
				Attributes struct {
					Configs struct {
						IPList struct {
							Item []map[string]json.RawMessage `json:"item"`
						} `json:"ip_list"`
					} `json:"configs"`
				} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &state); err != nil {
		t.Fatalf("decode state pull JSON: %v", err)
	}
	if len(state.Resources) == 0 || len(state.Resources[0].Instances) == 0 {
		t.Fatalf("state pull has no resource instances:\n%s", result.Stdout)
	}
	entries := state.Resources[0].Instances[0].Attributes.Configs.IPList.Item
	if len(entries) == 0 {
		t.Fatalf("state pull ip_list has no items:\n%s", result.Stdout)
	}
	for index, entry := range entries {
		if _, hasIdx := entry["idx"]; hasIdx {
			t.Fatalf("state ip_list item %d persists wire-only idx: %#v", index, entry)
		}
		gotKeys := make([]string, 0, len(entry))
		for key := range entry {
			gotKeys = append(gotKeys, key)
		}
		sort.Strings(gotKeys)
		if !reflect.DeepEqual(gotKeys, []string{"ip", "type"}) {
			t.Fatalf("state ip_list item %d keys = %#v, want exactly [ip type]", index, gotKeys)
		}
	}
}

func TestTerraformCLICustomRuleLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/custom-rule"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/custom_rule"
	mock := newTerraformCLICustomRuleMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"template": false,
		"configs": map[string]any{
			"status": false,
			"rule_list": []any{
				map[string]any{
					"idx":          1,
					"name":         "remote-rule",
					"action":       "alert",
					"block_period": 60,
					"filter_list": []any{
						map[string]any{"idx": 1, "type": "source-ip-filter", "ip": "192.0.2.1"},
					},
				},
			},
			"future_config": map[string]any{"keep": true},
		},
		"future_envelope": map[string]any{"keep": []any{"beta", float64(6)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-custom-rule")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLICustomRuleHCL(server.URL, epID, initialCustomRuleBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLITemplate(t, initialPut.Body, false)
	requireTerraformCLICustomRuleConfig(t, initialPut.Body, customRuleExpectedConfig{
		status: true,
		rules: []customRuleExpectedRule{
			{name: "rule-one", action: "alert_deny", challenge: "real-browser-enforcement", filters: []customRuleExpectedFilter{
				{filterType: "source-ip-filter", ip: "198.51.100.1", reverseMatch: true},
				{filterType: "url-filter", url: "/admin"},
			}},
		},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Wire-only idx is never persisted in Terraform state: rule/filter item
	// attributes carry no idx.
	requireTerraformCLICustomRuleStateHasNoIdx(t, cli.run(t, workDir, "state", "pull", "-no-color"))

	// Update: change status, the rule action/block_period, and the filter_list
	// to prove the GET-merge-PUT-GET update path regenerates one-based idx in
	// Terraform order and preserves unknown envelope/config fields. Dropping a
	// filter field (url) proves owned filters are config-authoritative.
	updateHCL := terraformCLICustomRuleHCL(server.URL, epID, updatedCustomRuleBody())
	writeTerraformCLIConfig(t, workDir, updateHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	updateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, updateRequests)
	updatePut := requireTerraformCLISinglePUT(t, updateRequests)
	requireTerraformCLICustomRuleConfig(t, updatePut.Body, customRuleExpectedConfig{
		status: false,
		rules: []customRuleExpectedRule{
			{name: "rule-one", action: "block_period", blockPeriod: 3600, challenge: "real-browser-enforcement", filters: []customRuleExpectedFilter{
				{filterType: "source-ip-filter", ip: "203.0.113.1"},
				{filterType: "occurrence", occurrence: 5, within: 60},
			}},
			{name: "rule-two", action: "deny_no_log", filters: nil},
		},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, updatePut.Body)

	// Re-apply the same updated config: idempotent, so only a refresh GET.
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-custom-rule")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, updateHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_custom_rule.test", epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Out-of-band drift in an owned scalar must be visible to Terraform.
	requireTerraformCLIBoolDrift(t, cli, importDir, mock, "status")

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: filter type / action / challenge / limit /
	// occurrence / within enum+range bounds are enforced at plan time without a
	// PUT. Each negative case pairs with an in-range control (exit code 2 = a
	// valid plan with changes, not a validator error which is exit 1).
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "filter type valid", body: customRuleBodyWithFilterType("source-ip-filter"), wantExitCode: 2},
		{name: "filter type invalid", body: customRuleBodyWithFilterType("not-a-real-filter"), wantExitCode: 1},
		{name: "action valid", body: customRuleBodyWithAction("alert_deny"), wantExitCode: 2},
		{name: "action invalid", body: customRuleBodyWithAction("permit"), wantExitCode: 1},
		{name: "challenge valid", body: customRuleBodyWithChallenge("captcha-enforcement"), wantExitCode: 2},
		{name: "challenge invalid", body: customRuleBodyWithChallenge("always"), wantExitCode: 1},
		{name: "block_period within 1..3600", body: customRuleBodyWithBlockPeriod(3600), wantExitCode: 2},
		{name: "block_period exceeds 3600", body: customRuleBodyWithBlockPeriod(3601), wantExitCode: 1},
		{name: "name within 40 UTF-8 chars", body: customRuleBodyWithName(strings.Repeat("n", 40)), wantExitCode: 2},
		{name: "name exceeds 40 UTF-8 chars", body: customRuleBodyWithName(strings.Repeat("n", 41)), wantExitCode: 1},
		{name: "limit within 1..65535", body: customRuleBodyWithLimit(100), wantExitCode: 2},
		{name: "limit exceeds 65535", body: customRuleBodyWithLimit(70000), wantExitCode: 1},
		{name: "limit below 1", body: customRuleBodyWithLimit(0), wantExitCode: 1},
		{name: "occurrence within 1..100000", body: customRuleBodyWithOccurrence(100000), wantExitCode: 2},
		{name: "occurrence exceeds 100000", body: customRuleBodyWithOccurrence(100001), wantExitCode: 1},
		{name: "occurrence below 1", body: customRuleBodyWithOccurrence(0), wantExitCode: 1},
		{name: "within within 1..600", body: customRuleBodyWithWithin(600), wantExitCode: 2},
		{name: "within exceeds 600", body: customRuleBodyWithWithin(601), wantExitCode: 1},
		{name: "within below 1", body: customRuleBodyWithWithin(0), wantExitCode: 1},
		{name: "block_period below 1", body: customRuleBodyWithBlockPeriod(0), wantExitCode: 1},
		{name: "header_type valid", body: customRuleBodyWithHeaderType("predefined"), wantExitCode: 2},
		{name: "header_type invalid", body: customRuleBodyWithHeaderType("unknown"), wantExitCode: 1},
		{name: "time_type valid", body: customRuleBodyWithTimeType("daily"), wantExitCode: 2},
		{name: "time_type invalid", body: customRuleBodyWithTimeType("weekly"), wantExitCode: 1},
		{name: "content_types valid", body: customRuleBodyWithContentTypes("application/json"), wantExitCode: 2},
		{name: "content_types invalid", body: customRuleBodyWithContentTypes("text/csv"), wantExitCode: 1},
		{name: "discriminator fields valid", body: customRuleBodyWithURLField(false), wantExitCode: 2},
		{name: "contradictory discriminator field", body: customRuleBodyWithURLField(true), wantExitCode: 1},
		{name: "required discriminator field missing", body: customRuleBodyWithMissingSourceIP(), wantExitCode: 1},
		{name: "daily time format invalid", body: customRuleBodyWithTimeValues("daily", "8:00", "17:00"), wantExitCode: 1},
		{name: "once time format valid", body: customRuleBodyWithTimeValues("once", "08:00 2026/07/23", "17:00 2026/07/23"), wantExitCode: 2},
		{name: "once time calendar invalid", body: customRuleBodyWithTimeValues("once", "08:00 2026/02/30", "17:00 2026/03/01"), wantExitCode: 1},
		{name: "header missing and empty conflict", body: customRuleBodyWithHeaderCheckConflict(), wantExitCode: 1},
		{name: "period block requires duration", body: customRuleBodyWithMissingBlockPeriod(), wantExitCode: 1},
		{name: "duration requires period block action", body: customRuleBodyWithUnexpectedBlockPeriod(), wantExitCode: 1},
		{name: "name within 40 UTF-8 runes (multibyte)", body: customRuleBodyWithName(strings.Repeat("ü", 40)), wantExitCode: 2},
		{name: "name exceeds 40 UTF-8 runes (multibyte)", body: customRuleBodyWithName(strings.Repeat("ü", 41)), wantExitCode: 1},
		{name: "name within 40 UTF-8 chars (ASCII)", body: customRuleBodyWithName(strings.Repeat("n", 40)), wantExitCode: 2},
		{name: "name exceeds 40 UTF-8 chars (ASCII)", body: customRuleBodyWithName(strings.Repeat("n", 41)), wantExitCode: 1},
		{name: "filter_list within 200-item bound", body: boundedCustomRuleFilterList(200), wantExitCode: 2},
		{name: "filter_list exceeds 200-item bound", body: boundedCustomRuleFilterList(201), wantExitCode: 1},
		{name: "rule_list within 24-item bound", body: boundedCustomRuleRuleList(24), wantExitCode: 2},
		{name: "rule_list exceeds 24-item bound", body: boundedCustomRuleRuleList(25), wantExitCode: 1},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-custom-rule", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLICustomRuleHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}
	mock.requireNoHandlerFailures(t)
}

func newTerraformCLIContentRoutingMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIContentRoutingResult)
}

func terraformCLIContentRoutingHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_content_routing", "test", epID, resourceBody)
}

func initialContentRoutingBody() string {
	return `  status = true

  policy_list {
    item {
      name        = "policy-one"
      server_pool = "pool-one"
      is_default  = false

      rule_list {
        item {
          match_object      = "http-request"
          match_condition   = "match-end"
          match_expression = ".html"
          concatenate       = "and"
          reverse           = false
        }
        item {
          match_object          = "url-parameter"
          name_match_condition  = "equal"
          name                  = "debug"
          value_match_condition = "equal"
          value                 = "1"
          concatenate           = "or"
          reverse               = false
        }
      }
    }
  }
`
}

func updatedContentRoutingBody() string {
	return `  status = false

  policy_list {
    item {
      name        = "policy-alpha"
      server_pool = "pool-alpha"
      is_default  = true

      rule_list {
        item {
          match_object    = "source-ip"
          match_condition = "ip-range"
          start_ip        = "10.0.0.0"
          end_ip          = "10.0.0.255"
          concatenate     = "or"
          reverse         = false
        }
      }
    }
    item {
      name        = "policy-beta"
      server_pool = "pool-beta"
      is_default  = false

      rule_list {}
    }
  }
`
}

// contentRoutingRuleBody is a single-policy/single-rule HCL body used by the
// enum-validation cases. The caller overrides one enum field.
func contentRoutingRuleBody(override string) string {
	return fmt.Sprintf(`  status = true

  policy_list {
    item {
      name        = "policy-v"
      server_pool = "pool-v"
      is_default  = false

      rule_list {
        item {
%s
        }
      }
    }
  }
`, override)
}

func contentRoutingBodyWithMatchObject(object string) string {
	if object == "http-host" {
		return contentRoutingRuleBody("          match_object = \"http-host\"\n          match_condition = \"equal\"\n          match_expression = \"example.com\"\n")
	}
	return contentRoutingRuleBody(fmt.Sprintf("          match_object = %s\n", strconv.Quote(object)))
}

func contentRoutingBodyWithMatchCondition(condition string) string {
	return contentRoutingRuleBody(fmt.Sprintf("          match_object = \"http-host\"\n          match_condition = %s\n          match_expression = \"example.com\"\n", strconv.Quote(condition)))
}

func contentRoutingBodyWithConcatenate(concatenate string) string {
	return contentRoutingRuleBody(fmt.Sprintf("          match_object = \"http-host\"\n          match_condition = \"match-reg\"\n          match_expression = \"example\\\\.com\"\n          concatenate = %s\n", strconv.Quote(concatenate)))
}

func contentRoutingBodyWithSourceRange(missingEnd bool) string {
	end := "          end_ip = \"192.0.2.10\"\n"
	if missingEnd {
		end = ""
	}
	return contentRoutingRuleBody("          match_object = \"source-ip\"\n          match_condition = \"ip-range\"\n          start_ip = \"192.0.2.1\"\n" + end)
}

func contentRoutingBodyWithContradictoryField() string {
	return contentRoutingRuleBody("          match_object = \"http-host\"\n          match_condition = \"equal\"\n          match_expression = \"example.com\"\n          ip_list = \"192.0.2.1\"\n")
}

func contentRoutingBodyWithMultipleDefaults() string {
	return `  status = true

  policy_list {
    item {
      name        = "first"
      server_pool = "pool-a"
      is_default  = true
    }
    item {
      name        = "second"
      server_pool = "pool-b"
      is_default  = true
    }
  }
`
}

func boundedContentRoutingPolicies(count int) string {
	var builder strings.Builder
	builder.WriteString("  status = true\n\n  policy_list {\n")
	for index := 0; index < count; index++ {
		builder.WriteString("    item {\n")
		builder.WriteString(fmt.Sprintf("      name = %s\n      server_pool = %s\n      is_default = false\n",
			strconv.Quote(fmt.Sprintf("policy-%d", index)),
			strconv.Quote(fmt.Sprintf("pool-%d", index)),
		))
		builder.WriteString("    }\n")
	}
	builder.WriteString("  }\n")
	return builder.String()
}

func boundedContentRoutingRules(count int) string {
	var builder strings.Builder
	builder.WriteString("  status = true\n\n  policy_list {\n    item {\n      name = \"policy-v\"\n      server_pool = \"pool-v\"\n      is_default = false\n\n      rule_list {\n")
	for index := 0; index < count; index++ {
		builder.WriteString("        item {\n")
		builder.WriteString("          match_object = \"http-host\"\n          match_condition = \"equal\"\n")
		builder.WriteString(fmt.Sprintf("          match_expression = %s\n", strconv.Quote(fmt.Sprintf("host-%d.example", index))))
		builder.WriteString("        }\n")
	}
	builder.WriteString("      }\n    }\n  }\n")
	return builder.String()
}

func validateTerraformCLIContentRoutingResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	if _, ok := result["status"]; !ok {
		return errors.New("status must be present")
	}
	// The content-routing envelope is flat {status, policy_list}; reject a
	// template field if one ever appears so the mock stays faithful to the
	// contract.
	if template, ok := result["template"]; ok && !bytes.Equal(bytes.TrimSpace(template), []byte("null")) {
		return errors.New("template must not be present on the content-routing envelope")
	}
	return nil
}

func requireTerraformCLIContentRoutingStatus(t *testing.T, body []byte, want bool) {
	t.Helper()
	var envelope struct {
		Status bool `json:"status"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode content routing PUT body: %v", err)
	}
	if envelope.Status != want {
		t.Fatalf("content routing PUT status = %v, want %v", envelope.Status, want)
	}
}

type contentRoutingExpectedRule struct {
	matchObject     string
	matchCondition  string
	matchExpression string
	name            string
	value           string
	concatenate     string
	reverse         bool
	startIP         string
	endIP           string
	ipList          string
	nameMatchCond   string
	valueMatchCond  string
	x509SubjectName string
}

type contentRoutingExpectedPolicy struct {
	name       string
	serverPool string
	isDefault  bool
	rules      []contentRoutingExpectedRule
}

func requireTerraformCLIContentRoutingPolicyList(t *testing.T, body []byte, want []contentRoutingExpectedPolicy) {
	t.Helper()
	var envelope struct {
		PolicyList []map[string]json.RawMessage `json:"policy_list"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode content routing PUT body policy_list: %v", err)
	}
	if len(envelope.PolicyList) != len(want) {
		t.Fatalf("policy_list length = %d, want %d: %s", len(envelope.PolicyList), len(want), string(body))
	}
	for index, policyRaw := range envelope.PolicyList {
		expected := want[index]
		if string(policyRaw["name"]) != strconv.Quote(expected.name) {
			t.Fatalf("policy_list[%d].name = %s, want %q", index, policyRaw["name"], expected.name)
		}
		if string(policyRaw["server_pool"]) != strconv.Quote(expected.serverPool) {
			t.Fatalf("policy_list[%d].server_pool = %s, want %q", index, policyRaw["server_pool"], expected.serverPool)
		}
		var isDefault bool
		if err := json.Unmarshal(policyRaw["is_default"], &isDefault); err != nil {
			t.Fatalf("policy_list[%d].is_default decode: %v", index, err)
		}
		if isDefault != expected.isDefault {
			t.Fatalf("policy_list[%d].is_default = %v, want %v", index, isDefault, expected.isDefault)
		}
		// Wire-only idx is regenerated one-based on write; assert it.
		var idx int
		if err := json.Unmarshal(policyRaw["idx"], &idx); err != nil || idx != index+1 {
			t.Fatalf("policy_list[%d].idx = %s, want %d", index, policyRaw["idx"], index+1)
		}
		requireTerraformCLIContentRoutingRules(t, policyRaw["rule_list"], expected.rules, index)
	}
}

func requireTerraformCLIContentRoutingRules(t *testing.T, rawRules []byte, want []contentRoutingExpectedRule, policyIndex int) {
	t.Helper()
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(rawRules, &rules); err != nil {
		t.Fatalf("decode policy_list[%d].rule_list: %v", policyIndex, err)
	}
	if len(rules) != len(want) {
		t.Fatalf("policy_list[%d].rule_list length = %d, want %d", policyIndex, len(rules), len(want))
	}
	for index, rule := range rules {
		expected := want[index]
		// Wire-only idx is regenerated one-based on write; assert it.
		var idx int
		if err := json.Unmarshal(rule["idx"], &idx); err != nil || idx != index+1 {
			t.Fatalf("policy_list[%d].rule_list[%d].idx = %s, want %d", policyIndex, index, rule["idx"], index+1)
		}
		if expected.matchObject != "" && string(rule["match_object"]) != strconv.Quote(expected.matchObject) {
			t.Fatalf("rule[%d].match_object = %s, want %q", index, rule["match_object"], expected.matchObject)
		}
		if expected.matchCondition != "" && string(rule["match_condition"]) != strconv.Quote(expected.matchCondition) {
			t.Fatalf("rule[%d].match_condition = %s, want %q", index, rule["match_condition"], expected.matchCondition)
		}
		if expected.matchExpression != "" && string(rule["match_expression"]) != strconv.Quote(expected.matchExpression) {
			t.Fatalf("rule[%d].match_expression = %s, want %q", index, rule["match_expression"], expected.matchExpression)
		}
		if expected.name != "" && string(rule["name"]) != strconv.Quote(expected.name) {
			t.Fatalf("rule[%d].name = %s, want %q", index, rule["name"], expected.name)
		}
		if expected.value != "" && string(rule["value"]) != strconv.Quote(expected.value) {
			t.Fatalf("rule[%d].value = %s, want %q", index, rule["value"], expected.value)
		}
		if expected.concatenate != "" && string(rule["concatenate"]) != strconv.Quote(expected.concatenate) {
			t.Fatalf("rule[%d].concatenate = %s, want %q", index, rule["concatenate"], expected.concatenate)
		}
		if expected.startIP != "" && string(rule["start_ip"]) != strconv.Quote(expected.startIP) {
			t.Fatalf("rule[%d].start_ip = %s, want %q", index, rule["start_ip"], expected.startIP)
		}
		if expected.endIP != "" && string(rule["end_ip"]) != strconv.Quote(expected.endIP) {
			t.Fatalf("rule[%d].end_ip = %s, want %q", index, rule["end_ip"], expected.endIP)
		}
		if expected.ipList != "" && string(rule["ip_list"]) != strconv.Quote(expected.ipList) {
			t.Fatalf("rule[%d].ip_list = %s, want %q", index, rule["ip_list"], expected.ipList)
		}
		if expected.nameMatchCond != "" && string(rule["name_match_condition"]) != strconv.Quote(expected.nameMatchCond) {
			t.Fatalf("rule[%d].name_match_condition = %s, want %q", index, rule["name_match_condition"], expected.nameMatchCond)
		}
		if expected.valueMatchCond != "" && string(rule["value_match_condition"]) != strconv.Quote(expected.valueMatchCond) {
			t.Fatalf("rule[%d].value_match_condition = %s, want %q", index, rule["value_match_condition"], expected.valueMatchCond)
		}
		if expected.x509SubjectName != "" && string(rule["x509_subject_name"]) != strconv.Quote(expected.x509SubjectName) {
			t.Fatalf("rule[%d].x509_subject_name = %s, want %q", index, rule["x509_subject_name"], expected.x509SubjectName)
		}
	}
}

// requireTerraformCLIContentRoutingUnknownFields asserts the flat content-
// routing envelope preserves the unknown top-level future_envelope field across
// GET-merge-PUT. Content routing has no configs wrapper, so this checks the
// top-level field directly (unlike requireTerraformCLIUnknownFields).
func requireTerraformCLIContentRoutingUnknownFields(t *testing.T, original, updated []byte) {
	t.Helper()
	originalEnvelope := requireTerraformCLIRawField(t, original, "future_envelope")
	updatedEnvelope := requireTerraformCLIRawField(t, updated, "future_envelope")
	requireTerraformCLIJSONEqual(t, updatedEnvelope, originalEnvelope, "unknown result-envelope field was not preserved")
}

func requireTerraformCLIContentRoutingStateHasNoIdx(t *testing.T, result terraformCLIResult) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var state struct {
		Resources []struct {
			Instances []struct {
				Attributes struct {
					PolicyList struct {
						Item []map[string]json.RawMessage `json:"item"`
					} `json:"policy_list"`
				} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &state); err != nil {
		t.Fatalf("decode state pull JSON: %v", err)
	}
	if len(state.Resources) == 0 || len(state.Resources[0].Instances) == 0 {
		t.Fatalf("state pull has no resource instances:\n%s", result.Stdout)
	}
	policies := state.Resources[0].Instances[0].Attributes.PolicyList.Item
	if len(policies) == 0 {
		t.Fatalf("state pull policy_list has no items:\n%s", result.Stdout)
	}
	for pIndex, policy := range policies {
		if _, hasIdx := policy["idx"]; hasIdx {
			t.Fatalf("state policy_list item %d persists wire-only idx: %#v", pIndex, policy)
		}
		// policy item keys are exactly name/server_pool/is_default/rule_list.
		gotKeys := make([]string, 0, len(policy))
		for key := range policy {
			gotKeys = append(gotKeys, key)
		}
		sort.Strings(gotKeys)
		if !reflect.DeepEqual(gotKeys, []string{"is_default", "name", "rule_list", "server_pool"}) {
			t.Fatalf("state policy_list item %d keys = %#v, want exactly [is_default name rule_list server_pool]", pIndex, gotKeys)
		}
		var rules struct {
			Item []map[string]json.RawMessage `json:"item"`
		}
		if err := json.Unmarshal(policy["rule_list"], &rules); err != nil {
			t.Fatalf("decode state policy_list[%d].rule_list: %v", pIndex, err)
		}
		for rIndex, rule := range rules.Item {
			if _, hasIdx := rule["idx"]; hasIdx {
				t.Fatalf("state policy_list[%d].rule_list[%d] persists wire-only idx: %#v", pIndex, rIndex, rule)
			}
		}
	}
}

func TestTerraformCLIMlApiProtectionLifecycle(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/ml-api-protection"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/ml_api_protection"
	mock := newTerraformCLIMlApiProtectionMock(t, expectedPath, terraformCLITestToken, map[string]any{
		"template": false,
		"configs": map[string]any{
			"status":        false,
			"threat_action": "alert",
			"ip_list_type":  "Block",
			"ip_list":       []any{map[string]any{"idx": 1, "ip": "192.0.2.1"}},
			"path_list":     []any{map[string]any{"idx": 1, "type": "plain", "pattern": "/api/v1"}},
			"future_config": map[string]any{"keep": true},
		},
		"future_envelope": map[string]any{"keep": []any{"beta", float64(6)}},
	})
	server := httptest.NewServer(mock)
	defer server.Close()

	initialUnknown := mock.remoteResult()
	workDir := filepath.Join(temporaryRoot, "lifecycle-ml-api-protection")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIMlApiProtectionHCL(server.URL, epID, initialMlApiProtectionBody()))

	t.Run("schema exposes Framework protocol-5 blocks", func(t *testing.T) {
		result := cli.run(t, workDir, "providers", "schema", "-json")
		requireTerraformCLIExit(t, result, 0)
		requireTerraformCLISchema(t, []byte(result.Stdout))
	})

	mock.resetRequests()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requests := mock.recordedRequests()
	requireTerraformCLIMethods(t, requests, []string{http.MethodGet, http.MethodPut, http.MethodGet})
	initialPut := requireTerraformCLISinglePUT(t, requests)
	requireTerraformCLITemplate(t, initialPut.Body, false)
	requireTerraformCLIMlApiProtectionConfig(t, initialPut.Body, mlApiProtectionExpectedConfig{
		status:       true,
		threatAction: "alert_deny",
		ipListType:   "Trust",
		ipList:       []mlApiProtectionExpectedIP{{ip: "198.51.100.1"}, {ip: "198.51.100.2"}},
		pathList:     []mlApiProtectionExpectedPath{{pathType: "plain", pattern: "/api/v1"}, {pathType: "regular", pattern: "/api/v2/.*"}},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, initialPut.Body)

	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Wire-only idx is never persisted in Terraform state: ip_list/path_list
	// item attributes carry no idx.
	requireTerraformCLIMlApiProtectionStateHasNoIdx(t, cli.run(t, workDir, "state", "pull", "-no-color"))

	// Update: change threat_action, ip_list_type, and the ip_list/path_list to
	// prove the GET-merge-PUT-GET update path regenerates one-based idx in
	// Terraform order and preserves unknown envelope/config fields.
	updateHCL := terraformCLIMlApiProtectionHCL(server.URL, epID, updatedMlApiProtectionBody())
	writeTerraformCLIConfig(t, workDir, updateHCL)
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	updateRequests := mock.recordedRequests()
	requireTerraformCLIGetPutGetSubsequence(t, updateRequests)
	updatePut := requireTerraformCLISinglePUT(t, updateRequests)
	requireTerraformCLIMlApiProtectionConfig(t, updatePut.Body, mlApiProtectionExpectedConfig{
		status:       true,
		threatAction: "disable",
		ipListType:   "Block",
		ipList:       []mlApiProtectionExpectedIP{{ip: "203.0.113.1"}, {ip: "203.0.113.2"}, {ip: "203.0.113.3"}},
		pathList:     []mlApiProtectionExpectedPath{{pathType: "plain", pattern: "/api/v3"}},
	})
	requireTerraformCLIUnknownFields(t, initialUnknown, updatePut.Body)

	// Idempotent re-apply: only a refresh GET.
	mock.resetRequests()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	importDir := filepath.Join(temporaryRoot, "import-ml-api-protection")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, updateHCL)
	mock.resetRequests()
	importResult := cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_ml_api_protection.test", epID)
	requireTerraformCLIExit(t, importResult, 0)
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Out-of-band drift: mutate the remote threat_action outside Terraform,
	// then a refresh+plan must detect the drift (non-empty plan, exit code 2)
	// and issue a GET. No PUT is sent during a plan. The ip_list/path_list are
	// kept identical to the updated config so ONLY threat_action drifts (an
	// absent owned list would independently make plan return 2).
	mock.setRemoteResult(t, map[string]any{
		"template": false,
		"configs": map[string]any{
			"status":        true,
			"threat_action": "alert",
			"ip_list_type":  "Block",
			"ip_list":       []any{map[string]any{"idx": 1, "ip": "203.0.113.1"}, map[string]any{"idx": 2, "ip": "203.0.113.2"}, map[string]any{"idx": 3, "ip": "203.0.113.3"}},
			"path_list":     []any{map[string]any{"idx": 1, "type": "plain", "pattern": "/api/v3"}},
			"future_config": map[string]any{"keep": true},
		},
		"future_envelope": map[string]any{"keep": []any{"beta", float64(6)}},
	})
	mock.resetRequests()
	driftResult := cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false")
	if driftResult.ExitCode != 2 {
		t.Fatalf("drift plan exit code = %d, want 2 (drift detected)\n%s", driftResult.ExitCode, driftResult.output())
	}
	requireTerraformCLIAtLeastOneGETAndNoPUT(t, mock.recordedRequests())

	// Restore the remote to match Terraform state so the subsequent destroy's
	// no-mutation assertion holds; a refresh+plan must converge to no-op again.
	mock.setRemoteResult(t, map[string]any{
		"template": false,
		"configs": map[string]any{
			"status":        true,
			"threat_action": "disable",
			"ip_list_type":  "Block",
			"ip_list":       []any{map[string]any{"idx": 1, "ip": "203.0.113.1"}, map[string]any{"idx": 2, "ip": "203.0.113.2"}, map[string]any{"idx": 3, "ip": "203.0.113.3"}},
			"path_list":     []any{map[string]any{"idx": 1, "type": "plain", "pattern": "/api/v3"}},
			"future_config": map[string]any{"keep": true},
		},
		"future_envelope": map[string]any{"keep": []any{"beta", float64(6)}},
	})
	mock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, mock.recordedRequests())

	// Verified disable-on-destroy through the served Terraform Delete path.
	requireTerraformCLIDisableOnDestroy(t, cli, importDir, mock)

	// Focused negative validation: threat_action / ip_list_type / path_list type
	// enums and the ip_list/path_list 30-item bounds are enforced at plan time
	// without a PUT. Each negative case pairs with an in-range control (exit
	// code 2 = a valid plan with changes, not a validator error which is exit 1).
	validationCases := []struct {
		name         string
		body         string
		wantExitCode int
	}{
		{name: "threat_action valid", body: mlApiProtectionBodyWithThreatAction("alert_deny"), wantExitCode: 2},
		{name: "threat_action invalid", body: mlApiProtectionBodyWithThreatAction("block"), wantExitCode: 1},
		{name: "ip_list_type valid", body: mlApiProtectionBodyWithIPListType("Trust"), wantExitCode: 2},
		{name: "ip_list_type invalid", body: mlApiProtectionBodyWithIPListType("Allow"), wantExitCode: 1},
		{name: "path_list type valid", body: mlApiProtectionBodyWithPathType("plain"), wantExitCode: 2},
		{name: "path_list type invalid", body: mlApiProtectionBodyWithPathType("glob"), wantExitCode: 1},
		{name: "ip_list within 30-item bound", body: boundedMlApiProtectionIPList(30, "198.51.100.1"), wantExitCode: 2},
		{name: "ip_list exceeds 30-item bound", body: boundedMlApiProtectionIPList(31, "198.51.100.1"), wantExitCode: 1},
		{name: "path_list within 30-item bound", body: boundedMlApiProtectionPathList(30), wantExitCode: 2},
		{name: "path_list exceeds 30-item bound", body: boundedMlApiProtectionPathList(31), wantExitCode: 1},
	}
	for _, testCase := range validationCases {
		t.Run(testCase.name, func(t *testing.T) {
			validationDir := filepath.Join(temporaryRoot, "validation-ml-api-protection", strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(validationDir, 0o755); err != nil {
				t.Fatalf("create validation directory: %v", err)
			}
			writeTerraformCLIConfig(t, validationDir, terraformCLIMlApiProtectionHCL(server.URL, epID, testCase.body))
			mock.resetRequests()
			result := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
			if result.ExitCode != testCase.wantExitCode {
				t.Fatalf("Terraform plan exit code = %d, want %d\n%s", result.ExitCode, testCase.wantExitCode, result.output())
			}
			requireTerraformCLINoPUT(t, mock.recordedRequests())
		})
	}
	mock.requireNoHandlerFailures(t)
}

func newTerraformCLICustomRuleMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLICustomRuleResult)
}

func terraformCLICustomRuleHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_custom_rule", "test", epID, resourceBody)
}

func initialCustomRuleBody() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        name          = "rule-one"
        action        = "alert_deny"
        challenge     = "real-browser-enforcement"

        filter_list {
          item {
            type          = "source-ip-filter"
            ip            = "198.51.100.1"
            reverse_match = true
          }
          item {
            type = "url-filter"
            url  = "/admin"
          }
        }
      }
    }
  }
`
}

func updatedCustomRuleBody() string {
	return `  template = false

  configs {
    status = false

    rule_list {
      item {
        name          = "rule-one"
        action        = "block_period"
        block_period  = 3600
        challenge     = "real-browser-enforcement"

        filter_list {
          item {
            type = "source-ip-filter"
            ip   = "203.0.113.1"
          }
          item {
            type       = "occurrence"
            occurrence = 5
            within     = 60
          }
        }
      }
      item {
        name   = "rule-two"
        action = "deny_no_log"
      }
    }
  }
`
}

// customRuleRuleBody is a single-rule HCL body with one filter, used by the
// enum/range validation cases. The caller overrides one field.
func customRuleRuleBody(filterBlock string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status = true

    rule_list {
      item {
        name   = "rule-v"
        action = "alert"
%s
      }
    }
  }
`, filterBlock)
}

func customRuleFilterBlock(override string) string {
	return fmt.Sprintf("        filter_list {\n          item {\n%s          }\n        }\n", override)
}

func customRuleBodyWithFilterType(filterType string) string {
	return customRuleRuleBody(customRuleFilterBlock(fmt.Sprintf("            type = %s\n            ip = \"198.51.100.1\"\n", strconv.Quote(filterType))))
}

func customRuleBodyWithAction(action string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status = true

    rule_list {
      item {
        name   = "rule-v"
        action = %s
        filter_list {
          item {
            type = "source-ip-filter"
            ip   = "198.51.100.1"
          }
        }
      }
    }
  }
`, strconv.Quote(action))
}

func customRuleBodyWithLimit(limit int) string {
	return customRuleRuleBody(customRuleFilterBlock(fmt.Sprintf("            type = \"access-limit-filter\"\n            limit = %d\n", limit)))
}

func customRuleBodyWithOccurrence(occurrence int) string {
	return customRuleRuleBody(customRuleFilterBlock(fmt.Sprintf("            type = \"occurrence\"\n            occurrence = %d\n            within = 60\n", occurrence)))
}

func customRuleBodyWithWithin(within int) string {
	return customRuleRuleBody(customRuleFilterBlock(fmt.Sprintf("            type = \"occurrence\"\n            occurrence = 5\n            within = %d\n", within)))
}

func customRuleBodyWithHeaderType(headerType string) string {
	return customRuleRuleBody(customRuleFilterBlock(fmt.Sprintf("            type = \"http-header-filter\"\n            header_check = true\n            header_type = %s\n            header_name = \"X-Test\"\n", strconv.Quote(headerType))))
}

func customRuleBodyWithTimeType(timeType string) string {
	return customRuleRuleBody(customRuleFilterBlock(fmt.Sprintf("            type = \"time-range-filter\"\n            time_type = %s\n            start = \"00:00\"\n            end = \"23:59\"\n", strconv.Quote(timeType))))
}

func customRuleBodyWithTimeValues(timeType, start, end string) string {
	return customRuleRuleBody(customRuleFilterBlock(fmt.Sprintf(
		"            type = \"time-range-filter\"\n            time_type = %s\n            start = %s\n            end = %s\n",
		strconv.Quote(timeType), strconv.Quote(start), strconv.Quote(end),
	)))
}

func customRuleBodyWithContentTypes(contentType string) string {
	return customRuleRuleBody(fmt.Sprintf("        filter_list {\n          item {\n            type = \"content-type\"\n            content_types = [%s]\n          }\n        }\n", strconv.Quote(contentType)))
}

func customRuleBodyWithURLField(contradictory bool) string {
	extra := ""
	if contradictory {
		extra = "            ip = \"192.0.2.1\"\n"
	}
	return customRuleRuleBody(customRuleFilterBlock(
		"            type = \"url-filter\"\n            url = \"/admin\"\n" + extra,
	))
}

func customRuleBodyWithMissingSourceIP() string {
	return customRuleRuleBody(customRuleFilterBlock("            type = \"source-ip-filter\"\n"))
}

func customRuleBodyWithHeaderCheckConflict() string {
	return customRuleRuleBody(customRuleFilterBlock(
		"            type = \"http-header-filter\"\n            header_check = true\n            http_hline_missing_check = true\n            http_hline_empty_check = true\n",
	))
}

func customRuleBodyWithMissingBlockPeriod() string {
	return customRuleBodyWithAction("block_period")
}

func customRuleBodyWithUnexpectedBlockPeriod() string {
	return `  template = false

  configs {
    status = true

    rule_list {
      item {
        name         = "rule-v"
        action       = "alert_deny"
        block_period = 60
      }
    }
  }
`
}

func customRuleBodyWithChallenge(challenge string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status = true

    rule_list {
      item {
        name      = "rule-v"
        action    = "alert"
        challenge = %s
        filter_list {
          item {
            type = "source-ip-filter"
            ip   = "198.51.100.1"
          }
        }
      }
    }
  }
`, strconv.Quote(challenge))
}

func customRuleBodyWithBlockPeriod(blockPeriod int) string {
	return fmt.Sprintf(`  template = false

  configs {
    status = true

    rule_list {
      item {
        name         = "rule-v"
        action       = "block_period"
        block_period = %d
        filter_list {
          item {
            type = "source-ip-filter"
            ip   = "198.51.100.1"
          }
        }
      }
    }
  }
`, blockPeriod)
}

func customRuleBodyWithName(name string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status = true

    rule_list {
      item {
        name   = %s
        action = "alert"
        filter_list {
          item {
            type = "source-ip-filter"
            ip   = "198.51.100.1"
          }
        }
      }
    }
  }
`, strconv.Quote(name))
}

func boundedCustomRuleFilterList(count int) string {
	var builder strings.Builder
	builder.WriteString("  template = false\n\n  configs {\n    status = true\n\n    rule_list {\n      item {\n        name = \"rule-v\"\n        action = \"alert\"\n        filter_list {\n")
	for i := 0; i < count; i++ {
		builder.WriteString("          item {\n")
		builder.WriteString(fmt.Sprintf("            type = \"source-ip-filter\"\n            ip = %s\n", strconv.Quote(fmt.Sprintf("198.51.100.%d", i%250+1))))
		builder.WriteString("          }\n")
	}
	builder.WriteString("        }\n      }\n    }\n  }\n")
	return builder.String()
}

func boundedCustomRuleRuleList(count int) string {
	var builder strings.Builder
	builder.WriteString("  template = false\n\n  configs {\n    status = true\n\n    rule_list {\n")
	for i := 0; i < count; i++ {
		builder.WriteString("      item {\n")
		builder.WriteString(fmt.Sprintf("        name = %s\n        action = \"alert\"\n", strconv.Quote(fmt.Sprintf("rule-%d", i))))
		builder.WriteString("      }\n")
	}
	builder.WriteString("    }\n  }\n")
	return builder.String()
}

func validateTerraformCLICustomRuleResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	for _, field := range []string{"status"} {
		if _, ok := configs[field]; !ok {
			return fmt.Errorf("configs missing %s", field)
		}
	}
	if _, ok := result["template"]; !ok {
		return errors.New("template must be present")
	}
	return nil
}

type customRuleExpectedFilter struct {
	filterType   string
	ip           string
	url          string
	value        string
	reverseMatch bool
	occurrence   int64
	within       int64
}

type customRuleExpectedRule struct {
	name        string
	action      string
	blockPeriod int64
	challenge   string
	filters     []customRuleExpectedFilter
}

type customRuleExpectedConfig struct {
	status bool
	rules  []customRuleExpectedRule
}

func requireTerraformCLICustomRuleConfig(t *testing.T, body []byte, want customRuleExpectedConfig) {
	t.Helper()
	var envelope struct {
		Template bool `json:"template"`
		Configs  struct {
			Status   bool                         `json:"status"`
			RuleList []map[string]json.RawMessage `json:"rule_list"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode custom rule PUT body: %v", err)
	}
	if envelope.Configs.Status != want.status {
		t.Fatalf("custom rule PUT status = %v, want %v", envelope.Configs.Status, want.status)
	}
	if len(envelope.Configs.RuleList) != len(want.rules) {
		t.Fatalf("rule_list length = %d, want %d: %s", len(envelope.Configs.RuleList), len(want.rules), string(body))
	}
	for index, ruleRaw := range envelope.Configs.RuleList {
		expected := want.rules[index]
		if string(ruleRaw["name"]) != strconv.Quote(expected.name) {
			t.Fatalf("rule_list[%d].name = %s, want %q", index, ruleRaw["name"], expected.name)
		}
		if string(ruleRaw["action"]) != strconv.Quote(expected.action) {
			t.Fatalf("rule_list[%d].action = %s, want %q", index, ruleRaw["action"], expected.action)
		}
		// Wire-only idx is regenerated one-based on write.
		var idx int
		if err := json.Unmarshal(ruleRaw["idx"], &idx); err != nil || idx != index+1 {
			t.Fatalf("rule_list[%d].idx = %s, want %d", index, ruleRaw["idx"], index+1)
		}
		if expected.blockPeriod != 0 {
			var bp int64
			if err := json.Unmarshal(ruleRaw["block_period"], &bp); err != nil || bp != expected.blockPeriod {
				t.Fatalf("rule_list[%d].block_period = %s, want %d", index, ruleRaw["block_period"], expected.blockPeriod)
			}
		}
		if expected.challenge != "" {
			if string(ruleRaw["challenge"]) != strconv.Quote(expected.challenge) {
				t.Fatalf("rule_list[%d].challenge = %s, want %q", index, ruleRaw["challenge"], expected.challenge)
			}
		}
		requireTerraformCLICustomRuleFilters(t, ruleRaw["filter_list"], expected.filters, index)
	}
}

func requireTerraformCLICustomRuleFilters(t *testing.T, rawFilters json.RawMessage, want []customRuleExpectedFilter, ruleIndex int) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	var filters []map[string]json.RawMessage
	if err := json.Unmarshal(rawFilters, &filters); err != nil {
		t.Fatalf("decode rule_list[%d].filter_list: %v", ruleIndex, err)
	}
	if len(filters) != len(want) {
		t.Fatalf("rule_list[%d].filter_list length = %d, want %d", ruleIndex, len(filters), len(want))
	}
	for index, filter := range filters {
		expected := want[index]
		if string(filter["type"]) != strconv.Quote(expected.filterType) {
			t.Fatalf("filter[%d].type = %s, want %q", index, filter["type"], expected.filterType)
		}
		var idx int
		if err := json.Unmarshal(filter["idx"], &idx); err != nil || idx != index+1 {
			t.Fatalf("filter[%d].idx = %s, want %d", index, filter["idx"], index+1)
		}
		if expected.ip != "" && string(filter["ip"]) != strconv.Quote(expected.ip) {
			t.Fatalf("filter[%d].ip = %s, want %q", index, filter["ip"], expected.ip)
		}
		if expected.url != "" && string(filter["url"]) != strconv.Quote(expected.url) {
			t.Fatalf("filter[%d].url = %s, want %q", index, filter["url"], expected.url)
		}
		if expected.value != "" && string(filter["value"]) != strconv.Quote(expected.value) {
			t.Fatalf("filter[%d].value = %s, want %q", index, filter["value"], expected.value)
		}
		if expected.occurrence != 0 {
			var occ int64
			if err := json.Unmarshal(filter["occurrence"], &occ); err != nil || occ != expected.occurrence {
				t.Fatalf("filter[%d].occurrence = %s, want %d", index, filter["occurrence"], expected.occurrence)
			}
		}
		if expected.within != 0 {
			var within int64
			if err := json.Unmarshal(filter["within"], &within); err != nil || within != expected.within {
				t.Fatalf("filter[%d].within = %s, want %d", index, filter["within"], expected.within)
			}
		}
		// Dropping a known field (e.g. url in the update) must clear it: the
		// owned filter is config-authoritative, so the key must be absent.
		if expected.url == "" {
			if _, hasURL := filter["url"]; hasURL {
				t.Fatalf("filter[%d].url carried forward from remote; owned filters must omit cleared fields: %s", index, string(rawFilters))
			}
		}
		if expected.reverseMatch {
			var rm bool
			if err := json.Unmarshal(filter["reverse_match"], &rm); err != nil || !rm {
				t.Fatalf("filter[%d].reverse_match = %s, want true", index, filter["reverse_match"])
			}
		}
	}
}

func requireTerraformCLICustomRuleStateHasNoIdx(t *testing.T, result terraformCLIResult) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var state struct {
		Resources []struct {
			Instances []struct {
				Attributes struct {
					Configs struct {
						RuleList struct {
							Item []map[string]json.RawMessage `json:"item"`
						} `json:"rule_list"`
					} `json:"configs"`
				} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &state); err != nil {
		t.Fatalf("decode state pull JSON: %v", err)
	}
	if len(state.Resources) == 0 || len(state.Resources[0].Instances) == 0 {
		t.Fatalf("state pull has no resource instances:\n%s", result.Stdout)
	}
	rules := state.Resources[0].Instances[0].Attributes.Configs.RuleList.Item
	if len(rules) == 0 {
		t.Fatalf("state pull rule_list has no items:\n%s", result.Stdout)
	}
	for rIndex, rule := range rules {
		if _, hasIdx := rule["idx"]; hasIdx {
			t.Fatalf("state rule_list item %d persists wire-only idx: %#v", rIndex, rule)
		}
		var filters struct {
			Item []map[string]json.RawMessage `json:"item"`
		}
		if ruleRaw, ok := rule["filter_list"]; ok && !bytes.Equal(bytes.TrimSpace(ruleRaw), []byte("null")) {
			if err := json.Unmarshal(ruleRaw, &filters); err != nil {
				t.Fatalf("decode state rule_list[%d].filter_list: %v", rIndex, err)
			}
			for fIndex, filter := range filters.Item {
				if _, hasIdx := filter["idx"]; hasIdx {
					t.Fatalf("state rule_list[%d].filter_list[%d] persists wire-only idx: %#v", rIndex, fIndex, filter)
				}
			}
		}
	}
}

func newTerraformCLIMlApiProtectionMock(t *testing.T, expectedPath, expectedToken string, initial any) *terraformCLIMock {
	t.Helper()
	return newTerraformCLIMock(t, expectedPath, expectedToken, initial, validateTerraformCLIMlApiProtectionResult)
}

func terraformCLIMlApiProtectionHCL(apiURL, epID, resourceBody string) string {
	return terraformCLIResourceHCL(apiURL, "fortiappseccloud_waf_ml_api_protection", "test", epID, resourceBody)
}

func initialMlApiProtectionBody() string {
	return `  template = false

  configs {
    status        = true
    threat_action = "alert_deny"
    ip_list_type  = "Trust"

    ip_list {
      item {
        ip = "198.51.100.1"
      }
      item {
        ip = "198.51.100.2"
      }
    }

    path_list {
      item {
        type    = "plain"
        pattern = "/api/v1"
      }
      item {
        type    = "regular"
        pattern = "/api/v2/.*"
      }
    }
  }
`
}

func updatedMlApiProtectionBody() string {
	return `  template = false

  configs {
    status        = true
    threat_action = "disable"
    ip_list_type  = "Block"

    ip_list {
      item {
        ip = "203.0.113.1"
      }
      item {
        ip = "203.0.113.2"
      }
      item {
        ip = "203.0.113.3"
      }
    }

    path_list {
      item {
        type    = "plain"
        pattern = "/api/v3"
      }
    }
  }
`
}

func mlApiProtectionConfigsBody(override string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status        = true
    threat_action = "alert"
    ip_list_type  = "Block"
%s
  }
`, override)
}

func mlApiProtectionBodyWithThreatAction(action string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status        = true
    threat_action = %s
    ip_list_type  = "Block"
  }
`, strconv.Quote(action))
}

func mlApiProtectionBodyWithIPListType(ipListType string) string {
	return fmt.Sprintf(`  template = false

  configs {
    status        = true
    threat_action = "alert"
    ip_list_type  = %s
  }
`, strconv.Quote(ipListType))
}

func mlApiProtectionBodyWithPathType(pathType string) string {
	return mlApiProtectionConfigsBody(fmt.Sprintf("    path_list {\n      item {\n        type    = %s\n        pattern = \"/api\"\n      }\n    }\n", strconv.Quote(pathType)))
}

func boundedMlApiProtectionIPList(count int, ip string) string {
	var builder strings.Builder
	builder.WriteString("  template = false\n\n  configs {\n    status = true\n    threat_action = \"alert\"\n    ip_list_type = \"Block\"\n\n    ip_list {\n")
	for i := 0; i < count; i++ {
		builder.WriteString("      item {\n")
		builder.WriteString(fmt.Sprintf("        ip = %s\n", strconv.Quote(ip)))
		builder.WriteString("      }\n")
	}
	builder.WriteString("    }\n  }\n")
	return builder.String()
}

func boundedMlApiProtectionPathList(count int) string {
	var builder strings.Builder
	builder.WriteString("  template = false\n\n  configs {\n    status = true\n    threat_action = \"alert\"\n    ip_list_type = \"Block\"\n\n    path_list {\n")
	for i := 0; i < count; i++ {
		builder.WriteString("      item {\n")
		builder.WriteString(fmt.Sprintf("        type = \"plain\"\n        pattern = %s\n", strconv.Quote(fmt.Sprintf("/api/%d", i))))
		builder.WriteString("      }\n")
	}
	builder.WriteString("    }\n  }\n")
	return builder.String()
}

func validateTerraformCLIMlApiProtectionResult(data []byte) error {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode result object: %w", err)
	}
	configsRaw, ok := result["configs"]
	if !ok || bytes.Equal(bytes.TrimSpace(configsRaw), []byte("null")) {
		return errors.New("configs must be a non-null object")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(configsRaw, &configs); err != nil {
		return fmt.Errorf("decode configs object: %w", err)
	}
	for _, field := range []string{"status", "threat_action", "ip_list_type"} {
		if _, ok := configs[field]; !ok {
			return fmt.Errorf("configs missing %s", field)
		}
	}
	if _, ok := result["template"]; !ok {
		return errors.New("template must be present")
	}
	return nil
}

type mlApiProtectionExpectedIP struct {
	ip string
}

type mlApiProtectionExpectedPath struct {
	pathType string
	pattern  string
}

type mlApiProtectionExpectedConfig struct {
	status       bool
	threatAction string
	ipListType   string
	ipList       []mlApiProtectionExpectedIP
	pathList     []mlApiProtectionExpectedPath
}

func requireTerraformCLIMlApiProtectionConfig(t *testing.T, body []byte, want mlApiProtectionExpectedConfig) {
	t.Helper()
	var envelope struct {
		Template bool `json:"template"`
		Configs  struct {
			Status       bool                         `json:"status"`
			ThreatAction string                       `json:"threat_action"`
			IPListType   string                       `json:"ip_list_type"`
			IPList       []map[string]json.RawMessage `json:"ip_list"`
			PathList     []map[string]json.RawMessage `json:"path_list"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode ml api protection PUT body: %v", err)
	}
	if envelope.Configs.Status != want.status {
		t.Fatalf("ml api protection PUT status = %v, want %v", envelope.Configs.Status, want.status)
	}
	if envelope.Configs.ThreatAction != want.threatAction {
		t.Fatalf("ml api protection PUT threat_action = %q, want %q", envelope.Configs.ThreatAction, want.threatAction)
	}
	if envelope.Configs.IPListType != want.ipListType {
		t.Fatalf("ml api protection PUT ip_list_type = %q, want %q", envelope.Configs.IPListType, want.ipListType)
	}
	if len(envelope.Configs.IPList) != len(want.ipList) {
		t.Fatalf("ip_list length = %d, want %d: %s", len(envelope.Configs.IPList), len(want.ipList), string(body))
	}
	for index, item := range envelope.Configs.IPList {
		var idx int
		if err := json.Unmarshal(item["idx"], &idx); err != nil || idx != index+1 {
			t.Fatalf("ip_list[%d].idx = %s, want %d", index, item["idx"], index+1)
		}
		if string(item["ip"]) != strconv.Quote(want.ipList[index].ip) {
			t.Fatalf("ip_list[%d].ip = %s, want %q", index, item["ip"], want.ipList[index].ip)
		}
	}
	if len(envelope.Configs.PathList) != len(want.pathList) {
		t.Fatalf("path_list length = %d, want %d: %s", len(envelope.Configs.PathList), len(want.pathList), string(body))
	}
	for index, item := range envelope.Configs.PathList {
		var idx int
		if err := json.Unmarshal(item["idx"], &idx); err != nil || idx != index+1 {
			t.Fatalf("path_list[%d].idx = %s, want %d", index, item["idx"], index+1)
		}
		if string(item["type"]) != strconv.Quote(want.pathList[index].pathType) {
			t.Fatalf("path_list[%d].type = %s, want %q", index, item["type"], want.pathList[index].pathType)
		}
		if string(item["pattern"]) != strconv.Quote(want.pathList[index].pattern) {
			t.Fatalf("path_list[%d].pattern = %s, want %q", index, item["pattern"], want.pathList[index].pattern)
		}
	}
}

func requireTerraformCLIMlApiProtectionStateHasNoIdx(t *testing.T, result terraformCLIResult) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var state struct {
		Resources []struct {
			Instances []struct {
				Attributes struct {
					Configs struct {
						IPList struct {
							Item []map[string]json.RawMessage `json:"item"`
						} `json:"ip_list"`
						PathList struct {
							Item []map[string]json.RawMessage `json:"item"`
						} `json:"path_list"`
					} `json:"configs"`
				} `json:"attributes"`
			} `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &state); err != nil {
		t.Fatalf("decode state pull JSON: %v", err)
	}
	if len(state.Resources) == 0 || len(state.Resources[0].Instances) == 0 {
		t.Fatalf("state pull has no resource instances:\n%s", result.Stdout)
	}
	configs := state.Resources[0].Instances[0].Attributes.Configs
	for _, check := range []struct {
		name  string
		items []map[string]json.RawMessage
	}{
		{"ip_list", configs.IPList.Item},
		{"path_list", configs.PathList.Item},
	} {
		for index, item := range check.items {
			if _, hasIdx := item["idx"]; hasIdx {
				t.Fatalf("state %s item %d persists wire-only idx: %#v", check.name, index, item)
			}
		}
	}
}

func TestTerraformCLIApplicationModulesDataSource(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/modules with spaces"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/modules"
	var mutex sync.Mutex
	remote := []map[string]string{
		{"id": "url_access", "status": "enable"},
		{"id": "advanced_bot_protection", "status": "disable", "inherited": "enable"},
	}
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		methods = append(methods, r.Method)
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.EscapedPath() != expectedPath {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Basic "+terraformCLITestToken {
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(remote); err != nil {
			t.Errorf("encode modules response: %v", err)
		}
	}))
	defer server.Close()

	workDir := filepath.Join(temporaryRoot, "modules-data-source")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create modules data source directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIApplicationModulesDataSourceHCL(server.URL, epID))

	schemaResult := cli.run(t, workDir, "providers", "schema", "-json")
	requireTerraformCLIExit(t, schemaResult, 0)
	requireTerraformCLISchema(t, []byte(schemaResult.Stdout))

	resetMethods := func() {
		mutex.Lock()
		defer mutex.Unlock()
		methods = nil
	}
	requireOnlyGETs := func() {
		mutex.Lock()
		defer mutex.Unlock()
		if len(methods) == 0 {
			t.Fatal("modules data source made no request")
		}
		for _, method := range methods {
			if method != http.MethodGet {
				t.Fatalf("modules data source method = %q, want only GET: %#v", method, methods)
			}
		}
	}

	resetMethods()
	applyResult := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, applyResult, 0)
	requireOnlyGETs()
	requireTerraformCLIApplicationModulesOutput(t, cli.run(t, workDir, "output", "-json", "modules"), []terraformCLIApplicationModuleOutput{
		{ID: "advanced_bot_protection", Status: "disable", Inherited: stringPointer("enable")},
		{ID: "url_access", Status: "enable"},
	})

	resetMethods()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireOnlyGETs()

	mutex.Lock()
	remote = []map[string]string{
		{"id": "url_access", "status": "disable", "inherited": "disable"},
		{"id": "advanced_bot_protection", "status": "disable", "inherited": "enable"},
	}
	mutex.Unlock()
	resetMethods()
	driftPlan := cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, driftPlan, 2)
	requireOnlyGETs()

	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireOnlyGETs()
	requireTerraformCLIApplicationModulesOutput(t, cli.run(t, workDir, "output", "-json", "modules"), []terraformCLIApplicationModuleOutput{
		{ID: "advanced_bot_protection", Status: "disable", Inherited: stringPointer("enable")},
		{ID: "url_access", Status: "disable", Inherited: stringPointer("disable")},
	})
	resetMethods()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireOnlyGETs()

	validationDir := filepath.Join(temporaryRoot, "modules-data-source-validation")
	if err := os.MkdirAll(validationDir, 0o755); err != nil {
		t.Fatalf("create modules validation directory: %v", err)
	}
	writeTerraformCLIConfig(t, validationDir, terraformCLIApplicationModulesDataSourceHCL(server.URL, " \t "))
	resetMethods()
	validation := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, validation, 1)
	mutex.Lock()
	if len(methods) != 0 {
		t.Fatalf("invalid modules configuration made API requests: %#v", methods)
	}
	mutex.Unlock()

	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "destroy", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	mutex.Lock()
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("data source destroy sent method %q", method)
		}
	}
	mutex.Unlock()
	stateList := cli.run(t, workDir, "state", "list", "-no-color")
	requireTerraformCLIExit(t, stateList, 0)
	if strings.TrimSpace(stateList.Stdout) != "" {
		t.Fatalf("Terraform state still contains the modules data source after destroy: %q", stateList.Stdout)
	}
}

func terraformCLIApplicationModulesDataSourceHCL(apiURL, epID string) string {
	return fmt.Sprintf(`terraform {
  required_providers {
    fortiappseccloud = {
      source = "fortinet/fortiappseccloud"
    }
  }
}

provider "fortiappseccloud" {
  hostname  = %s
  api_token = %s
}

data "fortiappseccloud_waf_modules" "test" {
  ep_id = %s
}

output "modules" {
  value = data.fortiappseccloud_waf_modules.test.modules
}
`, strconv.Quote(apiURL), strconv.Quote(terraformCLITestToken), strconv.Quote(epID))
}

type terraformCLIApplicationModuleOutput struct {
	ID        string  `json:"id"`
	Status    string  `json:"status"`
	Inherited *string `json:"inherited"`
}

func requireTerraformCLIApplicationModulesOutput(t *testing.T, result terraformCLIResult, want []terraformCLIApplicationModuleOutput) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var got []terraformCLIApplicationModuleOutput
	if err := json.Unmarshal([]byte(result.Stdout), &got); err != nil {
		t.Fatalf("decode modules output: %v\n%s", err, result.Stdout)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modules output = %#v, want %#v", got, want)
	}
}

func stringPointer(value string) *string {
	return &value
}

func TestTerraformCLISignatureExceptionDataSource(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to run the local Terraform CLI integration test")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	temporaryRoot := t.TempDir()
	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)

	epID := "application/signature exception"
	signatureID := "030000001"
	expectedPath := "/v2/waf/apps/" + url.PathEscape(epID) + "/signature_exception"
	var mutex sync.Mutex
	templateID := stringPointer("template-a")
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		methods = append(methods, r.Method)
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.EscapedPath() != expectedPath || r.URL.Query().Get("signatureid") != signatureID {
			http.Error(w, "unexpected signature identity", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Basic "+terraformCLITestToken {
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{}
		if templateID != nil {
			response["result"] = map[string]string{"template": *templateID}
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode signature exception response: %v", err)
		}
	}))
	defer server.Close()

	workDir := filepath.Join(temporaryRoot, "signature-exception-data-source")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create signature exception data source directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLISignatureExceptionDataSourceHCL(server.URL, epID, signatureID))

	resetMethods := func() {
		mutex.Lock()
		defer mutex.Unlock()
		methods = nil
	}
	requireOnlyGETs := func() {
		mutex.Lock()
		defer mutex.Unlock()
		if len(methods) == 0 {
			t.Fatal("signature exception data source made no request")
		}
		for _, method := range methods {
			if method != http.MethodGet {
				t.Fatalf("signature exception data source method = %q, want only GET: %#v", method, methods)
			}
		}
	}

	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireOnlyGETs()
	requireTerraformCLISignatureExceptionState(t, cli.run(t, workDir, "show", "-json"), stringPointer("template-a"))

	resetMethods()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireOnlyGETs()

	mutex.Lock()
	templateID = stringPointer("template-b")
	mutex.Unlock()
	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"), 2)
	requireOnlyGETs()
	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireOnlyGETs()
	requireTerraformCLISignatureExceptionState(t, cli.run(t, workDir, "show", "-json"), stringPointer("template-b"))

	mutex.Lock()
	templateID = nil
	mutex.Unlock()
	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"), 2)
	requireOnlyGETs()
	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireOnlyGETs()
	requireTerraformCLISignatureExceptionState(t, cli.run(t, workDir, "show", "-json"), nil)
	resetMethods()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireOnlyGETs()

	validationDir := filepath.Join(temporaryRoot, "signature-exception-validation")
	if err := os.MkdirAll(validationDir, 0o755); err != nil {
		t.Fatalf("create signature validation directory: %v", err)
	}
	writeTerraformCLIConfig(t, validationDir, terraformCLISignatureExceptionDataSourceHCL(server.URL, epID, " \t "))
	resetMethods()
	validation := cli.run(t, validationDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, validation, 1)
	mutex.Lock()
	if len(methods) != 0 {
		t.Fatalf("invalid signature exception configuration made requests: %#v", methods)
	}
	mutex.Unlock()

	resetMethods()
	requireTerraformCLIExit(t, cli.run(t, workDir, "destroy", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	mutex.Lock()
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("signature exception data source destroy sent method %q", method)
		}
	}
	mutex.Unlock()
	stateList := cli.run(t, workDir, "state", "list", "-no-color")
	requireTerraformCLIExit(t, stateList, 0)
	if strings.TrimSpace(stateList.Stdout) != "" {
		t.Fatalf("Terraform state still contains the signature exception data source after destroy: %q", stateList.Stdout)
	}
}

func terraformCLISignatureExceptionDataSourceHCL(apiURL, epID, signatureID string) string {
	return fmt.Sprintf(`terraform {
  required_providers {
    fortiappseccloud = {
      source = "fortinet/fortiappseccloud"
    }
  }
}

provider "fortiappseccloud" {
  hostname  = %s
  api_token = %s
}

data "fortiappseccloud_waf_signature_exception" "test" {
  ep_id        = %s
  signature_id = %s
}

output "template_id" {
  value = data.fortiappseccloud_waf_signature_exception.test.template_id
}
`, strconv.Quote(apiURL), strconv.Quote(terraformCLITestToken), strconv.Quote(epID), strconv.Quote(signatureID))
}

func requireTerraformCLISignatureExceptionState(t *testing.T, result terraformCLIResult, want *string) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var document struct {
		Values struct {
			RootModule struct {
				Resources []struct {
					Address string `json:"address"`
					Values  struct {
						TemplateID *string `json:"template_id"`
					} `json:"values"`
				} `json:"resources"`
			} `json:"root_module"`
		} `json:"values"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &document); err != nil {
		t.Fatalf("decode signature exception state: %v\n%s", err, result.Stdout)
	}
	var got *string
	found := false
	for _, resource := range document.Values.RootModule.Resources {
		if resource.Address == "data.fortiappseccloud_waf_signature_exception.test" {
			got = resource.Values.TemplateID
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("signature exception data source is absent from state:\n%s", result.Stdout)
	}
	if (got == nil) != (want == nil) || got != nil && *got != *want {
		t.Fatalf("signature exception state template = %#v, want %#v", got, want)
	}
}
