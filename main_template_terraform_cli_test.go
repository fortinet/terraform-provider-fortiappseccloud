package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestTerraformCLITemplateAndGeneratedModuleLifecycle(t *testing.T) {
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

	templateID := "tpl_123456"
	modulePath := "/v2/waf/template/" + url.PathEscape(templateID) + "/csrf_protection"
	moduleMock := newTerraformCLICSRFMock(t, modulePath, terraformCLITestToken, map[string]any{
		"configs": map[string]any{
			"action":    "alert",
			"status":    false,
			"page_list": []any{},
			"url_list":  []any{},
			"future_config": map[string]any{
				"keep": true,
			},
		},
		"template":        false,
		"future_envelope": map[string]any{"keep": "local"},
	})
	mock := &terraformCLITemplateMock{
		templateID: templateID,
		name:       "terraform-template",
		token:      terraformCLITestToken,
		modulePath: modulePath,
		module:     moduleMock,
	}
	server := httptest.NewServer(mock)
	defer server.Close()

	workDir := filepath.Join(temporaryRoot, "template-lifecycle")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create lifecycle directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLITemplateHCL(server.URL, "alert_deny", true))

	apply := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, apply, 0)
	if mock.createCountValue() != 1 {
		t.Fatalf("template POST count = %d, want 1", mock.createCountValue())
	}
	initialPut := requireTerraformCLISinglePUT(t, moduleMock.recordedRequests())
	requireTerraformCLITemplate(t, initialPut.Body, false)
	requireTerraformCLIConfigScalar(t, initialPut.Body, "action", "alert_deny")
	requireTerraformCLIConfigScalar(t, initialPut.Body, "status", true)

	mock.resetTemplateRequests()
	moduleMock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	if mock.createCountValue() != 1 {
		t.Fatalf("no-op plan issued another template POST")
	}
	requireTerraformCLINoPUT(t, moduleMock.recordedRequests())

	writeTerraformCLIConfig(t, workDir, terraformCLITemplateHCL(server.URL, "deny_no_log", false))
	moduleMock.resetRequests()
	update := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, update, 0)
	updatePut := requireTerraformCLISinglePUT(t, moduleMock.recordedRequests())
	requireTerraformCLIConfigScalar(t, updatePut.Body, "action", "deny_no_log")
	requireTerraformCLIConfigScalar(t, updatePut.Body, "status", false)

	importDir := filepath.Join(temporaryRoot, "template-import")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatalf("create import directory: %v", err)
	}
	writeTerraformCLIConfig(t, importDir, terraformCLITemplateHCL(server.URL, "deny_no_log", false))
	requireTerraformCLIExit(t, cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_template.test", templateID), 0)
	requireTerraformCLIExit(t, cli.run(t, importDir, "import", "-input=false", "-no-color", "-lock=false", "fortiappseccloud_waf_template_csrf_protection.test", templateID), 0)
	moduleMock.resetRequests()
	requireTerraformCLINoOpPlan(t, cli.run(t, importDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))
	requireTerraformCLINoPUT(t, moduleMock.recordedRequests())
	requireTerraformCLIExit(t, cli.run(t, importDir, "state", "rm", "fortiappseccloud_waf_template_csrf_protection.test"), 0)
	requireTerraformCLIExit(t, cli.run(t, importDir, "state", "rm", "fortiappseccloud_waf_template.test"), 0)

	writeTerraformCLIConfig(t, workDir, terraformCLITemplateHCL(server.URL, "deny_no_log", true))
	moduleMock.resetRequests()
	reenable := cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false")
	requireTerraformCLIExit(t, reenable, 0)
	reenablePut := requireTerraformCLISinglePUT(t, moduleMock.recordedRequests())
	requireTerraformCLIConfigScalar(t, reenablePut.Body, "status", true)

	requireTerraformCLIDisableOnDestroy(t, cli, workDir, moduleMock)
	if mock.deleteCountValue() != 1 || mock.existsValue() {
		t.Fatalf("template delete count/existence = %d/%t, want 1/false", mock.deleteCountValue(), mock.existsValue())
	}
	mock.requireNoFailures(t)
	moduleMock.requireNoHandlerFailures(t)
}

func terraformCLITemplateHCL(apiURL, action string, status bool) string {
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

resource "fortiappseccloud_waf_template" "test" {
  name = "terraform-template"
}

resource "fortiappseccloud_waf_template_csrf_protection" "test" {
  template_id = fortiappseccloud_waf_template.test.template_id

  configs {
    action = %s
    status = %t

    page_list {
      item {
        filter = true
        url    = "/checkout"
        name   = "csrf_token"
        value  = "expected"
      }
    }

    url_list {}
  }
}
`, strconv.Quote(apiURL), strconv.Quote(terraformCLITestToken), strconv.Quote(action), status)
}

type terraformCLITemplateMock struct {
	mu               sync.Mutex
	templateID       string
	name             string
	token            string
	modulePath       string
	module           http.Handler
	exists           bool
	createCount      int
	deleteCount      int
	templateRequests []terraformCLIRecordedRequest
	failures         []string
}

func (m *terraformCLITemplateMock) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.EscapedPath() == m.modulePath {
		m.module.ServeHTTP(response, request)
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		m.fail(response, http.StatusUnprocessableEntity, "read request body: %v", err)
		return
	}
	m.mu.Lock()
	m.templateRequests = append(m.templateRequests, terraformCLIRecordedRequest{
		Method:     request.Method,
		RequestURI: request.RequestURI,
		Host:       request.Host,
		Proto:      request.Proto,
		Header:     request.Header.Clone(),
		Body:       append([]byte(nil), body...),
	})
	m.mu.Unlock()
	if request.Header.Get("Authorization") != "Basic "+m.token {
		m.fail(response, http.StatusUnauthorized, "authorization header was not the dummy local token")
		return
	}
	if request.URL.RawQuery != "" {
		m.fail(response, http.StatusUnprocessableEntity, "unexpected query %q", request.URL.RawQuery)
		return
	}

	switch request.URL.EscapedPath() {
	case "/v2/waf/template":
		m.create(response, request, body)
	case "/v2/waf/template/" + url.PathEscape(m.templateID):
		m.detail(response, request, body)
	default:
		m.fail(response, http.StatusNotFound, "unexpected template path %q", request.URL.EscapedPath())
	}
}

func (m *terraformCLITemplateMock) create(response http.ResponseWriter, request *http.Request, body []byte) {
	if request.Method == http.MethodGet {
		if len(bytes.TrimSpace(body)) != 0 {
			m.fail(response, http.StatusUnprocessableEntity, "template collection GET contained a body")
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if !m.existsValue() {
			_, _ = fmt.Fprint(response, `{"result":[],"total":0,"user_perm":"rw"}`)
			return
		}
		_, _ = fmt.Fprintf(response, `{"result":[{"template_id":%s,"name":%s,"predefine":false,"features":["csrf_protection"],"endpoints":[]}],"total":1,"user_perm":"rw"}`,
			strconv.Quote(m.templateID), strconv.Quote(m.name))
		return
	}
	if request.Method != http.MethodPost {
		m.fail(response, http.StatusMethodNotAllowed, "template collection method = %s", request.Method)
		return
	}
	if request.Header.Get("Idempotency-Key") == "" {
		m.fail(response, http.StatusUnprocessableEntity, "template POST omitted Idempotency-Key")
		return
	}
	var payload struct {
		Name      string   `json:"name"`
		Endpoints []string `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		m.fail(response, http.StatusUnprocessableEntity, "decode template POST: %v", err)
		return
	}
	if payload.Name != m.name || payload.Endpoints == nil || len(payload.Endpoints) != 0 {
		m.fail(response, http.StatusUnprocessableEntity, "template POST payload = %#v", payload)
		return
	}
	m.mu.Lock()
	if m.exists {
		m.mu.Unlock()
		m.fail(response, http.StatusConflict, "template already exists")
		return
	}
	m.exists = true
	m.createCount++
	m.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Location", "/v2/waf/template/"+url.PathEscape(m.templateID))
	response.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(response, `{"result":{"template_id":%s,"name":%s,"predefine":false,"features":[],"endpoints":[]},"detail":"Template created"}`,
		strconv.Quote(m.templateID), strconv.Quote(m.name))
}

func (m *terraformCLITemplateMock) detail(response http.ResponseWriter, request *http.Request, body []byte) {
	switch request.Method {
	case http.MethodGet:
		if len(bytes.TrimSpace(body)) != 0 {
			m.fail(response, http.StatusUnprocessableEntity, "template GET contained a body")
			return
		}
		if !m.existsValue() {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(response, `{"result":{"template_id":%s,"name":%s,"predefine":false,"features":["csrf_protection"],"endpoints":[]}}`,
			strconv.Quote(m.templateID), strconv.Quote(m.name))
	case http.MethodDelete:
		if len(bytes.TrimSpace(body)) != 0 {
			m.fail(response, http.StatusUnprocessableEntity, "template DELETE contained a body")
			return
		}
		m.mu.Lock()
		m.exists = false
		m.deleteCount++
		m.mu.Unlock()
		response.WriteHeader(http.StatusNoContent)
	default:
		m.fail(response, http.StatusMethodNotAllowed, "template detail method = %s", request.Method)
	}
}

func (m *terraformCLITemplateMock) fail(response http.ResponseWriter, status int, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	m.mu.Lock()
	m.failures = append(m.failures, message)
	m.mu.Unlock()
	http.Error(response, message, status)
}

func (m *terraformCLITemplateMock) existsValue() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exists
}

func (m *terraformCLITemplateMock) createCountValue() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createCount
}

func (m *terraformCLITemplateMock) deleteCountValue() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteCount
}

func (m *terraformCLITemplateMock) resetTemplateRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.templateRequests = nil
}

func (m *terraformCLITemplateMock) requireNoFailures(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.failures) != 0 {
		t.Fatalf("template mock failures = %#v", m.failures)
	}
}
