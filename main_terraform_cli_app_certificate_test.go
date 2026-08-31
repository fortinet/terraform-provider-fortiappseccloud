package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"terraform-provider-fortiappseccloud/internal/client"
)

const terraformCLIAppCertificateAddress = "fortiappseccloud_waf_app.test"

func TestTerraformCLIApplicationCertificateModeLifecycle(t *testing.T) {
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

	mock := newTerraformCLIAppCertificateMock(t)
	server := httptest.NewServer(mock)
	defer server.Close()

	workDir := filepath.Join(temporaryRoot, "app-certificate-mode")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create application certificate-mode directory: %v", err)
	}
	writeTerraformCLIConfig(t, workDir, terraformCLIAppCertificateHCL(server.URL, "custom"))

	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	mock.requireCertificateType(t, 1)
	requireTerraformCLIAppCertificateMode(t, cli.run(t, workDir, "show", "-json"), "custom")
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))

	writeTerraformCLIConfig(t, workDir, terraformCLIAppCertificateHCL(server.URL, "automatic"))
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	mock.requireCertificateType(t, 0)
	mock.requirePreservedEndpointFields(t)
	requireTerraformCLIAppCertificateMode(t, cli.run(t, workDir, "show", "-json"), "automatic")
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))

	mock.setCertificateType(1)
	requireTerraformCLIExit(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"), 2)
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	mock.requireCertificateType(t, 0)
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))

	requireTerraformCLIExit(t, cli.run(t, workDir, "state", "rm", terraformCLIAppCertificateAddress), 0)
	requireTerraformCLIExit(t, cli.run(t, workDir, "import", "-input=false", "-no-color", "-lock=false", terraformCLIAppCertificateAddress, "100"), 0)
	requireTerraformCLIAppCertificateMode(t, cli.run(t, workDir, "show", "-json"), "automatic")
	requireTerraformCLIExit(t, cli.run(t, workDir, "apply", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	requireTerraformCLINoOpPlan(t, cli.run(t, workDir, "plan", "-detailed-exitcode", "-input=false", "-no-color", "-lock=false"))

	requireTerraformCLIExit(t, cli.run(t, workDir, "destroy", "-auto-approve", "-input=false", "-no-color", "-lock=false"), 0)
	mock.requireDeleted(t)
}

type terraformCLIAppCertificateMock struct {
	t        *testing.T
	mutex    sync.Mutex
	exists   bool
	app      map[string]any
	endpoint map[string]any
	lastPut  map[string]any
}

func newTerraformCLIAppCertificateMock(t *testing.T) *terraformCLIAppCertificateMock {
	return &terraformCLIAppCertificateMock{t: t}
}

func (m *terraformCLIAppCertificateMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if r.Header.Get("Authorization") != "Basic "+terraformCLITestToken {
		http.Error(w, "unexpected authorization", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method + " " + r.URL.Path {
	case "POST /v2/waf/apps":
		m.create(w, r)
	case "GET /v2/waf/apps":
		applications := []map[string]any{}
		if m.exists {
			applications = append(applications, cloneJSONMap(m.app))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"app_list": applications, "can_add": 1, "next_cursor": "", "prev_cursor": "", "total": len(applications),
		})
	case "GET /v2/waf/apps/100":
		if !m.exists {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"app_name": m.app["app_name"], "domain_name": m.app["domain_name"], "block_mode": m.app["block_mode"]})
	case "GET /v2/waf/apps/100/endpoint":
		if !m.exists {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(m.endpoint)
	case "PUT /v2/waf/apps/100/endpoint":
		if !m.exists {
			http.NotFound(w, r)
			return
		}
		var document map[string]any
		if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.endpoint = cloneJSONMap(document)
		m.lastPut = cloneJSONMap(document)
		_, _ = w.Write([]byte(`{"detail":"updated"}`))
	case "DELETE /v2/waf/apps/100":
		m.exists = false
		_, _ = w.Write([]byte(`{"detail":"deleted"}`))
	default:
		http.NotFound(w, r)
	}
}

func (m *terraformCLIAppCertificateMock) create(w http.ResponseWriter, r *http.Request) {
	if m.exists {
		http.Error(w, "already exists", http.StatusConflict)
		return
	}
	var request map[string]any
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	certType, ok := request["cert_type"].(float64)
	if !ok || certType != 1 {
		http.Error(w, "initial custom cert_type required", http.StatusBadRequest)
		return
	}
	if request["creation_origin"] != client.ApplicationCreationOriginTerraform {
		http.Error(w, "Terraform creation_origin required", http.StatusBadRequest)
		return
	}
	m.exists = true
	m.app = map[string]any{
		"ep_id": "100", "app_name": request["app_name"], "domain_name": request["domain_name"],
		"extra_domains": request["extra_domains"], "ep_cname": "demo.edge.example", "block_mode": request["block_mode"],
		"cdn_status": request["cdn_status"], "is_global_cdn": request["is_global_cdn"], "platform": request["platform"],
		"platform_region": request["region"], "template_id": "", "template_name": "",
	}
	services, _ := request["service"].([]any)
	customPort, _ := request["custom_port"].(map[string]any)
	m.endpoint = map[string]any{
		"extra_domains": request["extra_domains"],
		"http_status":   boolIntForTerraformCLITest(containsStringForTerraformCLITest(services, "http")),
		"https_status":  boolIntForTerraformCLITest(containsStringForTerraformCLITest(services, "https")),
		"custom_port":   customPort,
		"cert_type":     certType, "cert_auto_status": float64(7), "cert_challenge_mode": float64(2),
		"future_endpoint_field": map[string]any{"preserve": true},
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ep_id": "100", "app_name": request["app_name"],
		"domain_info": []map[string]string{{"domain": "demo.example.com", "dns": "demo.edge.example"}},
	})
}

func (m *terraformCLIAppCertificateMock) setCertificateType(value int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.endpoint["cert_type"] = float64(value)
}

func (m *terraformCLIAppCertificateMock) requireCertificateType(t *testing.T, want int) {
	t.Helper()
	m.mutex.Lock()
	defer m.mutex.Unlock()
	got, _ := m.endpoint["cert_type"].(float64)
	if got != float64(want) {
		t.Fatalf("remote cert_type = %v, want %d", m.endpoint["cert_type"], want)
	}
}

func (m *terraformCLIAppCertificateMock) requirePreservedEndpointFields(t *testing.T) {
	t.Helper()
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.lastPut == nil || m.lastPut["cert_auto_status"] != float64(7) || m.lastPut["cert_challenge_mode"] != float64(2) {
		t.Fatalf("certificate status/challenge fields were not preserved: %#v", m.lastPut)
	}
	future, ok := m.lastPut["future_endpoint_field"].(map[string]any)
	if !ok || future["preserve"] != true {
		t.Fatalf("unknown endpoint field was not preserved: %#v", m.lastPut)
	}
	for key := range m.lastPut {
		if strings.Contains(key, "certificate") || strings.Contains(key, "private_key") || strings.Contains(key, "pem") {
			t.Fatalf("endpoint PUT unexpectedly contained certificate content field %q", key)
		}
	}
}

func (m *terraformCLIAppCertificateMock) requireDeleted(t *testing.T) {
	t.Helper()
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.exists {
		t.Fatal("application still exists after destroy")
	}
}

func terraformCLIAppCertificateHCL(apiURL, mode string) string {
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

resource "fortiappseccloud_waf_app" "test" {
  app_name        = "certificate-mode-test"
  domain_name     = "demo.example.com"
  extra_domains   = ["api.example.com"]
  services        = ["http", "https"]
  http_port       = 80
  https_port      = 443
  platform        = "AWS"
  region          = "us-east-1"
  cdn             = false
  block_mode      = false
  certificate_mode = %s

  initial_origin {
    address  = "192.0.2.10"
    protocol = "https"
    port     = 443
  }
}
`, strconv.Quote(apiURL), strconv.Quote(terraformCLITestToken), strconv.Quote(mode))
}

func requireTerraformCLIAppCertificateMode(t *testing.T, result terraformCLIResult, want string) {
	t.Helper()
	requireTerraformCLIExit(t, result, 0)
	var document struct {
		Values struct {
			RootModule struct {
				Resources []struct {
					Address string `json:"address"`
					Values  struct {
						CertificateMode string `json:"certificate_mode"`
					} `json:"values"`
				} `json:"resources"`
			} `json:"root_module"`
		} `json:"values"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &document); err != nil {
		t.Fatalf("decode application certificate-mode state: %v\n%s", err, result.Stdout)
	}
	for _, resource := range document.Values.RootModule.Resources {
		if resource.Address == terraformCLIAppCertificateAddress {
			if resource.Values.CertificateMode != want {
				t.Fatalf("certificate_mode = %q, want %q", resource.Values.CertificateMode, want)
			}
			return
		}
	}
	t.Fatalf("%s is absent from state:\n%s", terraformCLIAppCertificateAddress, result.Stdout)
}

func cloneJSONMap(source map[string]any) map[string]any {
	data, _ := json.Marshal(source)
	var cloned map[string]any
	_ = json.Unmarshal(data, &cloned)
	return cloned
}

func containsStringForTerraformCLITest(values []any, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func boolIntForTerraformCLITest(value bool) int {
	if value {
		return 1
	}
	return 0
}
