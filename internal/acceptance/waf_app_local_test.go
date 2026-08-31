package acceptance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"terraform-provider-fortiappseccloud/internal/client"
)

// TestFrameworkAppTerraformLifecycle is a local Terraform CLI lifecycle. It
// deliberately uses only an httptest server and must never depend on TF_ACC or
// live credentials.
func TestFrameworkAppTerraformLifecycle(t *testing.T) {
	t.Parallel()
	mock := &localApplicationMock{}
	server := httptest.NewServer(mock)
	defer server.Close()

	initialConfiguration := localApplicationConfiguration(server.URL, false, "[]")
	updatedConfiguration := localApplicationConfiguration(server.URL, true, `["api.local.example.com"]`)

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: initialConfiguration, Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("fortiappseccloud_waf_app.test", "ep_id", "100"),
				resource.TestCheckResourceAttr("fortiappseccloud_waf_app.test", "placement_region", "us-east-1"),
			)},
			{Config: updatedConfiguration, Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("fortiappseccloud_waf_app.test", "block_mode", "true"),
				resource.TestCheckResourceAttr("fortiappseccloud_waf_app.test", "extra_domains.0", "api.local.example.com"),
			)},
			{Config: updatedConfiguration, PlanOnly: true},
			{
				ResourceName:                         "fortiappseccloud_waf_app.test",
				ImportState:                          true,
				ImportStateId:                        "100",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "ep_id",
				ImportStateVerifyIgnore:              []string{"initial_origin", "precheck"},
			},
		},
	})
	if exists, creates := mock.lifecycleCounts(); exists || creates != 1 {
		if exists {
			t.Error("local application still exists after Terraform destroy")
		}
		if creates != 1 {
			t.Errorf("application create count = %d, want 1 (import adoption must not replace)", creates)
		}
	}
}

// TestFrameworkAppTerraformImportAdoption starts from an existing application,
// imports it by the legacy app_name, adopts the bootstrap-only origin into
// state, and proves that Terraform neither replaces nor recreates the app.
func TestFrameworkAppTerraformImportAdoption(t *testing.T) {
	t.Parallel()
	mock := &localApplicationMock{exists: true, blockMode: 1, extraDomains: []string{"api.local.example.com"}}
	server := httptest.NewServer(mock)
	defer server.Close()
	configuration := localApplicationConfiguration(server.URL, true, `["api.local.example.com"]`)

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config:             configuration,
				ResourceName:       "fortiappseccloud_waf_app.test",
				ImportState:        true,
				ImportStateId:      "local-app",
				ImportStatePersist: true,
			},
			{Config: configuration, Check: resource.TestCheckResourceAttr("fortiappseccloud_waf_app.test", "ep_id", "100")},
			{Config: configuration, PlanOnly: true},
		},
	})
	if exists, creates := mock.lifecycleCounts(); exists || creates != 0 {
		if exists {
			t.Error("imported local application still exists after Terraform destroy")
		}
		if creates != 0 {
			t.Errorf("application create count = %d, want 0 (import adoption must not replace)", creates)
		}
	}
}

func localApplicationConfiguration(serverURL string, blockMode bool, extraDomains string) string {
	return fmt.Sprintf(`
provider "fortiappseccloud" {
  hostname  = %q
  api_token = "local-test-token"
}

resource "fortiappseccloud_waf_app" "test" {
  app_name        = "local-app"
  domain_name     = "local.example.com"
  services        = ["http", "https"]
  http_port       = 80
  https_port      = 443
  extra_domains   = %s
  platform        = "AWS"
  region          = "us-east-1"
  cdn             = false
  block_mode      = %t
  certificate_mode = "automatic"

  initial_origin {
    address  = "192.0.2.10"
    protocol = "https"
    port     = 443
  }
}
`, serverURL, extraDomains, blockMode)
}

type localApplicationMock struct {
	mu           sync.Mutex
	exists       bool
	blockMode    int
	extraDomains []string
	certType     int
	createCalls  int
}

func (m *localApplicationMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method + " " + r.URL.Path {
	case "POST /v2/waf/apps":
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request["creation_origin"] != client.ApplicationCreationOriginTerraform {
			http.Error(w, "Terraform creation_origin required", http.StatusBadRequest)
			return
		}
		m.createCalls++
		m.exists = true
		m.blockMode = 0
		m.extraDomains = []string{}
		fmt.Fprint(w, `{"ep_id":"100","app_name":"local-app","domain_info":[{"domain":"local.example.com","dns":"local.edge.example"}]}`)
	case "GET /v2/waf/apps":
		if !m.exists {
			fmt.Fprint(w, `{"app_list":[],"next_cursor":"","total":0}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"app_list": []map[string]any{{"ep_id": "100", "app_name": "local-app", "domain_name": "local.example.com", "extra_domains": m.extraDomains, "ep_cname": "local.edge.example", "block_mode": m.blockMode, "cdn_status": 0, "platform": "AWS", "platform_region": "us-east-1"}}, "next_cursor": "", "total": 1})
	case "GET /v2/waf/apps/100":
		if !m.exists {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"app_name": "local-app", "domain_name": "local.example.com", "block_mode": m.blockMode, "waf_regions": []string{"us-east-1"}})
	case "GET /v2/waf/apps/100/endpoint":
		if !m.exists {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"extra_domains": m.extraDomains, "http_status": 1, "https_status": 1, "custom_port": map[string]int{"http": 80, "https": 443}, "cert_type": m.certType})
	case "PUT /v2/waf/apps/100/endpoint":
		var document map[string]any
		if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
			http.Error(w, "invalid endpoint document", http.StatusBadRequest)
			return
		}
		m.extraDomains = nil
		for _, value := range document["extra_domains"].([]any) {
			m.extraDomains = append(m.extraDomains, value.(string))
		}
		if certType, ok := document["cert_type"].(float64); ok {
			m.certType = int(certType)
		}
		w.WriteHeader(http.StatusNoContent)
	case "PUT /v2/waf/apps/100/block":
		var document map[string]int
		if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
			http.Error(w, "invalid block document", http.StatusBadRequest)
			return
		}
		m.blockMode = document["block_mode"]
		w.WriteHeader(http.StatusNoContent)
	case "DELETE /v2/waf/apps/100":
		m.exists = false
		w.WriteHeader(http.StatusNoContent)
	default:
		var body any
		_ = json.NewDecoder(r.Body).Decode(&body)
		http.Error(w, "unexpected local application request", http.StatusNotFound)
	}
}

func (m *localApplicationMock) lifecycleCounts() (bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exists, m.createCalls
}
