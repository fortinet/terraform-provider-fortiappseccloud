package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInitialWAFReadAPIs(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Basic token" {
			t.Errorf("Authorization = %q, want Basic token", got)
		}

		switch {
		case r.URL.Path == "/v2/waf/apps" && r.URL.Query().Get("partial") == "true":
			fmt.Fprint(w, `[{"ep_id":"100","app_name":"demo","domain_name":"demo.example.com"}]`)
		case r.URL.Path == "/v2/waf/apps/100":
			fmt.Fprint(w, `{"app_name":"demo","domain_name":"demo.example.com","block_mode":0,"waf_regions":["us-east-1"]}`)
		case r.URL.Path == "/v2/waf/template":
			fmt.Fprint(w, `{"result":[{"template_id":"template-1","name":"Custom","predefine":false,"features":["knownattacks"],"endpoints":[["100","demo","demo.example.com"]]}],"total":1,"user_perm":"rw"}`)
		case r.URL.Path == "/v2/waf/template/template-1":
			fmt.Fprint(w, `{"result":{"name":"Custom","predefine":false,"features":["knownattacks"],"endpoints":["100"]}}`)
		case r.URL.Path == "/v2/waf/settings":
			fmt.Fprint(w, `{"preferred_platform":"AWS","preferred_region":"us-east-1","support_platform_regions":[{"platform":"AWS","provider":"Amazon Web Service","regions":[{"continent":"NA","logical_region":"us-east-1","physical_region":"US East (N. Virginia)"}]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	summaries, err := client.ListApplicationSummaries(context.Background())
	if err != nil {
		t.Fatalf("ListApplicationSummaries() error = %v", err)
	}
	if len(summaries) != 1 || summaries[0].EPID != "100" || summaries[0].AppName != "demo" {
		t.Fatalf("ListApplicationSummaries() = %#v", summaries)
	}

	application, err := client.GetApplication(context.Background(), "100")
	if err != nil {
		t.Fatalf("GetApplication() error = %v", err)
	}
	if application.AppName != "demo" || application.DomainName != "demo.example.com" || len(application.WAFRegions) != 1 {
		t.Fatalf("GetApplication() = %#v", application)
	}

	templates, err := client.ListTemplates(context.Background())
	if err != nil {
		t.Fatalf("ListTemplates() error = %v", err)
	}
	if len(templates.Templates) != 1 {
		t.Fatalf("ListTemplates() = %#v", templates)
	}
	listEndpoint := templates.Templates[0].Endpoints[0]
	if listEndpoint.EPID != "100" || listEndpoint.AppName != "demo" || listEndpoint.DomainName != "demo.example.com" {
		t.Fatalf("list endpoint = %#v", listEndpoint)
	}

	template, err := client.GetTemplate(context.Background(), "template-1")
	if err != nil {
		t.Fatalf("GetTemplate() error = %v", err)
	}
	if template.TemplateID != "template-1" || len(template.Endpoints) != 1 || template.Endpoints[0].EPID != "100" {
		t.Fatalf("GetTemplate() = %#v", template)
	}

	settings, err := client.GetWAFSettings(context.Background())
	if err != nil {
		t.Fatalf("GetWAFSettings() error = %v", err)
	}
	if len(settings.SupportedPlatforms) != 1 || len(settings.SupportedPlatforms[0].Regions) != 1 {
		t.Fatalf("GetWAFSettings() = %#v", settings)
	}
	region := settings.SupportedPlatforms[0].Regions[0]
	if region.LogicalRegion != "us-east-1" || region.Continent != "NA" {
		t.Fatalf("region = %#v", region)
	}
}

func TestTemplateEndpointRejectsInvalidShape(t *testing.T) {
	t.Parallel()

	for _, value := range []string{`{"ep_id":"100"}`, `null`, `""`, `[]`, `[""]`} {
		var endpoint TemplateEndpoint
		if err := endpoint.UnmarshalJSON([]byte(value)); err == nil {
			t.Fatalf("UnmarshalJSON(%s) error = nil, want error", value)
		}
	}
}

func TestListAllApplicationsAndFindByName(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cursor") {
		case "":
			if r.URL.Query().Get("forward") != "" {
				t.Errorf("first page forward = %q, want empty", r.URL.Query().Get("forward"))
			}
			fmt.Fprint(w, `{"app_list":[{"ep_id":"100","app_name":"first"}],"next_cursor":"cursor-1","total":2}`)
		case "cursor-1":
			if r.URL.Query().Get("forward") != "true" {
				t.Errorf("next page forward = %q, want true", r.URL.Query().Get("forward"))
			}
			fmt.Fprint(w, `{"app_list":[{"ep_id":"200","app_name":"target"}],"next_cursor":"","total":2}`)
		default:
			http.Error(w, "unexpected cursor", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	applications, err := client.ListAllApplications(context.Background(), ListApplicationsOptions{})
	if err != nil {
		t.Fatalf("ListAllApplications() error = %v", err)
	}
	if len(applications) != 2 || applications[1].EPID != "200" {
		t.Fatalf("ListAllApplications() = %#v", applications)
	}

	application, err := client.FindApplicationByName(context.Background(), "target")
	if err != nil {
		t.Fatalf("FindApplicationByName() error = %v", err)
	}
	if application.EPID != "200" {
		t.Fatalf("FindApplicationByName() = %#v", application)
	}
}

func TestListAllApplicationsRejectsRepeatedCursor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"app_list":[],"next_cursor":"same"}`)
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.ListAllApplications(context.Background(), ListApplicationsOptions{})
	if err == nil || err.Error() != `application pagination repeated cursor "same"` {
		t.Fatalf("ListAllApplications() error = %v", err)
	}
}

func TestListApplicationsRejectsInvalidPageSize(t *testing.T) {
	t.Parallel()

	client := &Client{}
	if _, err := client.ListApplications(context.Background(), ListApplicationsOptions{Size: 25}); err == nil {
		t.Fatal("ListApplications() error = nil, want error")
	}
}

func TestReadMethodsRejectEmptyIDs(t *testing.T) {
	t.Parallel()

	client := &Client{}
	if _, err := client.GetApplication(context.Background(), ""); err == nil {
		t.Fatal("GetApplication() error = nil, want error")
	}
	if _, err := client.GetTemplate(context.Background(), ""); err == nil {
		t.Fatal("GetTemplate() error = nil, want error")
	}
}

func TestApplicationExistsFallsBackToInventory(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/waf/apps/present":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"detail":"ambiguous"}`)
		case r.URL.Path == "/v2/waf/apps/missing":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"detail":"invalid_app_operation"}`)
		case r.URL.Path == "/v2/waf/apps":
			fmt.Fprint(w, `{"app_list":[{"ep_id":"present","app_name":"demo"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry:      RetryConfig{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	exists, err := client.ApplicationExists(context.Background(), "present")
	if err != nil || !exists {
		t.Fatalf("ApplicationExists(present) = %t, %v", exists, err)
	}
	exists, err = client.ApplicationExists(context.Background(), "missing")
	if err != nil || exists {
		t.Fatalf("ApplicationExists(missing) = %t, %v", exists, err)
	}
}

func TestTemplateExistsUsesInventory(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/waf/template" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"result":[{"template_id":"present","name":"demo","predefine":false,"features":[],"endpoints":[]}],"total":1,"user_perm":"rw"}`)
	}))
	defer server.Close()

	api, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry:      RetryConfig{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	exists, err := api.TemplateExists(context.Background(), "present")
	if err != nil || !exists {
		t.Fatalf("TemplateExists(present) = %t, %v", exists, err)
	}
	exists, err = api.TemplateExists(context.Background(), "missing")
	if err != nil || exists {
		t.Fatalf("TemplateExists(missing) = %t, %v", exists, err)
	}
}

func TestOriginServerAcceptsProductionLockedBooleanStrings(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		wire string
		want bool
	}{
		{wire: `false`, want: false}, {wire: `true`, want: true},
		{wire: `"0"`, want: false}, {wire: `"1"`, want: true},
		{wire: `""`, want: false}, {wire: `"disable"`, want: false}, {wire: `"unlocked"`, want: false},
		{wire: `"enable"`, want: true}, {wire: `"locked"`, want: true},
	} {
		var server OriginServer
		if err := json.Unmarshal([]byte(`{"locked":`+test.wire+`}`), &server); err != nil {
			t.Fatalf("Unmarshal locked %s: %v", test.wire, err)
		}
		if server.Locked == nil || *server.Locked != test.want {
			t.Fatalf("locked %s = %#v, want %t", test.wire, server.Locked, test.want)
		}
	}
}

func TestOriginServerLeavesUnsupportedServerOwnedLockedValueUnset(t *testing.T) {
	t.Parallel()

	var server OriginServer
	if err := json.Unmarshal([]byte(`{"locked":"provider-specific"}`), &server); err != nil {
		t.Fatal(err)
	}
	if server.Locked != nil {
		t.Fatalf("Locked = %#v, want nil for an unsupported server-owned representation", server.Locked)
	}
	wire, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(wire, &object); err != nil {
		t.Fatal(err)
	}
	if _, exists := object["locked"]; exists {
		t.Fatalf("server-owned unsupported locked value was written: %s", wire)
	}
}

func TestFrameworkApplicationAndOwnershipAPIs(t *testing.T) {
	t.Parallel()

	temporaryDirectory := t.TempDir()
	validationPath := filepath.Join(temporaryDirectory, "petstore.yaml")
	if err := os.WriteFile(validationPath, []byte("openapi: 3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /v2/waf/apps":
			var request ApplicationCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode application create: %v", err)
			}
			if request.AppName != "demo" || request.CreationOrigin != ApplicationCreationOriginTerraform || request.ServerAddress != "192.0.2.10" || request.Region != "us-east-1" || request.CertType == nil || *request.CertType != 1 {
				t.Errorf("application create = %#v", request)
			}
			fmt.Fprint(w, `[{"domain":"demo.example.com","dns":"demo.edge.example"}]`)
		case "POST /v2/waf/misc/dns-lookup":
			fmt.Fprint(w, `{"A":["192.0.2.10"]}`)
		case "GET /v2/waf/misc/backend-ip-test":
			if r.URL.Query().Get("backend_ip") != "192.0.2.10" || r.URL.Query().Get("backend_port") != "443" || r.URL.Query().Get("backend_type") != "HTTPS" {
				t.Errorf("connectivity query = %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"network_connectivity":1}`)
		case "PUT /v2/waf/apps/100":
			var request ApplicationUpdateRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.CDNStatus != 1 || request.IsGlobalCDN != 1 {
				t.Errorf("application update = %#v", request)
			}
		case "PUT /v2/waf/apps/100/block":
			var request map[string]int
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request["block_mode"] != 1 {
				t.Errorf("block request = %#v", request)
			}
		case "GET /v2/waf/apps/100/endpoint":
			fmt.Fprint(w, `{"extra_domains":[],"http_status":1,"https_status":1,"custom_port":{"http":80,"https":443}}`)
		case "PUT /v2/waf/apps/100/endpoint":
			var request map[string]any
			_ = json.NewDecoder(r.Body).Decode(&request)
			if _, found := request["custom_port"]; found || request["custom_http_port"] != float64(80) {
				t.Errorf("endpoint update = %#v", request)
			}
		case "GET /v2/waf/apps/100/servers":
			fmt.Fprint(w, `{"result":{"server_pools":[{"health":{"health_check":false,"future_health_field":{"preserve":true}},"lb_algo":"round-robin","name":"default_pool","persistence":{"type":"disable","future_persistence_field":{"preserve":true}},"server_balance":true,"server_list":[{"addr":"192.0.2.10","idx":1,"status":"enable","type":"ip","future_server_field":{"preserve":true}}],"future_pool_field":{"preserve":true}}]}}`)
		case "PUT /v2/waf/apps/100/servers":
			var request struct {
				ServerPools []struct {
					Name            string                       `json:"name"`
					Health          map[string]json.RawMessage   `json:"health"`
					Persistence     map[string]json.RawMessage   `json:"persistence"`
					Servers         []map[string]json.RawMessage `json:"server_list"`
					FuturePoolField json.RawMessage              `json:"future_pool_field"`
				} `json:"server_pools"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if len(request.ServerPools) != 1 || request.ServerPools[0].Name != "default_pool" || len(request.ServerPools[0].Servers) != 1 ||
				request.ServerPools[0].FuturePoolField == nil || request.ServerPools[0].Health["future_health_field"] == nil ||
				request.ServerPools[0].Persistence["future_persistence_field"] == nil || request.ServerPools[0].Servers[0]["future_server_field"] == nil {
				t.Errorf("origin update = %#v", request)
			}
		case "PUT /v2/waf/template/template-1":
			var request map[string][]string
			_ = json.NewDecoder(r.Body).Decode(&request)
			if !reflect.DeepEqual(request["endpoints"], []string{"100", "200"}) {
				t.Errorf("template update = %#v", request)
			}
		case "GET /v2/waf/apps/100/api_protection":
			fmt.Fprint(w, `{"result":{"configs":{"action":"alert","status":true,"file_list":[]},"template":false}}`)
		case "PUT /v2/waf/apps/100/api_protection":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("ParseMultipartForm() error = %v", err)
				return
			}
			if r.FormValue("template") != "false" || r.FormValue("configs") == "" {
				t.Errorf("multipart fields = %#v", r.MultipartForm.Value)
			}
			file, header, err := r.FormFile("file_1")
			if err != nil {
				t.Errorf("FormFile() error = %v", err)
				return
			}
			defer file.Close()
			contents, _ := io.ReadAll(file)
			if header.Filename != "petstore.yaml" || string(contents) != "openapi: 3.0.0\n" {
				t.Errorf("multipart file = %q %#v", contents, header)
			}
		case "DELETE /v2/waf/apps/100":
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	api, err := New(context.Background(), Config{BaseURL: server.URL, APIToken: "token", HTTPClient: server.Client(), Retry: RetryConfig{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	certType := 1
	created, err := api.CreateApplication(context.Background(), ApplicationCreateRequest{AppName: "demo", CreationOrigin: ApplicationCreationOriginTerraform, DomainName: "demo.example.com", CertType: &certType, ServerAddress: "192.0.2.10", ServerType: "https", ServerPort: 443, Region: "us-east-1", Platform: "AWS"})
	if err != nil || created.EPID != "" || len(created.DomainInfo) != 1 || created.DomainInfo[0].DNS != "demo.edge.example" {
		t.Fatalf("CreateApplication() = %#v, %v", created, err)
	}
	addresses, err := api.DNSLookup(context.Background(), "origin.example.com")
	if err != nil || !reflect.DeepEqual(addresses, []string{"192.0.2.10"}) {
		t.Fatalf("DNSLookup() = %#v, %v", addresses, err)
	}
	if err := api.TestBackendConnectivity(context.Background(), BackendConnectivityRequest{DomainName: "demo.example.com", Address: addresses[0], Protocol: "https", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if err := api.UpdateApplication(context.Background(), "100", ApplicationUpdateRequest{AppName: "demo", CDNStatus: 1, IsGlobalCDN: 1}); err != nil {
		t.Fatal(err)
	}
	if err := api.UpdateApplicationBlockMode(context.Background(), "100", true); err != nil {
		t.Fatal(err)
	}
	endpoint, err := api.GetApplicationEndpoint(context.Background(), "100")
	if err != nil {
		t.Fatal(err)
	}
	endpoint["custom_http_port"] = 80
	delete(endpoint, "custom_port")
	if err := api.PutApplicationEndpoint(context.Background(), "100", endpoint); err != nil {
		t.Fatal(err)
	}
	origins, err := api.GetOriginServers(context.Background(), "100")
	if err != nil {
		t.Fatal(err)
	}
	currentPool := origins.Result.ServerPools[0]
	plannedPools := []OriginServerPool{{
		Health: currentPool.Health, LBAlgorithm: currentPool.LBAlgorithm, Name: currentPool.Name,
		Persistence: currentPool.Persistence, ServerBalance: currentPool.ServerBalance,
		Servers: []OriginServer{{
			Address: currentPool.Servers[0].Address, Index: currentPool.Servers[0].Index,
			Status: currentPool.Servers[0].Status, Type: currentPool.Servers[0].Type,
		}},
	}}
	plannedPools[0].rawUnknown = nil
	plannedPools[0].Health.rawUnknown = nil
	plannedPools[0].Persistence.rawUnknown = nil
	plannedPools[0].Servers[0].rawUnknown = nil
	MergeOriginServerOmittedFields(plannedPools, origins.Result.ServerPools)
	if err := api.PutOriginServers(context.Background(), "100", plannedPools); err != nil {
		t.Fatal(err)
	}
	if err := api.PutTemplateEndpoints(context.Background(), "template-1", []string{"100", "200"}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.GetOpenAPIValidation(context.Background(), "100"); err != nil {
		t.Fatal(err)
	}
	config := OpenAPIValidationConfig{Action: "alert", Status: true, FileList: []OpenAPIValidationFile{{Name: "petstore.yaml", Index: 1}}}
	if err := api.PutOpenAPIValidation(context.Background(), "100", config, []OpenAPIUpload{{FieldName: "file_1", Path: validationPath}}); err != nil {
		t.Fatal(err)
	}
	if err := api.DeleteApplication(context.Background(), "100"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 13 {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestMergeOriginServerOmittedFieldsPreservesKnownComputedValues(t *testing.T) {
	t.Parallel()

	address, serverType, status := "origin.example.com", "domain", "enable"
	encryptionLevel, healthURL, persistenceDomain := "mozilla_intermediate", "/health", "example.com"
	locked := true
	current := []OriginServerPool{{
		Name:        "default_pool",
		Health:      OriginServerHealth{URL: &healthURL},
		Persistence: OriginServerPersistence{Domain: &persistenceDomain},
		Servers: []OriginServer{{
			Address: &address, Type: &serverType, Status: &status, EncryptionLevel: &encryptionLevel, Locked: &locked,
		}},
	}}
	planned := []OriginServerPool{{
		Name:    "default_pool",
		Servers: []OriginServer{{Address: &address, Type: &serverType, Status: &status}},
	}}

	MergeOriginServerOmittedFields(planned, current)
	server := planned[0].Servers[0]
	if server.EncryptionLevel == nil || *server.EncryptionLevel != encryptionLevel ||
		planned[0].Health.URL == nil || *planned[0].Health.URL != healthURL ||
		planned[0].Persistence.Domain == nil || *planned[0].Persistence.Domain != persistenceDomain {
		t.Fatalf("merged pools = %#v", planned)
	}
	if server.Locked != nil {
		t.Fatalf("server-owned locked field was merged into PUT: %#v", server.Locked)
	}
}

func TestApplicationCreateResponseShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		body     string
		wantEPID string
		wantDNS  string
	}{
		{name: "object", body: `{"ep_id":"100","app_name":"demo","domain_info":[{"dns":"demo.edge.example"}]}`, wantEPID: "100", wantDNS: "demo.edge.example"},
		{name: "legacy DNS array", body: `[{"domain":"demo.example.com","dns":"demo.edge.example"}]`, wantDNS: "demo.edge.example"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var response ApplicationCreateResponse
			if err := json.Unmarshal([]byte(test.body), &response); err != nil {
				t.Fatal(err)
			}
			if response.EPID != test.wantEPID || len(response.DomainInfo) != 1 || response.DomainInfo[0].DNS != test.wantDNS {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}
