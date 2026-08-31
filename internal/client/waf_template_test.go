package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestCreateTemplateFutureContract(t *testing.T) {
	t.Parallel()

	var gotRequest TemplateCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/waf/template" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Idempotency-Key") == "" {
			t.Fatal("Idempotency-Key header is empty")
		}
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Location", "/v2/waf/template/tpl_123456")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"result":{"template_id":"tpl_123456","name":"terraform-template","predefine":false,"features":[],"endpoints":[]},"detail":"Template created"}`)
	}))
	defer server.Close()

	api, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	response, err := api.CreateTemplate(context.Background(), TemplateCreateRequest{Name: " terraform-template "})
	if err != nil {
		t.Fatalf("CreateTemplate() error = %v", err)
	}
	if response.Result.TemplateID != "tpl_123456" || response.Result.Name != "terraform-template" ||
		response.Detail != "Template created" {
		t.Fatalf("CreateTemplate() = %#v", response)
	}
	if gotRequest.Name != "terraform-template" || !reflect.DeepEqual(gotRequest.Endpoints, []string{}) {
		t.Fatalf("request = %#v", gotRequest)
	}
}

func TestCreateTemplateRejectsResponseWithoutStableIdentity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/v2/waf/template/tpl_123456")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"result":{"name":"terraform-template","predefine":false,"features":[],"endpoints":[]},"detail":"Template created"}`)
	}))
	defer server.Close()
	api, err := New(context.Background(), Config{BaseURL: server.URL, APIToken: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := api.CreateTemplate(context.Background(), TemplateCreateRequest{Name: "terraform-template"}); err == nil {
		t.Fatal("CreateTemplate() accepted a response without result.template_id")
	}
}

func TestCreateTemplateRejectsWrongStatusOrLocation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		location string
	}{
		{name: "status", status: http.StatusOK, location: "/v2/waf/template/tpl_123456"},
		{name: "location", status: http.StatusCreated, location: "/v2/waf/template"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", test.location)
				w.WriteHeader(test.status)
				fmt.Fprint(w, `{"result":{"template_id":"tpl_123456","name":"terraform-template","predefine":false,"features":[],"endpoints":[]},"detail":"Template created"}`)
			}))
			defer server.Close()
			api, err := New(context.Background(), Config{BaseURL: server.URL, APIToken: "token", HTTPClient: server.Client()})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := api.CreateTemplate(context.Background(), TemplateCreateRequest{Name: "terraform-template"}); err == nil {
				t.Fatalf("CreateTemplate() accepted status=%d Location=%q", test.status, test.location)
			}
		})
	}
}

func TestCreateTemplateRejectsIncompleteFutureResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "missing features", body: `{"result":{"template_id":"tpl_123456","name":"terraform-template","predefine":false,"endpoints":[]},"detail":"Template created"}`},
		{name: "null endpoints", body: `{"result":{"template_id":"tpl_123456","name":"terraform-template","predefine":false,"features":[],"endpoints":null},"detail":"Template created"}`},
		{name: "detail nested in result", body: `{"result":{"template_id":"tpl_123456","name":"terraform-template","predefine":false,"features":[],"endpoints":[],"detail":"Template created"}}`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.Header().Set("Location", "/v2/waf/template/tpl_123456")
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			api, err := New(context.Background(), Config{BaseURL: server.URL, APIToken: "token", HTTPClient: server.Client()})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if _, err := api.CreateTemplate(context.Background(), TemplateCreateRequest{Name: "terraform-template"}); err == nil {
				t.Fatalf("CreateTemplate() accepted %s response", test.name)
			}
			if calls != 1 {
				t.Fatalf("CreateTemplate() calls = %d, want 1 after a malformed successful response", calls)
			}
		})
	}
}

func TestTemplateModuleTransportAcceptsOmittedTemplateFlagAndSendsFalse(t *testing.T) {
	t.Parallel()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v2/waf/template/template-1/csrf_protection" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"status":true}}}`)
		case http.MethodPut:
			var body struct {
				Template *bool                      `json:"template"`
				Configs  map[string]json.RawMessage `json:"configs"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode PUT: %v", err)
			}
			if body.Template == nil || *body.Template {
				t.Fatalf("PUT template = %#v, want false", body.Template)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("method = %q", r.Method)
		}
	}))
	defer server.Close()
	api, err := New(context.Background(), Config{BaseURL: server.URL, APIToken: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	endpoint := WAFTemplateModuleEndpoint{
		Path:      "/waf/template/{template_id}/csrf_protection",
		Operation: "CSRF protection",
	}
	document, err := api.GetWAFTemplateModule(context.Background(), endpoint, "template-1")
	if err != nil {
		t.Fatalf("GetWAFTemplateModule() error = %v", err)
	}
	if document.Result.Template {
		t.Fatal("omitted template flag did not normalize to false")
	}
	if err := api.PutWAFTemplateModule(context.Background(), endpoint, "template-1", document.Result); err != nil {
		t.Fatalf("PutWAFTemplateModule() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestAppModuleTransportStillRequiresTemplateFlag(t *testing.T) {
	t.Parallel()

	var document WAFModuleDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true}}}`), &document); err == nil {
		t.Fatal("app WAFModuleDocument accepted an omitted template flag")
	}
}

func TestTemplateModuleTransportRejectsTrueTemplateFlag(t *testing.T) {
	t.Parallel()

	var document WAFTemplateModuleDocument
	if err := json.Unmarshal([]byte(`{"result":{"template":true,"configs":{"status":true}}}`), &document); err == nil {
		t.Fatal("template WAFModuleDocument accepted template=true")
	}
}
