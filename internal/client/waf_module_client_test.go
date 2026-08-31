package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testCSRFEndpoint = WAFModuleEndpoint{
	Path:      "/waf/apps/{ep_id}/csrf_protection",
	Operation: "CSRF protection",
}

func TestGetWAFModuleUsesStaticEscapedPathAndAuthentication(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/csrf_protection" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Basic token" {
			t.Errorf("Authorization = %q", got)
		}
		fmt.Fprint(w, `{"result":{"configs":{"status":true,"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)
	}))
	defer server.Close()

	apiClient := testWAFModuleClient(t, server, RetryConfig{})
	document, err := apiClient.GetWAFModule(context.Background(), testCSRFEndpoint, "app/id")
	if err != nil {
		t.Fatalf("GetWAFModule() error = %v", err)
	}
	if document.Result.Template {
		t.Fatal("template = true, want false")
	}
	if _, ok := document.Result.Configs["future_config"]; !ok {
		t.Fatal("result lost future_config")
	}
}

func TestGetWAFModuleStrictEnvelopeDecode(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing result":   `{}`,
		"null result":      `{"result":null}`,
		"missing configs":  `{"result":{"template":false}}`,
		"null configs":     `{"result":{"configs":null,"template":false}}`,
		"wrong configs":    `{"result":{"configs":[],"template":false}}`,
		"missing template": `{"result":{"configs":{}}}`,
		"wrong template":   `{"result":{"configs":{},"template":"false"}}`,
		"trailing value":   `{"result":{"configs":{},"template":false}} {}`,
	}

	for name, payload := range tests {
		name, payload := name, payload
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, payload)
			}))
			defer server.Close()

			apiClient := testWAFModuleClient(t, server, RetryConfig{MaxAttempts: 1})
			if _, err := apiClient.GetWAFModule(context.Background(), testCSRFEndpoint, "123"); err == nil {
				t.Fatalf("GetWAFModule() accepted %s", payload)
			}
		})
	}
}

func TestPutWAFModuleRetriesWithCompleteReplayableBody(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	var bodiesMu sync.Mutex
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read PUT body: %v", err)
		}
		bodiesMu.Lock()
		bodies = append(bodies, append([]byte(nil), body...))
		bodiesMu.Unlock()
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	apiClient := testWAFModuleClient(t, server, RetryConfig{
		MaxAttempts:   2,
		MinDelay:      time.Nanosecond,
		MaxDelay:      time.Nanosecond,
		DisableJitter: true,
	})
	var document WAFModuleDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":false,"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`), &document); err != nil {
		t.Fatalf("json.Unmarshal(document) error = %v", err)
	}
	if err := apiClient.PutWAFModule(context.Background(), testCSRFEndpoint, "123", document.Result); err != nil {
		t.Fatalf("PutWAFModule() error = %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	bodiesMu.Lock()
	defer bodiesMu.Unlock()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("retry bodies = %q", bodies)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(bodies[0], &envelope); err != nil {
		t.Fatalf("decode PUT envelope: %v", err)
	}
	if _, ok := envelope["future_envelope"]; !ok {
		t.Fatal("PUT body lost future_envelope")
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(envelope["configs"], &configs); err != nil {
		t.Fatalf("decode PUT configs: %v", err)
	}
	if _, ok := configs["future_config"]; !ok {
		t.Fatal("PUT body lost future_config")
	}
}

func TestPutWAFModuleReturnsConflictWithoutRetry(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	apiClient := testWAFModuleClient(t, server, RetryConfig{
		MaxAttempts:   3,
		MinDelay:      time.Nanosecond,
		MaxDelay:      time.Nanosecond,
		DisableJitter: true,
	})
	err := apiClient.PutWAFModule(context.Background(), testCSRFEndpoint, "123", WAFModuleResult{
		Configs:  map[string]json.RawMessage{"status": json.RawMessage(`false`)},
		Template: false,
	})
	if !IsStatus(err, http.StatusConflict) {
		t.Fatalf("PutWAFModule() error = %v, want HTTP 409", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts = %d, want 1", attempts.Load())
	}
}

func TestWAFModuleEndpointRejectsUnsafeMetadataBeforeRequest(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	apiClient := testWAFModuleClient(t, server, RetryConfig{MaxAttempts: 1})

	tests := map[string]WAFModuleEndpoint{
		"relative":              {Path: "waf/apps/{ep_id}/csrf_protection", Operation: "CSRF protection"},
		"wrong prefix":          {Path: "/other/apps/{ep_id}/csrf_protection", Operation: "CSRF protection"},
		"missing placeholder":   {Path: "/waf/apps/static/csrf_protection", Operation: "CSRF protection"},
		"duplicate placeholder": {Path: "/waf/apps/{ep_id}/{ep_id}", Operation: "CSRF protection"},
		"wrong placeholder":     {Path: "/waf/apps/{id}/csrf_protection", Operation: "CSRF protection"},
		"extra segment":         {Path: "/waf/apps/{ep_id}/csrf/protection", Operation: "CSRF protection"},
		"empty segment":         {Path: "/waf/apps/{ep_id}/", Operation: "CSRF protection"},
		"traversal":             {Path: "/waf/apps/{ep_id}/..", Operation: "CSRF protection"},
		"encoded separator":     {Path: "/waf/apps/{ep_id}/csrf%2Fprotection", Operation: "CSRF protection"},
		"uppercase segment":     {Path: "/waf/apps/{ep_id}/CSRF_protection", Operation: "CSRF protection"},
		"query":                 {Path: "/waf/apps/{ep_id}/csrf_protection?other=true", Operation: "CSRF protection"},
		"fragment":              {Path: "/waf/apps/{ep_id}/csrf_protection#other", Operation: "CSRF protection"},
		"empty operation":       {Path: "/waf/apps/{ep_id}/csrf_protection"},
		"control operation":     {Path: "/waf/apps/{ep_id}/csrf_protection", Operation: "CSRF\nprotection"},
	}

	for name, endpoint := range tests {
		name, endpoint := name, endpoint
		t.Run(name, func(t *testing.T) {
			if _, err := apiClient.GetWAFModule(context.Background(), endpoint, "123"); err == nil {
				t.Fatal("GetWAFModule() error = nil")
			}
			if err := apiClient.PutWAFModule(context.Background(), endpoint, "123", WAFModuleResult{}); err == nil {
				t.Fatal("PutWAFModule() error = nil")
			}
		})
	}

	for _, id := range []string{"", "   "} {
		if _, err := apiClient.GetWAFModule(context.Background(), testCSRFEndpoint, id); err == nil {
			t.Fatalf("GetWAFModule() accepted ID %q", id)
		}
		if err := apiClient.PutWAFModule(context.Background(), testCSRFEndpoint, id, WAFModuleResult{}); err == nil {
			t.Fatalf("PutWAFModule() accepted ID %q", id)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
}

func testWAFModuleClient(t *testing.T, server *httptest.Server, retry RetryConfig) *Client {
	t.Helper()
	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry:      retry,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return apiClient
}
