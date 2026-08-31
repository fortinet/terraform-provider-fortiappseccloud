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

func TestGetApplicationModulesUsesReviewedEndpointAndCanonicalizes(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/modules" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Basic token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `[
			{"id":"url_access","status":"disable"},
			{"id":"advanced_bot_protection","status":"enable","inherited":"disable"}
		]`)
	}))
	defer server.Close()

	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	statuses, err := apiClient.GetApplicationModules(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetApplicationModules() error = %v", err)
	}
	if len(statuses) != 2 || statuses[0].ID != "advanced_bot_protection" || statuses[1].ID != "url_access" {
		t.Fatalf("statuses = %#v, want ID-sorted results", statuses)
	}
	if statuses[0].Inherited == nil || *statuses[0].Inherited != "disable" {
		t.Fatalf("advanced_bot_protection inherited = %#v", statuses[0].Inherited)
	}
	if statuses[1].Inherited != nil {
		t.Fatalf("url_access inherited = %#v, want nil for absent optional field", statuses[1].Inherited)
	}
}

func TestApplicationModuleStatusesStrictCodec(t *testing.T) {
	t.Parallel()

	valid := `[
		{"id":"url_access","status":"disable"},
		{"id":"known_attacks","status":"enable","inherited":"disable"}
	]`
	var control ApplicationModuleStatuses
	if err := json.Unmarshal([]byte(valid), &control); err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	if got := []string{control[0].ID, control[1].ID}; !reflect.DeepEqual(got, []string{"known_attacks", "url_access"}) {
		t.Fatalf("canonical IDs = %#v", got)
	}

	tests := map[string]string{
		"null response":         `null`,
		"object response":       `{}`,
		"null item":             `[null]`,
		"scalar item":           `[1]`,
		"unknown field":         `[{"id":"url_access","status":"enable","future":true}]`,
		"missing id":            `[{"status":"enable"}]`,
		"null id":               `[{"id":null,"status":"enable"}]`,
		"wrong id type":         `[{"id":1,"status":"enable"}]`,
		"empty id":              `[{"id":"","status":"enable"}]`,
		"unknown id":            `[{"id":"future_module","status":"enable"}]`,
		"missing status":        `[{"id":"url_access"}]`,
		"null status":           `[{"id":"url_access","status":null}]`,
		"wrong status type":     `[{"id":"url_access","status":true}]`,
		"unsupported status":    `[{"id":"url_access","status":"enabled"}]`,
		"null inherited":        `[{"id":"url_access","status":"enable","inherited":null}]`,
		"wrong inherited type":  `[{"id":"url_access","status":"enable","inherited":false}]`,
		"unsupported inherited": `[{"id":"url_access","status":"enable","inherited":"inherit"}]`,
		"duplicate id":          `[{"id":"url_access","status":"enable"},{"id":"url_access","status":"disable"}]`,
	}
	for name, body := range tests {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var statuses ApplicationModuleStatuses
			if err := json.Unmarshal([]byte(body), &statuses); err == nil {
				t.Fatalf("Unmarshal accepted %s: %#v", name, statuses)
			}
		})
	}
}

func TestApplicationModuleStatusesAcceptsEmptyArray(t *testing.T) {
	t.Parallel()

	var statuses ApplicationModuleStatuses
	if err := json.Unmarshal([]byte(`[]`), &statuses); err != nil {
		t.Fatalf("Unmarshal empty array error = %v", err)
	}
	if statuses == nil || len(statuses) != 0 {
		t.Fatalf("statuses = %#v, want non-nil empty slice", statuses)
	}
}

func TestGetApplicationModulesRejectsEmptyApplicationID(t *testing.T) {
	t.Parallel()

	if _, err := (&Client{}).GetApplicationModules(context.Background(), " \t "); err == nil {
		t.Fatal("GetApplicationModules accepted empty application ID")
	}
}

func TestGetApplicationModulesReturnsStatusErrorWithoutUnsafeRetry(t *testing.T) {
	t.Parallel()

	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"detail":"synthetic conflict"}`)
	}))
	defer server.Close()

	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry: RetryConfig{
			MaxAttempts: 3,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetApplicationModules(context.Background(), "app"); !IsStatus(err, http.StatusConflict) {
		t.Fatalf("GetApplicationModules error = %v, want HTTP 409", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}
