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

func TestAccountTakeoverGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/account_takeover" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Basic token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"action":"alert_deny","status":true,"auth_url":"/login","future_config":{"enabled":true}},"template":false,"future_envelope":"keep"}}`)
		case http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&putBody); err != nil {
				t.Errorf("decode PUT body: %v", err)
			}
			fmt.Fprint(w, `{"detail":"Module updated"}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
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

	document, err := apiClient.GetAccountTakeover(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetAccountTakeover() error = %v", err)
	}
	if document.Config.Status == nil || !*document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}

	updated := document.Clone()
	updated.Result.Template = false
	if err := updated.Merge(AccountTakeoverPatch{
		Status:  Optional[bool]{Set: true, Value: false},
		AuthURL: Optional[string]{Set: true, Value: ""},
	}); err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if err := apiClient.PutAccountTakeover(context.Background(), "app/id", updated.Result); err != nil {
		t.Fatalf("PutAccountTakeover() error = %v", err)
	}

	if _, ok := putBody["future_envelope"]; !ok {
		t.Fatalf("PUT body lost future_envelope: %s", mustJSON(putBody))
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(putBody["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	if _, ok := configs["future_config"]; !ok {
		t.Fatalf("PUT configs lost future_config: %s", mustJSON(configs))
	}
	var status bool
	if err := json.Unmarshal(configs["status"], &status); err != nil || status {
		t.Fatalf("PUT status = %s, error = %v", configs["status"], err)
	}
	var authURL string
	if err := json.Unmarshal(configs["auth_url"], &authURL); err != nil || authURL != "" {
		t.Fatalf("PUT auth_url = %s, error = %v", configs["auth_url"], err)
	}
}

func TestAccountTakeoverStrictResponseValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing result":   `{}`,
		"null result":      `{"result":null}`,
		"missing configs":  `{"result":{"template":false}}`,
		"missing template": `{"result":{"configs":{"action":"alert","status":false}}}`,
		"missing action":   `{"result":{"configs":{"status":false},"template":false}}`,
		"missing status":   `{"result":{"configs":{"action":"alert"},"template":false}}`,
		"wrong bool":       `{"result":{"configs":{"action":"alert","status":"false"},"template":false}}`,
	}

	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var document AccountTakeoverDocument
			if err := json.Unmarshal([]byte(payload), &document); err == nil {
				t.Fatalf("json.Unmarshal(%s) error = nil", payload)
			}
		})
	}
}

func TestAccountTakeoverAllowsNullOptionalFields(t *testing.T) {
	t.Parallel()

	payload := `{"result":{"configs":{"action":"alert","status":false,"auth_url":null,"cred_stuffing_protect":null,"logoff_url":null,"password":null,"redirect_url":null,"response_body":null,"return_code":null,"sess_fixation_protect":null,"sess_id_name":null,"username":null},"template":false}}`
	var document AccountTakeoverDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if document.Config.AuthURL != nil || document.Config.CredentialStuffing != nil || document.Config.LogoffURL != nil || document.Config.Password != nil || document.Config.RedirectURL != nil || document.Config.ResponseBody != nil || document.Config.ReturnCode != nil || document.Config.SessionFixationProtect != nil || document.Config.SessionIDName != nil || document.Config.Username != nil {
		t.Fatalf("optional config = %#v, want nil fields", document.Config)
	}
}

func TestPutAccountTakeoverRetriesReplayableServerFailure(t *testing.T) {
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

	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry: RetryConfig{
			MaxAttempts:   2,
			MinDelay:      time.Nanosecond,
			MaxDelay:      time.Nanosecond,
			DisableJitter: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result := WAFModuleResult{
		Configs: map[string]json.RawMessage{
			"action": json.RawMessage(`"alert"`),
			"status": json.RawMessage(`false`),
		},
		Template: false,
	}
	if err := apiClient.PutAccountTakeover(context.Background(), "123", result); err != nil {
		t.Fatalf("PutAccountTakeover() error = %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	bodiesMu.Lock()
	defer bodiesMu.Unlock()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("retry bodies = %q", bodies)
	}
}

func TestPutAccountTakeoverReturnsConflictWithoutRetry(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry: RetryConfig{
			MaxAttempts:   3,
			MinDelay:      time.Nanosecond,
			MaxDelay:      time.Nanosecond,
			DisableJitter: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result := WAFModuleResult{
		Configs: map[string]json.RawMessage{
			"action": json.RawMessage(`"alert"`),
			"status": json.RawMessage(`false`),
		},
	}
	err = apiClient.PutAccountTakeover(context.Background(), "123", result)
	if !IsStatus(err, http.StatusConflict) {
		t.Fatalf("PutAccountTakeover() error = %v, want HTTP 409", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts = %d, want 1", attempts.Load())
	}
}

func TestStatusHelpers(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("wrapped: %w", &APIError{StatusCode: http.StatusBadRequest})
	if status, ok := StatusCode(err); !ok || status != http.StatusBadRequest {
		t.Fatalf("StatusCode() = %d, %t", status, ok)
	}
	if !IsStatus(err, http.StatusBadRequest, http.StatusNotFound) {
		t.Fatal("IsStatus() = false")
	}
	if IsNotFound(err) {
		t.Fatal("IsNotFound() = true")
	}
}

func mustJSON(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}
