package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetSignatureExceptionUsesReviewedEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/signature_exception" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if r.URL.Query().Get("signatureid") != "030000001" {
			t.Errorf("signatureid = %q", r.URL.Query().Get("signatureid"))
		}
		if r.Header.Get("Authorization") != "Basic token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"result":{"template":"template-id"}}`)
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
	view, err := apiClient.GetSignatureException(context.Background(), "app/id", "030000001")
	if err != nil {
		t.Fatalf("GetSignatureException() error = %v", err)
	}
	if view.TemplateID == nil || *view.TemplateID != "template-id" {
		t.Fatalf("template ID = %#v", view.TemplateID)
	}
}

func TestSignatureExceptionViewCodec(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body         string
		wantTemplate *string
		wantErr      bool
	}{
		"template": {
			body:         `{"result":{"template":"template-id"}}`,
			wantTemplate: signatureExceptionStringPointer("template-id"),
		},
		"empty template": {
			body:         `{"result":{"template":""}}`,
			wantTemplate: signatureExceptionStringPointer(""),
		},
		"missing result":      {body: `{}`},
		"missing template":    {body: `{"result":{}}`},
		"excluded unknowns":   {body: `{"result":{"template":"template-id","future":true},"future_root":true}`, wantTemplate: signatureExceptionStringPointer("template-id")},
		"null response":       {body: `null`, wantErr: true},
		"array response":      {body: `[]`, wantErr: true},
		"null result":         {body: `{"result":null}`, wantErr: true},
		"wrong result type":   {body: `{"result":[]}`, wantErr: true},
		"null template":       {body: `{"result":{"template":null}}`, wantErr: true},
		"wrong template type": {body: `{"result":{"template":1}}`, wantErr: true},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var view SignatureExceptionView
			err := json.Unmarshal([]byte(test.body), &view)
			if test.wantErr {
				if err == nil {
					t.Fatalf("Unmarshal accepted %s: %#v", name, view)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal error = %v", err)
			}
			if (view.TemplateID == nil) != (test.wantTemplate == nil) {
				t.Fatalf("template ID = %#v, want %#v", view.TemplateID, test.wantTemplate)
			}
			if view.TemplateID != nil && *view.TemplateID != *test.wantTemplate {
				t.Fatalf("template ID = %q, want %q", *view.TemplateID, *test.wantTemplate)
			}
		})
	}
}

func TestGetSignatureExceptionRejectsEmptyIdentity(t *testing.T) {
	t.Parallel()

	for _, input := range []struct {
		epID        string
		signatureID string
	}{
		{epID: " ", signatureID: "030000001"},
		{epID: "app", signatureID: "\t"},
	} {
		if _, err := (&Client{}).GetSignatureException(context.Background(), input.epID, input.signatureID); err == nil {
			t.Fatalf("GetSignatureException accepted identity %#v", input)
		}
	}
}

func TestGetSignatureExceptionReturnsStatusErrorWithoutUnsafeRetry(t *testing.T) {
	t.Parallel()

	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"synthetic missing signature"}`)
	}))
	defer server.Close()

	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry:      RetryConfig{MaxAttempts: 3},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetSignatureException(context.Background(), "app", "030000001"); !IsStatus(err, http.StatusNotFound) {
		t.Fatalf("GetSignatureException error = %v, want HTTP 404", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func signatureExceptionStringPointer(value string) *string {
	return &value
}
