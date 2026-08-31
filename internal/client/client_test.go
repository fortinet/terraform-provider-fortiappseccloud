package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewValidatesAuthentication(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config  Config
		wantErr string
	}{
		"missing credentials": {
			config:  Config{},
			wantErr: "configure api_token or username and password",
		},
		"token conflicts with username": {
			config: Config{
				APIToken: "token",
				Username: "user",
			},
			wantErr: "configure either api_token or username and password, not both",
		},
		"username requires password": {
			config: Config{
				Username: "user",
			},
			wantErr: "username and password must be configured together",
		},
		"insecure conflicts with custom CA": {
			config: Config{
				APIToken:   "token",
				Insecure:   true,
				CACertFile: "ca.pem",
			},
			wantErr: "insecure and cacert_file cannot be configured together",
		},
		"custom HTTP client owns TLS configuration": {
			config: Config{
				APIToken:   "token",
				Insecure:   true,
				HTTPClient: &http.Client{},
			},
			wantErr: "custom HTTP client cannot be combined",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := New(context.Background(), test.config)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("New() error = %v, want error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestListApplicationsUsesBasicTokenAndEncodedQuery(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/waf/apps" {
			t.Errorf("path = %q, want /v2/waf/apps", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Basic api-key-secret" {
			t.Errorf("Authorization = %q, want Basic api-key-secret", got)
		}
		if got := r.URL.Query().Get("size"); got != "20" {
			t.Errorf("size = %q, want 20", got)
		}
		if got := r.URL.Query().Get("filter"); got != `[{"id":"app_name","value":["a&b"]}]` {
			t.Errorf("filter = %q", got)
		}
		if got := r.URL.Query().Get("forward"); got != "true" {
			t.Errorf("forward = %q, want true", got)
		}
		if got := r.URL.Query().Get("cursor"); got != "next/cursor" {
			t.Errorf("cursor = %q, want next/cursor", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"app_list":[{"ep_id":"123","app_name":"demo","domain_name":"example.com"}],"total":1}`)
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "api-key-secret",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	forward := true
	page, err := client.ListApplications(context.Background(), ListApplicationsOptions{
		Size:    20,
		Filter:  `[{"id":"app_name","value":["a&b"]}]`,
		Forward: &forward,
		Cursor:  "next/cursor",
	})
	if err != nil {
		t.Fatalf("ListApplications() error = %v", err)
	}
	if page.Total != 1 || len(page.Applications) != 1 || page.Applications[0].EPID != "123" {
		t.Fatalf("ListApplications() = %#v", page)
	}
}

func TestUsernamePasswordLogin(t *testing.T) {
	t.Parallel()

	var loginCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/token":
			loginCalls.Add(1)
			if got := r.Header.Get("Authorization"); got != "" {
				t.Errorf("login Authorization = %q, want empty", got)
			}
			var request loginRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode login request: %v", err)
			}
			if request.Username != "user" || request.Password != "password" {
				t.Errorf("login request = %#v", request)
			}
			fmt.Fprint(w, `{"token":"Session authenticated-token"}`)
		case "/v2/waf/settings":
			if got := r.Header.Get("Authorization"); got != "Session authenticated-token" {
				t.Errorf("settings Authorization = %q", got)
			}
			fmt.Fprint(w, `{"preferred_platform":"AWS"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		Username:   "user",
		Password:   "password",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	settings, err := client.GetWAFSettings(context.Background())
	if err != nil {
		t.Fatalf("GetWAFSettings() error = %v", err)
	}
	if settings.PreferredPlatform != "AWS" {
		t.Fatalf("PreferredPlatform = %q, want AWS", settings.PreferredPlatform)
	}
	if got := loginCalls.Load(); got != 1 {
		t.Fatalf("login calls = %d, want 1", got)
	}
}

func TestSafeGETRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"detail":"temporary"}`)
			return
		}
		fmt.Fprint(w, `{"preferred_region":"us-east-1"}`)
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Retry: RetryConfig{
			MaxAttempts:   3,
			DisableJitter: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.sleep = func(context.Context, time.Duration) error { return nil }

	settings, err := client.GetWAFSettings(context.Background())
	if err != nil {
		t.Fatalf("GetWAFSettings() error = %v", err)
	}
	if settings.PreferredRegion != "us-east-1" {
		t.Fatalf("PreferredRegion = %q, want us-east-1", settings.PreferredRegion)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3", got)
	}
}

func TestAPIErrorRedactsSecrets(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"detail":"invalid","password":"hunter2","nested":{"api_key":"secret-key"},"content":"private material"}`)
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

	_, err = client.GetWAFSettings(context.Background())
	if err == nil {
		t.Fatal("GetWAFSettings() error = nil, want API error")
	}
	for _, secret := range []string{"hunter2", "secret-key", "private material"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), redactedValue) {
		t.Fatalf("error = %v, want redaction marker", err)
	}
	if !strings.Contains(err.Error(), `"detail":"invalid"`) {
		t.Fatalf("error = %v, want readable validation detail", err)
	}
}

func TestAPIErrorShowsReasonAndRedactsTargetPathAndDetailValue(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"detail":"Invalid server domain: sensitive-origin"}`)
	}))
	defer server.Close()
	client, err := New(context.Background(), Config{BaseURL: server.URL, APIToken: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetOriginServers(context.Background(), "sensitive-endpoint-id")
	if err == nil {
		t.Fatal("GetOriginServers() error = nil")
	}
	for _, sensitive := range []string{"sensitive-endpoint-id", "sensitive-origin"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error leaked %q: %v", sensitive, err)
		}
	}
	if !strings.Contains(err.Error(), redactedValue) {
		t.Fatalf("error = %v, want redaction marker", err)
	}
	if !strings.Contains(err.Error(), "Invalid server domain:") {
		t.Fatalf("error = %v, want readable validation reason", err)
	}
}

func TestRedactBodyPreservesReadableValidationDiagnostics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		want      []string
		doNotWant []string
	}{
		{
			name: "plain detail",
			body: `{"detail":"No request URL specified"}`,
			want: []string{`"detail":"No request URL specified"`},
		},
		{
			name: "credential field name without a credential value",
			body: `{"detail":"api_key_loc is required"}`,
			want: []string{`"detail":"api_key_loc is required"`},
		},
		{
			name:      "message with rejected value",
			body:      `{"message":"Invalid request URL: /private/login"}`,
			want:      []string{`"message":"Invalid request URL: [REDACTED]"`},
			doNotWant: []string{"/private/login"},
		},
		{
			name: "structured detail",
			body: `{"detail":[{"loc":["body","request_url"],"message":"field is required","input":"/private/login"}]}`,
			want: []string{
				`"loc":["body","request_url"]`,
				`"message":"field is required"`,
				`"input":"[REDACTED]"`,
			},
			doNotWant: []string{"/private/login"},
		},
		{
			name:      "credential in diagnostic text",
			body:      `{"detail":"hunter2: invalid password"}`,
			want:      []string{`"detail":"password [REDACTED]"`},
			doNotWant: []string{"hunter2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := redactBody([]byte(test.body))
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Fatalf("redactBody(%s) = %s, want substring %s", test.body, got, want)
				}
			}
			for _, doNotWant := range test.doNotWant {
				if strings.Contains(got, doNotWant) {
					t.Fatalf("redactBody(%s) = %s, leaked %s", test.body, got, doNotWant)
				}
			}
		})
	}
}

func TestRequestHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.GetWAFSettings(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GetWAFSettings() error = %v, want context canceled", err)
	}
}

func TestCustomCACertificate(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"preferred_platform":"AWS"}`)
	}))
	defer server.Close()

	certificate := server.Certificate()
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	caFile, err := os.CreateTemp(t.TempDir(), "fortiappseccloud-ca-*.pem")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := caFile.Write(pemData); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	if err := caFile.Close(); err != nil {
		t.Fatalf("close CA file: %v", err)
	}

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		CACertFile: caFile.Name(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	settings, err := client.GetWAFSettings(context.Background())
	if err != nil {
		t.Fatalf("GetWAFSettings() error = %v", err)
	}
	if settings.PreferredPlatform != "AWS" {
		t.Fatalf("PreferredPlatform = %q, want AWS", settings.PreferredPlatform)
	}
}

func TestIsNotFoundHandlesWrappedError(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("read application: %w", &APIError{StatusCode: http.StatusNotFound})
	if !IsNotFound(err) {
		t.Fatal("IsNotFound() = false, want true")
	}
}

func TestBaseURLVersionAndEscapedPath(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/v2/waf/template/a%2Fb%25%3F" {
			t.Errorf("escaped path = %q", got)
		}
		fmt.Fprint(w, `{"result":{"template_id":"a/b%?","name":"Custom","endpoints":[]}}`)
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL + "/v2",
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.GetTemplate(context.Background(), "a/b%?"); err != nil {
		t.Fatalf("GetTemplate() error = %v", err)
	}
}

func TestBaseURLRejectsUserInformation(t *testing.T) {
	t.Parallel()

	_, err := New(context.Background(), Config{
		BaseURL:  "https://user:password@example.com/v2",
		APIToken: "token",
	})
	if err == nil || !strings.Contains(err.Error(), "must not include user information") {
		t.Fatalf("New() error = %v", err)
	}
}

func TestSafeGETRetriesResponseReadFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(&unexpectedEOFReader{}),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"preferred_region":"us-east-1"}`)),
		}, nil
	})}

	client, err := New(context.Background(), Config{
		BaseURL:    "https://example.test/v2",
		APIToken:   "token",
		HTTPClient: httpClient,
		Retry: RetryConfig{
			MaxAttempts:   2,
			DisableJitter: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.sleep = func(context.Context, time.Duration) error { return nil }

	settings, err := client.GetWAFSettings(context.Background())
	if err != nil {
		t.Fatalf("GetWAFSettings() error = %v", err)
	}
	if settings.PreferredRegion != "us-east-1" || calls.Load() != 2 {
		t.Fatalf("settings = %#v, calls = %d", settings, calls.Load())
	}
}

func TestRetryAfterHonorsConfiguredMaximumAndZero(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		retryAfter string
		wantDelay  time.Duration
	}{
		"maximum": {retryAfter: "86400", wantDelay: 2 * time.Second},
		"zero":    {retryAfter: "0", wantDelay: 0},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.Header().Set("Retry-After", test.retryAfter)
					w.WriteHeader(http.StatusTooManyRequests)
					fmt.Fprint(w, `{"detail":"slow down"}`)
					return
				}
				fmt.Fprint(w, `{"preferred_region":"us-east-1"}`)
			}))
			defer server.Close()

			client, err := New(context.Background(), Config{
				BaseURL:    server.URL,
				APIToken:   "token",
				HTTPClient: server.Client(),
				Retry: RetryConfig{
					MaxAttempts:   2,
					MinDelay:      time.Second,
					MaxDelay:      2 * time.Second,
					DisableJitter: true,
				},
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			var gotDelay time.Duration
			client.sleep = func(_ context.Context, delay time.Duration) error {
				gotDelay = delay
				return nil
			}
			if _, err := client.GetWAFSettings(context.Background()); err != nil {
				t.Fatalf("GetWAFSettings() error = %v", err)
			}
			if gotDelay != test.wantDelay {
				t.Fatalf("retry delay = %s, want %s", gotDelay, test.wantDelay)
			}
		})
	}
}

func TestOversizedErrorPreservesHTTPStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"detail":"a deliberately long not found response"}`)
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:     server.URL,
		APIToken:    "token",
		HTTPClient:  server.Client(),
		MaxBodySize: 8,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.GetWAFSettings(context.Background())
	if !IsNotFound(err) {
		t.Fatalf("GetWAFSettings() error = %v, want not found API error", err)
	}
}

func TestTypedReadRejectsEmptySuccessBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
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
	_, err = client.GetWAFSettings(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not include a JSON body") {
		t.Fatalf("GetWAFSettings() error = %v", err)
	}
}

func TestNonJSONErrorBodyIsRedacted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "authentication failed: token=abc123 password=hunter2")
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
	_, err = client.GetWAFSettings(context.Background())
	if err == nil {
		t.Fatal("GetWAFSettings() error = nil")
	}
	if strings.Contains(err.Error(), "abc123") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaked plaintext body: %v", err)
	}
	if !strings.Contains(err.Error(), "non-JSON response body redacted") {
		t.Fatalf("error = %v", err)
	}
}

func TestConfiguredTimeoutBoundsCustomHTTPClient(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
		Timeout:    50 * time.Millisecond,
		Retry:      RetryConfig{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.GetWAFSettings(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetWAFSettings() error = %v, want deadline exceeded", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type unexpectedEOFReader struct {
	read bool
}

func (r *unexpectedEOFReader) Read(buffer []byte) (int, error) {
	if r.read {
		return 0, io.ErrUnexpectedEOF
	}
	r.read = true
	return copy(buffer, `{"preferred_region":"partial`), io.ErrUnexpectedEOF
}
