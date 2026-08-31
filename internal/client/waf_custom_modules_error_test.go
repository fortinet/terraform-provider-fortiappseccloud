package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type customModuleClientCase struct {
	name string
	get  func(context.Context, *Client) error
	put  func(context.Context, *Client) error
}

func customModuleClientCases() []customModuleClientCase {
	return []customModuleClientCase{
		{
			name: "global trust list parameter",
			get: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetGlobalTrustList(ctx, "app/id")
				return err
			},
			put: func(ctx context.Context, apiClient *Client) error {
				return apiClient.PutGlobalTrustList(ctx, "app/id", GlobalTrustListResult{})
			},
		},
		{
			name: "anomaly detection",
			get: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetAnomalyDetection(ctx, "app/id")
				return err
			},
			put: func(ctx context.Context, apiClient *Client) error {
				return apiClient.PutAnomalyDetection(ctx, "app/id", WAFModuleResult{})
			},
		},
		{
			name: "CORS protection",
			get: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetCorsProtection(ctx, "app/id")
				return err
			},
			put: func(ctx context.Context, apiClient *Client) error {
				return apiClient.PutCorsProtection(ctx, "app/id", WAFModuleResult{})
			},
		},
		{
			name: "IP protection",
			get: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetIPProtection(ctx, "app/id")
				return err
			},
			put: func(ctx context.Context, apiClient *Client) error {
				return apiClient.PutIPProtection(ctx, "app/id", WAFModuleResult{})
			},
		},
		{
			name: "content routing",
			get: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetContentRouting(ctx, "app/id")
				return err
			},
			put: func(ctx context.Context, apiClient *Client) error {
				return apiClient.PutContentRouting(ctx, "app/id", ContentRoutingResult{})
			},
		},
		{
			name: "custom rule",
			get: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetCustomRule(ctx, "app/id")
				return err
			},
			put: func(ctx context.Context, apiClient *Client) error {
				return apiClient.PutCustomRule(ctx, "app/id", WAFModuleResult{})
			},
		},
		{
			name: "ML API protection",
			get: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetMlApiProtection(ctx, "app/id")
				return err
			},
			put: func(ctx context.Context, apiClient *Client) error {
				return apiClient.PutMlApiProtection(ctx, "app/id", WAFModuleResult{})
			},
		},
	}
}

func TestCustomModuleClientsReturnStatusErrorsWithoutUnsafeRetry(t *testing.T) {
	t.Parallel()

	statuses := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
	}
	for _, test := range customModuleClientCases() {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, method := range []struct {
				name string
				call func(context.Context, *Client) error
			}{
				{name: "GET", call: test.get},
				{name: "PUT", call: test.put},
			} {
				method := method
				t.Run(method.name, func(t *testing.T) {
					t.Parallel()

					for _, status := range statuses {
						status := status
						t.Run(http.StatusText(status), func(t *testing.T) {
							t.Parallel()

							var attempts atomic.Int32
							server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
								attempts.Add(1)
								w.WriteHeader(status)
								fmt.Fprint(w, `{"detail":"synthetic failure"}`)
							}))
							defer server.Close()

							apiClient := newCustomModuleErrorTestClient(t, server, RetryConfig{
								MaxAttempts:   3,
								MinDelay:      time.Nanosecond,
								MaxDelay:      time.Nanosecond,
								DisableJitter: true,
							})
							err := method.call(context.Background(), apiClient)
							if !IsStatus(err, status) {
								t.Fatalf("%s error = %v, want HTTP %d", method.name, err, status)
							}
							if attempts.Load() != 1 {
								t.Fatalf("%s attempts = %d, want 1 for HTTP %d", method.name, attempts.Load(), status)
							}
						})
					}
				})
			}
		})
	}
}

func TestConfigurationCustomModuleClientsRetryReplayablePUTBodies(t *testing.T) {
	t.Parallel()

	for _, test := range customModuleClientCases() {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var attempts atomic.Int32
			var bodiesMu sync.Mutex
			var bodies [][]byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
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

			apiClient := newCustomModuleErrorTestClient(t, server, RetryConfig{
				MaxAttempts:   2,
				MinDelay:      time.Nanosecond,
				MaxDelay:      time.Nanosecond,
				DisableJitter: true,
			})
			if err := test.put(context.Background(), apiClient); err != nil {
				t.Fatalf("PUT error = %v", err)
			}
			if attempts.Load() != 2 {
				t.Fatalf("attempts = %d, want 2", attempts.Load())
			}
			bodiesMu.Lock()
			defer bodiesMu.Unlock()
			if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
				t.Fatalf("retry bodies differ: %q", bodies)
			}
		})
	}
}

func TestCustomModuleClientsRejectMalformedSuccessBodies(t *testing.T) {
	t.Parallel()

	for _, test := range customModuleClientCases() {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for name, body := range map[string]string{
				"empty":     "",
				"malformed": `{"result":`,
			} {
				name, body := name, body
				t.Run(name, func(t *testing.T) {
					t.Parallel()

					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						fmt.Fprint(w, body)
					}))
					defer server.Close()

					apiClient := newCustomModuleErrorTestClient(t, server, RetryConfig{MaxAttempts: 1})
					if err := test.get(context.Background(), apiClient); err == nil {
						t.Fatalf("GET accepted %s successful response", name)
					}
				})
			}
		})
	}
}

func newCustomModuleErrorTestClient(t *testing.T, server *httptest.Server, retry RetryConfig) *Client {
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
