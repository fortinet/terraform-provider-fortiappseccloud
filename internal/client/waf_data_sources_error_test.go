package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWAFDataSourceClientsReturnStatusErrorsWithoutRetry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{
			name: "application modules",
			call: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetApplicationModules(ctx, "app/id")
				return err
			},
		},
		{
			name: "signature exception",
			call: func(ctx context.Context, apiClient *Client) error {
				_, err := apiClient.GetSignatureException(ctx, "app/id", "030000001")
				return err
			},
		},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, status := range []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusForbidden,
				http.StatusNotFound,
				http.StatusConflict,
			} {
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
					err := test.call(context.Background(), apiClient)
					if !IsStatus(err, status) {
						t.Fatalf("GET error = %v, want HTTP %d", err, status)
					}
					if attempts.Load() != 1 {
						t.Fatalf("GET attempts = %d, want 1 for HTTP %d", attempts.Load(), status)
					}
				})
			}
		})
	}
}
