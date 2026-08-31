package client

// Live verification for the FindApplicationByEPID ep_id-filter fast path.
// This test creates a real disposable application, then exercises the full
// FindApplicationByEPID lifecycle (Create -> waitForApplication -> Read ->
// Update -> Delete) that the Terraform app resource depends on. It requires
// the live account credentials and a disposable app name; gate it behind
// FORTIAPPSECCLOUD_LIVE_EPID_VERIFY=yes so it never runs by default.
//
// Run:
//   FORTIAPPSECCLOUD_LIVE_EPID_VERIFY=yes go test -v -run TestLiveEPIDFilterLifecycle ./internal/client/

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveEPIDFilterLifecycle(t *testing.T) {
	if os.Getenv("FORTIAPPSECCLOUD_LIVE_EPID_VERIFY") != "yes" {
		t.Skip("set FORTIAPPSECCLOUD_LIVE_EPID_VERIFY=yes to run the live ep_id filter lifecycle test")
	}
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live tests")
	}

	hostname := os.Getenv("FORTIAPPSECCLOUD_HOSTNAME")
	apiToken := os.Getenv("FORTIAPPSECCLOUD_API_TOKEN")
	appName := os.Getenv("FORTIAPPSECCLOUD_ACC_APP_NAME")
	domain := os.Getenv("FORTIAPPSECCLOUD_ACC_DOMAIN")
	originAddr := os.Getenv("FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS")
	platform := os.Getenv("FORTIAPPSECCLOUD_ACC_PLATFORM")
	region := os.Getenv("FORTIAPPSECCLOUD_ACC_REGION")
	for name, val := range map[string]string{
		"FORTIAPPSECCLOUD_HOSTNAME":           hostname,
		"FORTIAPPSECCLOUD_API_TOKEN":           apiToken,
		"FORTIAPPSECCLOUD_ACC_APP_NAME":       appName,
		"FORTIAPPSECCLOUD_ACC_DOMAIN":         domain,
		"FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS": originAddr,
		"FORTIAPPSECCLOUD_ACC_PLATFORM":       platform,
		"FORTIAPPSECCLOUD_ACC_REGION":         region,
	} {
		if strings.TrimSpace(val) == "" {
			t.Fatalf("%s must be set", name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	api, err := New(ctx, Config{BaseURL: hostname, APIToken: apiToken, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatalf("configure client: %v", err)
	}

	// Ensure no leftover app with this name from a previous failed run.
	if existing, findErr := api.FindApplicationByName(ctx, appName); findErr == nil {
		t.Logf("cleaning up leftover app %s (ep_id=%s) from a prior run", appName, existing.EPID)
		if delErr := api.DeleteApplication(ctx, existing.EPID); delErr != nil {
			t.Fatalf("cleanup leftover app: %v", delErr)
		}
		waitForAppAbsence(t, ctx, api, existing.EPID)
	} else if !strings.Contains(findErr.Error(), "was not found") && !strings.Contains(findErr.Error(), "multiple applications matched") {
		t.Fatalf("preflight FindApplicationByName: %v", findErr)
	}

	// --- Create: exercises FindApplicationByName fallback + waitForApplication polling ---
	t.Logf("creating disposable app %q", appName)
	created, err := api.CreateApplication(ctx, ApplicationCreateRequest{
		AppName:        appName,
		DomainName:     domain,
		ExtraDomains:   []string{},
		Service:        []string{"https"},
		ServerAddress:  originAddr,
		ServerType:     "https",
		ServerPort:     443,
		CDNStatus:       0,
		IsGlobalCDN:    0,
		Region:         region,
		Platform:       platform,
		CustomPort:     ApplicationCustomPort{HTTP: 80, HTTPS: 443},
		CreationOrigin: ApplicationCreationOriginTerraform,
	})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup if the test fails mid-way.
		if created.EPID != "" {
			_ = api.DeleteApplication(context.Background(), created.EPID)
			waitForAppAbsence(t, context.Background(), api, created.EPID)
		}
	})

	epID := strings.TrimSpace(created.EPID)
	if epID == "" {
		// Create response omitted ep_id (legacy array shape); resolve by name.
		resolved, resolveErr := api.FindApplicationByName(ctx, appName)
		if resolveErr != nil {
			t.Fatalf("create returned no ep_id and FindApplicationByName failed: %v", resolveErr)
		}
		epID = resolved.EPID
	}
	t.Logf("created app ep_id=%s", epID)

	// --- waitForApplication (present=true): the core FindApplicationByEPID polling path ---
	t.Log("waiting for application to become readable (FindApplicationByEPID polling)...")
	app, err := waitForAppPresent(ctx, api, epID, 30, 2*time.Second)
	if err != nil {
		t.Fatalf("waitForApplication present: %v", err)
	}
	t.Logf("FindApplicationByEPID resolved: ep_id=%s app_name=%s platform=%s", app.EPID, app.AppName, app.Platform)

	// --- Read: resolveStateApplication path (FindApplicationByEPID by ep_id) ---
	t.Log("read via FindApplicationByEPID (resolveStateApplication path)...")
	read, err := api.FindApplicationByEPID(ctx, epID)
	if err != nil {
		t.Fatalf("FindApplicationByEPID read: %v", err)
	}
	if read.EPID != epID {
		t.Fatalf("FindApplicationByEPID returned ep_id=%s, want %s", read.EPID, epID)
	}
	if read.AppName != appName {
		t.Fatalf("FindApplicationByEPID returned app_name=%q, want %q", read.AppName, appName)
	}
	t.Logf("read OK: domain=%s platform=%s cdn_status=%d", read.DomainName, read.Platform, read.CDNStatus)

	// --- IDOR guard: a foreign/non-existent ep_id must return not-found, no leak ---
	t.Log("verifying IDOR guard: foreign ep_id returns not-found...")
	if _, findErr := api.FindApplicationByEPID(ctx, "9999999999"); findErr == nil {
		t.Fatal("FindApplicationByEPID with foreign ep_id returned nil error (IDOR leak)")
	} else if !strings.Contains(findErr.Error(), "was not found") {
		t.Fatalf("FindApplicationByEPID with foreign ep_id returned unexpected error: %v", findErr)
	}
	t.Log("IDOR guard OK: foreign ep_id correctly returned not-found")

	// --- Delete: exercises waitForApplication (present=false) polling ---
	t.Logf("deleting app ep_id=%s", epID)
	if err := api.DeleteApplication(ctx, epID); err != nil {
		t.Fatalf("delete application: %v", err)
	}
	t.Log("waiting for application absence (FindApplicationByEPID + ApplicationExists polling)...")
	if err := waitForAppAbsenceWithClient(ctx, api, epID, 30, 2*time.Second); err != nil {
		t.Fatalf("waitForApplication absence: %v", err)
	}

	// --- Post-delete: FindApplicationByEPID must report not-found ---
	if _, findErr := api.FindApplicationByEPID(ctx, epID); findErr == nil {
		t.Fatal("FindApplicationByEPID after delete returned nil error (app still resolvable)")
	}
	t.Logf("post-delete FindApplicationByEPID correctly reports not-found")

	t.Log("✅ full FindApplicationByEPID lifecycle verified: Create → waitFor → Read → IDOR guard → Delete → absence")
}

func waitForAppPresent(ctx context.Context, api *Client, epID string, attempts int, delay time.Duration) (Application, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		app, err := api.FindApplicationByEPID(ctx, epID)
		if err == nil {
			return app, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return Application{}, ctx.Err()
		case <-time.After(delay):
		}
	}
	return Application{}, lastErr
}

func waitForAppAbsenceWithClient(ctx context.Context, api *Client, epID string, attempts int, delay time.Duration) error {
	for i := 0; i < attempts; i++ {
		exists, err := api.ApplicationExists(ctx, epID)
		if err == nil && !exists {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil
}

func waitForAppAbsence(t *testing.T, ctx context.Context, api *Client, epID string) {
	t.Helper()
	if err := waitForAppAbsenceWithClient(ctx, api, epID, 30, 2*time.Second); err != nil {
		t.Errorf("wait for absence: %v", err)
	}
}
