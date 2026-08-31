package acceptance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"terraform-provider-fortiappseccloud/internal/client"
)

type implementedModuleLiveCase struct {
	name             string
	terraformName    string
	endpoint         client.WAFModuleEndpoint
	accountTakeover  bool
	disableOnDestroy bool
	configExtras     func(bool) string
}

// TestAccAllImplementedModuleResources exercises every served app-module
// resource that is not already covered by the application vertical slice.
// One disposable application is shared, but each module owns an independent
// Terraform state directory and is restored before the next module starts.
func TestAccAllImplementedModuleResources(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_APP", "yes")

	appName := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_APP_NAME")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_ALL_RESOURCES_WRITE", "all_implemented_modules_serial_v1:"+appName)
	domain := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_DOMAIN")
	originAddress := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS")
	platform := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLATFORM")
	region := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_REGION")
	api := liveClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	refuseExistingApplicationName(t, ctx, api, appName)
	registerDisposableApplicationCleanup(t, api, appName)

	created, err := api.CreateApplication(ctx, client.ApplicationCreateRequest{
		AppName:        appName,
		CreationOrigin: client.ApplicationCreationOriginTerraform,
		DomainName:     domain,
		ExtraDomains:   []string{},
		BlockMode:      0,
		Service:        []string{"https"},
		ServerAddress:  originAddress,
		ServerType:     "https",
		ServerPort:     443,
		CDNStatus:      0,
		IsGlobalCDN:    0,
		Region:         region,
		Platform:       platform,
		CustomPort:     client.ApplicationCustomPort{HTTP: 80, HTTPS: 443},
	})
	if err != nil {
		t.Fatalf("create disposable application for all-resource acceptance: %v", err)
	}
	epID, err := waitForCreatedApplication(ctx, api, appName, created.EPID)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range allImplementedModuleLiveCases() {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.accountTakeover {
				runAccountTakeoverLiveLifecycle(t, api, epID, testCase.terraformName)
				return
			}
			runGeneratedModuleLiveLifecycle(t, api, epID, testCase)
		})
	}
}

func allImplementedModuleLiveCases() []implementedModuleLiveCase {
	module := func(name string) implementedModuleLiveCase {
		return implementedModuleLiveCase{
			name:             name,
			terraformName:    "fortiappseccloud_waf_" + name,
			disableOnDestroy: name != "caching_compression",
			endpoint: client.WAFModuleEndpoint{
				Path:      "/waf/apps/{ep_id}/" + name,
				Operation: strings.ReplaceAll(name, "_", " "),
			},
		}
	}

	cachingCompression := module("caching_compression")
	cachingCompression.configExtras = func(enabled bool) string {
		return fmt.Sprintf(`
    cache {
      status = %t
    }
    compress {
      status = %t
    }`, enabled, enabled)
	}

	return []implementedModuleLiveCase{
		{name: "account_takeover", terraformName: "fortiappseccloud_waf_account_takeover", accountTakeover: true},
		module("api_gateway"),
		module("biometrics_based_detection"),
		module("bot_deception"),
		cachingCompression,
		module("cookie_security"),
		module("csrf_protection"),
		module("ddos_prevention"),
		module("file_protection"),
		module("graphql_protection"),
		module("http_header_security"),
		module("information_leakage"),
		module("json_protection"),
		module("known_attacks"),
		module("known_bots"),
		module("mitb_protection"),
		module("ml_bot_detection"),
		module("mobile_api_protection"),
		module("parameter_validation"),
		module("request_limits"),
		module("rewriting_requests"),
		module("threshold_detection"),
		module("url_access"),
		module("waiting_room"),
		module("web_socket_security"),
		module("xml_protection_policy"),
	}
}

func runGeneratedModuleLiveLifecycle(t *testing.T, api *client.Client, epID string, testCase implementedModuleLiveCase) {
	t.Helper()
	snapshot := waitForModuleSnapshot(t, api, testCase.endpoint, epID)
	restoreModule(t, api, testCase.endpoint, epID, snapshot)

	resourceName := testCase.terraformName + ".test"
	moduleAcceptanceStatusLifecycle(t, epID, testCase.terraformName, resourceName, testCase.configExtras, func() error {
		current, err := api.GetWAFModule(context.Background(), testCase.endpoint, epID)
		if err != nil {
			return fmt.Errorf("read updated %s: %w", testCase.endpoint.Operation, err)
		}
		if current.Result.Template || !rawBool(current.Result.Configs["status"]) {
			return fmt.Errorf("%s did not report template=false and status=true", testCase.endpoint.Operation)
		}
		return nil
	})

	current, err := api.GetWAFModule(context.Background(), testCase.endpoint, epID)
	if err != nil {
		t.Fatalf("verify %s destroy: %v", testCase.endpoint.Operation, err)
	}
	wantStatus := !testCase.disableOnDestroy
	if current.Result.Template || rawBool(current.Result.Configs["status"]) != wantStatus {
		t.Fatalf("%s destroy status did not match the reviewed policy", testCase.endpoint.Operation)
	}
}

func runAccountTakeoverLiveLifecycle(t *testing.T, api *client.Client, epID, terraformName string) {
	t.Helper()
	snapshot := waitForAccountTakeoverSnapshot(t, api, epID)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := api.PutAccountTakeover(ctx, epID, snapshot.Result); err != nil {
			t.Errorf("restore account takeover: %v", err)
			return
		}
		verified, err := api.GetAccountTakeover(ctx, epID)
		if err != nil {
			t.Errorf("verify account takeover restoration: %v", err)
			return
		}
		assertSemanticJSON(t, "account takeover restoration", snapshot.Result, verified.Result)
	})

	moduleAcceptanceStatusLifecycle(t, epID, terraformName, terraformName+".test", nil, func() error {
		current, err := api.GetAccountTakeover(context.Background(), epID)
		if err != nil {
			return fmt.Errorf("read updated account takeover: %w", err)
		}
		if current.Result.Template || current.Config.Status == nil || !*current.Config.Status {
			return fmt.Errorf("account takeover did not report template=false and status=true")
		}
		return nil
	})

	current, err := api.GetAccountTakeover(context.Background(), epID)
	if err != nil {
		t.Fatalf("verify account takeover destroy: %v", err)
	}
	if current.Result.Template || current.Config.Status == nil || *current.Config.Status {
		t.Fatal("account takeover destroy did not report template=false and status=false")
	}
}

func moduleAcceptanceStatusLifecycle(t *testing.T, epID, terraformName, resourceName string, configExtras func(bool) string, remoteUpdated func() error) {
	t.Helper()
	configuration := func(enabled bool) string {
		extra := ""
		if configExtras != nil {
			extra = configExtras(enabled)
		}
		return fmt.Sprintf(`
resource %q "test" {
  ep_id   = %q
  template = false
  configs {
    status = %t%s
  }
}
`, terraformName, epID, enabled, extra)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: configuration(false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ep_id", epID),
					resource.TestCheckResourceAttr(resourceName, "configs.status", "false"),
				),
			},
			{
				Config: configuration(true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "configs.status", "true"),
					func(*terraform.State) error { return remoteUpdated() },
				),
			},
			{Config: configuration(true), PlanOnly: true},
			{
				ResourceName:     resourceName,
				ImportState:      true,
				ImportStateId:    epID,
				ImportStateCheck: checkImportedModuleIdentity(epID),
			},
		},
	})
}

func checkImportedModuleIdentity(epID string) resource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		if len(states) != 1 {
			return fmt.Errorf("import returned %d resource states, want 1", len(states))
		}
		if states[0] == nil || states[0].Attributes["ep_id"] != epID {
			return fmt.Errorf("import did not hydrate the expected application identity")
		}
		if states[0].Attributes["configs.status"] != "true" {
			return fmt.Errorf("import did not hydrate configs.status=true")
		}
		return nil
	}
}

func waitForModuleSnapshot(t *testing.T, api *client.Client, endpoint client.WAFModuleEndpoint, epID string) client.WAFModuleDocument {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for attempt := 0; attempt < 30; attempt++ {
		document, err := api.GetWAFModule(ctx, endpoint, epID)
		if err == nil {
			return document
		}
		if !client.IsStatus(err, 400, 403, 404, 409, 503) {
			t.Fatalf("snapshot %s: %v", endpoint.Operation, err)
		}
		waitForLiveRetry(t, ctx)
	}
	t.Fatalf("snapshot %s did not become available", endpoint.Operation)
	return client.WAFModuleDocument{}
}

func waitForAccountTakeoverSnapshot(t *testing.T, api *client.Client, epID string) client.AccountTakeoverDocument {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for attempt := 0; attempt < 30; attempt++ {
		document, err := api.GetAccountTakeover(ctx, epID)
		if err == nil {
			return document
		}
		if !client.IsStatus(err, 400, 403, 404, 409, 503) {
			t.Fatalf("snapshot account takeover: %v", err)
		}
		waitForLiveRetry(t, ctx)
	}
	t.Fatal("snapshot account takeover did not become available")
	return client.AccountTakeoverDocument{}
}

func refuseExistingApplicationName(t *testing.T, ctx context.Context, api *client.Client, appName string) {
	t.Helper()
	applications, err := api.ListAllApplications(ctx, client.ListApplicationsOptions{Size: 30})
	if err != nil {
		t.Fatalf("verify disposable application name: %v", err)
	}
	for _, application := range applications {
		if application.AppName == appName {
			t.Fatal("refusing all-resource acceptance: disposable app_name already exists")
		}
	}
}

func waitForCreatedApplication(ctx context.Context, api *client.Client, appName, candidateEPID string) (string, error) {
	const maxAttempts = 30
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var (
			application client.Application
			lookupErr   error
		)
		if strings.TrimSpace(candidateEPID) != "" {
			application, lookupErr = api.FindApplicationByEPID(ctx, candidateEPID)
		} else {
			application, lookupErr = api.FindApplicationByName(ctx, appName)
		}
		if lookupErr == nil {
			return application.EPID, nil
		}
		lastErr = lookupErr
		if waitErr := waitForLiveRetryError(ctx); waitErr != nil {
			return "", fmt.Errorf("disposable application did not become readable: %w; last lookup error: %v", waitErr, lastErr)
		}
	}
	return "", fmt.Errorf("disposable application did not become readable after %d attempts: %w", maxAttempts, lastErr)
}

func TestWaitForCreatedApplicationReportsLastLookupError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"app_list":[],"next_cursor":"","total":0}`)
	}))
	defer server.Close()
	api, err := client.New(context.Background(), client.Config{
		BaseURL:    server.URL,
		APIToken:   "test-token",
		HTTPClient: server.Client(),
		Retry:      client.RetryConfig{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatalf("configure test client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = waitForCreatedApplication(ctx, api, "test-app", "missing-ep-id")
	if err == nil {
		t.Fatal("waitForCreatedApplication() unexpectedly succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForCreatedApplication() error = %v, want context deadline", err)
	}
	if !strings.Contains(err.Error(), `last lookup error: application "missing-ep-id" was not found`) {
		t.Fatalf("waitForCreatedApplication() error = %v, want last lookup context", err)
	}
}

func registerDisposableApplicationCleanup(t *testing.T, api *client.Client, appName string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		applications, err := api.ListAllApplications(ctx, client.ListApplicationsOptions{Size: 30})
		if err != nil {
			t.Errorf("inspect disposable application during all-resource cleanup: %v", err)
			return
		}
		for _, application := range applications {
			if application.AppName != appName {
				continue
			}
			if err := api.DeleteApplication(ctx, application.EPID); err != nil {
				t.Errorf("cleanup all-resource disposable application: %v", err)
				return
			}
			if err := waitForApplicationAbsence(ctx, api, application.EPID); err != nil {
				t.Errorf("verify all-resource disposable application cleanup: %v", err)
			}
			return
		}
	})
}

func waitForLiveRetry(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := waitForLiveRetryError(ctx); err != nil {
		t.Fatal("live readiness wait was canceled")
	}
}

func waitForLiveRetryError(ctx context.Context) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
