package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/contract"
)

const customModulesLiveGateVersion = "custom_modules_serial_v4"

const (
	customModuleRestoreVerificationAttempts = 30
	customModuleRestoreVerificationInterval = 2 * time.Second
)

type customModuleLiveCase struct {
	name              string
	terraformName     string
	statusAttribute   string
	configuration     func(epID string, enabled bool) string
	snapshot          func(context.Context, *client.Client, string) (any, error)
	restore           func(context.Context, *client.Client, string, any) error
	remoteStatus      func(context.Context, *client.Client, string) (bool, error)
	normalizeSnapshot func(any) (any, error)
	snapshotLabel     string
	disableOnDestroy  bool
}

// TestAccCustomModuleResources is the separately gated production lifecycle
// prepared for the seven non-certificate custom resources. It is intentionally
// separate from the already authorized generated-resource campaign: an older
// all-resource gate cannot authorize these additional PUTs.
//
// The test creates its own disposable application, derives ep_id at runtime,
// exercises one resource at a time, restores every complete module snapshot
// before continuing, and deletes the disposable application at the end.
func TestAccCustomModuleResources(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_APP", "yes")

	appName := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_APP_NAME")
	skipUnlessExactEnvironment(
		t,
		"FORTIAPPSECCLOUD_ACC_CUSTOM_MODULES_WRITE",
		customModulesLiveGateVersion+":"+appName,
	)
	domain := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_DOMAIN")
	originAddress := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS")
	platform := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLATFORM")
	region := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_REGION")
	api := liveClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
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
		t.Fatalf("create disposable application for custom-module acceptance: %v", err)
	}
	epID, err := waitForCreatedApplication(ctx, api, appName, created.EPID)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range customModuleLiveCases() {
		if ok := t.Run(testCase.name, func(t *testing.T) {
			runCustomModuleLiveLifecycle(t, api, epID, testCase)
		}); !ok {
			t.FailNow()
		}
	}
}

// TestCustomModuleLiveCaseInventory keeps the new fixed-suite authorization
// bound to an exact, reviewable resource list without enabling any live call.
func TestCustomModuleLiveCaseInventory(t *testing.T) {
	t.Parallel()

	testCases := customModuleLiveCases()
	wantNames := []string{
		"global_trust_list_parameter",
		"anomaly_detection",
		"cors_protection",
		"ip_protection",
		"routings",
		"custom_rule",
		"ml_api_protection",
	}
	gotNames := make([]string, 0, len(testCases))
	terraformNames := make(map[string]struct{}, len(testCases))
	for _, testCase := range testCases {
		gotNames = append(gotNames, testCase.name)
		if testCase.terraformName == "" || testCase.statusAttribute == "" ||
			testCase.configuration == nil || testCase.snapshot == nil ||
			testCase.restore == nil || testCase.remoteStatus == nil {
			t.Errorf("%s has incomplete live-case metadata", testCase.name)
		}
		if testCase.name == "ip_protection" && testCase.normalizeSnapshot == nil {
			t.Error("ip_protection is missing its production-placeholder snapshot normalizer")
		}
		if testCase.name != "ip_protection" && testCase.normalizeSnapshot != nil {
			t.Errorf("%s unexpectedly has module-specific snapshot normalization", testCase.name)
		}
		if _, duplicate := terraformNames[testCase.terraformName]; duplicate {
			t.Errorf("duplicate Terraform resource %q", testCase.terraformName)
		}
		terraformNames[testCase.terraformName] = struct{}{}
		for _, enabled := range []bool{false, true} {
			configuration := testCase.configuration("review-only-ep-id", enabled)
			declaration := `resource "` + testCase.terraformName + `" "test"`
			if !strings.Contains(configuration, declaration) {
				t.Errorf("%s configuration is missing %q", testCase.name, declaration)
			}
			if !regexp.MustCompile(`(?m)^\s*ep_id\s*=\s*"review-only-ep-id"\s*$`).MatchString(configuration) {
				t.Errorf("%s configuration is missing the reviewed ep_id", testCase.name)
			}
			statusName := testCase.statusAttribute[strings.LastIndex(testCase.statusAttribute, ".")+1:]
			statusPattern := fmt.Sprintf(`(?m)^\s*%s\s*=\s*%t\s*$`, regexp.QuoteMeta(statusName), enabled)
			if !regexp.MustCompile(statusPattern).MatchString(configuration) {
				t.Errorf("%s configuration is missing %s=%t", testCase.name, testCase.statusAttribute, enabled)
			}
		}
	}
	if strings.Join(gotNames, "\x00") != strings.Join(wantNames, "\x00") {
		t.Fatalf("custom-module live cases = %#v, want %#v", gotNames, wantNames)
	}

	sorted := append([]string(nil), gotNames...)
	sort.Strings(sorted)
	for index := 1; index < len(sorted); index++ {
		if sorted[index] == sorted[index-1] {
			t.Fatalf("duplicate custom-module live case %q", sorted[index])
		}
	}
}

func TestRestoreCustomModuleSnapshot(t *testing.T) {
	t.Parallel()

	saved := map[string]any{"status": false, "opaque": map[string]any{"revision": float64(3)}}
	remote := map[string]any{"status": true}
	restoreCalls := 0
	testCase := customModuleLiveCase{
		snapshotLabel: "test module",
		restore: func(_ context.Context, _ *client.Client, _ string, snapshot any) error {
			restoreCalls++
			remote = snapshot.(map[string]any)
			return nil
		},
		snapshot: func(context.Context, *client.Client, string) (any, error) {
			return remote, nil
		},
	}
	if err := restoreCustomModuleSnapshot(context.Background(), nil, "ep-id", testCase, saved); err != nil {
		t.Fatalf("restoreCustomModuleSnapshot() error = %v", err)
	}
	if restoreCalls != 1 {
		t.Fatalf("restore calls = %d, want 1", restoreCalls)
	}

	testCase.restore = func(context.Context, *client.Client, string, any) error {
		return fmt.Errorf("put failed")
	}
	if err := restoreCustomModuleSnapshot(context.Background(), nil, "ep-id", testCase, saved); err == nil ||
		!strings.Contains(err.Error(), "put failed") {
		t.Fatalf("restore failure = %v, want put failure", err)
	}

	testCase.restore = func(context.Context, *client.Client, string, any) error { return nil }
	testCase.snapshot = func(context.Context, *client.Client, string) (any, error) {
		return nil, fmt.Errorf("get failed")
	}
	if err := restoreCustomModuleSnapshot(context.Background(), nil, "ep-id", testCase, saved); err == nil ||
		!strings.Contains(err.Error(), "verify restoration") {
		t.Fatalf("verification read failure = %v", err)
	}

	testCase.snapshot = func(context.Context, *client.Client, string) (any, error) {
		return map[string]any{"status": true}, nil
	}
	if err := restoreCustomModuleSnapshotWithRetry(context.Background(), nil, "ep-id", testCase, saved, 2, 0); err == nil ||
		!strings.Contains(err.Error(), "complete saved snapshot") {
		t.Fatalf("semantic mismatch = %v", err)
	}

	snapshotCalls := 0
	testCase.snapshot = func(context.Context, *client.Client, string) (any, error) {
		snapshotCalls++
		if snapshotCalls == 1 {
			return map[string]any{"status": true}, nil
		}
		return saved, nil
	}
	if err := restoreCustomModuleSnapshotWithRetry(context.Background(), nil, "ep-id", testCase, saved, 2, 0); err != nil {
		t.Fatalf("eventually consistent restoration = %v", err)
	}
	if snapshotCalls != 2 {
		t.Fatalf("snapshot calls = %d, want 2", snapshotCalls)
	}
}

func TestRestoreIPProtectionSnapshotNormalizesProductionNullPlaceholders(t *testing.T) {
	t.Parallel()

	saved := testWAFModuleResult(t, `{"template":false,"configs":{"status":true,"ip_reputation":true,"ip_list":[],"future_config":{"keep":true}},"future_envelope":"keep"}`)
	restored := testWAFModuleResult(t, `{"template":false,"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":null},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}],"future_config":{"keep":true}},"future_envelope":"keep"}`)
	testCase := customModuleLiveCase{
		snapshotLabel:     "ip protection",
		normalizeSnapshot: normalizeIPProtectionSnapshot,
		restore:           func(context.Context, *client.Client, string, any) error { return nil },
		snapshot: func(context.Context, *client.Client, string) (any, error) {
			return restored, nil
		},
	}
	if err := restoreCustomModuleSnapshotWithRetry(context.Background(), nil, "ep-id", testCase, saved, 1, 0); err != nil {
		t.Fatalf("canonical empty restoration mismatch: %v", err)
	}

	changed := testWAFModuleResult(t, `{"template":false,"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"1.1.1.1"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}],"future_config":{"keep":true}},"future_envelope":"keep"}`)
	testCase.snapshot = func(context.Context, *client.Client, string) (any, error) {
		return changed, nil
	}
	if err := restoreCustomModuleSnapshotWithRetry(context.Background(), nil, "ep-id", testCase, saved, 1, 0); err == nil {
		t.Fatal("IP Protection normalization hid an active-rule difference")
	}
}

func TestNormalizeIPProtectionSnapshotRejectsMalformedPlaceholder(t *testing.T) {
	t.Parallel()

	malformed := testWAFModuleResult(t, `{"template":false,"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":null,"future_key":"x"}]}}`)
	if _, err := normalizeIPProtectionSnapshot(malformed); err == nil {
		t.Fatal("normalizeIPProtectionSnapshot accepted an unknown-key null placeholder")
	}
}

func runCustomModuleLiveLifecycle(t *testing.T, api *client.Client, epID string, testCase customModuleLiveCase) {
	t.Helper()

	snapshot := waitForCustomModuleSnapshot(t, api, epID, testCase)
	restored := false
	t.Cleanup(func() {
		if restored {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := restoreCustomModuleSnapshot(ctx, api, epID, testCase, snapshot); err != nil {
			t.Errorf("emergency restore %s: %v", testCase.snapshotLabel, err)
		}
	})

	resourceName := testCase.terraformName + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: testCase.configuration(epID, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ep_id", epID),
					resource.TestCheckResourceAttr(resourceName, testCase.statusAttribute, "false"),
				),
			},
			{
				Config: testCase.configuration(epID, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, testCase.statusAttribute, "true"),
					func(*terraform.State) error {
						enabled, err := testCase.remoteStatus(context.Background(), api, epID)
						if err != nil {
							return fmt.Errorf("read updated %s: %w", testCase.snapshotLabel, err)
						}
						if !enabled {
							return fmt.Errorf("%s did not report status=true", testCase.snapshotLabel)
						}
						return nil
					},
				),
			},
			{Config: testCase.configuration(epID, true), PlanOnly: true},
			{
				ResourceName:  resourceName,
				ImportState:   true,
				ImportStateId: epID,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 || states[0] == nil {
						return fmt.Errorf("import returned %d resource states, want 1", len(states))
					}
					if states[0].Attributes["ep_id"] != epID {
						return fmt.Errorf("import did not hydrate the expected application identity")
					}
					if states[0].Attributes[testCase.statusAttribute] != "true" {
						return fmt.Errorf("import did not hydrate %s=true", testCase.statusAttribute)
					}
					return nil
				},
			},
		},
	})

	enabled, err := testCase.remoteStatus(context.Background(), api, epID)
	if err != nil {
		t.Fatalf("verify %s destroy: %v", testCase.snapshotLabel, err)
	}
	wantEnabled := !testCase.disableOnDestroy
	if enabled != wantEnabled {
		t.Fatalf("%s destroy status = %t, want %t", testCase.snapshotLabel, enabled, wantEnabled)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := restoreCustomModuleSnapshot(ctx, api, epID, testCase, snapshot); err != nil {
		t.Fatalf("restore %s before continuing: %v", testCase.snapshotLabel, err)
	}
	restored = true
}

func restoreCustomModuleSnapshot(
	ctx context.Context,
	api *client.Client,
	epID string,
	testCase customModuleLiveCase,
	snapshot any,
) error {
	return restoreCustomModuleSnapshotWithRetry(
		ctx,
		api,
		epID,
		testCase,
		snapshot,
		customModuleRestoreVerificationAttempts,
		customModuleRestoreVerificationInterval,
	)
}

func restoreCustomModuleSnapshotWithRetry(
	ctx context.Context,
	api *client.Client,
	epID string,
	testCase customModuleLiveCase,
	snapshot any,
	attempts int,
	interval time.Duration,
) error {
	if err := testCase.restore(ctx, api, epID, snapshot); err != nil {
		return err
	}
	if attempts < 1 {
		return fmt.Errorf("verify restoration: attempts must be positive")
	}
	normalizedWant := snapshot
	var err error
	if testCase.normalizeSnapshot != nil {
		normalizedWant, err = testCase.normalizeSnapshot(snapshot)
		if err != nil {
			return fmt.Errorf("normalize saved snapshot: %w", err)
		}
	}
	wantJSON, err := json.Marshal(normalizedWant)
	if err != nil {
		return fmt.Errorf("encode saved snapshot: %w", err)
	}
	var want any
	if err := json.Unmarshal(wantJSON, &want); err != nil {
		return fmt.Errorf("decode saved snapshot: %w", err)
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		restored, err := testCase.snapshot(ctx, api, epID)
		if err != nil {
			return fmt.Errorf("verify restoration: %w", err)
		}
		normalizedRestored := restored
		if testCase.normalizeSnapshot != nil {
			normalizedRestored, err = testCase.normalizeSnapshot(restored)
			if err != nil {
				return fmt.Errorf("normalize restored snapshot: %w", err)
			}
		}
		gotJSON, err := json.Marshal(normalizedRestored)
		if err != nil {
			return fmt.Errorf("encode restored snapshot: %w", err)
		}
		var got any
		if err := json.Unmarshal(gotJSON, &got); err != nil {
			return fmt.Errorf("decode restored snapshot: %w", err)
		}
		if reflect.DeepEqual(want, got) {
			return nil
		}
		if attempt == attempts {
			break
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("verify restoration: %w", ctx.Err())
		case <-timer.C:
		}
	}
	return fmt.Errorf("restored result does not match the complete saved snapshot after %d verification attempts", attempts)
}

func waitForCustomModuleSnapshot(t *testing.T, api *client.Client, epID string, testCase customModuleLiveCase) any {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for attempt := 0; attempt < 30; attempt++ {
		snapshot, err := testCase.snapshot(ctx, api, epID)
		if err == nil {
			return snapshot
		}
		if !client.IsStatus(err, 400, 403, 404, 409, 503) {
			t.Fatalf("snapshot %s: %v", testCase.snapshotLabel, err)
		}
		waitForLiveRetry(t, ctx)
	}
	t.Fatalf("snapshot %s did not become available", testCase.snapshotLabel)
	return nil
}

func customModuleLiveCases() []customModuleLiveCase {
	return []customModuleLiveCase{
		newTypedCustomModuleLiveCase(
			"global_trust_list_parameter",
			"fortiappseccloud_waf_global_trust_list_parameter",
			"configs.status",
			globalTrustListLiveConfiguration,
			func(ctx context.Context, api *client.Client, epID string) (client.GlobalTrustListDocument, error) {
				return api.GetGlobalTrustList(ctx, epID)
			},
			func(document client.GlobalTrustListDocument) client.GlobalTrustListResult { return document.Result },
			func(document client.GlobalTrustListDocument) (*bool, error) { return document.Config.Status, nil },
			func(ctx context.Context, api *client.Client, epID string, result client.GlobalTrustListResult) error {
				return api.PutGlobalTrustList(ctx, epID, result)
			},
		),
		newTypedCustomModuleLiveCase(
			"anomaly_detection",
			"fortiappseccloud_waf_anomaly_detection",
			"configs.status",
			anomalyDetectionLiveConfiguration,
			func(ctx context.Context, api *client.Client, epID string) (client.AnomalyDetectionDocument, error) {
				return api.GetAnomalyDetection(ctx, epID)
			},
			func(document client.AnomalyDetectionDocument) client.WAFModuleResult { return document.Result },
			func(document client.AnomalyDetectionDocument) (*bool, error) { return document.Config.Status, nil },
			func(ctx context.Context, api *client.Client, epID string, result client.WAFModuleResult) error {
				return api.PutAnomalyDetection(ctx, epID, result)
			},
		),
		newTypedCustomModuleLiveCase(
			"cors_protection",
			"fortiappseccloud_waf_cors_protection",
			"configs.status",
			corsProtectionLiveConfiguration,
			func(ctx context.Context, api *client.Client, epID string) (client.CorsProtectionDocument, error) {
				return api.GetCorsProtection(ctx, epID)
			},
			func(document client.CorsProtectionDocument) client.WAFModuleResult { return document.Result },
			func(document client.CorsProtectionDocument) (*bool, error) { return document.Config.Status, nil },
			func(ctx context.Context, api *client.Client, epID string, result client.WAFModuleResult) error {
				return api.PutCorsProtection(ctx, epID, result)
			},
		),
		newIPProtectionCustomModuleLiveCase(),
		newTypedCustomModuleLiveCase(
			"routings",
			"fortiappseccloud_waf_content_routing",
			"status",
			contentRoutingLiveConfiguration,
			func(ctx context.Context, api *client.Client, epID string) (client.ContentRoutingDocument, error) {
				return api.GetContentRouting(ctx, epID)
			},
			func(document client.ContentRoutingDocument) client.ContentRoutingResult { return document.Result },
			func(document client.ContentRoutingDocument) (*bool, error) { return document.Config.Status, nil },
			func(ctx context.Context, api *client.Client, epID string, result client.ContentRoutingResult) error {
				return api.PutContentRouting(ctx, epID, result)
			},
		),
		newTypedCustomModuleLiveCase(
			"custom_rule",
			"fortiappseccloud_waf_custom_rule",
			"configs.status",
			customRuleLiveConfiguration,
			func(ctx context.Context, api *client.Client, epID string) (client.CustomRuleDocument, error) {
				return api.GetCustomRule(ctx, epID)
			},
			func(document client.CustomRuleDocument) client.WAFModuleResult { return document.Result },
			func(document client.CustomRuleDocument) (*bool, error) { return document.Config.Status, nil },
			func(ctx context.Context, api *client.Client, epID string, result client.WAFModuleResult) error {
				return api.PutCustomRule(ctx, epID, result)
			},
		),
		newTypedCustomModuleLiveCase(
			"ml_api_protection",
			"fortiappseccloud_waf_ml_api_protection",
			"configs.status",
			mlAPIProtectionLiveConfiguration,
			func(ctx context.Context, api *client.Client, epID string) (client.MlApiProtectionDocument, error) {
				return api.GetMlApiProtection(ctx, epID)
			},
			func(document client.MlApiProtectionDocument) client.WAFModuleResult { return document.Result },
			func(document client.MlApiProtectionDocument) (*bool, error) { return document.Config.Status, nil },
			func(ctx context.Context, api *client.Client, epID string, result client.WAFModuleResult) error {
				return api.PutMlApiProtection(ctx, epID, result)
			},
		),
	}
}

func newIPProtectionCustomModuleLiveCase() customModuleLiveCase {
	testCase := newTypedCustomModuleLiveCase(
		"ip_protection",
		"fortiappseccloud_waf_ip_protection",
		"configs.status",
		ipProtectionLiveConfiguration,
		func(ctx context.Context, api *client.Client, epID string) (client.IPProtectionDocument, error) {
			return api.GetIPProtection(ctx, epID)
		},
		func(document client.IPProtectionDocument) client.WAFModuleResult { return document.Result },
		func(document client.IPProtectionDocument) (*bool, error) { return document.Config.Status, nil },
		func(ctx context.Context, api *client.Client, epID string, result client.WAFModuleResult) error {
			return api.PutIPProtection(ctx, epID, result)
		},
	)
	testCase.normalizeSnapshot = normalizeIPProtectionSnapshot
	return testCase
}

func normalizeIPProtectionSnapshot(snapshot any) (any, error) {
	result, ok := snapshot.(client.WAFModuleResult)
	if !ok {
		return nil, fmt.Errorf("IP Protection snapshot has unexpected type %T", snapshot)
	}
	return client.NormalizeIPProtectionResultForPut(result)
}

func testWAFModuleResult(t *testing.T, payload string) client.WAFModuleResult {
	t.Helper()
	var result client.WAFModuleResult
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
		t.Fatalf("decode WAF module result fixture: %v", err)
	}
	return result
}

func newTypedCustomModuleLiveCase[Document, Result any](
	name, terraformName, statusAttribute string,
	configuration func(epID string, enabled bool) string,
	get func(context.Context, *client.Client, string) (Document, error),
	result func(Document) Result,
	status func(Document) (*bool, error),
	put func(context.Context, *client.Client, string, Result) error,
) customModuleLiveCase {
	reviewed, reviewedExists := contract.ReviewedCustomResourceContract(name)
	return customModuleLiveCase{
		name:             name,
		terraformName:    terraformName,
		statusAttribute:  statusAttribute,
		configuration:    configuration,
		snapshotLabel:    strings.ReplaceAll(name, "_", " "),
		disableOnDestroy: reviewedExists && reviewed.DestroyPolicy == contract.CustomDestroyDisable,
		snapshot: func(ctx context.Context, api *client.Client, epID string) (any, error) {
			document, err := get(ctx, api, epID)
			if err != nil {
				return nil, err
			}
			return result(document), nil
		},
		restore: func(ctx context.Context, api *client.Client, epID string, snapshot any) error {
			typed, ok := snapshot.(Result)
			if !ok {
				return fmt.Errorf("internal snapshot type mismatch for %s", name)
			}
			return put(ctx, api, epID, typed)
		},
		remoteStatus: func(ctx context.Context, api *client.Client, epID string) (bool, error) {
			document, err := get(ctx, api, epID)
			if err != nil {
				return false, err
			}
			value, err := status(document)
			if err != nil {
				return false, err
			}
			if value == nil {
				return false, fmt.Errorf("%s response omitted required status", name)
			}
			return *value, nil
		},
	}
}

func globalTrustListLiveConfiguration(epID string, enabled bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_global_trust_list_parameter" "test" {
  ep_id = %q

  configs {
    status = %t

    trust_list {
      item {
        name   = "terraform-custom-module-live"
        status = true
        url    = "/terraform-custom-module-live"
      }
    }
  }
}
`, epID, enabled)
}

func anomalyDetectionLiveConfiguration(epID string, enabled bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_anomaly_detection" "test" {
  ep_id    = %q
  template = false

  configs {
    status       = %t
    action       = "alert"
    ip_list_type = "Block"

    ip_list {
      item {
        ip = "192.0.2.10"
      }
    }
  }
}
`, epID, enabled)
}

func corsProtectionLiveConfiguration(epID string, enabled bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_cors_protection" "test" {
  ep_id    = %q
  template = false

  configs {
    status             = %t
    block_cors_traffic = false

    allowed_origins {
      protocol            = "HTTPS"
      origin_name         = "terraform-custom-module-live.invalid"
      port                = 443
      include_sub_domains = false
    }
    allowed_methods {
      status  = true
      methods = ["GET", "HEAD"]
    }
    allowed_headers {
      status  = true
      headers = ["Content-Type"]
    }
    exposed_headers {
      status  = true
      headers = ["X-Terraform-Custom-Module-Live"]
    }
    url_pattern         = "/terraform-custom-module-live"
    allowed_credentials = "FALSE"
    allowed_maximum_age = 60
  }
}
`, epID, enabled)
}

func ipProtectionLiveConfiguration(epID string, enabled bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_ip_protection" "test" {
  ep_id    = %q
  template = false

  configs {
    status        = %t
    ip_reputation = false

    ip_list {
      item {
        type = "trust-ip"
        ip   = "1.1.1.1"
      }
    }
  }
}
`, epID, enabled)
}

func contentRoutingLiveConfiguration(epID string, enabled bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_content_routing" "test" {
  ep_id  = %q
  status = %t

  policy_list {
    item {
      name        = "terraform-custom-module-live"
      server_pool = "default_pool"
      is_default  = true

      rule_list {}
    }
  }
}
`, epID, enabled)
}

func customRuleLiveConfiguration(epID string, enabled bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_custom_rule" "test" {
  ep_id    = %q
  template = false

  configs {
    status = %t

    rule_list {
      item {
        name      = "terraform-custom-module-live"
        action    = "alert"
        challenge = "real-browser-enforcement"

        filter_list {
          item {
            type          = "source-ip-filter"
            ip            = "1.1.1.1-1.1.1.255"
            reverse_match = true
          }
        }
      }
    }
  }
}
`, epID, enabled)
}

func mlAPIProtectionLiveConfiguration(epID string, enabled bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_ml_api_protection" "test" {
  ep_id    = %q
  template = false

  configs {
    status        = %t
    threat_action = "alert"
    ip_list_type  = "Block"

    ip_list {
      item {
        ip = "192.0.2.13"
      }
    }

    path_list {
      item {
        type    = "plain"
        pattern = "/terraform-custom-module-live"
      }
    }
  }
}
`, epID, enabled)
}
