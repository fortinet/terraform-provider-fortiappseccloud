package acceptance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/resources/wafmodule"
)

const (
	devCompleteWAFMatrixGate     = "dev_full_waf_matrix_v1"
	devCompleteWAFMatrixHostname = "https://api.dev1.fortiappsec.com"
)

var matrixStatusLine = regexp.MustCompile(`(?m)^(\s*)status(\s*)=(\s*)true(\s*)$`)

type matrixCaseResult struct {
	CaseID        string `json:"case_id"`
	Module        string `json:"module"`
	Campaign      string `json:"campaign"`
	Result        string `json:"result"`
	DurationMS    int64  `json:"duration_ms"`
	Restoration   string `json:"restoration"`
	ErrorCategory string `json:"error_category,omitempty"`
}

type matrixSummary struct {
	Format             string             `json:"format"`
	StartedAtUTC       time.Time          `json:"started_at_utc"`
	FinishedAtUTC      time.Time          `json:"finished_at_utc"`
	Environment        string             `json:"environment"`
	CodeIdentity       string             `json:"code_identity"`
	Phase              string             `json:"phase"`
	Setup              string             `json:"setup"`
	ApplicationFixture string             `json:"application_fixture"`
	Cases              []matrixCaseResult `json:"cases"`
	AppCleanup         string             `json:"app_cleanup"`
	TemplateCleanup    string             `json:"template_cleanup"`

	mu *sync.Mutex
}

type matrixEvidence struct {
	restoration string
	category    string
}

type matrixOutcome struct {
	result      string
	restoration string
	category    string
	duration    time.Duration
}

type matrixHarness struct {
	t *testing.T

	api                 *client.Client
	suffix              string
	appName             string
	appDomain           string
	alternateAppDomain  string
	epID                string
	platform            string
	region              string
	baseTemplateName    string
	baseTemplateID      string
	inheritTemplateName string
	inheritTemplateID   string
	summary             *matrixSummary
	appOutcomes         map[string]matrixOutcome
	openAPIOutcome      matrixOutcome
}

type matrixStandardAppCase struct {
	module           string
	resourceType     string
	endpoint         client.WAFModuleEndpoint
	fixture          string
	templateCapable  bool
	disableOnDestroy bool
}

// TestAccDevCompleteWAFMatrix is the executable form of
// plan/2026-07-29-waf-complete-live-test-plan.md. It owns every runtime
// identity, executes the fixed 99-case inventory serially, restores every
// complete snapshot, and deletes only parents created by this run.
func TestAccDevCompleteWAFMatrix(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_HOSTNAME", devCompleteWAFMatrixHostname)
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DEV_FULL_WAF_WRITE", devCompleteWAFMatrixGate)
	requireEnvironment(t, "FORTIAPPSECCLOUD_API_TOKEN")

	suffix := matrixRandomSuffix(t)
	summary := &matrixSummary{
		Format:             "fortiappseccloud-dev-complete-waf-matrix-v1",
		StartedAtUTC:       time.Now().UTC(),
		Environment:        "dev1",
		CodeIdentity:       matrixCodeIdentity(),
		Phase:              "placement_preflight",
		Setup:              "pending",
		ApplicationFixture: "pending",
		AppCleanup:         "pending",
		TemplateCleanup:    "pending",
		mu:                 &sync.Mutex{},
	}
	harness := &matrixHarness{
		t:                   t,
		api:                 liveClient(t),
		suffix:              suffix,
		appName:             "tf-auto-waf-" + suffix,
		appDomain:           "tf-" + suffix + ".example.com",
		alternateAppDomain:  "tf-" + suffix + ".example.org",
		baseTemplateName:    "tf-auto-template-" + suffix,
		inheritTemplateName: "tf-auto-inherit-" + suffix,
		summary:             summary,
		appOutcomes:         make(map[string]matrixOutcome),
	}

	// Registered first so it runs after exact parent cleanup.
	t.Cleanup(func() {
		path, err := writeMatrixSummary(summary)
		if err != nil {
			t.Errorf("persist sanitized dev WAF matrix summary: %v", err)
			return
		}
		t.Logf("dev WAF matrix summary: %s", path)
	})
	t.Cleanup(harness.cleanupParents)

	harness.selectPlacement()
	harness.setPhase("template_crud_preflight")
	harness.runBaseTemplateTerraformPreflight()
	harness.setPhase("parent_creation")
	harness.createParents()
	harness.markSetupPassedIfPending()

	harness.setPhase("campaign_a")
	harness.runCampaignA()
	harness.setPhase("campaign_d")
	harness.runCampaignD()
	harness.setPhase("campaign_t")
	harness.runCampaignT()
	harness.setPhase("complete")

	if len(summary.Cases) != 99 {
		t.Errorf("matrix recorded %d cases, want 99", len(summary.Cases))
	}
}

func TestDevCompleteWAFMatrixInventory(t *testing.T) {
	t.Parallel()

	appCases := matrixStandardAppCases()
	if len(appCases) != 26 {
		t.Fatalf("standard app cases = %d, want 26", len(appCases))
	}
	customCases := customModuleLiveCases()
	if len(customCases) != 7 {
		t.Fatalf("custom app cases = %d, want 7", len(customCases))
	}
	templateNames := matrixTemplateModuleNames()
	if len(templateNames) != 31 {
		t.Fatalf("template cases = %d, want 31", len(templateNames))
	}
	disableNames := matrixDisableCandidateNames()
	if len(disableNames) != 29 {
		t.Fatalf("disable candidates = %d, want 29", len(disableNames))
	}
	for _, unsafe := range []string{"caching_compression", "global_trust_list_parameter", "routings"} {
		if stringSliceContains(disableNames, unsafe) {
			t.Errorf("unsafe module %q appeared in disable candidates", unsafe)
		}
	}

	seen := make(map[string]struct{}, len(templateNames))
	for _, name := range templateNames {
		if _, duplicate := seen[name]; duplicate {
			t.Errorf("duplicate template module %q", name)
		}
		seen[name] = struct{}{}
	}
}

func (h *matrixHarness) selectPlacement() {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	settings, err := h.api.GetWAFSettings(ctx)
	if err != nil {
		h.t.Fatal("dev WAF settings preflight failed")
	}
	type placement struct {
		platform string
		region   string
	}
	var placements []placement
	for _, supported := range settings.SupportedPlatforms {
		for _, region := range supported.Regions {
			if strings.TrimSpace(supported.Platform) == "" || strings.TrimSpace(region.LogicalRegion) == "" {
				continue
			}
			placements = append(placements, placement{platform: supported.Platform, region: region.LogicalRegion})
		}
	}
	if len(placements) == 0 {
		h.t.Fatal("dev WAF settings did not expose a supported logical placement")
	}
	sort.Slice(placements, func(i, j int) bool {
		if placements[i].platform == placements[j].platform {
			return placements[i].region < placements[j].region
		}
		return placements[i].platform < placements[j].platform
	})
	selected := placements[0]
	for _, candidate := range placements {
		if candidate.platform == settings.PreferredPlatform && candidate.region == settings.PreferredRegion {
			selected = candidate
			break
		}
	}
	h.platform = selected.platform
	h.region = selected.region
}

func (h *matrixHarness) runBaseTemplateTerraformPreflight() {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	refuseExistingTemplateName(h.t, ctx, h.api, h.baseTemplateName)
	cancel()

	configuration := fmt.Sprintf(`
resource "fortiappseccloud_waf_template" "test" {
  name = %q
}
`, h.baseTemplateName)
	passed := h.t.Run("template_crud_contract", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV5ProviderFactories: providerFactories(),
			CheckDestroy:             checkTemplateAbsent(h.api, h.baseTemplateName),
			Steps: []resource.TestStep{
				{
					Config: configuration,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("fortiappseccloud_waf_template.test", "name", h.baseTemplateName),
						resource.TestCheckResourceAttrSet("fortiappseccloud_waf_template.test", "template_id"),
					),
				},
				{Config: configuration, PlanOnly: true},
				{
					ResourceName:                         "fortiappseccloud_waf_template.test",
					ImportState:                          true,
					ImportStateIdFunc:                    templateImportID("fortiappseccloud_waf_template.test"),
					ImportStateVerify:                    true,
					ImportStateVerifyIdentifierAttribute: "template_id",
					ImportStateVerifyIgnore:              []string{"features"},
				},
			},
		})
	})
	if passed {
		return
	}
	h.setSetup("template_create_contract_failed")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	template, err := h.findUniqueUserTemplateByExactName(ctx, h.baseTemplateName)
	if err != nil {
		h.t.Fatal("failed template create contract did not leave one recoverable disposable template")
	}
	if _, err := waitForTemplateRead(ctx, h.api, template.TemplateID); err != nil {
		h.t.Fatal("recovered disposable template did not become readable")
	}
	h.baseTemplateID = template.TemplateID
}

func (h *matrixHarness) createParents() {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	refuseExistingApplicationName(h.t, ctx, h.api, h.appName)
	if strings.TrimSpace(h.baseTemplateID) == "" {
		refuseExistingTemplateName(h.t, ctx, h.api, h.baseTemplateName)
	}
	refuseExistingTemplateName(h.t, ctx, h.api, h.inheritTemplateName)

	h.epID = h.createApplication(ctx)
	if strings.TrimSpace(h.baseTemplateID) == "" {
		h.baseTemplateID = h.createTemplate(ctx, h.baseTemplateName)
	}
	h.inheritTemplateID = h.createTemplate(ctx, h.inheritTemplateName)
	if err := h.api.PutTemplateEndpoints(ctx, h.inheritTemplateID, []string{h.epID}); err != nil {
		h.t.Fatal("bind disposable inheritance template failed")
	}
	if err := h.waitForTemplateMembership(ctx, h.inheritTemplateID, h.epID); err != nil {
		h.t.Fatal("disposable inheritance template binding did not become observable")
	}
}

func (h *matrixHarness) createApplication(ctx context.Context) string {
	h.t.Helper()

	type appFixture struct {
		label    string
		domain   string
		origin   string
		platform string
		region   string
	}
	fixtures := []appFixture{
		{label: "generated_primary", domain: h.appDomain, origin: "origin.example.com", platform: h.platform, region: h.region},
		{label: "generated_alternate", domain: h.alternateAppDomain, origin: "origin.example.com", platform: h.platform, region: h.region},
	}
	fallbackDomain := strings.TrimSpace(os.Getenv("FORTIAPPSECCLOUD_ACC_DOMAIN"))
	fallbackOrigin := strings.TrimSpace(os.Getenv("FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS"))
	fallbackPlatform := strings.TrimSpace(os.Getenv("FORTIAPPSECCLOUD_ACC_PLATFORM"))
	fallbackRegion := strings.TrimSpace(os.Getenv("FORTIAPPSECCLOUD_ACC_REGION"))
	if fallbackOrigin != "" {
		fixtures = append(fixtures,
			appFixture{label: "generated_primary_verified_origin", domain: h.appDomain, origin: fallbackOrigin, platform: h.platform, region: h.region},
			appFixture{label: "generated_alternate_verified_origin", domain: h.alternateAppDomain, origin: fallbackOrigin, platform: h.platform, region: h.region},
		)
	}
	if fallbackDomain != "" && fallbackOrigin != "" {
		fixtures = append(fixtures,
			appFixture{label: "verified_environment", domain: fallbackDomain, origin: fallbackOrigin, platform: h.platform, region: h.region},
		)
		if fallbackPlatform != "" && fallbackRegion != "" &&
			(fallbackPlatform != h.platform || fallbackRegion != h.region) {
			fixtures = append(fixtures,
				appFixture{label: "verified_environment_placement", domain: fallbackDomain, origin: fallbackOrigin, platform: fallbackPlatform, region: fallbackRegion},
			)
		}
	}

	create := func(fixture appFixture) (client.ApplicationCreateResponse, error) {
		return h.api.CreateApplication(ctx, client.ApplicationCreateRequest{
			AppName:        h.appName,
			CreationOrigin: client.ApplicationCreationOriginTerraform,
			DomainName:     fixture.domain,
			ExtraDomains:   []string{},
			BlockMode:      0,
			Service:        []string{"https"},
			ServerAddress:  fixture.origin,
			ServerType:     "https",
			ServerPort:     443,
			CDNStatus:      0,
			IsGlobalCDN:    0,
			Region:         fixture.region,
			Platform:       fixture.platform,
			CustomPort:     client.ApplicationCustomPort{HTTP: 80, HTTPS: 443},
		})
	}

	var lastErr error
	for _, fixture := range fixtures {
		created, err := create(fixture)
		if err != nil {
			existing, findErr := h.api.FindApplicationByName(ctx, h.appName)
			if findErr == nil {
				h.setApplicationFixture(fixture.label)
				return existing.EPID
			}
			lastErr = fmt.Errorf("fixture %q create failed: %w; recovery lookup failed: %v", fixture.label, err, findErr)
			continue
		}
		epID, waitErr := waitForCreatedApplication(ctx, h.api, h.appName, created.EPID)
		if waitErr == nil {
			h.setApplicationFixture(fixture.label)
			return epID
		}
		existing, findErr := h.api.FindApplicationByName(ctx, h.appName)
		if findErr == nil {
			h.setApplicationFixture(fixture.label)
			return existing.EPID
		}
		lastErr = fmt.Errorf("fixture %q did not become readable: %w; recovery lookup failed: %v", fixture.label, waitErr, findErr)
	}
	h.setApplicationFixture("all_rejected")
	if lastErr != nil {
		h.t.Fatalf("create disposable dev application failed after %d fixture(s): %v", len(fixtures), lastErr)
	}
	h.t.Fatal("create disposable dev application failed")
	return ""
}

func (h *matrixHarness) createTemplate(ctx context.Context, name string) string {
	h.t.Helper()

	created, err := h.api.CreateTemplate(ctx, client.TemplateCreateRequest{Name: name, Endpoints: []string{}})
	if err != nil {
		recovered, recoverErr := h.findUniqueUserTemplateByExactName(ctx, name)
		if recoverErr != nil {
			h.t.Fatal("create disposable dev template failed without a uniquely recoverable identity")
		}
		if _, readErr := waitForTemplateRead(ctx, h.api, recovered.TemplateID); readErr != nil {
			h.t.Fatal("recovered disposable dev template did not become readable")
		}
		return recovered.TemplateID
	}
	if strings.TrimSpace(created.Result.TemplateID) == "" || created.Result.Name != name ||
		created.Result.Predefined || len(created.Result.Endpoints) != 0 {
		h.t.Fatal("disposable dev template create response did not match the reviewed contract")
	}
	read, err := waitForTemplateRead(ctx, h.api, created.Result.TemplateID)
	if err != nil || read.TemplateID != created.Result.TemplateID || read.Name != name {
		h.t.Fatal("disposable dev template identity did not become stable")
	}
	return created.Result.TemplateID
}

func (h *matrixHarness) findUniqueUserTemplateByExactName(ctx context.Context, name string) (client.Template, error) {
	templates, err := h.api.ListTemplates(ctx)
	if err != nil {
		return client.Template{}, err
	}
	matches := make([]client.Template, 0, 1)
	for _, template := range templates.Templates {
		if template.Name == name {
			matches = append(matches, template)
		}
	}
	if len(matches) != 1 || matches[0].Predefined || strings.TrimSpace(matches[0].TemplateID) == "" {
		return client.Template{}, fmt.Errorf("exact template name did not resolve to one user template")
	}
	return matches[0], nil
}

func (h *matrixHarness) waitForTemplateMembership(ctx context.Context, templateID, epID string) error {
	for attempt := 0; attempt < 30; attempt++ {
		template, err := h.api.GetTemplate(ctx, templateID)
		if err == nil && templateHasEPID(template, epID) {
			return nil
		}
		if err := waitTemplateCRUDRetry(ctx); err != nil {
			return err
		}
	}
	return fmt.Errorf("template membership did not become observable")
}

func (h *matrixHarness) runCampaignA() {
	h.t.Helper()

	caseNumber := 1
	for _, testCase := range matrixStandardAppCases() {
		caseID := fmt.Sprintf("A%02d", caseNumber)
		outcome := h.runCase(caseID, "A", testCase.module, func(t *testing.T, evidence *matrixEvidence) {
			h.runStandardAppLifecycle(t, evidence, testCase)
		})
		h.appOutcomes[testCase.module] = outcome
		h.recoverAppAfterFailedRestoration(outcome)
		caseNumber++
	}
	for _, testCase := range customModuleLiveCases() {
		caseID := fmt.Sprintf("A%02d", caseNumber)
		localCase := testCase
		outcome := h.runCase(caseID, "A", testCase.name, func(t *testing.T, evidence *matrixEvidence) {
			h.runCustomAppLifecycle(t, evidence, localCase)
		})
		h.appOutcomes[testCase.name] = outcome
		h.recoverAppAfterFailedRestoration(outcome)
		caseNumber++
	}
	h.openAPIOutcome = h.runCase("A34", "A", "openapi_validation", func(t *testing.T, evidence *matrixEvidence) {
		h.runOpenAPILifecycle(t, evidence)
	})
	h.appOutcomes["openapi_validation"] = h.openAPIOutcome
	h.recoverAppAfterFailedRestoration(h.openAPIOutcome)
}

func (h *matrixHarness) runStandardAppLifecycle(t *testing.T, evidence *matrixEvidence, testCase matrixStandardAppCase) {
	t.Helper()

	snapshot := waitForModuleSnapshot(t, h.api, testCase.endpoint, h.epID)
	evidence.restoration = "pending"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := restoreMatrixWAFModule(ctx, h.api, testCase.endpoint, h.epID, snapshot.Result, nil); err != nil {
			evidence.restoration = "failed"
			evidence.category = "restoration_failed"
			t.Error("complete app-module snapshot restoration failed")
			return
		}
		evidence.restoration = "passed"
	})

	initial := h.standardAppConfiguration(t, testCase, false)
	updated := h.standardAppConfiguration(t, testCase, true)
	resourceName := testCase.resourceType + ".test"
	controlEndpoint := matrixControlEndpoint(testCase.module)
	controlSnapshot := waitForModuleSnapshot(t, h.api, controlEndpoint, h.epID)

	steps := []resource.TestStep{
		{
			Config: initial,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "ep_id", h.epID),
				resource.TestCheckResourceAttr(resourceName, "configs.status", "false"),
				matrixStandardRemoteCheck(h.api, testCase.endpoint, h.epID, false, false, nil),
			),
		},
		{
			Config: updated,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "configs.status", "true"),
				matrixStandardRemoteCheck(h.api, testCase.endpoint, h.epID, false, true, nil),
			),
		},
		{Config: updated, PlanOnly: true},
		{
			ResourceName:     resourceName,
			ImportState:      true,
			ImportStateId:    h.epID,
			ImportStateCheck: matrixImportIdentityCheck("ep_id", h.epID, "configs.status", "true"),
		},
		{Config: updated, PlanOnly: true},
	}
	if testCase.templateCapable {
		templateOnly := matrixAppTemplateOnlyConfiguration(testCase.resourceType, h.epID)
		steps = append(steps,
			resource.TestStep{
				Config: templateOnly,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "template", "true"),
					resource.TestCheckNoResourceAttr(resourceName, "configs.status"),
					matrixStandardRemoteCheck(h.api, testCase.endpoint, h.epID, true, false, &controlCheck{
						endpoint: controlEndpoint,
						result:   controlSnapshot.Result,
					}),
				),
			},
			resource.TestStep{
				Config: updated,
				Check:  matrixStandardRemoteCheck(h.api, testCase.endpoint, h.epID, false, true, nil),
			},
			resource.TestStep{Config: updated, PlanOnly: true},
		)
	}

	resource.Test(t, resource.TestCase{ProtoV5ProviderFactories: providerFactories(), Steps: steps})

	current, err := h.api.GetWAFModule(context.Background(), testCase.endpoint, h.epID)
	if err != nil {
		t.Error("app-module destroy verification read failed")
		return
	}
	gotStatus, ok := matrixRawBool(current.Result.Configs["status"])
	if !ok {
		t.Error("app-module destroy verification returned a non-boolean status")
		return
	}
	wantStatus := !testCase.disableOnDestroy
	if current.Result.Template || gotStatus != wantStatus {
		t.Error("app-module destroy result did not match its reviewed policy")
	}
}

type controlCheck struct {
	endpoint client.WAFModuleEndpoint
	result   client.WAFModuleResult
}

func matrixStandardRemoteCheck(
	api *client.Client,
	endpoint client.WAFModuleEndpoint,
	epID string,
	wantTemplate bool,
	wantStatus bool,
	control *controlCheck,
) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		document, err := api.GetWAFModule(context.Background(), endpoint, epID)
		if err != nil {
			return fmt.Errorf("independent module GET failed")
		}
		status, ok := matrixRawBool(document.Result.Configs["status"])
		if !ok || document.Result.Template != wantTemplate || (!wantTemplate && status != wantStatus) {
			return fmt.Errorf("independent module GET did not match the expected template/status state")
		}
		if control != nil {
			controlDocument, err := api.GetWAFModule(context.Background(), control.endpoint, epID)
			if err != nil {
				return fmt.Errorf("independent control-module GET failed")
			}
			if !matrixSemanticEqual(control.result, controlDocument.Result) {
				return fmt.Errorf("switching one module to template mode changed the control module")
			}
		}
		return nil
	}
}

func (h *matrixHarness) standardAppConfiguration(t *testing.T, testCase matrixStandardAppCase, enabled bool) string {
	t.Helper()

	if testCase.module == "url_access" {
		return fmt.Sprintf(`
resource %q "test" {
  ep_id    = %q
  template = false
  configs {
    status = %t
    rule_list {
      item {
        action   = "pass"
        name     = "terraform-matrix-string-rule"
        url      = "/terraform-matrix/"
        url_type = "string"
      }
    }
  }
}
`, testCase.resourceType, h.epID, enabled)
	}
	contents := matrixExampleFixture(t, testCase.fixture)
	contents = strings.Replace(contents, ` "`+testCase.resourceType+`" "example"`, ` "`+testCase.resourceType+`" "test"`, 1)
	contents = strings.ReplaceAll(contents, "fortiappseccloud_waf_app.app_example.ep_id", strconv.Quote(h.epID))
	contents = strings.ReplaceAll(contents, "var.mobile_api_token_secret", strconv.Quote("terraform-matrix-dummy-signing-secret"))
	if marker := strings.Index(contents, "\nvariable \"mobile_api_token_secret\""); marker >= 0 {
		contents = contents[:marker] + "\n"
	}
	return matrixSetStatus(contents, testCase.module, enabled)
}

func (h *matrixHarness) runCustomAppLifecycle(t *testing.T, evidence *matrixEvidence, testCase customModuleLiveCase) {
	t.Helper()

	snapshot := waitForCustomModuleSnapshot(t, h.api, h.epID, testCase)
	evidence.restoration = "pending"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := restoreCustomModuleSnapshot(ctx, h.api, h.epID, testCase, snapshot); err != nil {
			evidence.restoration = "failed"
			evidence.category = "restoration_failed"
			t.Error("complete custom-module snapshot restoration failed")
			return
		}
		evidence.restoration = "passed"
	})

	resourceName := testCase.terraformName + ".test"
	initial := testCase.configuration(h.epID, false)
	updated := testCase.configuration(h.epID, true)
	steps := []resource.TestStep{
		{
			Config: initial,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "ep_id", h.epID),
				resource.TestCheckResourceAttr(resourceName, testCase.statusAttribute, "false"),
			),
		},
		{
			Config: updated,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, testCase.statusAttribute, "true"),
				matrixCustomRemoteStatusCheck(h.api, h.epID, testCase, true),
			),
		},
		{Config: updated, PlanOnly: true},
		{
			ResourceName:     resourceName,
			ImportState:      true,
			ImportStateId:    h.epID,
			ImportStateCheck: matrixImportIdentityCheck("ep_id", h.epID, testCase.statusAttribute, "true"),
		},
		{Config: updated, PlanOnly: true},
	}
	if matrixTemplateCustomModule(testCase.name) {
		endpoint := matrixAppEndpoint(testCase.name)
		controlEndpoint := matrixControlEndpoint(testCase.name)
		controlSnapshot := waitForModuleSnapshot(t, h.api, controlEndpoint, h.epID)
		steps = append(steps,
			resource.TestStep{
				Config: matrixAppTemplateOnlyConfiguration(testCase.terraformName, h.epID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "template", "true"),
					resource.TestCheckNoResourceAttr(resourceName, "configs.status"),
					matrixStandardRemoteCheck(h.api, endpoint, h.epID, true, false, &controlCheck{
						endpoint: controlEndpoint,
						result:   controlSnapshot.Result,
					}),
				),
			},
			resource.TestStep{Config: updated, Check: matrixCustomRemoteStatusCheck(h.api, h.epID, testCase, true)},
			resource.TestStep{Config: updated, PlanOnly: true},
		)
	}

	resource.Test(t, resource.TestCase{ProtoV5ProviderFactories: providerFactories(), Steps: steps})
	enabled, err := testCase.remoteStatus(context.Background(), h.api, h.epID)
	wantEnabled := !stringSliceContains(matrixDisableCandidateNames(), testCase.name)
	if err != nil || enabled != wantEnabled {
		t.Error("custom-module destroy status did not match its reviewed policy")
	}
}

func matrixCustomRemoteStatusCheck(api *client.Client, epID string, testCase customModuleLiveCase, want bool) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		got, err := testCase.remoteStatus(context.Background(), api, epID)
		if err != nil {
			return fmt.Errorf("independent custom-module GET failed")
		}
		if got != want {
			return fmt.Errorf("independent custom-module GET returned the wrong status")
		}
		return nil
	}
}

func (h *matrixHarness) runOpenAPILifecycle(t *testing.T, evidence *matrixEvidence) {
	t.Helper()

	snapshot, err := h.api.GetOpenAPIValidation(context.Background(), h.epID)
	if err != nil {
		t.Fatal("snapshot OpenAPI validation failed")
	}
	if len(snapshot.Result.Configs.FileList) != 0 {
		t.Fatal("new disposable app unexpectedly contained OpenAPI validation files")
	}
	evidence.restoration = "pending"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := h.api.PutOpenAPIValidation(ctx, h.epID, snapshot.Result.Configs, nil); err != nil {
			evidence.restoration = "failed"
			evidence.category = "restoration_failed"
			t.Error("OpenAPI validation snapshot restoration failed")
			return
		}
		restored, err := h.api.GetOpenAPIValidation(ctx, h.epID)
		if err != nil || !reflect.DeepEqual(snapshot.Result.Configs, restored.Result.Configs) {
			evidence.restoration = "failed"
			evidence.category = "restoration_failed"
			t.Error("OpenAPI validation snapshot restoration verification failed")
			return
		}
		evidence.restoration = "passed"
	})

	filePath := filepath.Join(t.TempDir(), "matrix-openapi.yaml")
	if err := os.WriteFile(filePath, []byte("openapi: 3.0.0\ninfo:\n  title: matrix\n  version: 1.0.0\npaths: {}\n"), 0o600); err != nil {
		t.Fatal("create temporary OpenAPI validation document failed")
	}
	configuration := func(enabled bool, action string, includeFile bool) string {
		files := "[]"
		if includeFile {
			files = "[" + strconv.Quote(filePath) + "]"
		}
		return fmt.Sprintf(`
resource "fortiappseccloud_waf_openapi_validation" "test" {
  ep_id            = %q
  enable           = %t
  action           = %q
  validation_files = %s
}
`, h.epID, enabled, action, files)
	}
	initial := configuration(false, "alert", false)
	updated := configuration(true, "alert_deny", true)
	resourceName := "fortiappseccloud_waf_openapi_validation.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: initial,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "enable", "false"),
					matrixOpenAPIRemoteCheck(h.api, h.epID, false, "alert", 0),
				),
			},
			{
				Config: updated,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "enable", "true"),
					resource.TestCheckResourceAttr(resourceName, "action", "alert_deny"),
					matrixOpenAPIRemoteCheck(h.api, h.epID, true, "alert_deny", 1),
				),
			},
			{Config: updated, PlanOnly: true},
			{
				ResourceName:     resourceName,
				ImportState:      true,
				ImportStateId:    h.epID,
				ImportStateCheck: matrixImportIdentityCheck("ep_id", h.epID, "enable", "true"),
			},
			{Config: updated, PlanOnly: true},
		},
	})
	disabled, err := h.api.GetOpenAPIValidation(context.Background(), h.epID)
	if err != nil || disabled.Result.Template || disabled.Result.Configs.Status ||
		len(disabled.Result.Configs.FileList) != 0 {
		t.Error("OpenAPI validation destroy did not disable and clear remote files")
	}
}

func matrixOpenAPIRemoteCheck(api *client.Client, epID string, enabled bool, action string, files int) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		document, err := api.GetOpenAPIValidation(context.Background(), epID)
		if err != nil {
			return fmt.Errorf("independent OpenAPI validation GET failed")
		}
		if document.Result.Template || document.Result.Configs.Status != enabled ||
			document.Result.Configs.Action != action || len(document.Result.Configs.FileList) != files {
			return fmt.Errorf("independent OpenAPI validation GET did not match the expected state")
		}
		return nil
	}
}

func (h *matrixHarness) runCampaignD() {
	h.t.Helper()
	const caseCount = 34

	derived := []struct {
		id     string
		module string
	}{
		{id: "D01", module: "account_takeover"},
		{id: "D05", module: "caching_compression"},
		{id: "D27", module: "global_trust_list_parameter"},
		{id: "D31", module: "routings"},
		{id: "D34", module: "openapi_validation"},
	}
	derivedByID := make(map[string]string, len(derived))
	for _, item := range derived {
		if _, exists := derivedByID[item.id]; exists {
			h.t.Fatalf("duplicate derived case ID: %s", item.id)
		}
		derivedByID[item.id] = item.module
	}
	candidates := matrixDisableCandidateNames()
	wantCandidates := caseCount - len(derivedByID)
	if len(candidates) != wantCandidates {
		h.t.Fatalf("disable candidates for campaign D = %d, want %d", len(candidates), wantCandidates)
	}
	candidateIndex := 0
	for caseNumber := 1; caseNumber <= caseCount; caseNumber++ {
		caseID := fmt.Sprintf("D%02d", caseNumber)
		if module, ok := derivedByID[caseID]; ok {
			source := h.appOutcomes[module]
			h.appendDerivedCase(caseID, "D", module, source)
			continue
		}
		if candidateIndex >= len(candidates) {
			h.t.Fatalf("disable candidates for campaign D exhausted at case %s", caseID)
		}
		module := candidates[candidateIndex]
		candidateIndex++
		outcome := h.runCase(caseID, "D", module, func(t *testing.T, evidence *matrixEvidence) {
			h.runDisableCandidate(t, evidence, module)
		})
		h.recoverAppAfterFailedRestoration(outcome)
	}
	if candidateIndex != len(candidates) {
		h.t.Fatalf("campaign D used %d disable candidates, want %d", candidateIndex, len(candidates))
	}
}

func (h *matrixHarness) runDisableCandidate(t *testing.T, evidence *matrixEvidence, module string) {
	t.Helper()

	endpoint := matrixAppEndpoint(module)
	snapshot := waitForModuleSnapshot(t, h.api, endpoint, h.epID)
	evidence.restoration = "pending"
	normalizer := func(result client.WAFModuleResult) (client.WAFModuleResult, error) { return result, nil }
	if module == "ip_protection" {
		normalizer = matrixNormalizeIPResult
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := restoreMatrixWAFModule(ctx, h.api, endpoint, h.epID, snapshot.Result, normalizer); err != nil {
			evidence.restoration = "failed"
			evidence.category = "restoration_failed"
			t.Error("disable-candidate snapshot restoration failed")
			return
		}
		evidence.restoration = "passed"
	})

	status, ok := matrixRawBool(snapshot.Result.Configs["status"])
	if !ok {
		evidence.category = "unsafe_status_shape"
		t.Fatal("fresh disable-candidate GET did not contain boolean configs.status")
	}
	_ = status
	enabled := snapshot.Result.Clone()
	enabled.Template = false
	if err := enabled.SetConfig("status", true); err != nil {
		t.Fatal("prepare enabled candidate failed")
	}
	if err := h.api.PutWAFModule(context.Background(), endpoint, h.epID, enabled); err != nil {
		evidence.category = "write_failed"
		t.Fatal("prepare enabled candidate PUT failed")
	}
	current, err := h.api.GetWAFModule(context.Background(), endpoint, h.epID)
	if err != nil {
		evidence.category = "read_failed"
		t.Fatal("verify enabled candidate GET failed")
	}
	normalizedEnabled, err := normalizer(enabled)
	if err != nil {
		t.Fatal("normalize intended enabled candidate failed")
	}
	normalizedCurrent, err := normalizer(current.Result)
	if err != nil || !matrixSemanticEqual(normalizedEnabled, normalizedCurrent) {
		evidence.category = "response_normalization"
		t.Fatal("enabling candidate changed fields outside template/configs.status")
	}

	var diagnostics diag.Diagnostics
	wafmodule.DisableOnDestroy(context.Background(), wafmodule.DisableRequest{
		ModuleName:      module,
		EPID:            h.epID,
		Field:           "status",
		Verified:        true,
		Current:         &current,
		NormalizeForPut: normalizer,
	}, wafmodule.DisableAccess{
		Get: func(ctx context.Context) (client.WAFModuleDocument, error) {
			return h.api.GetWAFModule(ctx, endpoint, h.epID)
		},
		Put: func(ctx context.Context, result client.WAFModuleResult) error {
			return h.api.PutWAFModule(ctx, endpoint, h.epID, result)
		},
		ApplicationExists: func(ctx context.Context) (bool, error) {
			return h.api.ApplicationExists(ctx, h.epID)
		},
	}, &diagnostics)
	if diagnostics.HasError() {
		evidence.category = matrixDiagnosticCategory(diagnostics)
		for _, diagnostic := range diagnostics.Errors() {
			t.Logf("disable diagnostic: %s: %s", diagnostic.Summary(), diagnostic.Detail())
		}
		t.Fatal("guarded disable engine rejected the live candidate")
	}
	disabled, err := h.api.GetWAFModule(context.Background(), endpoint, h.epID)
	if err != nil {
		evidence.category = "read_failed"
		t.Fatal("verify disabled candidate GET failed")
	}
	expected := current.Result.Clone()
	expected.Template = false
	if err := expected.SetConfig("status", false); err != nil {
		t.Fatal("prepare disabled candidate expectation failed")
	}
	normalizedExpected, err := normalizer(expected)
	if err != nil {
		t.Fatal("normalize intended disabled candidate failed")
	}
	normalizedDisabled, err := normalizer(disabled.Result)
	if err != nil || !matrixSemanticEqual(normalizedExpected, normalizedDisabled) {
		evidence.category = "unowned_field_changed"
		t.Error("disabled candidate did not preserve the complete result")
	}
}

func (h *matrixHarness) runCampaignT() {
	h.t.Helper()

	templateCases := matrixTemplateCases(h.t)
	for index, testCase := range templateCases {
		caseID := fmt.Sprintf("T%02d", index+1)
		outcome := h.runCase(caseID, "T", testCase.module, func(t *testing.T, evidence *matrixEvidence) {
			h.runTemplateModuleLifecycle(t, evidence, testCase)
		})
		h.recoverTemplateAfterFailedRestoration(outcome)
	}
}

type matrixTemplateCase struct {
	module        string
	resourceType  string
	endpoint      client.WAFTemplateModuleEndpoint
	configuration func(templateID string, enabled bool) string
}

func (h *matrixHarness) runTemplateModuleLifecycle(t *testing.T, evidence *matrixEvidence, testCase matrixTemplateCase) {
	t.Helper()

	snapshot := waitForMatrixTemplateModule(t, h.api, testCase.endpoint, h.baseTemplateID)
	evidence.restoration = "pending"
	normalizer := func(result client.WAFModuleResult) (client.WAFModuleResult, error) { return result, nil }
	if testCase.module == "ip_protection" {
		normalizer = matrixNormalizeIPResult
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := restoreMatrixTemplateModule(ctx, h.api, testCase.endpoint, h.baseTemplateID, snapshot.Result, normalizer); err != nil {
			evidence.restoration = "failed"
			evidence.category = "restoration_failed"
			t.Error("complete template-module snapshot restoration failed")
			return
		}
		evidence.restoration = "passed"
	})

	resourceName := testCase.resourceType + ".test"
	initial := testCase.configuration(h.baseTemplateID, false)
	updated := testCase.configuration(h.baseTemplateID, true)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: initial,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "template_id", h.baseTemplateID),
					resource.TestCheckResourceAttr(resourceName, "configs.status", "false"),
					matrixTemplateRemoteCheck(h.api, testCase.endpoint, h.baseTemplateID, false),
				),
			},
			{
				Config: updated,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "configs.status", "true"),
					matrixTemplateRemoteCheck(h.api, testCase.endpoint, h.baseTemplateID, true),
				),
			},
			{Config: updated, PlanOnly: true},
			{
				ResourceName:     resourceName,
				ImportState:      true,
				ImportStateId:    h.baseTemplateID,
				ImportStateCheck: matrixImportIdentityCheck("template_id", h.baseTemplateID, "configs.status", "true"),
			},
			{Config: updated, PlanOnly: true},
		},
	})
	current, err := h.api.GetWAFTemplateModule(context.Background(), testCase.endpoint, h.baseTemplateID)
	if err != nil {
		t.Error("template-module disable verification GET failed")
		return
	}
	normalizedCurrent, err := normalizer(current.Result)
	if err != nil {
		t.Error("template-module disable verification normalization failed")
		return
	}
	status, ok := matrixRawBool(normalizedCurrent.Configs["status"])
	if !ok || status || normalizedCurrent.Template {
		t.Error("template-module destroy did not disable the applied configuration")
	}
	if testCase.module == "caching_compression" {
		for _, field := range []string{"cache", "compress"} {
			nestedStatus, nestedOK := matrixNestedRawBool(normalizedCurrent.Configs[field], "status")
			if !nestedOK || nestedStatus {
				t.Errorf("template caching/compression destroy did not disable configs.%s.status", field)
			}
		}
	}
}

func matrixTemplateRemoteCheck(api *client.Client, endpoint client.WAFTemplateModuleEndpoint, templateID string, wantStatus bool) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		document, err := api.GetWAFTemplateModule(context.Background(), endpoint, templateID)
		if err != nil {
			return fmt.Errorf("independent template-module GET failed")
		}
		status, ok := matrixRawBool(document.Result.Configs["status"])
		if !ok || status != wantStatus || document.Result.Template {
			return fmt.Errorf("independent template-module GET did not match the expected state")
		}
		return nil
	}
}

func (h *matrixHarness) runCase(
	caseID, campaign, module string,
	run func(*testing.T, *matrixEvidence),
) matrixOutcome {
	h.t.Helper()

	evidence := &matrixEvidence{restoration: "not_attempted"}
	started := time.Now()
	passed := h.t.Run(caseID+"_"+module, func(t *testing.T) {
		run(t, evidence)
	})
	outcome := matrixOutcome{
		result:      "failed",
		restoration: evidence.restoration,
		category:    evidence.category,
		duration:    time.Since(started),
	}
	if passed {
		outcome.result = "passed"
	}
	if outcome.category == "" && !passed {
		outcome.category = "terraform_or_assertion_failed"
	}
	h.appendResult(matrixCaseResult{
		CaseID:        caseID,
		Module:        module,
		Campaign:      campaign,
		Result:        outcome.result,
		DurationMS:    outcome.duration.Milliseconds(),
		Restoration:   outcome.restoration,
		ErrorCategory: outcome.category,
	})
	return outcome
}

func (h *matrixHarness) appendDerivedCase(caseID, campaign, module string, source matrixOutcome) {
	result := source.result
	category := source.category
	if result == "" {
		result = "failed"
		category = "missing_source_evidence"
	}
	h.appendResult(matrixCaseResult{
		CaseID:        caseID,
		Module:        module,
		Campaign:      campaign,
		Result:        result,
		DurationMS:    0,
		Restoration:   source.restoration,
		ErrorCategory: category,
	})
	if result != "passed" {
		h.t.Fail()
	}
}

func (h *matrixHarness) appendResult(result matrixCaseResult) {
	h.summary.mu.Lock()
	defer h.summary.mu.Unlock()
	h.summary.Cases = append(h.summary.Cases, result)
}

func (h *matrixHarness) setPhase(phase string) {
	h.summary.mu.Lock()
	defer h.summary.mu.Unlock()
	h.summary.Phase = phase
}

func (h *matrixHarness) setSetup(result string) {
	h.summary.mu.Lock()
	defer h.summary.mu.Unlock()
	h.summary.Setup = result
}

func (h *matrixHarness) markSetupPassedIfPending() {
	h.summary.mu.Lock()
	defer h.summary.mu.Unlock()
	if h.summary.Setup == "pending" {
		h.summary.Setup = "passed"
	}
}

func (h *matrixHarness) setApplicationFixture(label string) {
	h.summary.mu.Lock()
	defer h.summary.mu.Unlock()
	h.summary.ApplicationFixture = label
}

func (h *matrixHarness) recoverAppAfterFailedRestoration(outcome matrixOutcome) {
	h.t.Helper()
	if outcome.restoration != "failed" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := h.deleteApplication(ctx, h.epID); err != nil {
		h.t.Fatal("failed restoration and exact disposable app recovery cleanup failed")
	}
	h.epID = h.createApplication(ctx)
	if err := h.api.PutTemplateEndpoints(ctx, h.inheritTemplateID, []string{h.epID}); err != nil {
		h.t.Fatal("failed restoration and disposable app recovery binding failed")
	}
	if err := h.waitForTemplateMembership(ctx, h.inheritTemplateID, h.epID); err != nil {
		h.t.Fatal("failed restoration and disposable app recovery binding was not observable")
	}
}

func (h *matrixHarness) recoverTemplateAfterFailedRestoration(outcome matrixOutcome) {
	h.t.Helper()
	if outcome.restoration != "failed" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := h.deleteTemplate(ctx, h.baseTemplateID, h.baseTemplateName); err != nil {
		h.t.Fatal("failed restoration and exact disposable template recovery cleanup failed")
	}
	h.baseTemplateID = h.createTemplate(ctx, h.baseTemplateName)
}

func (h *matrixHarness) cleanupParents() {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	appCleanup := "passed"
	templateCleanup := "passed"
	if strings.TrimSpace(h.epID) != "" {
		if err := h.deleteApplication(ctx, h.epID); err != nil {
			appCleanup = "failed"
			h.t.Error("exact disposable app cleanup failed")
		}
	} else if err := h.deleteApplicationByExactName(ctx); err != nil {
		appCleanup = "failed"
		h.t.Error("exact-name disposable app cleanup failed")
	}
	for _, target := range []struct {
		id   string
		name string
	}{
		{id: h.baseTemplateID, name: h.baseTemplateName},
		{id: h.inheritTemplateID, name: h.inheritTemplateName},
	} {
		var err error
		if strings.TrimSpace(target.id) == "" {
			err = h.deleteTemplateByExactName(ctx, target.name)
		} else {
			err = h.deleteTemplate(ctx, target.id, target.name)
		}
		if err != nil {
			templateCleanup = "failed"
			h.t.Error("exact disposable template cleanup failed")
		}
	}
	h.summary.mu.Lock()
	h.summary.AppCleanup = appCleanup
	h.summary.TemplateCleanup = templateCleanup
	h.summary.mu.Unlock()
}

func (h *matrixHarness) deleteApplicationByExactName(ctx context.Context) error {
	applications, err := h.api.ListAllApplications(ctx, client.ListApplicationsOptions{Size: 30})
	if err != nil {
		return err
	}
	matches := make([]client.Application, 0, 1)
	for _, application := range applications {
		if application.AppName == h.appName {
			matches = append(matches, application)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	if len(matches) != 1 {
		return fmt.Errorf("exact disposable app name was not unique")
	}
	return h.deleteApplication(ctx, matches[0].EPID)
}

func (h *matrixHarness) deleteTemplateByExactName(ctx context.Context, name string) error {
	templates, err := h.api.ListTemplates(ctx)
	if err != nil {
		return err
	}
	matches := make([]client.Template, 0, 1)
	for _, template := range templates.Templates {
		if template.Name == name {
			matches = append(matches, template)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	if len(matches) != 1 || matches[0].Predefined {
		return fmt.Errorf("exact disposable template name was not a unique user template")
	}
	return h.deleteTemplate(ctx, matches[0].TemplateID, name)
}

func (h *matrixHarness) deleteApplication(ctx context.Context, epID string) error {
	if err := h.api.DeleteApplication(ctx, epID); err != nil && !client.IsNotFound(err) {
		return err
	}
	return waitForApplicationAbsence(ctx, h.api, epID)
}

func (h *matrixHarness) deleteTemplate(ctx context.Context, templateID, templateName string) error {
	template, err := h.api.GetTemplate(ctx, templateID)
	if err == nil && template.Predefined {
		return fmt.Errorf("refusing predefined template cleanup: template_id=%q name=%q", templateID, template.Name)
	}
	if err != nil && !client.IsNotFound(err) && !client.IsStatus(err, http.StatusForbidden) {
		return err
	}
	if err := h.api.DeleteTemplate(ctx, templateID); err != nil && !client.IsNotFound(err) {
		return err
	}
	return waitForTemplateAbsence(ctx, h.api, templateName)
}

func matrixStandardAppCases() []matrixStandardAppCase {
	cases := make([]matrixStandardAppCase, 0, 26)
	for _, testCase := range allImplementedModuleLiveCases() {
		cases = append(cases, matrixStandardAppCase{
			module:           testCase.name,
			resourceType:     testCase.terraformName,
			endpoint:         matrixAppEndpoint(testCase.name),
			fixture:          testCase.name + ".tf",
			templateCapable:  true,
			disableOnDestroy: testCase.name != "caching_compression",
		})
	}
	return cases
}

func matrixTemplateCases(t *testing.T) []matrixTemplateCase {
	t.Helper()
	result := make([]matrixTemplateCase, 0, 31)
	for _, appCase := range matrixStandardAppCases() {
		localCase := appCase
		result = append(result, matrixTemplateCase{
			module:       localCase.module,
			resourceType: "fortiappseccloud_waf_template_" + localCase.module,
			endpoint:     matrixTemplateEndpoint(localCase.module),
			configuration: func(templateID string, enabled bool) string {
				appConfig := (&matrixHarness{epID: "matrix-placeholder"}).standardAppConfiguration(t, localCase, enabled)
				return matrixAppToTemplateConfiguration(appConfig, localCase.resourceType, localCase.module, templateID)
			},
		})
	}
	for _, customCase := range customModuleLiveCases() {
		if !matrixTemplateCustomModule(customCase.name) {
			continue
		}
		localCase := customCase
		result = append(result, matrixTemplateCase{
			module:       localCase.name,
			resourceType: "fortiappseccloud_waf_template_" + localCase.name,
			endpoint:     matrixTemplateEndpoint(localCase.name),
			configuration: func(templateID string, enabled bool) string {
				appConfig := localCase.configuration("matrix-placeholder", enabled)
				return matrixAppToTemplateConfiguration(appConfig, localCase.terraformName, localCase.name, templateID)
			},
		})
	}
	return result
}

func matrixAppToTemplateConfiguration(appConfig, appResourceType, module, templateID string) string {
	templateResourceType := "fortiappseccloud_waf_template_" + module
	configuration := strings.Replace(appConfig, `resource "`+appResourceType+`"`, `resource "`+templateResourceType+`"`, 1)
	lines := strings.Split(configuration, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ep_id") && strings.Contains(trimmed, "=") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			filtered = append(filtered, indent+"template_id = "+strconv.Quote(templateID))
			continue
		}
		if strings.HasPrefix(trimmed, "template") && strings.Contains(trimmed, "=") {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

func matrixTemplateModuleNames() []string {
	cases := matrixStandardAppCases()
	result := make([]string, 0, 31)
	for _, testCase := range cases {
		result = append(result, testCase.module)
	}
	result = append(result, "anomaly_detection", "cors_protection", "ip_protection", "custom_rule", "ml_api_protection")
	return result
}

func matrixDisableCandidateNames() []string {
	return []string{
		"api_gateway",
		"biometrics_based_detection",
		"bot_deception",
		"cookie_security",
		"csrf_protection",
		"ddos_prevention",
		"file_protection",
		"graphql_protection",
		"http_header_security",
		"information_leakage",
		"json_protection",
		"known_attacks",
		"known_bots",
		"mitb_protection",
		"ml_bot_detection",
		"mobile_api_protection",
		"parameter_validation",
		"request_limits",
		"rewriting_requests",
		"threshold_detection",
		"url_access",
		"waiting_room",
		"web_socket_security",
		"xml_protection_policy",
		"anomaly_detection",
		"cors_protection",
		"ip_protection",
		"custom_rule",
		"ml_api_protection",
	}
}

func matrixAppEndpoint(module string) client.WAFModuleEndpoint {
	return client.WAFModuleEndpoint{
		Path:      "/waf/apps/{ep_id}/" + module,
		Operation: strings.ReplaceAll(module, "_", " ") + " matrix",
	}
}

func matrixTemplateEndpoint(module string) client.WAFTemplateModuleEndpoint {
	return client.WAFTemplateModuleEndpoint{
		Path:      "/waf/template/{template_id}/" + module,
		Operation: strings.ReplaceAll(module, "_", " ") + " matrix",
	}
}

func matrixControlEndpoint(module string) client.WAFModuleEndpoint {
	if module == "known_attacks" {
		return matrixAppEndpoint("csrf_protection")
	}
	return matrixAppEndpoint("known_attacks")
}

func matrixTemplateCustomModule(module string) bool {
	switch module {
	case "anomaly_detection", "cors_protection", "ip_protection", "custom_rule", "ml_api_protection":
		return true
	default:
		return false
	}
}

func matrixAppTemplateOnlyConfiguration(resourceType, epID string) string {
	return fmt.Sprintf(`
resource %q "test" {
  ep_id    = %q
  template = true
}
`, resourceType, epID)
}

func matrixImportIdentityCheck(identityName, identityValue, statusName, statusValue string) resource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		if len(states) != 1 || states[0] == nil {
			return fmt.Errorf("import did not return exactly one state")
		}
		if states[0].Attributes[identityName] != identityValue {
			return fmt.Errorf("import did not hydrate the expected identity")
		}
		if states[0].Attributes[statusName] != statusValue {
			return fmt.Errorf("import did not hydrate the expected status")
		}
		return nil
	}
}

func matrixSetStatus(configuration, module string, enabled bool) string {
	limit := 1
	if module == "caching_compression" {
		limit = 3
	}
	matches := matrixStatusLine.FindAllStringIndex(configuration, limit)
	if len(matches) == 0 {
		return configuration
	}
	var builder strings.Builder
	previous := 0
	for _, match := range matches {
		builder.WriteString(configuration[previous:match[0]])
		line := configuration[match[0]:match[1]]
		builder.WriteString(strings.Replace(line, "true", strconv.FormatBool(enabled), 1))
		previous = match[1]
	}
	builder.WriteString(configuration[previous:])
	return builder.String()
}

func matrixExampleFixture(t *testing.T, filename string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve acceptance fixture location failed")
	}
	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "examples", "waf", filename)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reviewed matrix fixture %q: %v", filename, err)
	}
	return string(contents)
}

func waitForMatrixTemplateModule(
	t *testing.T,
	api *client.Client,
	endpoint client.WAFTemplateModuleEndpoint,
	templateID string,
) client.WAFTemplateModuleDocument {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for attempt := 0; attempt < 30; attempt++ {
		document, err := api.GetWAFTemplateModule(ctx, endpoint, templateID)
		if err == nil {
			return document
		}
		if !client.IsStatus(err, 400, 403, 404, 409, 503) {
			t.Fatal("template-module snapshot GET failed")
		}
		if err := waitTemplateCRUDRetry(ctx); err != nil {
			break
		}
	}
	t.Fatal("template-module snapshot did not become available")
	return client.WAFTemplateModuleDocument{}
}

func restoreMatrixWAFModule(
	ctx context.Context,
	api *client.Client,
	endpoint client.WAFModuleEndpoint,
	epID string,
	snapshot client.WAFModuleResult,
	normalize func(client.WAFModuleResult) (client.WAFModuleResult, error),
) error {
	if normalize == nil {
		normalize = func(result client.WAFModuleResult) (client.WAFModuleResult, error) { return result, nil }
	}
	if err := api.PutWAFModule(ctx, endpoint, epID, snapshot); err != nil {
		return err
	}
	want, err := normalize(snapshot)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 30; attempt++ {
		got, getErr := api.GetWAFModule(ctx, endpoint, epID)
		if getErr == nil {
			normalized, normalizeErr := normalize(got.Result)
			if normalizeErr == nil && matrixSemanticEqual(want, normalized) {
				return nil
			}
		}
		if err := matrixWait(ctx, time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("restored app-module result did not match its complete snapshot")
}

func restoreMatrixTemplateModule(
	ctx context.Context,
	api *client.Client,
	endpoint client.WAFTemplateModuleEndpoint,
	templateID string,
	snapshot client.WAFModuleResult,
	normalize func(client.WAFModuleResult) (client.WAFModuleResult, error),
) error {
	if err := api.PutWAFTemplateModule(ctx, endpoint, templateID, snapshot); err != nil {
		return err
	}
	want, err := normalize(snapshot)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 30; attempt++ {
		got, getErr := api.GetWAFTemplateModule(ctx, endpoint, templateID)
		if getErr == nil {
			normalized, normalizeErr := normalize(got.Result)
			if normalizeErr == nil && matrixSemanticEqual(want, normalized) {
				return nil
			}
		}
		if err := matrixWait(ctx, time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("restored template-module result did not match its complete snapshot")
}

func matrixNormalizeIPResult(result client.WAFModuleResult) (client.WAFModuleResult, error) {
	return client.NormalizeIPProtectionResultForPut(result)
}

func matrixRawBool(value json.RawMessage) (bool, bool) {
	var result bool
	if err := json.Unmarshal(value, &result); err != nil {
		return false, false
	}
	return result, true
}

func matrixNestedRawBool(value json.RawMessage, field string) (bool, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return false, false
	}
	return matrixRawBool(object[field])
}

func matrixSemanticEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	var leftValue, rightValue any
	if json.Unmarshal(leftJSON, &leftValue) != nil || json.Unmarshal(rightJSON, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func matrixDiagnosticCategory(diagnostics diag.Diagnostics) string {
	text := strings.ToLower(diagnostics.Errors()[0].Summary() + " " + diagnostics.Errors()[0].Detail())
	switch {
	case strings.Contains(text, "non-boolean"), strings.Contains(text, "omitted configs.status"):
		return "unsafe_status_shape"
	case strings.Contains(text, "unowned"):
		return "unowned_field_changed"
	case strings.Contains(text, "verify"), strings.Contains(text, "not applied"):
		return "verification_failed"
	default:
		return "write_failed"
	}
}

func matrixWait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func matrixRandomSuffix(t *testing.T) string {
	t.Helper()
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatalf("generate disposable matrix suffix: %v", err)
	}
	return hex.EncodeToString(bytes)
}

func matrixCodeIdentity() string {
	value := strings.TrimSpace(os.Getenv("FORTIAPPSECCLOUD_MATRIX_CODE_IDENTITY"))
	if value == "" {
		return "unknown"
	}
	return value
}

func writeMatrixSummary(summary *matrixSummary) (string, error) {
	summary.mu.Lock()
	summary.FinishedAtUTC = time.Now().UTC()
	copy := *summary
	copy.Cases = append([]matrixCaseResult(nil), summary.Cases...)
	summary.mu.Unlock()
	file, err := os.CreateTemp("", "fortiappseccloud-dev-waf-matrix-*.json")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(&copy); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return path, nil
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
