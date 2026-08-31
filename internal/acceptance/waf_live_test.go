package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"terraform-provider-fortiappseccloud/internal/client"
	frameworkprovider "terraform-provider-fortiappseccloud/internal/provider"
)

const providerName = "fortiappseccloud"

func TestAccExistingCoreModules(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	epID := requireEnvironment(t, "FORTIAPPSECCLOUD_TEST_EP_ID")
	appName := requireEnvironment(t, "FORTIAPPSECCLOUD_TEST_APP_NAME")
	api := liveClient(t)
	application, err := api.FindApplicationByEPID(context.Background(), epID)
	if err != nil {
		t.Fatalf("resolve authorized test application: %v", err)
	}
	if application.AppName != appName {
		t.Fatalf("FORTIAPPSECCLOUD_TEST_APP_NAME does not match the authorized ep_id")
	}

	t.Run("csrf_protection", func(t *testing.T) {
		skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_CSRF_PROTECTION_WRITE", "enable_alert_forget_preserve_collections_v2:"+epID)
		endpoint := client.WAFModuleEndpoint{Path: "/waf/apps/{ep_id}/csrf_protection", Operation: "CSRF protection"}
		snapshot, err := api.GetWAFModule(context.Background(), endpoint, epID)
		if err != nil {
			t.Fatalf("snapshot CSRF protection: %v", err)
		}
		restoreModule(t, api, endpoint, epID, snapshot)
		moduleAcceptance(t, epID, "fortiappseccloud_waf_csrf_protection.test", fmt.Sprintf(`
resource "fortiappseccloud_waf_csrf_protection" "test" {
  ep_id   = %q
  template = false
  configs {
    action = "alert"
	status = true
  }
}`, epID), "configs.page_list", "configs.url_list")
		verifyModuleDisabled(t, api, endpoint, epID)
	})

	t.Run("url_access", func(t *testing.T) {
		skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_URL_ACCESS_WRITE", "enable_alert_forget_preserve_rules_v2:"+epID)
		endpoint := client.WAFModuleEndpoint{Path: "/waf/apps/{ep_id}/url_access", Operation: "URL access"}
		snapshot, err := api.GetWAFModule(context.Background(), endpoint, epID)
		if err != nil {
			t.Fatalf("snapshot URL access: %v", err)
		}
		restoreModule(t, api, endpoint, epID, snapshot)
		moduleAcceptance(t, epID, "fortiappseccloud_waf_url_access.test", fmt.Sprintf(`
resource "fortiappseccloud_waf_url_access" "test" {
  ep_id   = %q
  template = false
  configs {
    action = "alert"
	status = true
  }
}`, epID), "configs.rule_list")
		verifyModuleDisabled(t, api, endpoint, epID)
	})

	t.Run("account_takeover", func(t *testing.T) {
		skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_ACCOUNT_TAKEOVER_WRITE", "enable_alert_then_disable_v2:"+epID)
		snapshot, err := api.GetAccountTakeover(context.Background(), epID)
		if err != nil {
			t.Fatalf("snapshot account takeover: %v", err)
		}
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
		moduleAcceptance(t, epID, "fortiappseccloud_waf_account_takeover.test", fmt.Sprintf(`
resource "fortiappseccloud_waf_account_takeover" "test" {
  ep_id   = %q
  template = false
  configs {
    action = "alert"
	status = true
  }
}`, epID))
		current, err := api.GetAccountTakeover(context.Background(), epID)
		if err != nil {
			t.Fatalf("verify account takeover destroy: %v", err)
		}
		if current.Result.Template || rawBool(current.Result.Configs["status"]) {
			t.Fatalf("account takeover destroy did not leave the verified disabled state")
		}
	})
}

func verifyModuleDisabled(t *testing.T, api *client.Client, endpoint client.WAFModuleEndpoint, epID string) {
	t.Helper()
	current, err := api.GetWAFModule(context.Background(), endpoint, epID)
	if err != nil {
		t.Fatalf("verify %s destroy: %v", endpoint.Operation, err)
	}
	if current.Result.Template || rawBool(current.Result.Configs["status"]) || rawString(current.Result.Configs["action"]) != "alert" {
		t.Fatalf("%s disable-on-destroy did not preserve action while setting status=false", endpoint.Operation)
	}
}

func rawBool(value json.RawMessage) bool {
	var result bool
	_ = json.Unmarshal(value, &result)
	return result
}

func rawString(value json.RawMessage) string {
	var result string
	_ = json.Unmarshal(value, &result)
	return result
}

func TestAccApplicationVerticalSlice(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_APP", "yes")

	appName := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_APP_NAME")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_APP_LIFECYCLE_WRITE", "application_origin_template_openapi_csrf_v4:"+appName)
	domain := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_DOMAIN")
	originAddress := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS")
	originEncryptionLevel := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_ORIGIN_ENCRYPTION_LEVEL")
	originType := "domain"
	if net.ParseIP(strings.TrimSpace(originAddress)) != nil {
		originType = "ip"
	}
	platform := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLATFORM")
	region := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_REGION")
	templateID := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_TEMPLATE_ID")
	validationPath := filepath.Join(t.TempDir(), "acceptance-openapi.yaml")
	if err := os.WriteFile(validationPath, []byte("openapi: 3.0.0\ninfo:\n  title: acceptance\n  version: 1.0.0\npaths: {}\n"), 0o600); err != nil {
		t.Fatalf("create acceptance OpenAPI document: %v", err)
	}
	api := liveClient(t)

	applications, err := api.ListAllApplications(context.Background(), client.ListApplicationsOptions{Size: 30})
	if err != nil {
		t.Fatalf("verify disposable application name: %v", err)
	}
	for _, application := range applications {
		if application.AppName == appName {
			t.Fatalf("refusing application acceptance: app_name already exists")
		}
	}
	templateSnapshot, err := api.GetTemplate(context.Background(), templateID)
	if err != nil {
		t.Fatalf("snapshot template membership: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		ids := make([]string, 0, len(templateSnapshot.Endpoints))
		for _, endpoint := range templateSnapshot.Endpoints {
			ids = append(ids, endpoint.EPID)
		}
		if restoreErr := api.PutTemplateEndpoints(ctx, templateID, ids); restoreErr != nil {
			t.Errorf("restore template membership: %v", restoreErr)
		}

		currentApplications, listErr := api.ListAllApplications(ctx, client.ListApplicationsOptions{Size: 30})
		if listErr != nil {
			t.Errorf("inspect disposable application during cleanup: %v", listErr)
		} else {
			for _, current := range currentApplications {
				if current.AppName != appName {
					continue
				}
				if deleteErr := api.DeleteApplication(ctx, current.EPID); deleteErr != nil {
					t.Errorf("cleanup disposable application: %v", deleteErr)
					break
				}
				if waitErr := waitForApplicationAbsence(ctx, api, current.EPID); waitErr != nil {
					t.Errorf("verify disposable application cleanup: %v", waitErr)
				}
				break
			}
		}
	})

	configuration := func(blockMode bool, originWeight int, openAPIAction string) string {
		return fmt.Sprintf(`
resource "fortiappseccloud_waf_app" "test" {
  app_name    = %q
  domain_name = %q
  services    = ["https"]
  platform    = %q
  region      = %q
  cdn         = false
	block_mode  = %t

  initial_origin {
    address  = %q
    protocol = "https"
    port     = 443
  }
}

resource "fortiappseccloud_waf_origin_servers" "test" {
  ep_id = fortiappseccloud_waf_app.test.ep_id
  server_pools {
    name = "default_pool"
    health { enabled = false }
    persistence { type = "disable" }
    servers {
      address = %q
      port    = 443
      ssl     = true
      status  = "enable"
	  type    = %q
	  encryption_level = %q
	  weight  = %d
    }
  }
}

resource "fortiappseccloud_waf_template_attachment" "test" {
  ep_id       = fortiappseccloud_waf_app.test.ep_id
  template_id = %q
}

resource "fortiappseccloud_waf_openapi_validation" "test" {
	  ep_id            = fortiappseccloud_waf_app.test.ep_id
	  action           = %q
	  enable           = true
	  validation_files = [%q]
	  depends_on       = [fortiappseccloud_waf_template_attachment.test]
}

resource "fortiappseccloud_waf_csrf_protection" "test" {
  ep_id    = fortiappseccloud_waf_app.test.ep_id
  template = false
  configs {
    action = %q
    status = true
  }
	depends_on = [fortiappseccloud_waf_template_attachment.test]
}
`, appName, domain, platform, region, blockMode, originAddress, originAddress, originType, originEncryptionLevel, originWeight, templateID, openAPIAction, validationPath, openAPIAction)
	}
	initialConfiguration := configuration(false, 1, "alert")
	updatedConfiguration := configuration(true, 2, "alert_deny")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		CheckDestroy:             checkApplicationVerticalDestroy(api, appName, templateSnapshot),
		Steps: []resource.TestStep{
			{Config: initialConfiguration, Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("fortiappseccloud_waf_app.test", "app_name", appName),
				resource.TestCheckResourceAttrSet("fortiappseccloud_waf_app.test", "ep_id"),
			)},
			{Config: updatedConfiguration, Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("fortiappseccloud_waf_app.test", "block_mode", "true"),
				resource.TestCheckResourceAttr("fortiappseccloud_waf_origin_servers.test", "server_pools.0.servers.0.weight", "2"),
				resource.TestCheckResourceAttr("fortiappseccloud_waf_openapi_validation.test", "action", "alert_deny"),
				resource.TestCheckResourceAttr("fortiappseccloud_waf_csrf_protection.test", "configs.action", "alert_deny"),
				checkApplicationVerticalRemote(api, templateID),
			)},
			{Config: updatedConfiguration, PlanOnly: true},
			{
				ResourceName:                         "fortiappseccloud_waf_app.test",
				ImportState:                          true,
				ImportStateId:                        appName,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "ep_id",
				// Template membership is owned by the separate attachment resource.
				// App import independently observes it, while the pre-import app state
				// can predate the attachment created later in the same apply.
				ImportStateVerifyIgnore: []string{"initial_origin", "precheck", "attached_template_id", "attached_template_name"},
			},
			{
				ResourceName:                         "fortiappseccloud_waf_origin_servers.test",
				ImportState:                          true,
				ImportStateIdFunc:                    applicationEPIDImportID("fortiappseccloud_waf_app.test"),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "ep_id",
			},
			{
				ResourceName:                         "fortiappseccloud_waf_template_attachment.test",
				ImportState:                          true,
				ImportStateIdFunc:                    templateAttachmentImportID(templateID, "fortiappseccloud_waf_app.test"),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "ep_id",
			},
			{
				ResourceName:                         "fortiappseccloud_waf_openapi_validation.test",
				ImportState:                          true,
				ImportStateIdFunc:                    applicationEPIDImportID("fortiappseccloud_waf_app.test"),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "ep_id",
				ImportStateVerifyIgnore:              []string{"validation_files", "validation_file_hashes"},
			},
			{
				ResourceName:                         "fortiappseccloud_waf_csrf_protection.test",
				ImportState:                          true,
				ImportStateIdFunc:                    applicationEPIDImportID("fortiappseccloud_waf_app.test"),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "ep_id",
				ImportStateVerifyIgnore:              []string{"configs.page_list", "configs.url_list"},
			},
		},
	})
}

func TestAccApplicationVerticalCleanupState(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_APP", "yes")
	appName := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_APP_NAME")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_APP_LIFECYCLE_WRITE", "application_origin_template_openapi_csrf_v4:"+appName)
	templateID := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_TEMPLATE_ID")
	api := liveClient(t)

	applications, err := api.ListAllApplications(context.Background(), client.ListApplicationsOptions{Size: 30})
	if err != nil {
		t.Fatalf("verify disposable application cleanup: %v", err)
	}
	for _, application := range applications {
		if application.AppName == appName {
			t.Fatal("disposable application remains after the failed lifecycle")
		}
	}
	template, err := api.GetTemplate(context.Background(), templateID)
	if err != nil {
		t.Fatalf("verify template cleanup: %v", err)
	}
	for _, endpoint := range template.Endpoints {
		if endpoint.AppName == appName {
			t.Fatal("disposable application remains attached to the template")
		}
	}
}

func applicationEPIDImportID(resourceName string) resource.ImportStateIdFunc {
	return func(state *terraform.State) (string, error) {
		return stateResourceAttribute(state, resourceName, "ep_id")
	}
}

func templateAttachmentImportID(templateID, appResourceName string) resource.ImportStateIdFunc {
	return func(state *terraform.State) (string, error) {
		epID, err := stateResourceAttribute(state, appResourceName, "ep_id")
		if err != nil {
			return "", err
		}
		return templateID + ":" + epID, nil
	}
}

func stateResourceAttribute(state *terraform.State, resourceName, attribute string) (string, error) {
	if state == nil || state.RootModule() == nil {
		return "", fmt.Errorf("Terraform state has no root module")
	}
	resourceState, ok := state.RootModule().Resources[resourceName]
	if !ok || resourceState == nil || resourceState.Primary == nil {
		return "", fmt.Errorf("Terraform state has no resource %q", resourceName)
	}
	value := strings.TrimSpace(resourceState.Primary.Attributes[attribute])
	if value == "" {
		return "", fmt.Errorf("Terraform resource %q has no %s", resourceName, attribute)
	}
	return value, nil
}

func checkApplicationVerticalRemote(api *client.Client, templateID string) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		epID, err := stateResourceAttribute(state, "fortiappseccloud_waf_app.test", "ep_id")
		if err != nil {
			return err
		}
		application, err := api.FindApplicationByEPID(context.Background(), epID)
		if err != nil {
			return fmt.Errorf("read updated application: %w", err)
		}
		if application.BlockMode != 1 {
			return fmt.Errorf("updated application did not report block_mode=1")
		}
		origins, err := api.GetOriginServers(context.Background(), epID)
		if err != nil {
			return fmt.Errorf("read updated origins: %w", err)
		}
		if len(origins.Result.ServerPools) != 1 || len(origins.Result.ServerPools[0].Servers) != 1 || origins.Result.ServerPools[0].Servers[0].Weight == nil || *origins.Result.ServerPools[0].Servers[0].Weight != 2 {
			return fmt.Errorf("updated origins did not report the planned single server with weight=2")
		}
		template, err := api.GetTemplate(context.Background(), templateID)
		if err != nil {
			return fmt.Errorf("read updated template membership: %w", err)
		}
		if !templateHasEPID(template, epID) {
			return fmt.Errorf("template did not report the managed application membership")
		}
		openAPI, err := api.GetOpenAPIValidation(context.Background(), epID)
		if err != nil {
			return fmt.Errorf("read updated OpenAPI validation: %w", err)
		}
		if !openAPI.Result.Configs.Status || openAPI.Result.Configs.Action != "alert_deny" || len(openAPI.Result.Configs.FileList) != 1 {
			return fmt.Errorf("OpenAPI validation did not report the updated enabled single-file configuration")
		}
		csrf, err := api.GetWAFModule(context.Background(), client.WAFModuleEndpoint{Path: "/waf/apps/{ep_id}/csrf_protection", Operation: "CSRF protection"}, epID)
		if err != nil {
			return fmt.Errorf("read updated CSRF protection: %w", err)
		}
		if csrf.Result.Template || rawString(csrf.Result.Configs["action"]) != "alert_deny" || !rawBool(csrf.Result.Configs["status"]) {
			return fmt.Errorf("CSRF protection did not report the updated enabled alert_deny configuration")
		}
		return nil
	}
}

func checkApplicationVerticalDestroy(api *client.Client, appName string, snapshot client.Template) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		applications, err := api.ListAllApplications(context.Background(), client.ListApplicationsOptions{Size: 30})
		if err != nil {
			return fmt.Errorf("verify application destroy: %w", err)
		}
		for _, application := range applications {
			if application.AppName == appName {
				return fmt.Errorf("application %q still exists after Terraform destroy", appName)
			}
		}
		current, err := api.GetTemplate(context.Background(), snapshot.TemplateID)
		if err != nil {
			return fmt.Errorf("verify template restoration after destroy: %w", err)
		}
		want, got := templateEPIDs(snapshot), templateEPIDs(current)
		if !reflect.DeepEqual(want, got) {
			return fmt.Errorf("template membership was not restored after destroy")
		}
		return nil
	}
}

func templateEPIDs(template client.Template) []string {
	ids := make([]string, 0, len(template.Endpoints))
	for _, endpoint := range template.Endpoints {
		ids = append(ids, endpoint.EPID)
	}
	sort.Strings(ids)
	return ids
}

func templateHasEPID(template client.Template, epID string) bool {
	for _, endpoint := range template.Endpoints {
		if endpoint.EPID == epID {
			return true
		}
	}
	return false
}

func waitForApplicationAbsence(ctx context.Context, api *client.Client, epID string) error {
	for attempt := 0; attempt < 30; attempt++ {
		exists, err := api.ApplicationExists(ctx, epID)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if attempt == 29 {
			break
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("application remained observable after delete")
}

func moduleAcceptance(t *testing.T, epID, resourceName, configuration string, importIgnore ...string) {
	t.Helper()
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: configuration, Check: resource.TestCheckResourceAttr(resourceName, "ep_id", epID)},
			{Config: configuration, PlanOnly: true},
			{ResourceName: resourceName, ImportState: true, ImportStateId: epID, ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "ep_id", ImportStateVerifyIgnore: importIgnore},
		},
	})
}

func restoreModule(t *testing.T, api *client.Client, endpoint client.WAFModuleEndpoint, epID string, snapshot client.WAFModuleDocument) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := api.PutWAFModule(ctx, endpoint, epID, snapshot.Result); err != nil {
			t.Errorf("restore %s: %v", endpoint.Operation, err)
			return
		}
		verified, err := api.GetWAFModule(ctx, endpoint, epID)
		if err != nil {
			t.Errorf("verify %s restoration: %v", endpoint.Operation, err)
			return
		}
		assertSemanticJSON(t, endpoint.Operation+" restoration", snapshot.Result, verified.Result)
	})
}

func providerFactories() map[string]func() (tfprotov5.ProviderServer, error) {
	return map[string]func() (tfprotov5.ProviderServer, error){providerName: providerserver.NewProtocol5WithError(frameworkprovider.New("acc", "acc")())}
}

func liveClient(t *testing.T) *client.Client {
	t.Helper()
	api, err := client.New(context.Background(), client.Config{
		BaseURL: os.Getenv("FORTIAPPSECCLOUD_HOSTNAME"), APIToken: os.Getenv("FORTIAPPSECCLOUD_API_TOKEN"),
		Username: os.Getenv("FORTIAPPSECCLOUD_USERNAME"), Password: os.Getenv("FORTIAPPSECCLOUD_PASSWORD"), Timeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("configure acceptance client: %v", err)
	}
	return api
}

func requireEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s must be set for this acceptance test", name)
	}
	return value
}

func skipUnlessExactEnvironment(t *testing.T, name, expected string) {
	t.Helper()
	if os.Getenv(name) != expected {
		t.Skipf("%s does not authorize this exact target and write lifecycle", name)
	}
}

func assertSemanticJSON(t *testing.T, label string, want, got any) {
	t.Helper()
	wantBytes, wantErr := json.Marshal(want)
	gotBytes, gotErr := json.Marshal(got)
	if wantErr != nil || gotErr != nil {
		t.Errorf("%s encode errors: %v / %v", label, wantErr, gotErr)
		return
	}
	var wantValue, gotValue any
	if err := json.Unmarshal(wantBytes, &wantValue); err != nil {
		t.Errorf("%s decode snapshot: %v", label, err)
		return
	}
	if err := json.Unmarshal(gotBytes, &gotValue); err != nil {
		t.Errorf("%s decode result: %v", label, err)
		return
	}
	if !reflect.DeepEqual(wantValue, gotValue) {
		t.Errorf("%s did not reproduce the complete saved envelope", label)
	}
}
