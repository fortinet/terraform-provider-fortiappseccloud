package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"terraform-provider-fortiappseccloud/internal/client"
)

const (
	devCertificateModeHostname = "https://api.dev1.fortiappsec.com"
	devCertificateModeGate     = "certificate_mode_v1"
)

// TestAccDevApplicationCertificateModeLifecycle creates one uniquely named
// disposable dev application through Terraform, transitions automatic ->
// custom -> automatic, verifies the independent endpoint response after every
// step, and lets the served waf_app Delete path remove the application.
func TestAccDevApplicationCertificateModeLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_HOSTNAME", devCertificateModeHostname)
	skipUnlessExactEnvironment(
		t,
		"FORTIAPPSECCLOUD_ACC_DEV_CERTIFICATE_MODE_WRITE",
		devCertificateModeGate,
	)
	requireEnvironment(t, "FORTIAPPSECCLOUD_API_TOKEN")

	api := liveClient(t)
	platform, region := selectCertificateModePlacement(t, api)
	suffix := matrixRandomSuffix(t)
	appName := "tf-auto-cert-mode-" + suffix
	domain := "tf-cert-" + suffix + ".example.com"
	origin := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	refuseExistingApplicationName(t, ctx, api, appName)
	registerDisposableApplicationCleanup(t, api, appName)

	var epID string
	configuration := func(mode string) string {
		return fmt.Sprintf(`
resource "fortiappseccloud_waf_app" "test" {
  app_name         = %q
  domain_name      = %q
  extra_domains    = []
  services         = ["https"]
  http_port        = 80
  https_port       = 443
  platform         = %q
  region           = %q
  cdn              = false
  block_mode       = false
  certificate_mode = %q
  precheck         = false

  initial_origin {
    address  = %q
    protocol = "https"
    port     = 443
  }
}
`, appName, domain, platform, region, mode, origin)
	}

	resourceName := "fortiappseccloud_waf_app.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: configuration("automatic"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "certificate_mode", "automatic"),
					certificateModeRemoteCheck(api, appName, 0, &epID),
				),
			},
			{
				Config: configuration("custom"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "certificate_mode", "custom"),
					certificateModeRemoteCheck(api, appName, 1, &epID),
				),
			},
			{Config: configuration("custom"), PlanOnly: true},
			{
				Config: configuration("automatic"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "certificate_mode", "automatic"),
					certificateModeRemoteCheck(api, appName, 0, &epID),
				),
			},
			{Config: configuration("automatic"), PlanOnly: true},
		},
	})

	if strings.TrimSpace(epID) == "" {
		t.Fatal("certificate-mode lifecycle did not capture the disposable application ep_id")
	}
	absenceCtx, absenceCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer absenceCancel()
	if err := waitForApplicationAbsence(absenceCtx, api, epID); err != nil {
		t.Fatalf("served Terraform destroy did not remove the certificate-mode application: %v", err)
	}
}

func selectCertificateModePlacement(t *testing.T, api *client.Client) (string, string) {
	t.Helper()

	settings, err := api.GetWAFSettings(context.Background())
	if err != nil {
		t.Fatalf("read dev WAF placement settings: %v", err)
	}
	type placement struct {
		platform string
		region   string
	}
	var placements []placement
	for _, supported := range settings.SupportedPlatforms {
		for _, supportedRegion := range supported.Regions {
			platform := strings.TrimSpace(supported.Platform)
			region := strings.TrimSpace(supportedRegion.LogicalRegion)
			if platform != "" && region != "" {
				placements = append(placements, placement{platform: platform, region: region})
			}
		}
	}
	if len(placements) == 0 {
		t.Fatal("dev WAF settings did not expose a supported logical placement")
	}
	sort.Slice(placements, func(i, j int) bool {
		if placements[i].platform == placements[j].platform {
			return placements[i].region < placements[j].region
		}
		return placements[i].platform < placements[j].platform
	})
	for _, candidate := range placements {
		if candidate.platform == settings.PreferredPlatform &&
			candidate.region == settings.PreferredRegion {
			return candidate.platform, candidate.region
		}
	}
	return placements[0].platform, placements[0].region
}

func certificateModeRemoteCheck(
	api *client.Client,
	appName string,
	want int64,
	epID *string,
) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		if state == nil || state.RootModule() == nil {
			return fmt.Errorf("Terraform state omitted the root module")
		}
		instance, ok := state.RootModule().Resources["fortiappseccloud_waf_app.test"]
		if !ok || instance == nil || instance.Primary == nil {
			return fmt.Errorf("Terraform state omitted the certificate-mode application")
		}
		stateEPID := strings.TrimSpace(instance.Primary.Attributes["ep_id"])
		if stateEPID == "" {
			return fmt.Errorf("Terraform state omitted the application ep_id")
		}
		application, err := api.FindApplicationByName(context.Background(), appName)
		if err != nil {
			return fmt.Errorf("resolve certificate-mode application: %w", err)
		}
		if application.EPID != stateEPID {
			return fmt.Errorf("application ep_id did not match Terraform state")
		}
		endpoint, err := api.GetApplicationEndpoint(context.Background(), stateEPID)
		if err != nil {
			return fmt.Errorf("read certificate-mode application endpoint: %w", err)
		}
		got, err := certificateModeWireInteger(endpoint["cert_type"])
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("endpoint cert_type = %d, want %d", got, want)
		}
		*epID = stateEPID
		return nil
	}
}

func certificateModeWireInteger(value any) (int64, error) {
	switch value := value.(type) {
	case float64:
		if value != float64(int64(value)) {
			return 0, fmt.Errorf("endpoint returned non-integral cert_type %v", value)
		}
		return int64(value), nil
	case int:
		return int64(value), nil
	case int64:
		return value, nil
	case json.Number:
		parsed, err := value.Int64()
		if err != nil {
			return 0, fmt.Errorf("endpoint returned invalid cert_type %q", value)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("endpoint returned non-numeric cert_type %T", value)
	}
}
