package acceptance

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"terraform-provider-fortiappseccloud/internal/client"
)

const (
	devEndpointFieldsHostname = "https://api.dev1.fortiappsec.com"
	devEndpointFieldsGate     = "endpoint_fields_v1"
)

// TestAccDevApplicationEndpointFieldsLifecycle creates one uniquely named
// disposable dev application through Terraform and drives the endpoint
// attributes added in 2.1.0 (http2_status, ipv6_option, cert_challenge_mode,
// block_url, and the ssl_options block) through create, update, and no-op
// steps, verifying the independent endpoint GET response after every step so
// every value is proven to pass the real API.
func TestAccDevApplicationEndpointFieldsLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_HOSTNAME", devEndpointFieldsHostname)
	skipUnlessExactEnvironment(
		t,
		"FORTIAPPSECCLOUD_ACC_DEV_ENDPOINT_FIELDS_WRITE",
		devEndpointFieldsGate,
	)
	requireEnvironment(t, "FORTIAPPSECCLOUD_API_TOKEN")

	api := liveClient(t)
	platform, region := selectCertificateModePlacement(t, api)
	suffix := matrixRandomSuffix(t)
	appName := "tf-endpoint-fields-" + suffix
	domain := "tf-epf-" + suffix + ".example.com"
	origin := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	refuseExistingApplicationName(t, ctx, api, appName)
	registerDisposableApplicationCleanup(t, api, appName)

	// Step values: create with http2 + dns challenge + intermediate level +
	// HSTS on; then update to a different challenge mode, level, and HSTS
	// settings; then re-apply the same configuration to prove a clean no-op.
	configuration := func(challenge, level string, hstsHeader bool, hstsMaxAge int64) string {
		hsts := ""
		if hstsHeader {
			hsts = fmt.Sprintf("hsts_header = true\n    hsts_max_age = %d\n    hsts_preload = false\n    hsts_sub_domains = false", hstsMaxAge)
		} else {
			hsts = "hsts_header = false"
		}
		return fmt.Sprintf(`
resource "fortiappseccloud_waf_app" "test" {
  app_name            = %q
  domain_name         = %q
  extra_domains       = []
  services            = ["http", "https"]
  http_port           = 80
  https_port          = 443
  platform            = %q
  region              = %q
  cdn                 = false
  block_mode          = false
  certificate_mode    = "automatic"
  cert_challenge_mode = %q
  http2_status        = true
  block_url           = "PredefinedMsg"

  ssl_options {
    encryption_level        = %q
    http_2_https            = false
    %s
    internal_cookie_secure = true
    internal_cookie_httponly = true
  }

  initial_origin {
    address  = %q
    protocol = "https"
    port     = 443
  }
}
`, appName, domain, platform, region, challenge, level, hsts, origin)
	}

	resourceName := "fortiappseccloud_waf_app.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: configuration("dns", "mozilla_intermediate", true, 31536000),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cert_challenge_mode", "dns"),
					resource.TestCheckResourceAttr(resourceName, "http2_status", "true"),
					resource.TestCheckResourceAttr(resourceName, "block_url", "PredefinedMsg"),
					resource.TestCheckResourceAttr(resourceName, "ssl_options.encryption_level", "mozilla_intermediate"),
					resource.TestCheckResourceAttr(resourceName, "ssl_options.hsts_max_age", "31536000"),
					resource.TestCheckResourceAttr(resourceName, "ssl_options.internal_cookie_secure", "true"),
					endpointFieldsRemoteCheck(api, appName, map[string]any{
						"cert_challenge_mode":        float64(2),
						"http2_status":               float64(1),
						"block_url":                  "PredefinedMsg",
						"ssl.encryption_level":       "mozilla_intermediate",
						"ssl.hsts_max_age":           float64(31536000),
						"ssl.internal_cookie_secure": float64(1),
					}),
				),
			},
			{
				Config: configuration("http", "mozilla_old", true, 3600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "cert_challenge_mode", "http"),
					resource.TestCheckResourceAttr(resourceName, "ssl_options.encryption_level", "mozilla_old"),
					resource.TestCheckResourceAttr(resourceName, "ssl_options.hsts_max_age", "3600"),
					endpointFieldsRemoteCheck(api, appName, map[string]any{
						"cert_challenge_mode":  float64(1),
						"ssl.encryption_level": "mozilla_old",
						"ssl.hsts_max_age":     float64(3600),
						// HTTP/2 disables TLS 1.1 even with mozilla_old.
						"ssl.tls_1_1": float64(0),
						"ssl.tls_1_2": float64(1),
						"ssl.tls_1_3": float64(1),
					}),
				),
			},
			{
				Config:   configuration("http", "mozilla_old", true, 3600),
				PlanOnly: true,
			},
		},
	})
}

// endpointFieldsRemoteCheck reads the independent GET endpoint document and
// asserts the exact remote values, proving each configured field passed the
// API and was stored. Keys use "ssl." prefixed names for ssl_options members.
func endpointFieldsRemoteCheck(api *client.Client, appName string, want map[string]any) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		if state == nil || state.RootModule() == nil {
			return fmt.Errorf("Terraform state omitted the root module")
		}
		resources := state.RootModule().Resources
		rs, ok := resources["fortiappseccloud_waf_app.test"]
		if !ok {
			return fmt.Errorf("state missing the application resource")
		}
		epID := rs.Primary.Attributes["ep_id"]
		if epID == "" {
			return fmt.Errorf("state missing ep_id")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		document, err := api.GetApplicationEndpoint(ctx, epID)
		if err != nil {
			return fmt.Errorf("read application endpoint: %w", err)
		}
		for key, wantValue := range want {
			var got any
			if len(key) > 4 && key[:4] == "ssl." {
				options, ok := document["ssl_options"].(map[string]any)
				if !ok {
					return fmt.Errorf("remote endpoint has no ssl_options document")
				}
				got = options[key[4:]]
			} else {
				got = document[key]
			}
			if !jsonEqual(got, wantValue) {
				return fmt.Errorf("remote endpoint %s = %v (%T), want %v (%T)", key, got, got, wantValue, wantValue)
			}
		}
		return nil
	}
}

// jsonEqual compares decoded JSON values with numeric tolerance for the
// float64/int64 distinction in decoded endpoint documents.
func jsonEqual(got, want any) bool {
	switch want := want.(type) {
	case float64:
		gotNumber, ok := toFloat(got)
		return ok && gotNumber == want
	case int64:
		gotNumber, ok := toFloat(got)
		return ok && int64(gotNumber) == want
	case string:
		gotString, ok := got.(string)
		return ok && gotString == want
	case bool:
		gotBool, ok := got.(bool)
		return ok && gotBool == want
	}
	return false
}

func toFloat(value any) (float64, bool) {
	switch value := value.(type) {
	case float64:
		return value, true
	case int64:
		return float64(value), true
	case int:
		return float64(value), true
	}
	return 0, false
}
