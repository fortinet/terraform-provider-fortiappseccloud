package fortiappseccloud

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fortiappseccloud/fortiappseccloud/waf"
	"terraform-provider-fortiappseccloud/internal/providerconfig"
)

func TestLegacyProviderSchemaResourcesAndConfigure(t *testing.T) {
	for _, name := range []string{
		providerconfig.EnvHostname,
		providerconfig.EnvAPIToken,
		providerconfig.EnvUsername,
		providerconfig.EnvPassword,
		"FORTIWEB_CLOUD_SESSION",
		"FORTIWEB_CLOUD_SESSION_TIMESTAMP",
	} {
		t.Setenv(name, "")
	}

	configured := Provider()
	if err := configured.InternalValidate(); err != nil {
		t.Fatalf("legacy Provider().InternalValidate() error = %v", err)
	}
	if len(configured.Schema) != 4 {
		t.Fatalf("legacy provider attributes = %d, want 4", len(configured.Schema))
	}
	for _, name := range []string{"hostname", "api_token", "username", "password"} {
		attribute, ok := configured.Schema[name]
		if !ok || !attribute.Optional {
			t.Fatalf("legacy provider attribute %q is missing or not optional", name)
		}
	}
	for _, name := range []string{"api_token", "password"} {
		if !configured.Schema[name].Sensitive {
			t.Errorf("legacy provider attribute %q is not sensitive", name)
		}
	}
	wantResources := []string{
		"fortiappseccloud_waf_app",
		"fortiappseccloud_waf_openapi_validation",
	}
	if len(configured.ResourcesMap) != len(wantResources) {
		t.Fatalf("legacy resources = %d, want %d", len(configured.ResourcesMap), len(wantResources))
	}
	for _, name := range wantResources {
		if configured.ResourcesMap[name] == nil {
			t.Errorf("legacy provider is missing resource %q", name)
		}
	}

	data := schema.TestResourceDataRaw(t, configured.Schema, map[string]interface{}{
		"hostname":  "https://legacy.example.test",
		"api_token": "unit-token",
	})
	providerData, diagnostics := providerConfigure(context.Background(), data)
	if diagnostics.HasError() {
		t.Fatalf("legacy providerConfigure() diagnostics = %v", diagnostics)
	}
	legacy, ok := providerData.(*waf.WAFClient)
	if !ok || legacy.CloudClient == nil {
		t.Fatalf("legacy provider data = %T, want configured *waf.WAFClient", providerData)
	}
	if legacy.CloudClient.Host != "https://legacy.example.test" || legacy.CloudClient.Token != "Basic unit-token" || !legacy.CloudClient.Init {
		t.Fatalf("legacy cloud client = %#v", legacy.CloudClient)
	}
}

func TestLegacyProviderConfigureRejectsInvalidAuthentication(t *testing.T) {
	for _, name := range []string{
		providerconfig.EnvHostname,
		providerconfig.EnvAPIToken,
		providerconfig.EnvUsername,
		providerconfig.EnvPassword,
	} {
		t.Setenv(name, "")
	}
	configured := Provider()
	data := schema.TestResourceDataRaw(t, configured.Schema, map[string]interface{}{
		"api_token": "secret-token",
		"username":  "user",
		"password":  "secret-password",
	})
	_, diagnostics := providerConfigure(context.Background(), data)
	if !diagnostics.HasError() {
		t.Fatal("legacy providerConfigure() accepted conflicting authentication modes")
	}
	for _, diagnostic := range diagnostics {
		for _, secret := range []string{"secret-token", "secret-password"} {
			if strings.Contains(diagnostic.Summary, secret) || strings.Contains(diagnostic.Detail, secret) {
				t.Fatalf("legacy provider diagnostic leaked %q", secret)
			}
		}
	}
}
