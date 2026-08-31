package generator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	profile "terraform-provider-fortiappseccloud/internal/generator/profile/waf"
)

func TestReviewedDocsExamplesMatchFixtures(t *testing.T) {
	t.Parallel()

	overrides, err := profile.DecodeOverrides(profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviewedDocsExamples) != len(overrides.Resources) {
		t.Fatalf("reviewed documentation examples = %d, want %d", len(reviewedDocsExamples), len(overrides.Resources))
	}
	for _, resource := range overrides.Resources {
		resource := resource
		t.Run(resource.TerraformName, func(t *testing.T) {
			t.Parallel()
			module := strings.TrimPrefix(resource.TypeNameSuffix, "waf_")
			path := filepath.Join("..", "..", "examples", "waf", module+".tf")
			fixture, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := reviewedDocsExamples[resource.TerraformName]
			if !ok {
				t.Fatalf("reviewed documentation example is missing; run go generate ./internal/generator")
			}
			if strings.TrimSpace(got) != strings.TrimSpace(string(fixture)) {
				t.Fatalf("reviewed documentation example differs from %s; run go generate ./internal/generator", path)
			}
		})
	}
}

func TestGeneratedDocsUseReviewedExamples(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := Generate(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	overrides, err := profile.DecodeOverrides(profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range overrides.Resources {
		module := strings.TrimPrefix(resource.TypeNameSuffix, "waf_")
		appPath := "website/docs/r/" + resource.TypeNameSuffix + ".html.markdown"
		appPage := string(outputs[appPath])
		for _, required := range []string{
			`resource "` + resource.TerraformName + `" "example"`,
			`ep_id    = fortiappseccloud_waf_app.example.ep_id`,
			"Set `template = false` and provide `configs`",
		} {
			if !strings.Contains(appPage, required) {
				t.Errorf("%s is missing %q", appPath, required)
			}
		}
		if strings.Contains(appPage, `ep_id    = "application-endpoint-id"`) {
			t.Errorf("%s uses the schema-coverage placeholder instead of a reviewed example", appPath)
		}

		templatePath := "website/docs/r/waf_template_" + module + ".html.markdown"
		templatePage := string(outputs[templatePath])
		for _, required := range []string{
			`resource "fortiappseccloud_waf_template_` + module + `" "example"`,
			`template_id = fortiappseccloud_waf_template.example.template_id`,
			"matching app module resource with `template = true`",
		} {
			if !strings.Contains(templatePage, required) {
				t.Errorf("%s is missing %q", templatePath, required)
			}
		}
		if strings.Contains(templatePage, "fortiappseccloud_waf_app.") {
			t.Errorf("%s retains an app-resource reference", templatePath)
		}
	}

	for path, required := range map[string][]string{
		"website/docs/r/waf_api_gateway.html.markdown":           {"api_key_verify    = true", `field_name        = "X-API-Key"`},
		"website/docs/r/waf_caching_compression.html.markdown":   {"cache {", "compress {", "`cache.cache_timeout`", "    - `content_type_list` (Optional Block, at most 10 items)", "      - `content_type_list.item.type`", "    - `cookie_list` (Optional Block, at most 32 items)", "      - `cookie_list.item.name`", "    - `rule_list` (Optional Block, at most 32 items)", "      - `rule_list.item.bypass_arg`"},
		"website/docs/r/waf_file_protection.html.markdown":       {"json_file_support = false", `data_type        = "string"`},
		"website/docs/r/waf_http_header_security.html.markdown":  {`header_value                 = "default-src 'self'"`},
		"website/docs/r/waf_parameter_validation.html.markdown":  {"arg_val"},
		"website/docs/r/waf_threshold_detection.html.markdown":   {"request_url"},
		"website/docs/r/waf_xml_protection_policy.html.markdown": {"this resource does not upload schema files"},
		"website/docs/r/waf_mobile_api_protection.html.markdown": {`variable "mobile_api_token_secret"`, "Protect state storage"},
	} {
		page := string(outputs[path])
		for _, fragment := range required {
			if !strings.Contains(page, fragment) {
				t.Errorf("%s is missing reviewed example or guidance %q", path, fragment)
			}
		}
	}
	cachingDocs := string(outputs["website/docs/r/waf_caching_compression.html.markdown"])
	for _, ambiguousSibling := range []string{
		"    - `type` (Required",
		"    - `name` (Required",
		"    - `bypass_arg` (Optional",
	} {
		if strings.Contains(cachingDocs, ambiguousSibling) {
			t.Errorf("caching/compression argument hierarchy retains ambiguous sibling %q", ambiguousSibling)
		}
	}
}
