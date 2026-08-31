package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicDocumentationCodeFencesDeclareLanguages(t *testing.T) {
	t.Parallel()

	err := filepath.WalkDir(filepath.Join("website", "docs"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".markdown") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		insideFence := false
		scanner := bufio.NewScanner(file)
		for line := 1; scanner.Scan(); line++ {
			text := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(text, "```") {
				continue
			}
			if insideFence {
				if text != "```" {
					t.Errorf("%s:%d closing code fence must not include text", path, line)
				}
				insideFence = false
				continue
			}
			if text != "```hcl" && text != "```shell" && text != "```json" {
				t.Errorf("%s:%d code fence must declare hcl, shell, or json", path, line)
			}
			insideFence = true
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		if insideFence {
			t.Errorf("%s has an unclosed code fence", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicDocumentationUsesRegistryFrontmatter(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob(filepath.Join("website", "docs", "**", "*.markdown"))
	if err != nil {
		t.Fatal(err)
	}
	rootPages, err := filepath.Glob(filepath.Join("website", "docs", "*.markdown"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, rootPages...)
	if len(paths) != 75 {
		t.Fatalf("public documentation pages = %d, want 75", len(paths))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, legacyKey := range []string{"layout", "sidebar_current"} {
			if strings.Contains(string(raw), "\n"+legacyKey+":") {
				t.Errorf("%s contains unsupported Terraform Registry %s frontmatter", path, legacyKey)
			}
		}
	}

	for name, title := range map[string]string{
		"waf_modules":             "fortiappseccloud_waf_modules Data Source - fortiappseccloud",
		"waf_signature_exception": "fortiappseccloud_waf_signature_exception Data Source - fortiappseccloud",
	} {
		path := filepath.Join("website", "docs", "d", name+".html.markdown")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `page_title: "`+title+`"`) {
			t.Errorf("%s does not use the standard data-source page title %q", path, title)
		}
	}
}

func TestV105MigrationGuideCoversVerifiedPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join("website", "docs", "guides", "v1_0_5_to_v2_0_0.html.markdown")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	guide := string(raw)
	for _, required := range []string{
		`version = "= 2.0.0"`,
		`app_service = {`,
		`services    = ["http", "https"]`,
		`initial_origin {`,
		`block_mode`,
		`ep_id  = fortiappseccloud_waf_app.example.ep_id`,
		`terraform plan -refresh-only -out=v2-refresh.tfplan`,
		`terraform plan -detailed-exitcode`,
		`fortiappseccloud_waf_template_attachment`,
		`fortiappseccloud_waf_origin_servers`,
		`fortiappseccloud_waf_app.example.cnames`,
		"initializes `http_port` and `https_port` in upgraded state to `80` and `443`",
		"it does not copy custom port values from the legacy map",
		`## Rollback`,
	} {
		if !strings.Contains(guide, required) {
			t.Errorf("migration guide is missing %q", required)
		}
	}
	for _, internal := range []string{"api.dev1", "code.claude.com", "test-app", "4.30 seconds", "captured-state gate"} {
		if strings.Contains(guide, internal) {
			t.Errorf("public migration guide contains internal fixture detail %q", internal)
		}
	}
}

func TestPrivateProviderMigrationGuideIsSequentialAndVersionAccurate(t *testing.T) {
	t.Parallel()

	path := filepath.Join("website", "docs", "guides", "fortiwebcloud_migration.html.markdown")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	guide := string(raw)
	headings := []string{
		"## 1. Verify the Existing Terraform State and Provider Configuration",
		"## 2. Modify the Provider and Resources",
		"## 3. Modify the Provider Information in the State File",
		"## 4. Test and Validate",
		"## 5. Apply Changes",
	}
	previousHeading := -1
	for _, heading := range headings {
		position := strings.Index(guide, heading)
		if position < 0 {
			t.Errorf("private-provider migration guide is missing %q", heading)
			continue
		}
		if position <= previousHeading {
			t.Errorf("private-provider migration heading %q is out of order", heading)
		}
		previousHeading = position
	}
	for _, required := range []string{
		"### 2.2 Replace the Provider Block and Hostname",
		`value = fortiappseccloud_waf_app.app_example.ep_id`,
		`value = fortiappseccloud_waf_app.app_example.cname`,
		"Public provider v1.0.5 still exposes `cname` as a computed string.",
		`"type": "fortiappseccloud_waf_app"`,
		"It is not an actual list in v1.0.5 state.",
		"the v2 provider state upgrader converts it to the real `cnames` list",
		"## 4. Test and Validate\n\n",
		"## 5. Apply Changes\n\n",
	} {
		if !strings.Contains(guide, required) {
			t.Errorf("private-provider migration guide is missing %q", required)
		}
	}
	for _, stale := range []string{
		"## 5. Test and Validate",
		"### 6. Apply Changes",
		"Replace your host to fortiappseccloud",
		"`fortiwebcloud_openapi_validation `",
		"value = fortiwebcloud_app.app_example.ep_id",
		"value = fortiwebcloud_app.app_example.cname",
		"jsonformatter.testdomain",
	} {
		if strings.Contains(guide, stale) {
			t.Errorf("private-provider migration guide retains stale content %q", stale)
		}
	}
}

func TestWAFConfigurationGuidanceCoversScopeAndImportSafety(t *testing.T) {
	t.Parallel()

	path := filepath.Join("website", "docs", "guides", "waf_configuration_guidance.html.markdown")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	guide := string(raw)
	for _, required := range []string{
		"does not manage the WAF log settings module",
		"does not upload certificate material",
		`certificate_mode = "automatic" # Or "custom".`,
		"It does not upload a CA certificate to a WAF application.",
		"## Strongly Recommended: Manage Origin Servers Explicitly",
		"fortiappseccloud_waf_origin_servers",
		"exists only to bootstrap application creation",
		"is replacement-only and is not the standard resource for ongoing origin configuration",
		"owns the complete remote pool",
		`resource "fortiappseccloud_waf_origin_servers" "example"`,
		`encryption_level = "mozilla_intermediate"`,
		"fortiappseccloud_waf_known_attacks",
		"fortiappseccloud_waf_request_limits",
		"fortiappseccloud_waf_ddos_prevention",
		"fortiappseccloud_waf_known_bots",
		"fortiappseccloud_waf_ip_protection",
		"imports only the application resource",
		"are not disabled merely because the application was imported",
		"keep each specific module resource declared in HCL",
		"Removing its HCL block after import therefore plans a Terraform destroy that disables that live module",
		"All 31 typed template-module resources also use disable-on-destroy.",
		"caching/compression additionally sets `configs.cache.status = false` and `configs.compress.status = false`",
		"terraform state rm fortiappseccloud_waf_known_attacks.baseline",
	} {
		if !strings.Contains(guide, required) {
			t.Errorf("WAF configuration guidance is missing %q", required)
		}
	}
	for _, internal := range []string{"api.dev1", "live-verified", "2026-", "captured-state gate"} {
		if strings.Contains(guide, internal) {
			t.Errorf("public WAF configuration guidance contains internal detail %q", internal)
		}
	}
}

func TestWAFResourceDocumentationHasCompleteExamples(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob(filepath.Join("website", "docs", "r", "waf_*.html.markdown"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 69 {
		t.Fatalf("WAF resource documentation pages = %d, want 69", len(paths))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		resourceType := "fortiappseccloud_" + strings.TrimSuffix(filepath.Base(path), ".html.markdown")
		document := string(raw)
		for _, required := range []string{
			`page_title: "` + resourceType + ` Resource - fortiappseccloud"`,
			`subcategory: "WAF"`,
			"## Argument Reference",
			"## Import",
			"## Destroy Behavior",
		} {
			if !strings.Contains(document, required) {
				t.Errorf("%s is missing standardized resource documentation %q", path, required)
			}
		}
		if strings.Contains(document, "- `configs` (Required)") &&
			!strings.Contains(document, "Its attributes and ownership-wrapper blocks are identical to") {
			t.Errorf("%s does not use the standardized template-module configs cross-reference", path)
		}
		block := hclGuideBlockContaining(t, document, `resource "`+resourceType+`" "example"`)
		if strings.Contains(block, "fortiappseccloud_waf_app.app_example") {
			t.Errorf("%s uses the examples/waf-only app_example address", path)
		}
	}

	for path, required := range map[string][]string{
		"waf_content_routing.html.markdown":      {`server_pool = "default_pool"`, "rule_list {}", "must exactly match an existing origin-pool name"},
		"waf_custom_rule.html.markdown":          {`challenge = "real-browser-enforcement"`, `ip            = "1.1.1.1-1.1.1.255"`},
		"waf_ip_protection.html.markdown":        {"ip_reputation = false", `type = "trust-ip"`},
		"waf_openapi_validation.html.markdown":   {`${path.module}/openapi.yaml`, "must remain readable"},
		"waf_origin_servers.html.markdown":       {"### `server_pools.health`", "### `server_pools.persistence`", "### `server_pools.servers`", "### `server_pools.servers.connection_filters`", "Required when `ssl = true`", "No unconditional Terraform default is applied"},
		"waf_template_custom_rule.html.markdown": {`challenge = "real-browser-enforcement"`},
	} {
		raw, err := os.ReadFile(filepath.Join("website", "docs", "r", path))
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range required {
			if !strings.Contains(string(raw), fragment) {
				t.Errorf("%s is missing working example or explanation %q", path, fragment)
			}
		}
	}
}

func TestTerraformCLIWAFConfigurationGuidanceBaseline(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to validate the public guide configuration with Terraform CLI")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}

	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	guidePath := filepath.Join("website", "docs", "guides", "waf_configuration_guidance.html.markdown")
	raw, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatal(err)
	}
	baseline := hclGuideBlockContaining(t, string(raw), `variable "app_ep_id"`)
	originExample := hclGuideBlockContaining(t, string(raw), `resource "fortiappseccloud_waf_origin_servers" "example"`)
	originExample = strings.Replace(originExample, "fortiappseccloud_waf_app.example.ep_id", `"documentation-validation-id"`, 1)

	temporaryRoot := t.TempDir()
	workDir := filepath.Join(temporaryRoot, "recommended-baseline")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf(`terraform {
  required_providers {
    fortiappseccloud = {
      source = "fortinet/fortiappseccloud"
    }
  }
}

provider "fortiappseccloud" {
  hostname  = "https://api.example.com"
  api_token = "dummy-documentation-validation-token"
}

%s
%s`, originExample, baseline)
	if err := os.WriteFile(filepath.Join(workDir, "main.tf"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}

	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)
	result := cli.run(t, workDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false", "-var=app_ep_id=documentation-validation-id")
	if result.ExitCode != 2 {
		t.Fatalf("recommended baseline plan exit code = %d, want 2 for six valid resource creates\n%s", result.ExitCode, result.output())
	}
}

func TestTerraformCLIWAFResourceDocumentationExamples(t *testing.T) {
	if os.Getenv("TF_CLI_TEST") != "1" {
		t.Skip("set TF_CLI_TEST=1 to validate all WAF resource documentation examples with Terraform CLI")
	}
	terraformPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform CLI is not available")
	}
	repositoryRoot, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join("website", "docs", "r", "waf_*.html.markdown"))
	if err != nil {
		t.Fatal(err)
	}

	var examples strings.Builder
	mobileSecretVariableIncluded := false
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		resourceType := "fortiappseccloud_" + strings.TrimSuffix(filepath.Base(path), ".html.markdown")
		block := hclGuideBlockContaining(t, string(raw), `resource "`+resourceType+`" "example"`)
		if variableAt := strings.Index(block, `variable "mobile_api_token_secret"`); variableAt >= 0 {
			if mobileSecretVariableIncluded {
				block = block[:variableAt]
			} else {
				mobileSecretVariableIncluded = true
			}
		}
		examples.WriteString(block)
		examples.WriteByte('\n')
	}

	temporaryRoot := t.TempDir()
	workDir := filepath.Join(temporaryRoot, "waf-resource-documentation")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf(`terraform {
  required_providers {
    fortiappseccloud = {
      source = "fortinet/fortiappseccloud"
    }
  }
}

provider "fortiappseccloud" {
  hostname  = "https://api.example.com"
  api_token = "dummy-documentation-validation-token"
}

%s`, examples.String())
	if err := os.WriteFile(filepath.Join(workDir, "main.tf"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	openAPI := []byte("openapi: 3.0.0\ninfo:\n  title: Documentation validation\n  version: 1.0.0\npaths: {}\n")
	if err := os.WriteFile(filepath.Join(workDir, "openapi.yaml"), openAPI, 0o600); err != nil {
		t.Fatal(err)
	}

	cli := buildTerraformCLIProvider(t, terraformPath, repositoryRoot, temporaryRoot)
	result := cli.run(t, workDir, "plan", "-detailed-exitcode", "-refresh=false", "-input=false", "-no-color", "-lock=false", "-var=mobile_api_token_secret=documentation-validation-secret")
	if result.ExitCode != 2 || !strings.Contains(result.output(), "Plan: 69 to add, 0 to change, 0 to destroy.") {
		t.Fatalf("documentation example plan did not validate all 69 WAF resources (exit code %d)\n%s", result.ExitCode, result.output())
	}
}

func hclGuideBlockContaining(t *testing.T, document, marker string) string {
	t.Helper()
	lines := strings.Split(document, "\n")
	inside := false
	var block strings.Builder
	for _, line := range lines {
		switch strings.TrimSpace(line) {
		case "```hcl":
			inside = true
			block.Reset()
			continue
		case "```":
			if inside && strings.Contains(block.String(), marker) {
				return block.String()
			}
			inside = false
			continue
		}
		if inside {
			block.WriteString(line)
			block.WriteByte('\n')
		}
	}
	t.Fatalf("HCL guide block containing %q was not found", marker)
	return ""
}
