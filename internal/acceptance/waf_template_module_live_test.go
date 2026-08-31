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

const templateKnownAttacksGateVersion = "template_known_attacks_v1"

var templateKnownAttacksEndpoint = client.WAFTemplateModuleEndpoint{
	Path:      "/waf/template/{template_id}/known_attacks",
	Operation: "known attacks",
}

func TestAccTemplateKnownAttacksLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_HOSTNAME", templateCRUDDevHostname)
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_TEMPLATE", "yes")

	templateName := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_TEMPLATE_NAME")
	skipUnlessExactEnvironment(
		t,
		"FORTIAPPSECCLOUD_ACC_TEMPLATE_MODULE_WRITE",
		templateKnownAttacksGateVersion+":"+templateName,
	)
	requireEnvironment(t, "FORTIAPPSECCLOUD_API_TOKEN")

	api := liveClient(t)
	preflightCtx, preflightCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	refuseExistingTemplateName(t, preflightCtx, api, templateName)
	preflightCancel()

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cleanupCancel()
		cleanupTemplatesByExactName(t, cleanupCtx, api, templateName)
	})

	initialConfig := templateKnownAttacksConfig(templateName, "alert_deny", true)
	updatedConfig := templateKnownAttacksConfig(templateName, "deny_no_log", false)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providerFactories(),
		CheckDestroy:             checkTemplateAbsent(api, templateName),
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("fortiappseccloud_waf_template.test", "name", templateName),
					resource.TestCheckResourceAttrSet("fortiappseccloud_waf_template.test", "template_id"),
					resource.TestCheckResourceAttr("fortiappseccloud_waf_template_known_attacks.test", "configs.action", "alert_deny"),
					resource.TestCheckResourceAttr("fortiappseccloud_waf_template_known_attacks.test", "configs.status", "true"),
					checkTemplateKnownAttacksRemote(api, templateName, "alert_deny", true),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("fortiappseccloud_waf_template_known_attacks.test", "configs.action", "deny_no_log"),
					resource.TestCheckResourceAttr("fortiappseccloud_waf_template_known_attacks.test", "configs.status", "false"),
					checkTemplateKnownAttacksRemote(api, templateName, "deny_no_log", false),
				),
			},
			{
				Config:   updatedConfig,
				PlanOnly: true,
			},
			{
				ResourceName:                         "fortiappseccloud_waf_template.test",
				ImportState:                          true,
				ImportStateIdFunc:                    templateImportID("fortiappseccloud_waf_template.test"),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "template_id",
				ImportStateVerifyIgnore:              []string{"features"},
			},
			{
				ResourceName:                         "fortiappseccloud_waf_template_known_attacks.test",
				ImportState:                          true,
				ImportStateIdFunc:                    templateImportID("fortiappseccloud_waf_template.test"),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "template_id",
				ImportStateVerifyIgnore: []string{
					"configs.sig_except_rules",
					"configs.stx_except_rules",
				},
			},
		},
	})
}

func templateKnownAttacksConfig(templateName, action string, status bool) string {
	return fmt.Sprintf(`
resource "fortiappseccloud_waf_template" "test" {
  name = %q
}

resource "fortiappseccloud_waf_template_known_attacks" "test" {
  template_id = fortiappseccloud_waf_template.test.template_id

  configs {
    action = %q
    status = %t
  }
}
`, templateName, action, status)
}

func checkTemplateKnownAttacksRemote(api *client.Client, templateName, action string, status bool) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		template, err := findTemplateByExactName(ctx, api, templateName)
		if err != nil {
			return err
		}
		document, err := api.GetWAFTemplateModule(ctx, templateKnownAttacksEndpoint, template.TemplateID)
		if err != nil {
			return fmt.Errorf("read live known attacks template configuration: %w", err)
		}
		if document.Result.Template {
			return fmt.Errorf("live known attacks template response reported template=true")
		}
		if got := rawString(document.Result.Configs["action"]); got != action {
			return fmt.Errorf("live known attacks action = %q, want %q", got, action)
		}
		if got := rawBool(document.Result.Configs["status"]); got != status {
			return fmt.Errorf("live known attacks status = %t, want %t", got, status)
		}
		return nil
	}
}

func checkTemplateAbsent(api *client.Client, templateName string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return waitForTemplateAbsence(ctx, api, templateName)
	}
}

func templateImportID(resourceName string) resource.ImportStateIdFunc {
	return func(state *terraform.State) (string, error) {
		return stateResourceAttribute(state, resourceName, "template_id")
	}
}

func findTemplateByExactName(ctx context.Context, api *client.Client, templateName string) (client.Template, error) {
	templates, err := api.ListTemplates(ctx)
	if err != nil {
		return client.Template{}, fmt.Errorf("list templates: %w", err)
	}
	var match client.Template
	count := 0
	for _, template := range templates.Templates {
		if template.Name == templateName {
			match = template
			count++
		}
	}
	if count != 1 {
		return client.Template{}, fmt.Errorf("template name %q resolved to %d templates, want 1", templateName, count)
	}
	return match, nil
}
