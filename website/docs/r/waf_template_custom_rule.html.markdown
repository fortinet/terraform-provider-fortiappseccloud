---
page_title: "fortiappseccloud_waf_template_custom_rule Resource - fortiappseccloud"
subcategory: "WAF"
description: |-
  Configures ordered custom WAF rules for a FortiAppSec Cloud WAF template.
---

# fortiappseccloud_waf_template_custom_rule

Configures ordered custom rules and filters for one WAF template. Applications inherit these settings only when their matching app module resource uses `template = true` and omits `configs`.

Declare only one `fortiappseccloud_waf_template_custom_rule` resource for a WAF template.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template_custom_rule" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    status = true

    rule_list {
      item {
        name      = "block-bad-ips"
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
```

Set `challenge` explicitly for every configured rule. FortiAppSec Cloud currently rejects an omitted challenge even though the API schema publishes a default.

## Argument Reference

- `template_id` (Required, Forces replacement) — WAF template ID.
- `configs` (Required) — Typed custom rule configuration. Its attributes and ownership-wrapper blocks are identical to `fortiappseccloud_waf_custom_rule` when that app resource uses `template = false`.

## Import

```shell
terraform import fortiappseccloud_waf_template_custom_rule.example TEMPLATE_ID
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets `template=false` and `configs.status=false`, sends the complete PUT, and verifies the normalized GET response before Terraform removes the resource from state.
