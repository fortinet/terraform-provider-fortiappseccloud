---
page_title: "fortiappseccloud_waf_template_ip_protection Resource - fortiappseccloud"
subcategory: "WAF"
description: |-
  Configures IP protection for a FortiAppSec Cloud WAF template.
---

# fortiappseccloud_waf_template_ip_protection

Configures IP reputation, geographic policy, and ordered IP rules for one WAF template. Applications inherit these settings only when their matching app module resource uses `template = true` and omits `configs`.

Declare only one `fortiappseccloud_waf_template_ip_protection` resource for a WAF template. The provider normalizes unused `ip: null` slots returned by the API.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template_ip_protection" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    status        = true
    ip_reputation = false

    ip_list {
      item {
        type = "trust-ip"
        ip   = "1.1.1.1"
      }
    }
  }
}
```

This example avoids account-specific FortiGuard reputation and geographic settings. Add those fields only when you intend the template to own that policy.

## Argument Reference

- `template_id` (Required, Forces replacement) — WAF template ID.
- `configs` (Required) — Typed IP protection configuration. Its attributes and ownership-wrapper blocks are identical to `fortiappseccloud_waf_ip_protection` when that app resource uses `template = false`.

## Import

```shell
terraform import fortiappseccloud_waf_template_ip_protection.example TEMPLATE_ID
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets `template=false` and `configs.status=false`, sends the complete PUT, and verifies the normalized GET response before Terraform removes the resource from state.
