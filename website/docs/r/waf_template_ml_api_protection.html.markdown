---
page_title: "fortiappseccloud_waf_template_ml_api_protection Resource - fortiappseccloud"
subcategory: "WAF"
description: |-
  Configures ML API protection for a FortiAppSec Cloud WAF template.
---

# fortiappseccloud_waf_template_ml_api_protection

Configures ML API protection for one WAF template. Applications inherit these settings only when their matching app module resource uses `template = true` and omits `configs`.

Declare only one `fortiappseccloud_waf_template_ml_api_protection` resource for a WAF template.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template_ml_api_protection" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    status        = true
    threat_action = "alert"
    ip_list_type  = "Block"

    ip_list {
      item {
        ip = "192.0.2.13"
      }
    }
    path_list {
      item {
        type    = "plain"
        pattern = "/api/v1"
      }
    }
  }
}
```

## Argument Reference

- `template_id` (Required, Forces replacement) — WAF template ID.
- `configs` (Required) — Typed ML API protection configuration. Its attributes and ownership-wrapper blocks are identical to `fortiappseccloud_waf_ml_api_protection` when that app resource uses `template = false`.

## Import

```shell
terraform import fortiappseccloud_waf_template_ml_api_protection.example TEMPLATE_ID
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets `template=false` and `configs.status=false`, sends the complete PUT, and verifies the normalized GET response before Terraform removes the resource from state.
