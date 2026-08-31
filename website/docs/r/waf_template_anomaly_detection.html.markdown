---
page_title: "fortiappseccloud_waf_template_anomaly_detection Resource - fortiappseccloud"
subcategory: "WAF"
description: |-
  Configures anomaly detection for a FortiAppSec Cloud WAF template.
---

# fortiappseccloud_waf_template_anomaly_detection

Configures anomaly detection for one WAF template. Applications inherit these settings only when their matching app module resource uses `template = true` and omits `configs`.

Declare only one `fortiappseccloud_waf_template_anomaly_detection` resource for a WAF template.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template_anomaly_detection" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    status       = true
    action       = "alert"
    ip_list_type = "Block"

    ip_list {
      item {
        ip = "192.0.2.10"
      }
    }
  }
}
```

## Argument Reference

- `template_id` (Required, Forces replacement) — WAF template ID.
- `configs` (Required) — Typed anomaly detection configuration. Its attributes and ownership-wrapper blocks are identical to `fortiappseccloud_waf_anomaly_detection` when that app resource uses `template = false`.

## Import

```shell
terraform import fortiappseccloud_waf_template_anomaly_detection.example TEMPLATE_ID
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets `template=false` and `configs.status=false`, sends the complete PUT, and verifies the normalized GET response before Terraform removes the resource from state.
