---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_anomaly_detection Resource - fortiappseccloud"
description: |-
  Configures anomaly detection directly or through template inheritance for a FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_anomaly_detection

Configures anomaly detection for one WAF application. Set `template = false` and provide `configs` to manage it directly. Set `template = true` and omit `configs` to inherit it from the application's attached WAF template.

## Example Usage

```hcl
resource "fortiappseccloud_waf_anomaly_detection" "example" {
  ep_id    = fortiappseccloud_waf_app.example.ep_id
  template = false

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

Declare only one `fortiappseccloud_waf_anomaly_detection` resource for an application endpoint. The IP-list wrapper owns the complete ordered list only when it is present.

## Argument Reference

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `template` - (Required) Whether configuration is inherited. `configs` is required when false and forbidden when true.
* `configs` - (Optional) Locally managed anomaly-detection configuration.

The `configs` block supports:

* `status` - (Required) Whether anomaly detection is enabled.
* `action` - (Required) `alert` or `alert_deny`.
* `ip_list_type` - (Required) `Trust` or `Block`.
* `ip_list` - (Optional) Complete ordered-list ownership wrapper, maximum 30 items. Omission preserves the remote array; an empty block sends `[]`.

Each `ip_list.item` requires `ip`. Wire-only indices are generated one-based and are not stored in state.

## Import

```shell
terraform import fortiappseccloud_waf_anomaly_detection.example 3206359425
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets only
`template=false` and `configs.status=false`, PUTs the result, verifies the
complete semantic result with another GET, and then removes the resource from
state.
