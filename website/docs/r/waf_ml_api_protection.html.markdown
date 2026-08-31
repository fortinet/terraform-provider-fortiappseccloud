---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_ml_api_protection Resource - fortiappseccloud"
description: |-
  Configures ML API protection directly or through template inheritance for a FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_ml_api_protection

Configures the durable `ml_api_protection` GET/PUT settings for one WAF application. Set `template = false` and provide `configs` to manage them directly, or set `template = true` and omit `configs` to inherit them. Model refresh/rebuild, download, schema, timeline, URL-report, and related imperative endpoints are outside this resource.

## Example Usage

```hcl
resource "fortiappseccloud_waf_ml_api_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.example.ep_id
  template = false

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

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `template` - (Required) Whether configuration is inherited.
* `configs` - (Optional) Required when `template` is false and forbidden when true.

The `configs` block supports:

* `status` - (Required) Whether ML API protection is enabled.
* `threat_action` - (Required) `alert`, `alert_deny`, or `disable`. `disable` is a threat action, not module-disable/destroy behavior.
* `ip_list_type` - (Required) `Trust` or `Block`.
* `ip_list` - (Optional) Complete ordered ownership wrapper, maximum 30 items. Each item requires `ip`.
* `path_list` - (Optional) Complete ordered ownership wrapper, maximum 30 items. Each item requires `type` (`plain` or `regular`) and `pattern`, which must start with `/`.

Omitted wrappers preserve remote arrays; empty wrappers send `[]`. Wire-only indices are regenerated and omitted from state.

## Import

```shell
terraform import fortiappseccloud_waf_ml_api_protection.example 3206359425
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets only
`template=false` and `configs.status=false`, PUTs the result, verifies the
complete semantic result with another GET, and then removes the resource from
state.
