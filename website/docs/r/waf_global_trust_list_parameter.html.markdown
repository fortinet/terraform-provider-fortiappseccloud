---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_global_trust_list_parameter Resource - fortiappseccloud"
description: |-
  Configures the global trust-list parameter for a FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_global_trust_list_parameter

Configures the global trust-list parameter for one WAF application. This API has a `configs` envelope but no `template` field, so this resource always manages direct application settings.

## Example Usage

```hcl
resource "fortiappseccloud_waf_global_trust_list_parameter" "example" {
  ep_id = fortiappseccloud_waf_app.example.ep_id

  configs {
    status = true

    trust_list {
      item {
        name   = "trusted-login"
        status = true
        url    = "/login"
      }
    }
  }
}
```

## Argument Reference

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `configs` - (Required) Global trust-list configuration.

The `configs` block supports:

* `status` - (Required) Whether the module is enabled.
* `trust_list` - (Optional) Complete ordered-list ownership wrapper. Omit it to preserve the remote array, use an empty block to send `[]`, or configure `item` blocks to replace the array. Maximum 30 items.

Each `trust_list.item` supports:

* `name` - (Required) Entry name. Maximum 63 UTF-8 characters.
* `status` - (Optional, Computed) Whether the entry is enabled.
* `url` - (Optional) Entry URL. Maximum 255 UTF-8 characters.

Wire-only indices are generated one-based and are not stored in Terraform state.

## Import

```shell
terraform import fortiappseccloud_waf_global_trust_list_parameter.example 3206359425
```

## Destroy Behavior

The API exposes no compatible delete or disable operation. Destroy forgets the resource with a warning and does not change the remote module.
This resource has no standard app-module `template` field, so it is not
eligible for the `template=false` plus `configs.status=false`
disable-on-destroy lifecycle.
