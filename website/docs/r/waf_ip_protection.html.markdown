---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_ip_protection Resource - fortiappseccloud"
description: |-
  Configures IP protection directly or through template inheritance for a FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_ip_protection

Configures IP reputation, geographic policy, and ordered IP rules for one WAF application. Set `template = false` and provide `configs` to manage them directly, or set `template = true` and omit `configs` to inherit them.

## Example Usage

```hcl
resource "fortiappseccloud_waf_ip_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.example.ep_id
  template = false

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

This example keeps FortiGuard IP reputation disabled and manages one explicit trusted address, so it does not depend on an account-specific reputation or geographic policy. Add `geo_ip_mode` and `block_country_list` only when you intend to own that policy.

## Argument Reference

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `template` - (Required) Whether configuration is inherited.
* `configs` - (Optional) Required when `template` is false and forbidden when true.

The `configs` block supports:

* `status` - (Required) Whether IP protection is enabled.
* `ip_reputation` - (Required) Whether FortiGuard reputation is enforced.
* `geo_ip_mode` - (Optional, Computed) `block` or `allow`.
* `block_country_list` - (Optional, Computed) Supported country names.
* `ip_list` - (Optional) Complete ordered-list ownership wrapper, maximum 256 items.

Each configured `ip_list.item` requires a non-empty `ip` and optionally sets
`type` to `trust-ip`, `block-ip`, or `allow-only-ip`. Omission preserves the
remote list, while an empty wrapper sends `[]`. API responses can return fixed
entries for inactive rule types with `ip: null`; the provider strictly validates
and filters those GET-only placeholders. Terraform state and PUT requests
contain active rules only, and GET-only indices are omitted from both.

## Import

```shell
terraform import fortiappseccloud_waf_ip_protection.example 3206359425
```

## Destroy Behavior

Destroy performs a fresh GET, normalizes GET-only indices and
inactive null placeholders, preserves the complete writable response, sets
only `template=false` and `configs.status=false`, PUTs the result, verifies the
normalized semantic result with another GET, and then removes the resource
from state.
