---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_modules Data Source - fortiappseccloud"
description: |-
  Reads the WAF module status inventory for a FortiAppSec Cloud application.
---

# fortiappseccloud_waf_modules

Reads the complete app-level WAF module status inventory. This data source is read-only and never changes remote state: it does not enable, disable, or otherwise configure a module.

The bulk `PUT /waf/apps/{ep_id}/modules` operation is intentionally not exposed because it would overlap with the individual resources that own each module's complete configuration.

## Example Usage

```hcl
data "fortiappseccloud_waf_modules" "example" {
  ep_id = fortiappseccloud_waf_app.app_example.ep_id
}

output "waf_module_statuses" {
  value = data.fortiappseccloud_waf_modules.example.modules
}
```

## Argument Reference

* `ep_id` - (Required) Application endpoint ID whose module statuses are read.

## Attribute Reference

* `modules` - Module status objects sorted by `id`.

Each `modules` object contains:

* `id` - Module identifier from the reviewed public `ApplicationModuleStatus` enum.
* `status` - `enable` or `disable`.
* `inherited` - `enable` or `disable` when the API returns the optional field; otherwise `null`.

The provider rejects malformed entries, unknown module identifiers, duplicate identifiers, unsupported status values, and response fields outside the pinned public schema instead of publishing ambiguous state.
