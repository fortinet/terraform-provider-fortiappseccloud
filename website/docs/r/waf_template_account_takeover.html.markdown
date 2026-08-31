---
page_title: "fortiappseccloud_waf_template_account_takeover Resource - fortiappseccloud"
subcategory: "WAF"
description: |-
  Configures account takeover protection for a FortiAppSec Cloud WAF template.
---

# fortiappseccloud_waf_template_account_takeover

Configures account takeover protection for one WAF template. Applications inherit these settings only when their matching `fortiappseccloud_waf_account_takeover` resource uses `template = true` and omits `configs`.

Declare only one `fortiappseccloud_waf_template_account_takeover` resource for a WAF template.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template_account_takeover" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    status                = true
    action                = "alert_deny"
    auth_url              = "/login"
    cred_stuffing_protect = true
    sess_fixation_protect = true
    sess_id_name          = "session_id"
    username              = "username"
    password              = "password"
  }
}
```

## Argument Reference

- `template_id` (Required, Forces replacement) — WAF template ID.
- `configs` (Required) — Typed account takeover configuration. Its attributes and ownership-wrapper blocks are identical to `fortiappseccloud_waf_account_takeover` when that app resource uses `template = false`.

## Import

```shell
terraform import fortiappseccloud_waf_template_account_takeover.example TEMPLATE_ID
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets `template=false` and `configs.status=false`, sends the complete PUT, and verifies the normalized GET response before Terraform removes the resource from state.
