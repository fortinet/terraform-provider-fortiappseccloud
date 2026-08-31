---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_account_takeover Resource - fortiappseccloud"
description: |-
  Configures account takeover protection directly or through template inheritance for a FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_account_takeover

Configures the account takeover module for an existing FortiAppSec Cloud WAF application. Set `template = false` and provide `configs` to manage the module directly. Set `template = true` and omit `configs` to inherit the module from the application's attached WAF template.

Declare only one `fortiappseccloud_waf_account_takeover` resource for an application endpoint. The resource reads the current API document before each update and overlays only values present in Terraform configuration, preserving API fields not yet represented by the provider.

## Example Usage

```hcl
resource "fortiappseccloud_waf_account_takeover" "example" {
  ep_id    = fortiappseccloud_waf_app.example.ep_id
  template = false

  configs {
    status                  = true
    action                  = "alert_deny"
    auth_url                = "/login"
    cred_stuffing_protect   = true
    sess_fixation_protect   = true
    sess_id_name            = "session_id"
    username                = "username"
    password                = "password"
  }
}
```

To inherit the module configuration from the application's attached template, omit `configs`:

```hcl
resource "fortiappseccloud_waf_account_takeover" "inherited" {
  ep_id    = fortiappseccloud_waf_app.example.ep_id
  template = true
}
```

## Argument Reference

The following arguments are supported:

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `template` - (Required) Whether the module inherits its effective configuration from the application's attached template. When `true`, `configs` must be omitted. When `false`, `configs` is required.
* `configs` - (Optional) Locally managed account takeover settings. This block is required when `template` is `false` and forbidden when `template` is `true`.

The `configs` block supports:

* `action` - (Optional) Action taken when account takeover protection matches. Valid values are `alert`, `alert_deny`, and `deny_no_log`.
* `auth_url` - (Optional) Authentication URL used by account takeover protection.
* `cred_stuffing_protect` - (Optional) Whether credential stuffing protection is enabled.
* `logoff_url` - (Optional) Logoff URL.
* `password` - (Optional, Sensitive) Password matching value sent to the account takeover API. The provider marks this value sensitive in normal Terraform output, but protocol-5 Terraform state can still contain it in plaintext. Protect state accordingly. Confirm the API's readback and masking behavior before using this field for sensitive material.
* `redirect_url` - (Optional) Redirect URL.
* `response_body` - (Optional) Response body configuration.
* `return_code` - (Optional) Return code configuration.
* `sess_fixation_protect` - (Optional) Whether session fixation protection is enabled.
* `sess_id_name` - (Optional) Session ID field name. Maximum length is 63 characters.
* `status` - (Optional) Whether account takeover protection is enabled.
* `username` - (Optional) Username field name. Maximum length is 63 characters.

`username` and `password` also have a maximum length of 63 characters.

Values omitted from `configs` are populated from the API during refresh and are preserved during updates. Explicit `false` and empty-string values are sent as configured.

When `template` is `true`, `configs` remains null in Terraform state even if the API reports effective inherited settings.

## Import

Import the resource using the application endpoint ID:

```shell
terraform import fortiappseccloud_waf_account_takeover.example 3206359425
```

Application names and composite import IDs are not accepted.

## Destroy Behavior

The FortiAppSec Cloud API does not expose a DELETE operation for this module. Destroying the Terraform resource disables account takeover protection by setting `template=false` and `status=false`, verifies the result, and then removes the resource from Terraform state. It does not delete the WAF application or a remote subresource.

## Provider Credentials

Configure credentials in provider HCL or with the canonical environment variables `FORTIAPPSECCLOUD_API_TOKEN`, or `FORTIAPPSECCLOUD_USERNAME` together with `FORTIAPPSECCLOUD_PASSWORD`. The optional API hostname can be set with `FORTIAPPSECCLOUD_HOSTNAME`. Do not commit credentials to configuration or local credential files.
