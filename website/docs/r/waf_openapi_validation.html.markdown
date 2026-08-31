---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_openapi_validation Resource - fortiappseccloud"
description: |-
  Configures file-backed OpenAPI validation for a WAF application without storing document contents in Terraform state.
---

# fortiappseccloud_waf_openapi_validation

Uploads local OpenAPI documents for one WAF application without storing their contents in Terraform state. State retains paths, SHA-256 hashes, and server-returned file metadata. Destroy disables validation and clears the managed remote file list.

## Example Usage

```hcl
resource "fortiappseccloud_waf_openapi_validation" "example" {
  ep_id  = fortiappseccloud_waf_app.example.ep_id
  enable = true
  action = "alert_deny"
  validation_files = [
    "${path.module}/openapi.yaml",
  ]
}
```

Create `openapi.yaml` beside the Terraform configuration and ensure it contains a valid OpenAPI document before planning. Relative paths are resolved by Terraform, and every configured file must remain readable during create and update.

## Argument Reference

* `ep_id` - (Required for new resources) Stable application endpoint ID.
* `enable` - (Optional) Enable validation; defaults to `true`.
* `action` - (Required) `alert`, `alert_deny`, or `deny_no_log`.
* `validation_files` - (Optional) Ordered list of up to ten local OpenAPI document paths.

## Attributes Reference

* `validation_file_hashes` - SHA-256 hashes matching `validation_files` order.
* `remote_files` - Server-returned name, title, description, URL, and MD5 metadata.
* `legacy_app_name` - Migration-only application name; normally null after refresh.

## Import

```shell
terraform import fortiappseccloud_waf_openapi_validation.example 1234567890
```

## Destroy Behavior

Destroy disables OpenAPI validation by setting its status to `false` and replacing the managed remote file list with an empty list. The provider verifies both values before removing the resource from state. It does not delete the WAF application or the local files referenced by `validation_files`.

## Migrating v1.0.5 Configuration

The v2 resource uses stable `ep_id` instead of `app_name`. Preserve all referenced local documents and follow the complete [v1.0.5 to v2.0 upgrade guide](../guides/v1_0_5_to_v2_0_0.html).
