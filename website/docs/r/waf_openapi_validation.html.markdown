---
subcategory: "WAF"
layout: "fortiappseccloud"
page_title: "FortiAppSecCloud: fortiappseccloud_waf_openapi_validation"
sidebar_current: "docs-fortiappseccloud-waf-openapi-validation"
description: |- 
  This resource supports OpenAPI validation configuration for FortiAppSecCloud.
---

# fortiappseccloud_waf_openapi_validation

This resource supports configuring OpenAPI validation for WAF applications in FortiAppSecCloud.

## Example Usage

```terraform
resource "fortiappseccloud_waf_openapi_validation" "openapi_validation_example" {
  app_name = "from_terraform"
  enable   = true
  action   = "alert_deny"
  validation_files = [
    "/path/openapi_validation_file.yaml",
    "/path/openapi_validation_file2.yaml"
  ]
  depends_on = [
    fortiappseccloud_waf_app.app_example
  ]
}
```

## Argument Reference
The following arguments are supported:

* `app_name` - (Required) The name of the WAF application associated with the OpenAPI validation module.
* `enable` - (Required) Whether to enable the OpenAPI validation module.
* `action` - (Required) The action to take when validation fails. Possible values are:
  - `alert`: Accept the request but generate alert emails and/or log messages.
  - `alert_deny`: Block the request (or reset the connection) and generate alert emails and/or log messages.
  - `deny_no_log`: Block the request (or reset the connection) without generating logs.
* `validation_files` - (Required) A list of file paths to OpenAPI validation files that define the API schema.
