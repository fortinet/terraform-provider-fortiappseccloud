---
page_title: "fortiappseccloud_waf_template Resource - fortiappseccloud"
subcategory: "WAF"
description: |-
  Creates, reads, and deletes a FortiAppSec Cloud WAF template.
---

# fortiappseccloud_waf_template

Creates, reads, and deletes one user WAF template. The resource always creates the template with `endpoints = []`; application membership is owned independently by `fortiappseccloud_waf_template_attachment`.

The create lifecycle requires a `201 Created` response containing `result.template_id` and `Location: /v2/waf/template/{template_id}`.

Changing `name` replaces the template because the public API has no rename operation.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template" "example" {
  name = "terraform-template"
}
```

## Argument Reference

* `name` - (Required, Forces replacement) Template name.

## Attribute Reference

* `template_id` - Stable template ID.
* `predefined` - Whether the backend reports this as a predefined template.
* `features` - Observed module feature identifiers.

## Import

```shell
terraform import fortiappseccloud_waf_template.example TEMPLATE_ID
```

## Destroy Behavior

Destroy deletes a user-created WAF template from FortiAppSec Cloud and waits until its removal is observable. Destroy its template-module and application-attachment resources first; Terraform normally orders them correctly when their `template_id` refers to this resource. Predefined templates are not destroyable: if an imported template is reported as predefined, destroy fails without sending `DELETE`; remove it from Terraform state instead.
