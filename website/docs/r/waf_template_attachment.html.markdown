---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_template_attachment Resource - fortiappseccloud"
description: |-
  Attaches one FortiAppSec Cloud WAF application to one WAF template.
---

# fortiappseccloud_waf_template_attachment

Attaches one application to one WAF template. Manage template creation with `fortiappseccloud_waf_template`; manage the template's module settings with the typed `fortiappseccloud_waf_template_*` resources.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template_attachment" "example" {
  ep_id       = fortiappseccloud_waf_app.example.ep_id
  template_id = fortiappseccloud_waf_template.example.template_id
}
```

## Argument Reference

- `ep_id` (Required, Forces replacement) — Application endpoint ID.
- `template_id` (Required, Forces replacement) — WAF template ID.

Updates preserve unrelated template memberships.

## Import

Import with `template_id:ep_id`:

```shell
terraform import fortiappseccloud_waf_template_attachment.example template-id:1234567890
```

## Destroy Behavior

Destroy removes only the managed application from the template's endpoint membership and verifies the updated membership. It preserves other applications attached to the template and does not delete either the application or the template.
