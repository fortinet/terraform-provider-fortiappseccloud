---
page_title: "fortiappseccloud_waf_template_cors_protection Resource - fortiappseccloud"
subcategory: "WAF"
description: |-
  Configures CORS protection for a FortiAppSec Cloud WAF template.
---

# fortiappseccloud_waf_template_cors_protection

Configures CORS protection for one WAF template. Applications inherit these settings only when their matching app module resource uses `template = true` and omits `configs`.

Declare only one `fortiappseccloud_waf_template_cors_protection` resource for a WAF template. All four policy blocks shown below are required by the PUT schema.

## Example Usage

```hcl
resource "fortiappseccloud_waf_template_cors_protection" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol            = "HTTPS"
      origin_name         = "partner.example.com"
      port                = 443
      include_sub_domains = false
    }
    allowed_methods {
      status  = true
      methods = ["GET", "HEAD"]
    }
    allowed_headers {
      status  = true
      headers = ["Content-Type"]
    }
    exposed_headers {
      status  = true
      headers = ["X-Request-Id"]
    }
    url_pattern         = "/api"
    allowed_credentials = "FALSE"
    allowed_maximum_age = 60
  }
}
```

## Argument Reference

- `template_id` (Required, Forces replacement) — WAF template ID.
- `configs` (Required) — Typed CORS protection configuration. Its attributes and ownership-wrapper blocks are identical to `fortiappseccloud_waf_cors_protection` when that app resource uses `template = false`.

## Import

```shell
terraform import fortiappseccloud_waf_template_cors_protection.example TEMPLATE_ID
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets `template=false` and `configs.status=false`, sends the complete PUT, and verifies the normalized GET response before Terraform removes the resource from state.
