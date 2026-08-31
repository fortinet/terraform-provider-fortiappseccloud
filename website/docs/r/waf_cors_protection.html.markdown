---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_cors_protection Resource - fortiappseccloud"
description: |-
  Configures CORS protection directly or through template inheritance for a FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_cors_protection

Configures CORS protection for one WAF application. Set `template = false` and provide `configs` to manage it directly, or set `template = true` and omit `configs` to inherit it. The four policy blocks are required for direct configuration; `allowed_origins` is one object despite its plural API name.

## Example Usage

```hcl
resource "fortiappseccloud_waf_cors_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.example.ep_id
  template = false

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

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `template` - (Required) Whether configuration is inherited.
* `configs` - (Optional) Required when `template` is false and forbidden when true.

`configs` supports required `status`, `block_cors_traffic`, `allowed_origins`, `allowed_methods`, `allowed_headers`, and `exposed_headers`, plus:

* `url_pattern` - (Optional, Computed) Protected URL pattern.
* `allowed_credentials` - (Optional, Computed) `None`, `TRUE`, or `FALSE`.
* `allowed_maximum_age` - (Optional, Computed) Preflight lifetime from 0 through 86400 seconds.

`allowed_origins` requires `protocol` (`ANY`, `HTTP`, or `HTTPS`) and `origin_name`; `port` is optional/computed from 0 through 65535 and `include_sub_domains` is optional/computed.

The other three policy blocks require `status`. `allowed_methods.methods` accepts `GET`, `POST`, `HEAD`, `TRACE`, `CONNECT`, `DELETE`, `PUT`, and `PATCH`; the header lists contain strings.

## Import

```shell
terraform import fortiappseccloud_waf_cors_protection.example 3206359425
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets only
`template=false` and `configs.status=false`, PUTs the result, verifies the
complete semantic result with another GET, and then removes the resource from
state.

The provider enforces template/config mutual exclusion and requires all four policy objects for both values of `block_cors_traffic`. When blocking all CORS traffic, the restriction policies are inactive according to the product guide, but the PUT schema still requires the objects, so complete configurations in either mode are accepted. No undocumented credential or method/header-status coupling is imposed.
