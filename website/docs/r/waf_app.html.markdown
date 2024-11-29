---
subcategory: "WAF"
layout: "fortiappseccloud"
page_title: "FortiAppSecCloud: fortiappseccloud_waf_app"
sidebar_current: "docs-fortiappseccloud-waf-app"
description: |-
  This resource supports application creation for FortiAppSecCloud.
---

# fortiappseccloud_waf_app

This resource supports application creation within FortiAppSecCloud.

## Example Usage

```terraform
resource "fortiappseccloud_waf_app" "example" {
  app_name             = "test-app"
  domain_name          = "www.example.com"
  app_service = {
      http  = 80
      https = 443
  }
  origin_server_ip     = "1.1.1.1"
  origin_server_service = "HTTPS"
  cdn                  = false
  continent_cdn        = false
}
```

## Argument Reference
The following arguments are supported:

* `app_name` -  (Required) The name of the application.
* `domain_name` - (Required) The primary domain name for the application (e.g., www.example.com).
* `extra_domains` - (Optional) A list of additional domain names (e.g., ["www.example1.com", "www.example2.com"]).
* `app_service` - (Optional) Application service .
* `origin_server_ip` - (Required) Origin server IP or domain.
* `origin_server_service` - (Optional) Origin server service or domain. Defaults to HTTPS.
* `origin_server_port` - (Optional) Origin server port. Defaults to 443.
* `cdn` - (Optional) Enable CDN or not. Defaults to false.
* `block` - (Optional) Enable block_mode or not. Defaults to false.
* `template` - (Optional) The template name.

## Attributes Reference
The following attributes are exported:
* `ep_id` - Application id.
* `cname` - CNAME of the application.
