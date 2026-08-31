resource "fortiappseccloud_waf_cors_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status             = true
    block_cors_traffic = false

    allowed_origins {
      protocol            = "HTTPS"
      origin_name         = "partner.example.com"
      port                = 8443
      include_sub_domains = true
    }
    allowed_methods {
      status  = true
      methods = ["GET", "POST", "HEAD"]
    }
    allowed_headers {
      status  = true
      headers = ["Authorization", "Content-Type"]
    }
    exposed_headers {
      status  = true
      headers = ["X-Request-Id"]
    }
    url_pattern         = "/api"
    allowed_credentials = "TRUE"
    allowed_maximum_age = 600
  }
}
