resource "fortiappseccloud_waf_caching_compression" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true

    cache {
      status            = true
      cache_timeout     = 120
      timeout_type      = "minutes"
      allow_method      = "GET,HEAD"
      allow_return_code = "200"
    }

    compress {
      status = true
    }

    cookie_list {
      item {
        name = "session-cookie"
      }
    }

    content_type_list {
      item {
        type = "text/html"
      }
    }
  }
}
