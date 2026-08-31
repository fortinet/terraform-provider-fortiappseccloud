resource "fortiappseccloud_waf_csrf_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    action = "alert_deny"
    status = true

    # Omit this ownership wrapper to preserve the complete remote page_list.
    # Keep the wrapper but remove every item block to explicitly send [].
    page_list {
      item {
        filter = true
        url    = "/checkout"
        name   = "csrf_token"
        value  = "expected"
      }
    }

    url_list {
      item {
        filter = true
        url    = "/api/orders"
        name   = "csrf_token"
        value  = "expected"
      }
    }
  }
}
