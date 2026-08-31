resource "fortiappseccloud_waf_request_limits" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status              = true
    body_param_len      = 8192
    cookie_num          = 128
    http_req_len        = 2048
    malformed_url_check = true
    range_num           = 5
    http_header_action  = "alert_deny"

    # Omit this ownership wrapper to preserve the complete remote allow_methods
    # array. Keep the wrapper but remove every item block to explicitly send [].
    allow_methods {
      item { method = "get" }
      item { method = "post" }
      item { method = "head" }
    }
  }
}
