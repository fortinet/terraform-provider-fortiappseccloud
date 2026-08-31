resource "fortiappseccloud_waf_cookie_security" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status            = true
    action            = "alert_deny"
    mode              = "signed"
    replay_protection = true
    max_age           = 180
    secure_cookie     = true
    http_only         = true
    samesite          = false
    samesite_value    = "Lax"

    cookie_except_list {
      item {
        name     = "__utma"
        wildcard = false
      }
    }
  }
}
