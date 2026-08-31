resource "fortiappseccloud_waf_bot_deception" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status        = true
    action        = "alert_deny"
    deception_url = "/url.html"

    url_list {
      item {
        url = "/login"
      }
    }

    exception_list {
      item {
        concatenate_type = "AND"
        match_target     = "COOKIE"
        operator         = "REGEXP_MATCH"
        value_name       = "session_id"
        value_check      = true
        value            = "terraform-matrix"
      }
    }
  }
}
