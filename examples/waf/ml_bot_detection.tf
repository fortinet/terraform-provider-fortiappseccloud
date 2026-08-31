resource "fortiappseccloud_waf_ml_bot_detection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status                = true
    action                = "block_period"
    identification_method = "IP-and-User-Agent"
    model_type            = "Strict"
    anomaly_count         = 1
    challenge             = "Real-Browser-Enforcement"
    block_duration        = 600

    ip_list {
      item {
        ip = "1.1.1.1"
      }
    }

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
