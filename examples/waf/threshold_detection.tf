resource "fortiappseccloud_waf_threshold_detection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status                 = true
    action                 = "block_period"
    challenge              = "RBE"
    crawler                = false
    vulnerability_scan     = true
    slow_attack            = false
    content_scraping       = false
    credential_brute_force = true
    request_url            = "/login"
    occurrence             = 10
    range                  = 60

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
