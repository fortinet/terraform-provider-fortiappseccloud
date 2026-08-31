resource "fortiappseccloud_waf_waiting_room" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status                    = true
    path                      = "/.*"
    enable_total_active_users = true
    total_active_users        = 1000
    enable_new_users_per_min  = false
    new_users_per_min         = 60
    session_duration          = 5
    custom_wt_page            = "Predefined"

    bypass_rules {
      item {
        rule_type  = "source-ip"
        rule_value = "192.0.2.10"
      }
    }
  }
}
