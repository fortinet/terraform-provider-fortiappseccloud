resource "fortiappseccloud_waf_account_takeover" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status                = true
    action                = "alert_deny"
    auth_url              = "/login"
    cred_stuffing_protect = true
    sess_fixation_protect = true
    sess_id_name          = "session_id"
    username              = "USERNAME"
    password              = "PASSWORD"
  }
}
