resource "fortiappseccloud_waf_mitb_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status      = true
    action      = "alert_deny"
    request_url = "/login"
    post_url    = "/submit"

    param_list {
      item {
        type            = "regular-input"
        name            = "password"
        obfuscate       = true
        encrypt         = false
        anti_key_logger = false
      }
    }

    domain_list {
      item {
        domain = "https://maps.googleapis.com"
      }
    }
  }
}
