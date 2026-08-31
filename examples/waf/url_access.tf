resource "fortiappseccloud_waf_url_access" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true

    # Omit this ownership wrapper to preserve the complete remote rule_list.
    # Keep the wrapper but remove every item block to explicitly send [].
    rule_list {
      item {
        action   = "pass"
        name     = "allow-application-api"
        url      = "/api/application/"
        url_type = "string"
      }

      item {
        action   = "alert_deny"
        name     = "deny-admin-area"
        url      = "^/admin/(login|setup)$"
        url_type = "regex"
      }
    }
  }
}
