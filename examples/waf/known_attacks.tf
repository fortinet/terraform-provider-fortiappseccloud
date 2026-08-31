resource "fortiappseccloud_waf_known_attacks" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status            = true
    sensitivity_level = 2
    action            = "alert_deny"
    cross_site_script = true
    sql_inject        = true
    trojans           = true

    # Omit this ownership wrapper to preserve the complete remote
    # sig_except_rules array. Keep the wrapper but remove every item block
    # to explicitly send [].
    sig_except_rules {
      item {
        sig_id   = "030000010"
        sig_name = "SQL Injection"
        cookie {
          status = true
          type   = "string"
          value  = "sessionid"
        }
        host {
          status = true
          type   = "string"
          value  = "www.example.com"
        }
        http_header {
          status = true
          type   = "string"
          value  = "X-Example"
        }
        json {
          status = true
          type   = "string"
          value  = "data"
        }
        param {
          status = true
          type   = "string"
          value  = "query"
        }
        url {
          status = true
          type   = "regex"
          value  = "^/admin"
        }
      }
    }
  }
}
