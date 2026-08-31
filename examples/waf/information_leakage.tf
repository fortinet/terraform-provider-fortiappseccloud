resource "fortiappseccloud_waf_information_leakage" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status               = true
    action               = "deny_erase_no_log"
    cloak_error_pages    = true
    erase_http_headers   = true
    personal_info        = true
    server_info_disclose = true

    http_headers {
      item {
        header = "Server"
      }
    }

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
