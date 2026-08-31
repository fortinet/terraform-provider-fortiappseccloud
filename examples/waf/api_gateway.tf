resource "fortiappseccloud_waf_api_gateway" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name              = "example-rule"
        api_key_verify    = true
        api_key_loc       = "http-header"
        field_name        = "X-API-Key"
        rate_limit_period = 60
        rate_limit_req    = 100

        url_list {
          item {
            frontend = "/api"
            backend  = "/backend"
          }
        }

        user_list {
          item {
            user = "example-user"
          }
        }
      }
    }

    user_list {
      item {
        name     = "example-user"
        email    = "user@example.com"
        comments = "example user"

        ip_list {
          item {
            ip = "10.0.0.1"
          }
        }

        referer_list {
          item {
            referer = "example.com"
          }
        }
      }
    }
  }
}
