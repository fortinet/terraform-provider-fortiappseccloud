resource "fortiappseccloud_waf_graphql_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name        = "graphql-default"
        request_url = "/graphql"
      }
    }
  }
}
