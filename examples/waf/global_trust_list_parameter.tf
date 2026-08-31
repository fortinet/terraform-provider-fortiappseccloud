resource "fortiappseccloud_waf_global_trust_list_parameter" "example" {
  ep_id = fortiappseccloud_waf_app.app_example.ep_id

  configs {
    status = true

    trust_list {
      item {
        name   = "trusted-login"
        status = true
        url    = "/login"
      }
      item {
        name   = "trusted-api"
        status = true
        url    = "/api/v1/health"
      }
    }
  }
}
