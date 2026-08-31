resource "fortiappseccloud_waf_ml_api_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status        = true
    threat_action = "alert"
    ip_list_type  = "Block"

    ip_list {
      item {
        ip = "192.0.2.13"
      }
    }

    path_list {
      item {
        type    = "plain"
        pattern = "/terraform-example"
      }
    }
  }
}
