resource "fortiappseccloud_waf_ip_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status        = true
    ip_reputation = false

    ip_list {
      item {
        type = "trust-ip"
        ip   = "1.1.1.1"
      }
    }
  }
}
