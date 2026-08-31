resource "fortiappseccloud_waf_anomaly_detection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status       = true
    action       = "alert"
    ip_list_type = "Block"

    ip_list {
      item {
        ip = "192.0.2.10"
      }
      item {
        ip = "198.51.100.11"
      }
    }
  }
}
