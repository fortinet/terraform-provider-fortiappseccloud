resource "fortiappseccloud_waf_ddos_prevention" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status             = true
    action             = "block_period"
    challenge          = "real-browser-enforcement"
    http_access_limit  = true
    http_request_limit = 1000
    conn_flood_check   = true
    conn_flood_limit   = 100
    http_flood_prevent = true
    http_session_limit = 500
    tcp_flood_prevent  = false
    tcp_conn_num_limit = 255
    block_period       = 600

    ip_exception {
      item {
        ip = "1.1.1.1-1.1.1.2,1.1.1.4"
      }
    }
  }
}
