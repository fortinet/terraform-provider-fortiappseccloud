resource "fortiappseccloud_waf_web_socket_security" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true
    action = "alert_deny"

    rule_list {
      item {
        name              = "ws-rule"
        url               = "/ws"
        allow_binary_text = true
        allow_plain_text  = true
        allow_websocket   = true
        block_attacks     = true
        block_extensions  = false
        max_frm_size      = 64
        max_msg_size      = 1024

        origin_list {
          item {
            origin = "https://example.com"
          }
        }
      }
    }
  }
}
