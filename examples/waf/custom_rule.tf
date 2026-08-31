resource "fortiappseccloud_waf_custom_rule" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true

    rule_list {
      item {
        name      = "block-bad-ips"
        action    = "alert"
        challenge = "real-browser-enforcement"

        filter_list {
          item {
            type          = "source-ip-filter"
            ip            = "1.1.1.1-1.1.1.255"
            reverse_match = true
          }
        }
      }
    }
  }
}
