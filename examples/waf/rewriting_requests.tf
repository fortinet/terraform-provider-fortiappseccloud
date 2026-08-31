resource "fortiappseccloud_waf_rewriting_requests" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status               = true
    x_forwarded_for      = true
    identify_original_ip = true
    x_header             = "X-Forwarded-For"

    rule_list {
      item {
        name                = "rewrite-example"
        action              = "rewrite-header-advanced"
        host_filter         = true
        host_expression     = "^(example\\.com)$"
        header_status       = true
        insert_header_name  = "X-Terraform-Matrix"
        insert_header_value = "enabled"

        remove_header {
          item {
            header = "X-Old-Header"
          }
        }
      }
    }
  }
}
