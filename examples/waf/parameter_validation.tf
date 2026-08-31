resource "fortiappseccloud_waf_parameter_validation" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true

    rule_list {
      item {
        name         = "param-rule"
        url          = "/api/params"
        action       = "alert_deny"
        block_period = 60

        sub_rule_list {
          item {
            name       = "username"
            arg_type   = "data-type"
            arg_val    = "string"
            max_len    = 128
            required   = true
            type_check = true
          }
        }
      }
    }
  }
}
