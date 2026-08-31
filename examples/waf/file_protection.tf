resource "fortiappseccloud_waf_file_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status            = true
    action            = "alert_deny"
    trojan            = false
    sandbox           = false
    av_scan           = true
    file_action       = "Allow"
    file_size         = 10240
    url               = "/1"
    json_file_support = false

    file_types {
      item {
        type = "GIF"
        tid  = "00001"
      }
    }

    custom_file_types {
      item {
        name           = "custom-archive"
        file_extension = "foo"

        file_content_match_rule {
          item {
            data_value       = "magic-bytes"
            offset_from      = "beginning"
            offset           = 0
            operation        = "equal"
            data_type        = "string"
            concatenate_type = "AND"
          }
        }
      }
    }
  }
}
