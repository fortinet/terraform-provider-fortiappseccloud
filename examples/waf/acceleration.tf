resource "fortiappseccloud_waf_acceleration" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status             = true
    css_minify         = true
    html_minify        = true
    html_css2head      = true
    html_combine_heads = false
    js_minify          = true

    # Omit this ownership wrapper to preserve the complete remote exception_list.
    # Keep the wrapper but remove every item block to explicitly send [].
    exception_list {
      item {
        host_status = true
        host        = "static.example.com"
        url_pattern = "^/assets/"
        url_type    = "regex"
      }

      item {
        host_status = false
        url_pattern = "/health-check"
        url_type    = "string"
      }
    }
  }
}
