resource "fortiappseccloud_waf_http_header_security" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status                       = true
    content_security_policy      = true
    header_value                 = "default-src 'self'"
    referrer_policy              = true
    referrer_policy_header_value = "strict-origin-when-cross-origin"
    x_content_type_options       = true
    x_frame_options              = true
    x_xss_protection             = true
  }
}
