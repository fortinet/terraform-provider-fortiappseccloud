resource "fortiappseccloud_waf_mobile_api_protection" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status       = true
    action       = "alert_deny"
    token_header = "Jwt_Token"
    # Sensitive: the JWT signing secret. Reference a variable or secret store
    # rather than inlining the literal secret value.
    token_secret = var.mobile_api_token_secret

    url_list {
      item {
        url = "/login"
      }
    }
  }
}

variable "mobile_api_token_secret" {
  type      = string
  sensitive = true
}
