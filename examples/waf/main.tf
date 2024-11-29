terraform {
  required_providers {
    fortiappseccloud = {
      source  = "fortinet/fortiappseccloud"
      version = "1.0.0"
    }
  }
}

provider "fortiappseccloud" {
  hostname  = "api.appsec.fortinet.com"
  api_token = "specify your token"
}

resource "fortiappseccloud_waf_app" "app_example" {
  app_name    = "from_terraform"
  domain_name = "www.example.com"
  app_service = {
    http  = 80
    https = 443
  }
  origin_server_ip      = "your server ip"
  origin_server_service = "HTTPS"
  cdn                   = false
  continent_cdn         = false
}

resource "fortiappseccloud_waf_openapi_validation" "openapi_validation_example" {
  app_name = "from_terraform"
  enable   = true
  action   = "alert_deny"
  validation_files = [
    "/path/openapi_validation_file.yaml",
    "/path/openapi_validation_file2.yaml"
  ]
  depends_on = [
    fortiappseccloud_waf_app.app_example
  ]
}
