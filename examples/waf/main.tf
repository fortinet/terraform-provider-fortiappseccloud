terraform {
  required_providers {
    fortiappseccloud = {
      source  = "fortinet/fortiappseccloud"
      version = ">= 2.0.0"
    }
  }
}

# Set FORTIAPPSECCLOUD_API_TOKEN before running this example.
provider "fortiappseccloud" {
  hostname = "api.appsec.fortinet.com"
}

resource "fortiappseccloud_waf_app" "app_example" {
  app_name         = "from_terraform"
  domain_name      = "www.example.com"
  services         = ["http", "https"]
  http_port        = 80
  https_port       = 443
  platform         = "AWS"
  region           = "us-east-1"
  cdn              = false
  block_mode       = false
  certificate_mode = "automatic"

  initial_origin {
    address  = "origin.example.com"
    protocol = "https"
    port     = 443
  }
}

resource "fortiappseccloud_waf_openapi_validation" "openapi_validation_example" {
  ep_id  = fortiappseccloud_waf_app.app_example.ep_id
  enable = true
  action = "alert_deny"
  validation_files = [
    "${path.module}/openapi.yaml"
  ]
}
