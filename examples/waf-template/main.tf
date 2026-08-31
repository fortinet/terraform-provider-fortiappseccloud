terraform {
  required_providers {
    fortiappseccloud = {
      source  = "fortinet/fortiappseccloud"
      version = ">= 2.0.0"
    }
  }
}

# Set FORTIAPPSECCLOUD_API_TOKEN before using this example.
provider "fortiappseccloud" {
  hostname = "api.appsec.fortinet.com"
}

resource "fortiappseccloud_waf_template" "example" {
  name = "terraform-template"
}

resource "fortiappseccloud_waf_template_account_takeover" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    status                = true
    action                = "alert_deny"
    auth_url              = "/login"
    cred_stuffing_protect = true
    sess_fixation_protect = true
    sess_id_name          = "session_id"
    username              = "username"
    password              = "password"
  }
}

resource "fortiappseccloud_waf_template_csrf_protection" "example" {
  template_id = fortiappseccloud_waf_template.example.template_id

  configs {
    action = "alert_deny"
    status = true

    page_list {
      item {
        filter = true
        url    = "/checkout"
        name   = "csrf_token"
        value  = "expected"
      }
    }
  }
}
