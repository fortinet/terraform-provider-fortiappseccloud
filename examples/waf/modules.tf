data "fortiappseccloud_waf_modules" "example" {
  ep_id = fortiappseccloud_waf_app.app_example.ep_id
}

output "waf_module_statuses" {
  value = data.fortiappseccloud_waf_modules.example.modules
}
