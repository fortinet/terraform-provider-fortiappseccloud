data "fortiappseccloud_waf_signature_exception" "example" {
  ep_id        = fortiappseccloud_waf_app.app_example.ep_id
  signature_id = "030000001"
}

output "signature_exception_template_id" {
  value = data.fortiappseccloud_waf_signature_exception.example.template_id
}
