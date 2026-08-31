resource "fortiappseccloud_waf_xml_protection_policy" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status = true
    action = "alert_deny"
    # file_list is omitted because creating a schema entry requires real file
    # content, which this generic module resource intentionally does not upload.
  }
}
