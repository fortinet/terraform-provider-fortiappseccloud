resource "fortiappseccloud_waf_content_routing" "example" {
  ep_id  = fortiappseccloud_waf_app.app_example.ep_id
  status = true

  policy_list {
    item {
      name        = "default_policy"
      server_pool = "default_pool"
      is_default  = true

      rule_list {}
    }
  }
}
