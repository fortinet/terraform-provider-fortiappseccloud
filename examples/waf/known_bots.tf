resource "fortiappseccloud_waf_known_bots" "example" {
  ep_id    = fortiappseccloud_waf_app.app_example.ep_id
  template = false

  configs {
    status           = true
    bad_bots         = true
    bad_bots_action  = "block_period"
    good_bots_action = "bypass"

    bad_bots_list {
      item {
        cat    = "DoS"
        status = true
        allow_list {
          item {
            value = "AB"
          }
        }
      }
    }

    good_bots_list {
      item {
        cat    = "Known Search Engines"
        status = true
        deny_list {
          item {
            value = "Ask"
          }
        }
      }
    }

    exception_list {
      item {
        concatenate_type = "AND"
        match_target     = "COOKIE"
        operator         = "REGEXP_MATCH"
        value_name       = "session_id"
        value_check      = true
        value            = "terraform-matrix"
      }
    }
  }
}
