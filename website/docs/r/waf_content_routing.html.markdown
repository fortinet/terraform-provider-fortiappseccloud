---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_content_routing Resource - fortiappseccloud"
description: |-
  Configures ordered content-routing policies for a FortiAppSec Cloud WAF application.
---

# fortiappseccloud_waf_content_routing

Configures the public `/routings` settings for one WAF application. It owns routing policies and references origin pools by name; create and manage those pools with `fortiappseccloud_waf_origin_servers`.

## Example Usage

```hcl
resource "fortiappseccloud_waf_content_routing" "example" {
  ep_id  = fortiappseccloud_waf_app.example.ep_id
  status = true

  policy_list {
    item {
      name        = "default-routing"
      server_pool = "default_pool"
      is_default  = true

      rule_list {}
    }
  }
}
```

`server_pool` must exactly match an existing origin-pool name. A newly created WAF application includes `default_pool`, so this example works without assuming a separately created `api_pool`. A default policy requires `is_default = true` and an empty `rule_list`.

## Argument Reference

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `status` - (Required) Whether content routing is enabled.
* `policy_list` - (Optional) Complete ordered policy-list ownership wrapper, maximum 32 items. Omission preserves the remote list; an empty wrapper sends `[]`. At most one item may set `is_default = true`.

Each `policy_list.item` supports required `name`, optional `server_pool`, optional/computed `is_default`, and optional `rule_list`.

Each ordered `rule_list` supports at most 32 items. Every item requires `match_object`; `concatenate` (`and`/`or`) and `reverse` may be used with any object. Variant fields are:

* `url-parameter`, `http-cookie`, `http-header` - require `name_match_condition`, `name`, `value_match_condition`, and `value`.
* `http-host`, `http-request`, `http-referer`, `https-sni` - require `match_condition` and `match_expression`. Their conditions are `match-begin`, `match-end`, `match-sub`, `match-domain`, `match-dir`, `match-reg`, or `equal`.
* `source-ip` - requires `match_condition`. `ip-range`/`ip-range6` require `start_ip` and `end_ip`; `ip-list` requires `ip_list`. Range and list fields are mutually exclusive.
* `x509-certificate-Subject` - requires `x509_subject_name`, `value_match_condition`, and `match_expression`.
* `x509-certificate-Extension` - requires `value_match_condition` and `value`.

`name_match_condition` and `value_match_condition` accept `match-begin`, `match-end`, `match-sub`, `equal`, or `match-reg`. Fields belonging to another variant are rejected during planning.

Unknown backend keys are preserved. Known configured fields remain authoritative. Wire-only policy/rule indices are regenerated and omitted from state.

## Import

```shell
terraform import fortiappseccloud_waf_content_routing.example 3206359425
```

## Destroy Behavior

Destroy forgets the resource with a warning and leaves the remote content-routing configuration unchanged.
The routing API uses a root-level status and no standard app-module
`template + configs.status` envelope, so this resource is not eligible for the
standard disable-on-destroy lifecycle.
