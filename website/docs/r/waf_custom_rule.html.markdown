---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_custom_rule Resource - fortiappseccloud"
description: |-
  Configures ordered custom WAF rules directly or through template inheritance for a FortiAppSec Cloud application.
---

# fortiappseccloud_waf_custom_rule

Configures ordered custom rules and their ordered filters for one WAF application. Set `template = false` and provide `configs` to manage them directly, or set `template = true` and omit `configs` to inherit them.

## Example Usage

```hcl
resource "fortiappseccloud_waf_custom_rule" "example" {
  ep_id    = fortiappseccloud_waf_app.example.ep_id
  template = false

  configs {
    status = true

    rule_list {
      item {
        name      = "block-bad-ips"
        action    = "alert"
        challenge = "real-browser-enforcement"

        filter_list {
          item {
            type          = "source-ip-filter"
            ip            = "1.1.1.1-1.1.1.255"
            reverse_match = true
          }
        }
      }
    }
  }
}
```

Set `challenge` explicitly for every configured rule. FortiAppSec Cloud currently rejects an omitted challenge even though the API schema publishes a default. Source-IP filters accept a single address or an address range such as the one shown.

## Argument Reference

* `ep_id` - (Required, Forces replacement) Application endpoint ID.
* `template` - (Required) Whether configuration is inherited.
* `configs` - (Optional) Required when `template` is false and forbidden when true.

`configs` requires `status` and optionally owns `rule_list`. The list accepts at most 24 ordered `item` blocks; omission preserves the remote list and an empty wrapper sends `[]`.

Each rule requires `name` (maximum 40 UTF-8 characters), `action` (`alert`, `alert_deny`, `block_period`, or `deny_no_log`), and an explicit `challenge` (`real-browser-enforcement`, `disabled`, or `captcha-enforcement`). `action = "block_period"` requires `block_period` (1–3600); other actions forbid an explicitly configured `block_period`. `filter_list` contains at most 200 ordered filters.

Each filter requires `type`. Supported contract-visible types are `source-ip-filter`, `user-filter`, `url-filter`, `parameter`, `http-header-filter`, `content-type`, `response-code`, `security-rules`, `access-limit-filter`, `packet-interval`, `http-transaction`, `occurrence`, and `time-range-filter`.

The provider enforces this discriminator matrix and rejects fields from other variants:

* `source-ip-filter` requires `ip`; `user-filter` requires `username`; `url-filter` requires `url`. Those three may use `reverse_match`.
* `parameter` requires `name` and `value`.
* `http-header-filter` requires `header_check` or `method_check` to be true and owns the header/method fields. `http_hline_missing_check` and `http_hline_empty_check` cannot both be true.
* `content-type` requires a non-empty `content_types`; `response-code` requires Terraform `response_code`, encoded as the OpenAPI 26.3.a wire field `code`.
* `security-rules` requires at least one of `cross_site_scripting`, `sql_injection`, `generic_attacks`, `known_exploits`, or `trojans` to be true.
* `access-limit-filter` requires `limit`; `packet-interval` and `http-transaction` require `timeout`; `occurrence` requires `occurrence` and `within`.
* `time-range-filter` requires `time_type`, `start`, and `end`. Daily values use `HH:MM`; once values use `HH:MM YYYY/MM/DD`, with valid calendar dates.

OpenAPI 26.3.a exposes `geo-filter` as a public `type` discriminator. Use `country_list` and optional `match_exclusively` only with that filter type.

## Import

```shell
terraform import fortiappseccloud_waf_custom_rule.example 3206359425
```

## Destroy Behavior

Destroy performs a fresh GET, preserves the complete response, sets only
`template=false` and `configs.status=false`, PUTs the result, verifies the
complete semantic result with another GET, and then removes the resource from
state.
