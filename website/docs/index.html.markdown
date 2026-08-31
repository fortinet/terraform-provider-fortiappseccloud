---
page_title: "Provider: FortiAppSecCloud"
description: |-
  The fortiappseccloud provider interacts with FortiAppSecCloud.
---

# Terraform provider for FortiAppSecCloud

`fortiappseccloud` is used to interact with the resources supported by FortiAppSecCloud. Before use, the provider must be configured with the proper credentials.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) 1.5 or later. The registry-style `source` addressing used below has been available since Terraform 0.13, but the v2 provider targets 1.5+.
- An FortiAppSecCloud account with an API token, or a username and password.
- A network path from the machine running Terraform to the FortiAppSecCloud API endpoint.

### Installation

Declare the provider in your configuration and run `terraform init` to install it:

```hcl
terraform {
  required_providers {
    fortiappseccloud = {
      source  = "fortinet/fortiappseccloud"
      version = ">= 2.0.0"
    }
  }
}
```

```shell
$ terraform init
```

## Configuration for FortiAppSecCloud

### Example Usage

```shell
export FORTIAPPSECCLOUD_API_TOKEN="your_api_token"
```

```hcl
# Configure the FortiAppSecCloud Provider
provider "fortiappseccloud" {
  hostname = "api.appsec.fortinet.com"
}
```

### Argument Reference

The following arguments are supported:

* `hostname` - (Optional) The FortiAppSecCloud API endpoint. Defaults to `api.appsec.fortinet.com` and can be set with `FORTIAPPSECCLOUD_HOSTNAME`.
* `username` - (Optional) The username for your FortiAppSecCloud account. Can be set with `FORTIAPPSECCLOUD_USERNAME` and must be used together with `password`.
* `password` - (Optional, Sensitive) The password for your FortiAppSecCloud account. Can be set with `FORTIAPPSECCLOUD_PASSWORD` and must be used together with `username`.
* `api_token` - (Optional, Sensitive) The API key for accessing your FortiAppSecCloud account. Can be set with `FORTIAPPSECCLOUD_API_TOKEN`.
* `insecure` - (Optional) Disables TLS certificate verification. Defaults to `false` and should be used only for an explicitly trusted development endpoint.
* `cacert_file` - (Optional) Path to a custom CA certificate bundle used to verify the API endpoint. It cannot be combined with `insecure = true`.
* `timeout_seconds` - (Optional) Maximum duration for one API operation. Defaults to `60` and accepts values from `1` through `3600`.

~> **Note** `insecure` and `cacert_file` are not needed for normal use. The default public endpoint (`api.appsec.fortinet.com`) is trusted by standard operating systems, so most customers leave both unset. Only configure them when the machine running Terraform has a custom trust chain — for example a corporate TLS-inspection proxy (e.g. Zscaler) or an internal CA — in which case the CA bundle comes from your own IT or security team, not from Fortinet. Prefer `cacert_file` over `insecure`; reserve `insecure` for explicitly trusted development endpoints only.

Configure exactly one authentication mode: `api_token`, or `username` together with `password`. Credentials can be supplied in HCL or canonical environment variables; do not commit them to configuration or local credential files.

## Important Usage Guidance

Before managing WAF modules or importing an existing application, review the [WAF configuration and import guidance](guides/waf_configuration_guidance.html). It explains explicit origin-server ownership, unsupported log and certificate-upload features, recommended protections, and module disable-on-destroy behavior.

## Upgrade Guide

Before upgrading existing public-provider state from v1.0.5, follow the [v1.0.5 to v2.0 migration guide](guides/v1_0_5_to_v2_0_0.html).

## Resources

The provider serves 69 resources: application lifecycle resources, 34 app-level WAF configuration resources, one base template resource, one template-attachment resource, and 31 typed template-module resources.

### Application lifecycle

* [`fortiappseccloud_waf_app`](r/waf_app.html) - Onboards and manages a WAF application.
* [`fortiappseccloud_waf_origin_servers`](r/waf_origin_servers.html) - Owns the application's complete origin server-pool configuration.

### Application WAF configuration

* [`fortiappseccloud_waf_account_takeover`](r/waf_account_takeover.html)
* [`fortiappseccloud_waf_anomaly_detection`](r/waf_anomaly_detection.html)
* [`fortiappseccloud_waf_api_gateway`](r/waf_api_gateway.html)
* [`fortiappseccloud_waf_biometrics_based_detection`](r/waf_biometrics_based_detection.html)
* [`fortiappseccloud_waf_bot_deception`](r/waf_bot_deception.html)
* [`fortiappseccloud_waf_caching_compression`](r/waf_caching_compression.html)
* [`fortiappseccloud_waf_content_routing`](r/waf_content_routing.html)
* [`fortiappseccloud_waf_cookie_security`](r/waf_cookie_security.html)
* [`fortiappseccloud_waf_cors_protection`](r/waf_cors_protection.html)
* [`fortiappseccloud_waf_csrf_protection`](r/waf_csrf_protection.html)
* [`fortiappseccloud_waf_custom_rule`](r/waf_custom_rule.html)
* [`fortiappseccloud_waf_ddos_prevention`](r/waf_ddos_prevention.html)
* [`fortiappseccloud_waf_file_protection`](r/waf_file_protection.html)
* [`fortiappseccloud_waf_global_trust_list_parameter`](r/waf_global_trust_list_parameter.html)
* [`fortiappseccloud_waf_graphql_protection`](r/waf_graphql_protection.html)
* [`fortiappseccloud_waf_http_header_security`](r/waf_http_header_security.html)
* [`fortiappseccloud_waf_information_leakage`](r/waf_information_leakage.html)
* [`fortiappseccloud_waf_ip_protection`](r/waf_ip_protection.html)
* [`fortiappseccloud_waf_json_protection`](r/waf_json_protection.html)
* [`fortiappseccloud_waf_known_attacks`](r/waf_known_attacks.html)
* [`fortiappseccloud_waf_known_bots`](r/waf_known_bots.html)
* [`fortiappseccloud_waf_mitb_protection`](r/waf_mitb_protection.html)
* [`fortiappseccloud_waf_ml_api_protection`](r/waf_ml_api_protection.html)
* [`fortiappseccloud_waf_ml_bot_detection`](r/waf_ml_bot_detection.html)
* [`fortiappseccloud_waf_mobile_api_protection`](r/waf_mobile_api_protection.html)
* [`fortiappseccloud_waf_openapi_validation`](r/waf_openapi_validation.html)
* [`fortiappseccloud_waf_parameter_validation`](r/waf_parameter_validation.html)
* [`fortiappseccloud_waf_request_limits`](r/waf_request_limits.html)
* [`fortiappseccloud_waf_rewriting_requests`](r/waf_rewriting_requests.html)
* [`fortiappseccloud_waf_threshold_detection`](r/waf_threshold_detection.html)
* [`fortiappseccloud_waf_url_access`](r/waf_url_access.html)
* [`fortiappseccloud_waf_waiting_room`](r/waf_waiting_room.html)
* [`fortiappseccloud_waf_web_socket_security`](r/waf_web_socket_security.html)
* [`fortiappseccloud_waf_xml_protection_policy`](r/waf_xml_protection_policy.html)

Account takeover and OpenAPI validation use their separately reviewed disable behavior. Another 29 app modules with a standalone writable `configs.status` use a guarded GET/PUT/GET disable-on-destroy lifecycle. The app-scoped `fortiappseccloud_waf_caching_compression`, `fortiappseccloud_waf_content_routing`, and `fortiappseccloud_waf_global_trust_list_parameter` resources remain forget-with-warning because they do not have the same safe standalone disable contract. This app-resource behavior does not apply to typed template-module resources; all 31 template-module resources disable their remote template configuration on destroy.

### Template lifecycle and configuration

* [`fortiappseccloud_waf_template`](r/waf_template.html) - Creates, reads, imports, and deletes a user WAF template.
* [`fortiappseccloud_waf_template_attachment`](r/waf_template_attachment.html) - Owns one application-to-template membership.
* [`fortiappseccloud_waf_template_account_takeover`](r/waf_template_account_takeover.html)
* [`fortiappseccloud_waf_template_anomaly_detection`](r/waf_template_anomaly_detection.html)
* [`fortiappseccloud_waf_template_api_gateway`](r/waf_template_api_gateway.html)
* [`fortiappseccloud_waf_template_biometrics_based_detection`](r/waf_template_biometrics_based_detection.html)
* [`fortiappseccloud_waf_template_bot_deception`](r/waf_template_bot_deception.html)
* [`fortiappseccloud_waf_template_caching_compression`](r/waf_template_caching_compression.html)
* [`fortiappseccloud_waf_template_cookie_security`](r/waf_template_cookie_security.html)
* [`fortiappseccloud_waf_template_cors_protection`](r/waf_template_cors_protection.html)
* [`fortiappseccloud_waf_template_csrf_protection`](r/waf_template_csrf_protection.html)
* [`fortiappseccloud_waf_template_custom_rule`](r/waf_template_custom_rule.html)
* [`fortiappseccloud_waf_template_ddos_prevention`](r/waf_template_ddos_prevention.html)
* [`fortiappseccloud_waf_template_file_protection`](r/waf_template_file_protection.html)
* [`fortiappseccloud_waf_template_graphql_protection`](r/waf_template_graphql_protection.html)
* [`fortiappseccloud_waf_template_http_header_security`](r/waf_template_http_header_security.html)
* [`fortiappseccloud_waf_template_information_leakage`](r/waf_template_information_leakage.html)
* [`fortiappseccloud_waf_template_ip_protection`](r/waf_template_ip_protection.html)
* [`fortiappseccloud_waf_template_json_protection`](r/waf_template_json_protection.html)
* [`fortiappseccloud_waf_template_known_attacks`](r/waf_template_known_attacks.html)
* [`fortiappseccloud_waf_template_known_bots`](r/waf_template_known_bots.html)
* [`fortiappseccloud_waf_template_mitb_protection`](r/waf_template_mitb_protection.html)
* [`fortiappseccloud_waf_template_ml_api_protection`](r/waf_template_ml_api_protection.html)
* [`fortiappseccloud_waf_template_ml_bot_detection`](r/waf_template_ml_bot_detection.html)
* [`fortiappseccloud_waf_template_mobile_api_protection`](r/waf_template_mobile_api_protection.html)
* [`fortiappseccloud_waf_template_parameter_validation`](r/waf_template_parameter_validation.html)
* [`fortiappseccloud_waf_template_request_limits`](r/waf_template_request_limits.html)
* [`fortiappseccloud_waf_template_rewriting_requests`](r/waf_template_rewriting_requests.html)
* [`fortiappseccloud_waf_template_threshold_detection`](r/waf_template_threshold_detection.html)
* [`fortiappseccloud_waf_template_url_access`](r/waf_template_url_access.html)
* [`fortiappseccloud_waf_template_waiting_room`](r/waf_template_waiting_room.html)
* [`fortiappseccloud_waf_template_web_socket_security`](r/waf_template_web_socket_security.html)
* [`fortiappseccloud_waf_template_xml_protection_policy`](r/waf_template_xml_protection_policy.html)

Typed template-module resources are always local (`template=false` on the wire) and import by `template_id`. Because the public module endpoints expose no `DELETE` operation, destroy preserves the complete response, applies the resource's reviewed disable statuses, PUTs it, and verifies the normalized GET before removing state. Template caching/compression requires its top-level, cache, and compression statuses to be false together.

## Data Sources

* [`fortiappseccloud_waf_modules`](d/waf_modules.html) - Reads the complete app-level WAF module status inventory without changing module configuration.
* [`fortiappseccloud_waf_signature_exception`](d/waf_signature_exception.html) - Reads the optional template ID exposed for one application/signature pair; it does not expose or manage exception rules.

## Support

For bug reports, feature requests, or technical assistance, please contact FortiAppSecCloud Support. Note that access to support may require a valid subscription or license. For more information on obtaining support, visit the [Fortinet Support](https://support.fortinet.com). For details on how to contact support, see [Contacting Customer Service](https://docs.fortinet.com/document/fortiweb-cloud/latest/user-guide/796808/contacting-customer-service).
