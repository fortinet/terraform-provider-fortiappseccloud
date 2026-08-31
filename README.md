
# Terraform Provider for FortiAppSecCloud

- Official website: [https://www.terraform.io](https://www.terraform.io)
- For support, please contact your Fortinet representative.

## Requirements

- Terraform 1.5 or later

## Installation

To automatically install this provider, add the following configuration to your `main.tf` file:

```hcl
terraform {
  required_providers {
    fortiappseccloud = {
      source  = "fortinet/fortiappseccloud"
      version = ">= 2.0.0"
    }
  }
}

# Set FORTIAPPSECCLOUD_API_TOKEN in the environment.
provider "fortiappseccloud" {
  hostname = "api.appsec.fortinet.com"
}
```

Then run `terraform init` to download and install the provider:

```shell
$ terraform init
```

Provider credentials can be supplied in HCL or through `FORTIAPPSECCLOUD_API_TOKEN`, or `FORTIAPPSECCLOUD_USERNAME` together with `FORTIAPPSECCLOUD_PASSWORD`. Do not commit credentials to Terraform configuration or local credential files.

## WAF Resources

- `fortiappseccloud_waf_app` owns application identity, placement, listeners, block mode, automatic/custom certificate-management mode, and a bootstrap-only initial origin. Certificate mode does not upload certificate or private-key content.
- `fortiappseccloud_waf_origin_servers` owns ongoing origin server pools.
- `fortiappseccloud_waf_template` creates, reads, imports, and deletes user templates by stable `template_id`. Renaming replaces the template, and application membership remains separate.
- `fortiappseccloud_waf_template_attachment` owns one application-to-template membership.
- `fortiappseccloud_waf_openapi_validation` manages file-backed OpenAPI validation by application `ep_id`.
- `fortiappseccloud_waf_account_takeover` manages app-level account takeover protection. Because the API has no DELETE operation for this module, Terraform destroy disables it by setting `template=false` and `status=false`.
- `fortiappseccloud_waf_csrf_protection` manages app-level CSRF protection with protocol-5 ownership wrappers for `page_list` and `url_list`. Omitting a wrapper preserves its complete remote array, an empty wrapper clears it, and repeated `item` blocks replace it in Terraform order.
- `fortiappseccloud_waf_url_access` manages ordered app-level URL access rules. Its `rule_list` ownership wrapper preserves an omitted remote list, clears it when explicitly empty, or replaces it in Terraform order while generating hidden one-based indices.
- All 29 app modules with a standalone writable boolean `configs.status` disable on destroy. The provider performs a fresh GET, preserves the complete response, sets only `template=false` and `configs.status=false`, PUTs the result, and verifies it with another GET before removing state. Modules without a safe standalone status remain forget-with-warning.
- `fortiappseccloud_waf_template_<module>` resources manage typed template-level configuration for 31 supported modules. They use the same typed `configs` schema as their app-level counterpart and identify the template with `template_id`. Because the module endpoints have no `DELETE`, destroy disables the module with a preserving GET/PUT/GET lifecycle. Thirty resources change only `template=false` and `configs.status=false`; caching/compression uses its API-required coupled disable and also sets `configs.cache.status=false` and `configs.compress.status=false`.

Template creation requires a `201 Created` response containing `result.template_id`. The provider does not serve `log_settings` or certificate, private-key, CA, or CRL content-upload resources. `certificate_mode` only switches the application between `automatic` and `custom` certificate management.

See [`examples/waf`](examples/waf), [`examples/waf-template`](examples/waf-template), the [WAF configuration and import guidance](website/docs/guides/waf_configuration_guidance.html.markdown), the [v1.0.5 to v2.0 upgrade guide](website/docs/guides/v1_0_5_to_v2_0_0.html.markdown), the [template resource documentation](website/docs/r/waf_template.html.markdown), and the generated [CSRF protection](website/docs/r/waf_csrf_protection.html.markdown) and [template CSRF protection](website/docs/r/waf_template_csrf_protection.html.markdown) documentation.

Maintainers can use the target-gated [WAF v2.0 live-testing guide](guide/waf-v2-live-testing.md) for disposable app creation, resource lifecycle verification, and the separately gated captured-state migration check.

## Compatibility

The v2 provider is continuously exercised with Terraform CLI lifecycle tests. The current local verification baseline uses Terraform 1.15.x, and Terraform 1.5 or later is required (the registry-style `source` addressing used by the provider has been available since Terraform 0.13, but the v2 provider targets 1.5+).

## License

This project is licensed under the [MIT License](https://github.com/fortinet/terraform-provider-fortiappseccloud/blob/main/LICENSE).

## Releasing

Maintainers should follow the [release procedure](RELEASING.md) so every tag
publishes curated highlights together with GitHub-generated change details.

## Support

For bug reports, feature requests, or technical assistance, please contact FortiAppSecCloud Support. Note that access to support may require a valid subscription or license. For more information on obtaining support, visit the [Fortinet Support](https://support.fortinet.com). For details on how to contact support, see [Contacting Customer Service](https://docs.fortinet.com/document/fortiweb-cloud/latest/user-guide/796808/contacting-customer-service).
