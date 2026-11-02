## Unreleased

## 2.1.0 (November 2, 2026)

NOTES:

* **Pinned OpenAPI contract refresh:** The pinned `openapi_spec/openapi.json` input is now version 26.4 (SHA-256 `c96ba675c156cb5846bd70c7dbc820cc3ac39c72fbbd4deda71f27d9152d6741`), covering 273 WAF operations (267 public / 6 non-public). New public operations added by the API are classified as follows: `acceleration` is implemented as a generated module; `cert_proxy` is an explicit product-scope exclusion because it uploads CA certificate, private-key, and optional password content against an import/delete action shape (the same exclusion family as the certificate/CRL uploads); `traffic_summary/agent_statistics` joins the other read-only traffic statistics exclusions. The `dns_resolve` GET/PUT and `cert_domains` detail/refresh pairs are explicit scope exclusions.
* **Application platforms:** `fortiappseccloud_waf_app.platform` now accepts `AWS`, `Azure`, and `GCP`. Configurations using `OCI` or `C8T` no longer pass validation.

FEATURES:

* **Web content acceleration:** Added `fortiappseccloud_waf_acceleration` for typed management of CSS/JS/HTML minification, head combining, CSS-to-head movement, and the bounded (max 256) ordered `exception_list`, with verified disable-on-destroy via `configs.status=false`.
* **Template web content acceleration:** Added `fortiappseccloud_waf_template_acceleration` using the same typed configuration model as the application-level resource, with guarded disable-on-destroy.
* **Application endpoint attributes:** `fortiappseccloud_waf_app` now manages `http2_status`, `ipv6_option`, `cert_challenge_mode` (`http`/`dns`), `block_url`, and the complete `ssl_options` block on the application endpoint. Unset fields preserve the remote value and refresh records the observed configuration; enabled TLS versions and the cipher lists in effect are computed from the remote configuration, and the HSTS max-age, preload, and sub-domains settings are validated as dependents of `hsts_header`. One-click GSLB and client-certificate settings remain outside this resource and keep their remote values during updates.

BUG FIXES:

* **Optional SSL configuration:** Existing application configurations can omit `ssl_options` without requiring an encryption level or importing the remote SSL block into Terraform state. Remote SSL settings remain preserved during unrelated endpoint updates.
* **Application endpoint failure recovery:** Preserve the created application's identity in Terraform state if a subsequent endpoint read or settings update fails, allowing Terraform to clean up a partial creation.
* **Endpoint state and validation:** Preserve empty block-page names returned by the API and defer HSTS dependency validation while `hsts_header` is unknown.

## 2.0.1 (September 7, 2026)

ENHANCEMENTS:

* **ML bot detection challenge disable option:** `fortiappseccloud_waf_ml_bot_detection` now accepts `Disable` for the `challenge` field, allowing ML bot enforcement to be disabled without changing the rest of the module configuration. Omission still preserves the current value.

## 2.0.0 (August 31, 2026)

NOTES:

* **Major WAF provider expansion:** Version 2.0 grows the provider from two resources to 69 resources and two data sources. It adds typed Terraform management for application configuration, WAF modules, templates, template modules, origin servers, template attachments, and supporting read-only views.
* **Supported scope:** `certificate_mode` switches an application between automatic and custom certificate management, but this release does not upload certificate, private-key, CA, or CRL content. The `log_settings` API is also not exposed because it does not provide a durable typed configuration contract.
* **Legacy provider code scheduled for removal in v2.1.0:** The v1.0.5 SDKv2 provider implementation is retained in v2.0 only for automatic state upgrade and is not used by the Framework provider that v2 serves. It will be removed in v2.1.0 and later. Removal is safe for any configuration that has already completed the [v1.0.5 to v2.0 upgrade guide](https://github.com/fortinet/terraform-provider-fortiappseccloud/blob/main/website/docs/guides/v1_0_5_to_v2_0_0.html.markdown); state upgrade is performed by built-in Framework upgraders that do not depend on the legacy code. Users still on v1.0.5 should complete the v2.0 migration before upgrading to v2.1.0 or later.

BREAKING CHANGES:

* **Configuration migration is required:** Existing v1.0.5 state for `fortiappseccloud_waf_app` and `fortiappseccloud_waf_openapi_validation` is upgraded automatically, but configurations must be updated to the v2 schema before the first normal plan. Follow the [v1.0.5 to v2.0 upgrade guide](https://github.com/fortinet/terraform-provider-fortiappseccloud/blob/v2.0.0/website/docs/guides/v1_0_5_to_v2_0_0.html.markdown), begin with a refresh-only plan, and do not apply an unexpected delete or replacement plan.
* **Application schema and identity:** `fortiappseccloud_waf_app` now uses stable application endpoint IDs and replaces legacy arguments such as `app_service`, `origin_server_*`, `block`, and computed `cname` with typed `services`, `initial_origin`, `block_mode`, and `cnames` fields. Platform and placement must be represented explicitly where required.
* **OpenAPI validation identity:** `fortiappseccloud_waf_openapi_validation` now identifies its application with `ep_id` instead of `app_name`. Keep the existing Terraform resource address and validation-file paths during migration.

FEATURES:

* **Application-level WAF modules:** Added 33 typed `fortiappseccloud_waf_<module>` resources covering security rules, access controls, API protection, bot mitigation, request and response controls, DDoS protection, waiting rooms, caching and compression, request rewriting, content routing, and other WAF configuration modules.
* **WAF templates and template modules:** Added `fortiappseccloud_waf_template` for create, read, import, and delete lifecycle management by stable `template_id`; `fortiappseccloud_waf_template_attachment` for application membership; and 31 typed `fortiappseccloud_waf_template_<module>` resources that use the same typed configuration models as their application-level counterparts.
* **Application and origin management:** Reworked `fortiappseccloud_waf_app` to manage application identity, placement, listeners, CDN and block modes, bootstrap origin, and observed certificate mode. Added `fortiappseccloud_waf_origin_servers` for ongoing ownership of complete origin-server pools.
* **WAF data sources:** Added `fortiappseccloud_waf_modules` for application module status and `fortiappseccloud_waf_signature_exception` for read-only signature-exception details.
* **Certificate management mode:** Added `certificate_mode` to `fortiappseccloud_waf_app` for switching between `automatic` and `custom` certificate management without placing certificate or private-key content in Terraform configuration.

ENHANCEMENTS:

* **Preserving WAF module updates:** Module updates use fresh remote reads and merge typed Terraform changes into the complete result so fields outside the resource's ownership are preserved.
* **Safe module destroy behavior:** App modules with a safe writable status are disabled before Terraform removes them from state; modules without a safe disable operation are left unchanged with a warning. All 31 template-module resources use guarded disable-on-destroy and verify the resulting remote configuration. The caching and compression resource also disables its API-coupled cache and compression status fields.
* **Typed validation and collection ownership:** Module schemas enforce reviewed API types, ranges, enums, cross-field rules, and ordered collection behavior. Omitted collections preserve remote values, explicit empty collections clear them, and configured collections replace them in Terraform order.
* **Provider connectivity controls:** Added configurable request timeout, custom CA certificate support, and an explicit insecure-TLS opt-in for development environments while retaining API-token and username/password authentication options.

BUG FIXES:

* **Readable API validation errors:** Preserve sanitized `detail` and `message` reasons in provider diagnostics while continuing to redact credentials, request values, endpoint identifiers, and secret-bearing response fields.

## 1.0.5 (October 14, 2025)

BUG FIXES:
* resource/fortiappseccloud_waf_app: Fixed panic when head_availability and head_status_code have no default values by implementing getFloat64OrDefault helper function.

## 1.0.4 (October 3, 2025)

BUG FIXES:
* resource/fortiappseccloud_waf_app: Prevent panic (`interface{} is nil, not []interface{}`) when IPRegion API response no longer includes `region` and instead returns `support_platform_regions`.

ENHANCEMENTS:
* resource/fortiappseccloud_waf_app: Extract platform from current API field `cluster:platform` instead of deprecated `region`.

## 1.0.3 (December 9, 2024)

BUG FIXES:

* **Guides:** Fix migration document path from Guides to guides.

## 1.0.2 (December 8, 2024)

IMPROVEMENTS:

* **Guides:** Added document for FortiWebCloud migration.


## 1.0.1 (December 8, 2024)

IMPROVEMENTS:

* **openapi_validation:** Added document in `waf_openapi_validation.html.markdown`


## 1.0.0

FEATURES:

* **New Resource:** `FrotiAppSec Cloud`
