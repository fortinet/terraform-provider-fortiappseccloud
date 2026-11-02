---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_app Resource - fortiappseccloud"
description: |-
  Manages a FortiAppSec Cloud WAF application using stable endpoint identity.
---

# fortiappseccloud_waf_app

Owns application identity, placement, public listener settings (including HTTP/2 and IPv6), SSL/TLS options, block mode, certificate-management mode and ACME challenge mode, and the block-page message. `initial_origin` is required only to bootstrap application creation and is replacement-only; ongoing server-pool configuration belongs to `fortiappseccloud_waf_origin_servers`. Template membership belongs to `fortiappseccloud_waf_template_attachment`.

## Example Usage

```hcl
resource "fortiappseccloud_waf_app" "example" {
  app_name            = "test-app"
  domain_name         = "www.example.com"
  services            = ["http", "https"]
  http_port           = 80
  https_port          = 443
  platform            = "AWS"
  region              = "us-east-1"
  cdn                 = false
  block_mode          = false
  certificate_mode    = "automatic"
  cert_challenge_mode = "http"
  http2_status        = true
  block_url           = "PredefinedMsg"
  precheck            = true

  ssl_options {
    encryption_level       = "mozilla_intermediate"
    http_2_https           = true
    hsts_header            = true
    hsts_max_age           = 31536000
    internal_cookie_secure = true
  }

  initial_origin {
    address  = "origin.example.com"
    protocol = "https"
    port     = 443
  }
}
```

## Argument Reference

* `app_name` - (Required, replacement-only) Application name.
* `domain_name` - (Required, replacement-only) Primary protected domain.
* `extra_domains` - (Optional) Up to nine additional domains.
* `services` - (Required) Set containing `http`, `https`, or both.
* `http_port` - (Optional) HTTP listener port; defaults to `80`.
* `https_port` - (Optional) HTTPS listener port; defaults to `443`.
* `platform` - (Required, replacement-only) `AWS`, `Azure`, `GCP`.
* `region` - (Required when `cdn=false`) Public logical region.
* `cdn` - (Optional) Enables CDN placement; defaults to `false`.
* `global_cdn` - (Optional) With `cdn=true`, choose global CDN instead of a continent.
* `continent` - (Optional) With `cdn=true`, choose continent placement instead of global CDN.
* `block_mode` - (Optional) Application block mode; defaults to `false`.
* `certificate_mode` - (Optional) Certificate-management mode: `automatic` maps to API `cert_type=0`, and `custom` maps to `cert_type=1`. When omitted, the create API chooses its default and Terraform records the observed mode during refresh. Switching this field does not upload or attach certificate, private-key, CA, or CRL content; custom certificate material must be managed outside this provider.
* `cert_challenge_mode` - (Optional) ACME challenge mode used by automatic certificates: `http` or `dns`. Applies when `certificate_mode` is `automatic`; the API ignores it for custom certificates.
* `http2_status` - (Optional) Enables HTTP/2 on the HTTPS listener. The API requires the `https` service and standard listener ports; invalid combinations are rejected by the API.
* `ipv6_option` - (Optional) Enables IPv6 listener addresses. The API supports this on AWS applications with standard listener ports; other combinations are rejected by the API.
* `block_url` - (Optional) Block-page message name used for blocking responses. Valid names depend on the block-page messages configured for your account; the API validates the name.
* `precheck` - (Optional) Run public DNS and origin-connectivity checks before create; defaults to `false`.
* `initial_origin` - (Required for create, replacement-only) Bootstrap address, `http`/`https` protocol, and port.
* `ssl_options` - (Optional) SSL/TLS options. Omit the block to preserve the remote SSL/TLS configuration and keep the block absent from Terraform state. Its nested attributes are documented below.

#### `ssl_options` attributes

* `encryption_level` - (Required when `ssl_options` is configured) `mozilla_modern` (TLS 1.3 only), `mozilla_intermediate` (TLS 1.2/1.3), or `mozilla_old` (TLS 1.1/1.2/1.3).
* `tls_1_1`, `tls_1_2`, `tls_1_3` - (Computed) Enabled TLS versions. The API derives them from `encryption_level` (and disables TLS 1.1 when HTTP/2 is enabled), so they are recorded, not configured.
* `http_2_https` - (Optional) Redirect HTTP to HTTPS. The API allows this only when both services are enabled and the listener ports remain 80/443.
* `hsts_header` - (Optional) Send the HSTS header. The HSTS settings below depend on this switch: setting any of `hsts_max_age`, `hsts_preload`, or `hsts_sub_domains` while `hsts_header` is disabled fails configuration validation with an error — enable `hsts_header` or remove the dependent fields.
* `hsts_max_age` - (Optional) HSTS max-age in seconds; 3600-31536000. Only meaningful with `hsts_header` enabled; configuring it while HSTS is disabled is rejected.
* `hsts_preload` - (Optional) Include this application in browser preload lists. Only meaningful with `hsts_header` enabled; configuring it while HSTS is disabled is rejected.
* `hsts_sub_domains` - (Optional) Apply HSTS to sub-domains. Only meaningful with `hsts_header` enabled; configuring it while HSTS is disabled is rejected.
* `internal_cookie_secure` - (Optional) Mark internal cookies `Secure`.
* `internal_cookie_httponly` - (Optional) Mark internal cookies `HttpOnly`.
* `selected_ssl_custom_cipher`, `selected_ssl_custom_cipher_http2`, `selected_tls13_custom_cipher` - (Computed) Cipher lists in effect, recorded from the remote configuration. Custom cipher selection is not configurable through this resource; do not add these attributes to configuration.
* `available_ssl_custom_cipher`, `available_ssl_custom_cipher_http2`, `available_tls13_custom_cipher` - (Computed) Cipher lists available to this application.

### Endpoint fields not managed by this resource

The application endpoint API exposes one-click GSLB settings and client-certificate verification/forwarding attributes. These settings are intentionally not declared by this resource. Values configured for them outside Terraform are preserved on every update: the resource reads the complete endpoint document before writing and only replaces the fields it owns. Do not add these attributes to configuration; they cannot be managed here.

## Attributes Reference

* `ep_id` - Stable application endpoint ID and Terraform identity.
* `cnames` - CNAME values returned by onboarding and refresh.
* `placement_region` - Server-reported platform region.
* `attached_template_id` - Observed remote template ID. This is read-only; declare `fortiappseccloud_waf_template_attachment` to own membership.
* `attached_template_name` - Observed remote template name, including the v1 template selection after migration refresh.
* `legacy_app_name` - Migration-only identity; normally null after refresh.

## Import

Import using either stable `ep_id` or a unique legacy application name:

```shell
terraform import fortiappseccloud_waf_app.example 1234567890
```

Because the public read APIs do not expose the bootstrap origin, the first configured `initial_origin` after import is adopted into Terraform state without replacing the existing application. Later changes to that known value remain replacement-only.

Import records the remote `ssl_options`. Keep the block in configuration to manage those settings, or omit it to remove the block from Terraform state while preserving the remote SSL configuration.

Legacy v1.0.5 state is upgraded in-provider; no manual state JSON editing is intended.

Importing this resource does not import separately managed WAF modules. Before adopting existing module configuration, follow the [WAF configuration and import guidance](../guides/waf_configuration_guidance), including its disable-on-destroy warning.

## Migrating v1.0.5 Configuration

State migration does not rewrite Terraform configuration. Follow the complete [v1.0.5 to v2.0 upgrade guide](../guides/v1_0_5_to_v2_0_0) before selecting v2 or applying changes.

## Destroy Behavior

Destroy deletes the WAF application from FortiAppSec Cloud and waits until its removal is observable before Terraform removes the resource from state. This is a remote delete, not a state-only operation. Destroy separately managed application modules, origin-server configuration, and template attachment resources first; Terraform normally orders them correctly when their `ep_id` refers to this resource.
