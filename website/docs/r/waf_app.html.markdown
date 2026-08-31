---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_app Resource - fortiappseccloud"
description: |-
  Manages a FortiAppSec Cloud WAF application using stable endpoint identity.
---

# fortiappseccloud_waf_app

Owns application identity, placement, public listener settings, block mode, and automatic/custom certificate-management mode. `initial_origin` is required only to bootstrap application creation and is replacement-only; ongoing server-pool configuration belongs to `fortiappseccloud_waf_origin_servers`. Template membership belongs to `fortiappseccloud_waf_template_attachment`.

## Example Usage

```hcl
resource "fortiappseccloud_waf_app" "example" {
  app_name         = "test-app"
  domain_name      = "www.example.com"
  services         = ["http", "https"]
  http_port        = 80
  https_port       = 443
  platform         = "AWS"
  region           = "us-east-1"
  cdn              = false
  block_mode       = false
  certificate_mode = "automatic"
  precheck         = true

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
* `platform` - (Required, replacement-only) `AWS`, `Azure`, `GCP`, `OCI`, or `C8T`.
* `region` - (Required when `cdn=false`) Public logical region.
* `cdn` - (Optional) Enables CDN placement; defaults to `false`.
* `global_cdn` - (Optional) With `cdn=true`, choose global CDN instead of a continent.
* `continent` - (Optional) With `cdn=true`, choose continent placement instead of global CDN.
* `block_mode` - (Optional) Application block mode; defaults to `false`.
* `certificate_mode` - (Optional) Certificate-management mode: `automatic` maps to API `cert_type=0`, and `custom` maps to `cert_type=1`. When omitted, the create API chooses its default and Terraform records the observed mode during refresh. Switching this field does not upload or attach certificate, private-key, CA, or CRL content; custom certificate material must be managed outside this provider.
* `precheck` - (Optional) Run public DNS and origin-connectivity checks before create; defaults to `false`.
* `initial_origin` - (Required for create, replacement-only) Bootstrap address, `http`/`https` protocol, and port.

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

Legacy v1.0.5 state is upgraded in-provider; no manual state JSON editing is intended.

Importing this resource does not import separately managed WAF modules. Before adopting existing module configuration, follow the [WAF configuration and import guidance](../guides/waf_configuration_guidance.html), including its disable-on-destroy warning.

## Migrating v1.0.5 Configuration

State migration does not rewrite Terraform configuration. Follow the complete [v1.0.5 to v2.0 upgrade guide](../guides/v1_0_5_to_v2_0_0.html) before selecting v2 or applying changes.

## Destroy Behavior

Destroy deletes the WAF application from FortiAppSec Cloud and waits until its removal is observable before Terraform removes the resource from state. This is a remote delete, not a state-only operation. Destroy separately managed application modules, origin-server configuration, and template attachment resources first; Terraform normally orders them correctly when their `ep_id` refers to this resource.
