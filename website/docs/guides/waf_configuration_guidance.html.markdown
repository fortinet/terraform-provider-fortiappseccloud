---
subcategory: ""
page_title: "FortiAppSecCloud WAF configuration and import guidance"
description: |-
  Important provider scope, recommended WAF protections, and safe import lifecycle guidance.
---

# WAF Configuration and Import Guidance

Review this guidance before managing an existing FortiAppSecCloud application or its WAF modules with Terraform.

## Certificate and Log Settings Scope

The provider does not manage the WAF log settings module. There is no `fortiappseccloud_waf_log_settings` resource or data source.

The provider also does not upload certificate material, including:

* custom server certificates or private keys;
* intermediate certificates;
* client-authentication or custom CA certificates;
* origin-server CA certificates; or
* certificate revocation lists.

The `fortiappseccloud_waf_app.certificate_mode` argument only selects one of the application certificate-management modes:

```hcl
resource "fortiappseccloud_waf_app" "example" {
  # Other application arguments are omitted.
  certificate_mode = "automatic" # Or "custom".
}
```

Selecting `custom` does not upload, attach, or validate a certificate, private key, CA, or CRL. Provision and manage custom certificate material through a supported FortiAppSecCloud workflow; switching the mode through Terraform does not replace that workflow. Do not place PEM data, private keys, or certificate passwords in Terraform configuration or state.

The provider-level `cacert_file` argument is different: it supplies a local CA bundle used by the Terraform provider to verify the FortiAppSecCloud API TLS connection. It does not upload a CA certificate to a WAF application.

## Strongly Recommended: Manage Origin Servers Explicitly

We strongly recommend declaring a [`fortiappseccloud_waf_origin_servers`](../r/waf_origin_servers.html) resource for every Terraform-managed application.

The `initial_origin` block in `fortiappseccloud_waf_app` exists only to bootstrap application creation. It is replacement-only and is not the standard resource for ongoing origin configuration. Use `fortiappseccloud_waf_origin_servers` to manage the application's complete mutable origin server pool, including multiple servers, health checks, persistence, weights, status, and TLS settings.

Because `fortiappseccloud_waf_origin_servers` owns the complete remote pool, declare every origin server that must remain configured. Do not provide a partial server list. Existing applications should follow the resource's import instructions and require a zero-change plan before Terraform takes ownership.

For example, this configuration manages one HTTPS origin in the application's complete `default_pool`:

```hcl
resource "fortiappseccloud_waf_origin_servers" "example" {
  ep_id = fortiappseccloud_waf_app.example.ep_id

  server_pools {
    name = "default_pool"

    health {
      enabled = false
    }

    persistence {
      type = "disable"
    }

    servers {
      address          = "origin.example.com"
      port             = 443
      ssl              = true
      encryption_level = "mozilla_intermediate"
      status           = "enable"
      type             = "domain"
    }
  }
}
```

Add another `servers` block for each additional origin in the pool. Review health checks, persistence, weights, and TLS policy for the application rather than copying example values unchanged.

## Recommended Minimum WAF Modules

As a minimum Terraform-managed protection baseline, configure these five modules for each protected application:

| Protection | Terraform resource | Purpose |
| --- | --- | --- |
| Known Attacks | [`fortiappseccloud_waf_known_attacks`](../r/waf_known_attacks.html) | Detects common attacks and known exploit signatures. |
| Request Limits | [`fortiappseccloud_waf_request_limits`](../r/waf_request_limits.html) | Enforces request-size, count, method, and malformed-request limits. |
| DDoS Prevention | [`fortiappseccloud_waf_ddos_prevention`](../r/waf_ddos_prevention.html) | Configures connection, request, session, and flood controls. |
| Known Bots | [`fortiappseccloud_waf_known_bots`](../r/waf_known_bots.html) | Controls known good and bad bot categories and exceptions. |
| IP Protection | [`fortiappseccloud_waf_ip_protection`](../r/waf_ip_protection.html) | Applies IP reputation, geographic policy, and explicit IP rules. |

Choose one ownership model for each module:

* Set `template = false` and declare a `configs` block to manage application-local settings.
* Set `template = true` and omit `configs` to inherit the module from the application's attached template. Ensure the corresponding `fortiappseccloud_waf_template_<module>` resource manages the template configuration.

The following application-local example establishes the five resource addresses and enables their top-level status. It is a starting structure, not a universal security policy. Review and configure actions, thresholds, lists, exceptions, and rollout mode for the application's normal traffic before applying it.

```hcl
variable "app_ep_id" {
  type = string
}

resource "fortiappseccloud_waf_known_attacks" "baseline" {
  ep_id    = var.app_ep_id
  template = false

  configs {
    status = true
  }
}

resource "fortiappseccloud_waf_request_limits" "baseline" {
  ep_id    = var.app_ep_id
  template = false

  configs {
    status = true
  }
}

resource "fortiappseccloud_waf_ddos_prevention" "baseline" {
  ep_id    = var.app_ep_id
  template = false

  configs {
    status = true
  }
}

resource "fortiappseccloud_waf_known_bots" "baseline" {
  ep_id    = var.app_ep_id
  template = false

  configs {
    status = true
  }
}

resource "fortiappseccloud_waf_ip_protection" "baseline" {
  ep_id    = var.app_ep_id
  template = false

  configs {
    status        = true
    ip_reputation = true
  }
}
```

For an application created in the same configuration, `ep_id` can refer directly to `fortiappseccloud_waf_app.example.ep_id`. Consider starting enforcement-sensitive settings in an alerting mode, observing legitimate traffic, and then moving to the reviewed blocking policy.

## Import Existing Applications Safely

Importing `fortiappseccloud_waf_app` imports only the application resource. It does not automatically import the application's WAF modules, template attachment, origin server pool, or other separately managed resources. Remote modules that are absent from Terraform state remain unmanaged and are not disabled merely because the application was imported.

To bring an existing WAF module under Terraform management:

1. Create the matching resource block before importing it. Set `ep_id` to the existing application, select the current `template` mode, and make local `configs` match the current remote configuration.
2. Import that specific module using the application `ep_id`.
3. Run a normal plan and require no changes before proceeding to the next module.

For example:

```shell
terraform import fortiappseccloud_waf_known_attacks.baseline 1234567890
terraform plan -detailed-exitcode
```

Repeat this process for every existing module that Terraform should own. Import modules one at a time so configuration differences and complete-list ownership are easy to review. After import, keep each specific module resource declared in HCL; the `fortiappseccloud_waf_app` resource does not replace those declarations.

## Removing an Imported Module Resource

Do not remove an imported module's resource block and apply the resulting plan unless the remote disable is intentional.

The five recommended app-module resources above use disable-on-destroy behavior. When Terraform destroys one of those resources, the provider preserves the remaining remote response, sets `template = false` and `configs.status = false`, verifies the update, and then removes the resource from state. Removing its HCL block after import therefore plans a Terraform destroy that disables that live module; it does not merely stop tracking it.

All 31 typed template-module resources also use disable-on-destroy. Removing an imported `fortiappseccloud_waf_template_<module>` resource preserves the remaining template-module response, applies its reviewed status fields, verifies the update, and disables that module in the template. Thirty resources set `template = false` and `configs.status = false`; caching/compression additionally sets `configs.cache.status = false` and `configs.compress.status = false`. Removing the base `fortiappseccloud_waf_template` resource is different: it deletes a user-defined template after its dependent resources are destroyed.

Always read the resource's **Destroy Behavior** section before removing any WAF resource. Some app-scoped resources forget state while preserving remote configuration, but none of the 31 typed template-module resources is forget-only. Lifecycle behavior must not be assumed from another resource.

If the goal is to stop Terraform management while keeping a module enabled, do not apply the destroy plan. Back up state, remove the resource from Terraform state without destroying it, and remove its HCL block as part of the same reviewed change:

```shell
umask 077
terraform state pull > terraform-state-before-module-removal.backup
terraform state rm fortiappseccloud_waf_known_attacks.baseline
terraform plan
```

The final plan must not propose recreating, changing, or destroying the remote module. Keep the state backup protected and do not commit it.
