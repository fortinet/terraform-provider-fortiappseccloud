# Terraform: FortiAppSecCloud as a Provider

FortiAppSecCloud's Terraform support provides users with efficient ways to deploy, manage, and automate application security across multiple cloud environments. By using Terraform, various IT infrastructure needs can be automated, reducing errors from repetitive manual configurations.

The Terraform FortiAppSecCloud provider can be used to automatically onboard or delete applications.

Before using these examples, review the public [WAF configuration and import guidance](../../website/docs/guides/waf_configuration_guidance.html.markdown). The provider does not manage WAF log settings or upload certificate/CA content, and imported app-module resources can disable their remote module when destroyed.

The following example demonstrates how to use the Terraform FortiAppSecCloud provider to perform configuration changes on FortiAppSecCloud. Requirements are as follows:

1. FortiAppSecCloud API access.
2. FortiAppSecCloud Provider version 2.0.0 or later.
3. A Terraform version supported by provider 2.0.0.

## Configure FortiAppSecCloud with the Terraform Provider

### Step 1: Initialize the `fortiappseccloud` Provider

1. Create a new file with the `.tf` extension for configuring your FortiAppSecCloud:

    ```shell
    $ touch main.tf
    $ ls
    main.tf
    ```

2. Export an API token with the necessary permissions, then edit the `main.tf` Terraform configuration file. Environment variables avoid placing credentials in Terraform configuration or local credential files.

   ```shell
   export FORTIAPPSECCLOUD_API_TOKEN="your_api_key"
   ```

   ```hcl
   # Configure the FortiAppSecCloud Provider
   provider "fortiappseccloud" {
     hostname = "api.appsec.fortinet.com"
   }
   ```

## Step 2: Configure Resources for Application Onboarding

1. Specify your application name, domain, server settings, and other preferences in main.tf. Here’s an example configuration:

    ```hcl
    # Example resource for application onboarding
    resource "fortiappseccloud_waf_app" "app_example" {
        app_name     = "from_terraform"
        domain_name  = "www.example.com"
        services     = ["http", "https"]
        http_port    = 80
        https_port   = 443
        platform     = "AWS"
        region       = "us-east-1"
        cdn          = false
        block_mode   = false

        initial_origin {
            address  = "origin.example.com"
            protocol = "https"
            port     = 443
        }
    }

    # Example resource for OpenAPI validation
    resource "fortiappseccloud_waf_openapi_validation" "openapi_validation_example" {
        ep_id             = fortiappseccloud_waf_app.app_example.ep_id
        enable            = true
        action            = "alert_deny"
        validation_files = [
            "${path.module}/openapi.yaml"
        ]
    }

    # Example app-level account takeover configuration
    resource "fortiappseccloud_waf_account_takeover" "account_takeover_example" {
        ep_id    = fortiappseccloud_waf_app.app_example.ep_id
        template = false

        configs {
            status                = true
            action                = "alert_deny"
            auth_url              = "/login"
            cred_stuffing_protect = true
            username              = "USERNAME"
            password              = "PASSWORD"
        }
    }

    # Example app-level CSRF protection configuration
    resource "fortiappseccloud_waf_csrf_protection" "csrf_protection_example" {
        ep_id    = fortiappseccloud_waf_app.app_example.ep_id
        template = false

        configs {
            status = true
            action = "alert_deny"

            page_list {
                item {
                    filter = true
                    url    = "/checkout"
                    name   = "csrf_token"
                    value  = "expected"
                }
            }

            url_list {
                item {
                    url = "/api/orders"
                }
            }
        }
    }

    # Example app-level URL access configuration
    resource "fortiappseccloud_waf_url_access" "url_access_example" {
        ep_id    = fortiappseccloud_waf_app.app_example.ep_id
        template = false

        configs {
            status = true

            rule_list {
                item {
                    action   = "pass"
                    name     = "allow-application-api"
                    url      = "/api/application/"
                    url_type = "string"
                }

                item {
                    action   = "alert_deny"
                    name     = "deny-admin-area"
                    url      = "^/admin/(login|setup)$"
                    url_type = "regex"
                }
            }
        }
    }
    ```

## Step 3: Initialize the Working Directory

1. Save the `main.tf` configuration file.

2. In the terminal, enter `terraform init` to initialize the working directory:

    ```shell
    $ terraform init
    ```
    This initializes the backend and provider plugins for Terraform.

## Step 4: Verify the Provider Version

1. Run `terraform -v` to verify the Terraform and provider versions:

    ```shell
    $ terraform -v
    Terraform v1.15.x
    + provider registry.terraform.io/fortinet/fortiappseccloud v2.0.0
    ```

## Step 5: Preview Configuration Changes

1. Use `terraform plan` to view the changes that Terraform will apply to FortiAppSecCloud:

    ```shell
    $ terraform plan
    ```
    The plan output will indicate the resources that will be created or modified. This directory contains 34 application/application-module resource examples and both read-only data sources. Review every `.tf` file and replace placeholder domains, origins, IDs, and validation-file paths before applying it.

## Step 6: Apply the Configuration

1. After verifying the plan, use `terraform apply` to apply the configuration:

    ```shell
    $ terraform apply
    ```
    Terraform will prompt for confirmation. Enter `yes` to proceed. Because Terraform loads every `.tf` file in the directory, this applies the complete example set rather than only the abbreviated configuration shown above.

## Step 7: Delete Resources

1. To delete the resources and configurations from FortiAppSecCloud, use `terraform destroy`:

    ```shell
    $ terraform destroy
    ```
    Terraform will confirm the resources to be deleted. Enter `yes` to proceed.

    Destroying `fortiappseccloud_waf_account_takeover` disables the module by setting `template=false` and `status=false`, then removes it from Terraform state. The API does not expose a DELETE operation for this module, so destroy does not delete the application or a backend subresource.

    Destroying `fortiappseccloud_waf_csrf_protection` performs a fresh GET, preserves unowned fields, sets only `template=false` and `configs.status=false`, PUTs the complete result, and verifies it with another GET before removing state.

    Destroying `fortiappseccloud_waf_url_access` uses the same guarded disable-and-verify lifecycle.

    Destroying `fortiappseccloud_waf_request_limits` also uses the guarded disable-and-verify lifecycle. These resources are among the 29 app modules that use guarded disable-on-destroy. All 31 typed template-module resources use the same preserving lifecycle against their template endpoints. Thirty disable with `configs.status=false`; template caching/compression also sets its API-coupled cache and compression statuses false.

## Account Takeover Configuration Rules

`fortiappseccloud_waf_account_takeover` manages app-level settings and imports by application `ep_id`. Set `template=true` without a `configs` block to inherit from the application's attached template. Set `template=false` with a `configs` block to manage local settings. Template-level account takeover APIs are not covered by this resource.

## CSRF Protection Configuration Rules

`fortiappseccloud_waf_csrf_protection` is generated from the pinned CSRF contract and manages app-level settings imported by application `ep_id`. Set `template=true` without `configs`, or set `template=false` with `configs` for local ownership. The protocol-5 `page_list` and `url_list` ownership wrappers distinguish three cases: omit the wrapper to preserve the complete raw remote array, use an empty wrapper such as `url_list {}` to send `[]`, or add repeated `item` blocks to replace the array in Terraform order. The provider generates hidden one-based `idx` values. See the generated [CSRF resource documentation](../../website/docs/r/waf_csrf_protection.html.markdown) for validation, import, and fail-closed unknown-item behavior.

## URL Access Configuration Rules

`fortiappseccloud_waf_url_access` is generated from the pinned URL-access contract and imports by application `ep_id`. With `template=false`, the optional `rule_list` ownership wrapper distinguishes omission (preserve the complete raw remote list), an empty wrapper (send `[]`), and repeated `item` blocks (replace the complete ordered list). Every rule requires `action`, `name`, `url`, and `url_type`; `action` must be `pass`, `alert_deny`, `deny_no_log`, or `continue`; `url_type` is defined by pinned OpenAPI 26.3.a and must be `string` (literal URL matching) or `regex` (regular-expression matching). The provider generates hidden sequential one-based `idx` values and rejects unknown item keys when the list is owned or imported. See the generated [URL access resource documentation](../../website/docs/r/waf_url_access.html.markdown).

## Request Limits Configuration Rules

`fortiappseccloud_waf_request_limits` is generated from the pinned request-limits contract and imports by application `ep_id`. With `template=false`, the `configs` block manages the pinned integer, boolean, enum, and read-only scalar fields plus the `allow_methods` ownership wrapper. `allow_methods` is an array of HTTP-method enum strings encoded as an ownership wrapper of `item` blocks carrying a synthetic `method` attribute: omit the wrapper to preserve the complete raw remote array, use an empty wrapper such as `allow_methods {}` to send `[]`, or add repeated `item` blocks to replace the array in Terraform order. Integer scalars are validated against their reviewed minimum/maximum at plan time. See the generated [request limits resource documentation](../../website/docs/r/waf_request_limits.html.markdown).

Provider credentials can be supplied in HCL or through `FORTIAPPSECCLOUD_API_TOKEN`, or `FORTIAPPSECCLOUD_USERNAME` together with `FORTIAPPSECCLOUD_PASSWORD`. Do not commit credentials to Terraform files or local credential files. The `password` setting is sensitive in Terraform output but can still be stored in Terraform state.

---

This guide provides an example of onboarding an application with OpenAPI validation on FortiAppSecCloud using Terraform. For further configuration options, refer to the main [README](../../README.md) or the Terraform Registry documentation.
