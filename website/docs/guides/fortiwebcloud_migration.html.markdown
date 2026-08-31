---
subcategory: ""
page_title: "Legacy: migrate FortiWebCloud private provider to FortiAppSecCloud 1.0.5"
description: |-
  Legacy migration from the FortiWebCloud private provider to FortiAppSecCloud 1.0.5.
---

# Legacy migration from FortiWebCloud private provider to FortiAppSecCloud 1.0.5

This guide covers only the provider-address and resource-name migration from the historical private provider to public provider version `1.0.5`. The legacy configuration shown below is not valid v2 configuration, so the version is intentionally pinned instead of using an open-ended constraint that could select v2.

After this migration is complete, follow the [v1.0.5 to v2.0 upgrade guide](v1_0_5_to_v2_0_0.html) before selecting provider version `2.0.0` or later. The v2 provider upgrades same-provider v1.0.5 state in-process; do not manually edit state JSON for that separate upgrade.

## Important Notes
**State File Backup**: Before modifying the state file, ensure it is backed up to prevent data loss.

## 1. Verify the Existing Terraform State and Provider Configuration
Check the current Terraform Provider configuration, especially the source of the private provider:

```hcl
terraform {
  required_providers {
    fortiwebcloud = {
      source  = "fortinet/terraform/fortiwebcloud" # old private provider
      version = "1.0.2"
    }
  }
}
```

Check the current Terraform State file to ensure all resources are correctly bound to the existing provider:

```shell
terraform state list
```

The output should be similar to:
```shell
fortiwebcloud_app.app_example
```
This confirms that your resources are correctly bound to the private provider resource `fortiwebcloud_app` and are ready for migration.

## 2. Modify the Provider and Resources

### 2.1 Replace the Provider with the Public Provider
Replace the provider configuration from the local or private source `fortinet/terraform/fortiwebcloud` to the public source `fortinet/fortiappseccloud`. This step switches to the newly published provider `fortiappseccloud`.

```hcl
terraform {
  required_providers {
    fortiappseccloud = {
      source  = "fortinet/fortiappseccloud"  # Use the public provider name
      version = "= 1.0.5"                    # Keep this legacy migration pinned
    }
  }
}
```

### 2.2 Replace the Provider Block and Hostname

1. Rename the provider block from `fortiwebcloud` to `fortiappseccloud`.
2. Set `hostname` to the FortiAppSec Cloud API hostname, such as `api.appsec.fortinet.com`.
3. If necessary, replace the API token with one issued for FortiAppSec Cloud. Do not commit credentials to the configuration.

```hcl
provider "fortiappseccloud" {
  hostname  = "api.appsec.fortinet.com"
  api_token = "your-new-api-token"
}
```

### 2.3 Replace Resource Type Names for the Public Provider

1. Replace the resource type `fortiwebcloud_app` with `fortiappseccloud_waf_app`.
2. If used, replace `fortiwebcloud_openapi_validation` with `fortiappseccloud_waf_openapi_validation`.
3. If used, replace references such as `fortiwebcloud_app.app_example` with `fortiappseccloud_waf_app.app_example`.

```hcl
resource "fortiappseccloud_waf_app" "app_example" {
  app_name    = "from_terraform"
  domain_name = "www.example.com"
  app_service = {
    http  = 80
    https = 443
  }
  origin_server_ip      = "your server ip"
  origin_server_service = "HTTPS"
  cdn                   = false
  continent_cdn         = false
}

# Optional configuration if used
resource "fortiappseccloud_waf_openapi_validation" "openapi_validation_example" {
  app_name = "from_terraform"
  enable   = true
  action   = "alert_deny"
  validation_files = [
    "/path/openapi_validation_file.yaml",
    "/path/openapi_validation_file2.yaml"
  ]
  depends_on = [
    fortiappseccloud_waf_app.app_example
  ]
}
```

### 2.4 Replace Output Configuration

If output declarations reference the renamed application resource, update the resource address as shown:

```hcl
output "ep_id" {
  value = fortiappseccloud_waf_app.app_example.ep_id
}

output "cname" {
  value = fortiappseccloud_waf_app.app_example.cname
}
```

Keep the singular `cname` attribute during this private-provider-to-v1.0.5 migration. Public provider v1.0.5 still exposes `cname` as a computed string. The separate [v1.0.5 to v2.0 upgrade](v1_0_5_to_v2_0_0.html) replaces it with the computed `cnames` list.

Then initialize Terraform to automatically download the new provider:

```shell
terraform init
```

## 3. Modify the Provider Information in the State File
When switching providers, the existing resources in the `.tfstate` file may still reference the old provider. This requires manual updates.

### 3.1 Use `terraform state replace-provider`
Terraform provides a command to update provider bindings:

```shell
terraform state replace-provider 'fortinet/terraform/fortiwebcloud' 'fortinet/fortiappseccloud'
```

The output should be:
```shell
~/projects/terraform-provider-fortiappseccloud/examples/test$ terraform state replace-provider 'fortinet/terraform/fortiwebcloud' 'fortinet/fortiappseccloud'
Terraform will perform the following actions:

  ~ Updating provider:
    - fortinet/terraform/fortiwebcloud
    + registry.terraform.io/fortinet/fortiappseccloud

Changing 1 resources:

  fortiwebcloud_app.app_example

Do you want to make these changes?
Only 'yes' will be accepted to continue.

Enter a value: yes

Successfully replaced provider for 1 resources.
```

This updates the provider binding for all matching resources. It does not rename their Terraform resource types; complete that separate change in the next step.

### 3.2 Rename Resource Types for the Private-to-Public Migration Only

This manual resource-type rename applies only to the historical private-provider migration described by this guide. Do not use it for the later same-provider v1.0.5-to-v2 schema upgrade.

Inspect the resource `type` fields in a protected state backup. If they are `fortiwebcloud_app` or `fortiwebcloud_openapi_validation`, change only those type names to `fortiappseccloud_waf_app` and `fortiappseccloud_waf_openapi_validation`, respectively. Preserve the resource names, instances, attributes, output values, lineage, and serial metadata.

The relevant state shape after the application resource-type rename resembles the following abbreviated example:

```json
{
  "version": 4,
  "terraform_version": "1.9.6",
  "serial": 3,
  "lineage": "example-lineage-id",
  "outputs": {
    "cname": {
      "value": "[\"edge.example.com\"]",
      "type": "string"
    },
    "ep_id": {
      "value": "application-endpoint-id",
      "type": "string"
    }
  },
  "resources": [
    {
      "mode": "managed",
      "type": "fortiappseccloud_waf_app",
      "name": "app_example",
      "provider": "provider[\"registry.terraform.io/fortinet/fortiappseccloud\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "app_name": "from_terraform",
            "app_service": {
              "http": 80,
              "https": 443
            },
            "block": false,
            "cdn": false,
            "cname": "[\"edge.example.com\"]",
            "continent": "",
            "continent_cdn": false,
            "domain_name": "www.example.com",
            "ep_id": "application-endpoint-id",
            "extra_domains": null,
            "id": "from_terraform",
            "origin_server_ip": "origin.example.com",
            "origin_server_port": 443,
            "origin_server_service": "HTTPS",
            "template": null
          },
          "sensitive_attributes": [],
          "private": "bnVsbA=="
        }
      ]
    }
  ],
  "check_results": null
}
```

The quoted value `"[\"edge.example.com\"]"` is intentional at this stage: v1.0.5 declares `cname` as a Terraform string whose contents are a JSON-encoded list. It is not an actual list in v1.0.5 state. Do not convert it during this resource-type rename; the v2 provider state upgrader converts it to the real `cnames` list.

## 4. Test and Validate

After replacing the provider, test the new configuration to ensure it runs correctly. Pay close attention to the output of `terraform plan` to ensure existing resources are recognized and no new resources are created:

```shell
terraform init
terraform plan
```

The output should only reflect changes to the provider and resource names. There should be no changes to the app configuration. If any app configuration changes are detected, do not proceed further.

## 5. Apply Changes

Once the `terraform plan` results meet expectations, apply the changes to finalize the migration:

```shell
terraform apply
```
