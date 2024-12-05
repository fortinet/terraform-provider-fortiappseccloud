---
subcategory: ""
layout: "fortiappseccloud"
page_title: "Migrate FortiWebCloud private provider to FortiAppSecCloud"
description: |-
  Migrate FortiWebCloud private provider to FortiAppSecCloud.
---

# Migrate FortiWebCloud private provider to FortiAppSecCloud


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

```bash
terraform state list
```

The output should be similar to:
```
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
      version = ">= 1.0.1"                   # Specify the target version
    }
  }
}
```

### 2.2 Replace your host to fortiappseccloud
1. Replace provider from `fortiwebcloud` to  `fortiappseccloud`
2. Replace host name to fortiappsec `api.appsec.fortinet.com`
3. (Optional) Replace a new api-token if needed.
```hcl
provider "fortiappseccloud" {
  hostname  = "api.appsec.fortinet.com"
  api_token = "your-new-api-token"
}
```

### 2.3 Replace resource name for public provider

1. Replace resource name from `fortiwebcloud_app` to `fortiappseccloud_waf_app`
2. (Optional)Replace resource name from `fortiwebcloud_openapi_validation ` to `fortiappseccloud_waf_openapi_validation`
3. (Optional)Replace depends_on from `fortiwebcloud_app.app_example` to `fortiappseccloud_waf_app.app_example`

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

### 2.4 Replace output configuration
If `output.tf` exists, replace `fortiwebcloud_app` with `fortiappseccloud_waf_app`

```
output "ep_id" {
  value = fortiwebcloud_app.app_example.ep_id
}

output "cname" {
  value = fortiwebcloud_app.app_example.cname
}
```

Then initialize Terraform to automatically download the new provider:

```bash
terraform init
```

## 3. Modify the Provider Information in the State File
When switching providers, the existing resources in the `.tfstate` file may still reference the old provider. This requires manual updates.

### 3.1 Use `terraform state replace-provider`
Terraform provides a command to update provider bindings:

```bash
terraform state replace-provider 'fortinet/terraform/fortiwebcloud' 'fortinet/fortiappseccloud'
```

The output should be:
```bash
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

This converts all resources from the private provider to the public provider.


### 3.2 Modify State File

Check resources type in your `terraform.tfstate`.

If type is `fortiwebcloud_app` or `fortiwebcloud_openapi_validation`,
please modify to `fortiappseccloud_waf_app` and `fortiappseccloud_waf_openapi_validation`
```tfstate
{
  "version": 4,
  "terraform_version": "1.9.6",
  "serial": 3,
  "lineage": "9e89f8c5-74b0-68b8-a749-6b4ab123609f",
  "outputs": {
    "cname": {
      "value": "[\"jsonformatter.testdomain.P3206359425.fortiwebcloud.net\"]",
      "type": "string"
    },
    "ep_id": {
      "value": "3206359425",
      "type": "string"
    }
  },
  "resources": [
    {
      "mode": "managed",
      "type": "fortiwebcloud_app", # please modify this field to fortiappseccloud_waf_app
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
            "cname": "[\"jsonformatter.testdomain.P3206359425.fortiwebcloud.net\"]",
            "continent": "",
            "continent_cdn": false,
            "domain_name": "jsonformatter.testdomain.com",
            "ep_id": "3206359425",
            "extra_domains": null,
            "id": "from_terraform",
            "origin_server_ip": "104.26.12.202",
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

## 5. Test and Validate
After replacing the provider, test the new configuration to ensure it runs correctly. Pay close attention to the output of `terraform plan` to ensure existing resources are recognized and no new resources are created:

```bash
terraform init
terraform plan
```

The output should only reflect changes to the provider and resource names. There should be no changes to the app configuration. If any app configuration changes are detected, do not proceed further.

### 6. Apply Changes
Once the `terraform plan` results meet expectations, apply the changes to finalize the migration:

```bash
terraform apply
```
