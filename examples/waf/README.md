# Terraform: FortiAppSecCloud as a Provider

FortiAppSecCloud's Terraform support provides users with efficient ways to deploy, manage, and automate application security across multiple cloud environments. By using Terraform, various IT infrastructure needs can be automated, reducing errors from repetitive manual configurations.

The Terraform FortiAppSecCloud provider can be used to automatically onboard or delete applications.

The following example demonstrates how to use the Terraform FortiAppSecCloud provider to perform configuration changes on FortiAppSecCloud. Requirements are as follows:

1. FortiAppSecCloud API access.
2. FortiAppSecCloud Provider version 1.0.0 or later.
3. Terraform version 0.13 or later.

## Configure FortiAppSecCloud with the Terraform Provider

### Step 1: Initialize the `fortiappseccloud` Provider

1. Create a new file with the `.tf` extension for configuring your FortiAppSecCloud:

    ```sh
    $ touch main.tf
    $ ls
    main.tf
    ```

2. Edit the `main.tf` Terraform configuration file. In this example, you will connect to the FortiAppSecCloud API gateway. Ensure the `api_token` provided has the necessary permissions.

   ```hcl
   # Configure the FortiAppSecCloud Provider
   provider "fortiappseccloud" {
     hostname   = "api.appsec.fortinet.com"
     api_token  = "your_api_key"
   }
   ```

## Step 2: Configure Resources for Application Onboarding

1. Specify your application name, domain, server settings, and other preferences in main.tf. Here’s an example configuration:

    ```hcl
    # Example resource for application onboarding
    resource "fortiappseccloud_waf_app" "app_example" {
        app_name              = "from_terraform"
        domain_name           = "www.example.com"
        app_service = {
            http  = 80
            https = 443
        }
        origin_server_ip      = "93.184.216.34"
        origin_server_service = "HTTPS"
        cdn                   = false
        continent_cdn         = false
    }

    # Example resource for OpenAPI validation
    resource "fortiappseccloud_waf_openapi_validation" "openapi_validation_example" {
        app_name          = fortiappseccloud_waf_app.app_example.app_name
        enable            = true
        action            = "alert_deny"
        validation_files  = [
            "/path/to/openapi_validation_file.yaml",
            "/path/to/openapi_validation_file2.yaml"
        ]
        depends_on = [
            fortiappseccloud_waf_app.app_example
        ]
    }
    ```

## Step 3: Initialize the Working Directory

1. Save the `main.tf` configuration file.

2. In the terminal, enter `terraform init` to initialize the working directory:

    ```sh
    $ terraform init
    ```
    This initializes the backend and provider plugins for Terraform.

## Step 4: Verify the Provider Version

1. Run `terraform -v` to verify the Terraform and provider versions:

    ```sh
    $ terraform -v
    Terraform v1.0.6
    + provider.fortiappseccloud v1.0.0
    ```

## Step 5: Preview Configuration Changes

1. Use `terraform plan` to view the changes that Terraform will apply to FortiAppSecCloud:

    ```sh
    $ terraform plan
    ```
    The plan output will indicate the resources that will be created or modified.

## Step 6: Apply the Configuration

1. After verifying the plan, use `terraform apply` to apply the configuration:

    ```sh
    $ terraform apply
    ```
    Terraform will prompt for confirmation. Enter `yes` to proceed. The `fortiappseccloud_waf_app` and `fortiappseccloud_waf_openapi_validation` resources will be created.

## Step 7: Delete Resources

1. To delete the resources and configurations from FortiAppSecCloud, use `terraform destroy`:

    ```sh
    $ terraform destroy
    ```
    Terraform will confirm the resources to be deleted. Enter `yes` to proceed.

---

This guide provides an example of onboarding an application with OpenAPI validation on FortiAppSecCloud using Terraform. For further configuration options, refer to the main [README](../../README.md) or the Terraform Registry documentation.

