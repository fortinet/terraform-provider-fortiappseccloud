
# Terraform Provider for FortiAppSecCloud

- Official website: [https://www.terraform.io](https://www.terraform.io)
- For support, please contact your Fortinet representative.

## Requirements

- Terraform 0.13.x or higher

## Installation

To automatically install this provider, add the following configuration to your `main.tf` file:

```hcl
terraform {
  required_providers {
    fortiappseccloud = {
      source  = "fortinet/fortiappseccloud"
      version = "1.0.0"
    }
  }
}

provider "fortiappseccloud" {
  hostname  = "api.appsec.fortinet.com"
  api_token = "your_api_token"
}
```

Then run `terraform init` to download and install the provider:

```sh
$ terraform init
```

## Compatibility

This provider has been tested with Terraform version 1.0.6. Versions above this may work but have not been fully tested.

## License

This project is licensed under the [MIT License](https://github.com/fortinet/terraform-provider-fortiappseccloud/blob/main/LICENSE).

## Support

For bug reports, feature requests, or technical assistance, please contact FortiAppSecCloud Support. Note that access to support may require a valid subscription or license. For more information on obtaining support, visit the [Fortinet Support](https://support.fortinet.com). For details on how to contact support, see [Contacting Customer Service](https://docs.fortinet.com/document/fortiweb-cloud/latest/user-guide/796808/contacting-customer-service).
