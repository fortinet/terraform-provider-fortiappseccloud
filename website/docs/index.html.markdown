---
layout: "fortiappseccloud"
page_title: "Provider: FortiAppSecCloud"
sidebar_current: "docs-fortiappseccloud-index"
description: |-
  The fortiappseccloud provider interacts with FortiAppSecCloud.
---

# Terraform provider for FortiAppSecCloud

`fortiappseccloud` is used to interact with the resources supported by FortiAppSecCloud. Before use, the provider must be configured with the proper credentials.

## Configuration for FortiAppSecCloud

### Example Usage

```hcl
# Configure the FortiAppSecCloud Provider
provider "fortiappseccloud" {
  hostname   = "api.appsec.fortinet.com"
  api_token  = "your_api_token"
}
```

### Argument Reference

The following arguments are supported:

* `hostname` - (Required) The FortiAppSecCloud API endpoint (e.g., api.appsec.fortinet.com).
* `username` - (Optional) The username for your FortiAppSecCloud account (if not using api_token).
* `password` - (Optional) The password for your FortiAppSecCloud account (if not using api_token).
* `api_token` - (Optional) The API key for accessing your FortiAppSecCloud account.


## Support

For bug reports, feature requests, or technical assistance, please contact FortiAppSecCloud Support. Note that access to support may require a valid subscription or license. For more information on obtaining support, visit the [Fortinet Support](https://support.fortinet.com). For details on how to contact support, see [Contacting Customer Service](https://docs.fortinet.com/document/fortiweb-cloud/latest/user-guide/796808/contacting-customer-service).
