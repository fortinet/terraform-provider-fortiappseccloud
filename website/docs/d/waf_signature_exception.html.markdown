---
subcategory: "WAF"
page_title: "fortiappseccloud_waf_signature_exception Data Source - fortiappseccloud"
description: |-
  Reads the limited signature-exception template view for a FortiAppSec Cloud application.
---

# fortiappseccloud_waf_signature_exception

Reads the limited public signature-exception view for one application and signature. The public GET returns only an optional template identifier; it does not return the exception rule.

This data source never changes remote state and does not manage signature-exception rules. The public PUT accepts rule objects that the GET cannot reconstruct, so the provider intentionally excludes that write operation instead of exposing a write-only Terraform resource.

## Example Usage

```hcl
data "fortiappseccloud_waf_signature_exception" "example" {
  ep_id        = fortiappseccloud_waf_app.app_example.ep_id
  signature_id = "030000001"
}

output "signature_exception_template_id" {
  value = data.fortiappseccloud_waf_signature_exception.example.template_id
}
```

## Argument Reference

* `ep_id` - (Required) Application endpoint ID.
* `signature_id` - (Required) Signature ID to query. The public GET requires this value but does not declare a length or format constraint.

## Attribute Reference

* `template_id` - Template identifier returned for the signature, or `null` when the optional public response field is absent.

This result is an observation only. It cannot be used to infer, import, refresh, or manage the exception-rule object accepted by the public PUT.
