package generator

// docsConfigurationNotes records backend relationships that are important to
// a usable example but are not completely expressible as single-field schema
// constraints. Keep these notes user-facing and action-oriented.
func docsConfigurationNotes(terraformName string) string {
	return map[string]string{
		"fortiappseccloud_waf_api_gateway":           "- Set `api_key_verify = true` before configuring `api_key_loc` and `field_name`. The example enables all three together and gives referenced users matching entries in `user_list`.",
		"fortiappseccloud_waf_caching_compression":   "- The module, cache, and compression statuses are coupled. When enabling this module, configure `status`, `cache.status`, and `compress.status` together as shown.",
		"fortiappseccloud_waf_file_protection":       "- When `json_file_support = true`, also set `json_key_field`. Each file type needs a compatible `type` and five-digit `tid`; hexadecimal content values must contain valid, even-length hexadecimal data.",
		"fortiappseccloud_waf_http_header_security":  "- Enabling a response-header control can require its associated value. For example, enable `content_security_policy` together with `header_value` as shown.",
		"fortiappseccloud_waf_json_protection":       "- `file_list` references JSON-schema files already present in FortiAppSec Cloud. Omit that block when no uploaded schema exists; this resource does not upload schema files.",
		"fortiappseccloud_waf_mobile_api_protection": "- `token_secret` is sensitive but remains part of Terraform state. Protect state storage and supply the value through a sensitive variable.",
		"fortiappseccloud_waf_parameter_validation":  "- Rules using a data-type check must include a compatible `arg_val`; set it explicitly as shown instead of relying on an API default.",
		"fortiappseccloud_waf_threshold_detection":   "- Credential brute-force detection requires `request_url`. Exception IP values must use an address or address range accepted by FortiAppSec Cloud.",
		"fortiappseccloud_waf_xml_protection_policy": "- `file_list` references XML-schema files already present in FortiAppSec Cloud. Omit that block when no uploaded schema exists; this resource does not upload schema files.",
	}[terraformName]
}
