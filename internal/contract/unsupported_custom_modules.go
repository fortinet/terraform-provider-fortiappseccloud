package contract

// UnsupportedCustomModuleContract records a reviewed product-scope exclusion.
// These are terminal outcomes for the current provider goal, not temporary
// implementation blockers or invitations to infer a missing API contract.
type UnsupportedCustomModuleContract struct {
	Module           string
	TerraformName    string
	PublicPath       string
	DetailPath       string
	SecretFields     []string
	ReviewedEvidence string
	Reason           string
	ScopeDecision    string
}

var reviewedUnsupportedCustomModuleContracts = []UnsupportedCustomModuleContract{
	{
		Module: "log_settings", TerraformName: "fortiappseccloud_waf_log_settings",
		PublicPath:       "/waf/apps/{ep_id}/log_settings",
		SecretFields:     []string{"user_secret_key"},
		ReviewedEvidence: "the pinned OpenAPI declares both GET and PUT as SingleJsonObject and provides examples only",
		Reason:           "the API has no durable typed configuration schema and includes credential-bearing fields",
		ScopeDecision:    "do not serve a log_settings resource or data source",
	},
	{
		Module: "inter_certificate", TerraformName: "fortiappseccloud_waf_inter_certificate",
		PublicPath: "/waf/apps/{ep_id}/inter_certificate", DetailPath: "/waf/apps/{ep_id}/inter_cert_detail",
		SecretFields:     []string{"certificate"},
		ReviewedEvidence: "the typed action API imports or deletes intermediate certificate content and exposes a paginated numeric-ID list",
		Reason:           "certificate content upload and lifecycle ownership are outside the provider goal",
		ScopeDecision:    "do not serve the prepared intermediate-certificate resource or upload client",
	},
	{
		Module: "sni_certificate", TerraformName: "fortiappseccloud_waf_sni_certificate",
		PublicPath: "/waf/apps/{ep_id}/sni_certificate", DetailPath: "/waf/apps/{ep_id}/sni_cert_detail",
		SecretFields:     []string{"certificate", "private_key", "passwd"},
		ReviewedEvidence: "the typed action API accepts server certificate, private-key, and optional password content while the detail response remains untyped",
		Reason:           "custom server certificate content upload is outside the provider goal",
		ScopeDecision:    "do not serve an SNI certificate upload resource",
	},
	{
		Module: "server_ca", TerraformName: "fortiappseccloud_waf_server_ca",
		PublicPath: "/waf/apps/{ep_id}/server_ca", DetailPath: "/waf/apps/{ep_id}/server_ca_detail",
		SecretFields:     []string{"certificate"},
		ReviewedEvidence: "the typed action API uploads CA content attached to an origin pool/server and the detail identity remains untyped",
		Reason:           "origin-server CA attachment upload is outside the provider goal",
		ScopeDecision:    "do not serve a server CA attachment resource",
	},
	{
		Module: "server_crl", TerraformName: "fortiappseccloud_waf_server_crl",
		PublicPath: "/waf/apps/{ep_id}/server_crl", DetailPath: "/waf/apps/{ep_id}/server_crl_detail",
		SecretFields:     []string{"certificate"},
		ReviewedEvidence: "the typed action API uploads CRL content attached to an origin pool/server and the detail identity remains untyped",
		Reason:           "origin-server CRL attachment upload is outside the provider goal",
		ScopeDecision:    "do not serve a server CRL attachment resource",
	},
	{
		Module: "ca_certificate", TerraformName: "fortiappseccloud_waf_ca_certificate",
		PublicPath:       "/waf/apps/{ep_id}/ca_certificate",
		SecretFields:     []string{"certificate"},
		ReviewedEvidence: "the pinned OpenAPI keeps GET and PUT as SingleJsonObject",
		Reason:           "client-authentication CA content upload is outside the provider goal",
		ScopeDecision:    "do not serve a client-authentication CA certificate resource",
	},
	{
		Module: "crl_certificate", TerraformName: "fortiappseccloud_waf_crl_certificate",
		PublicPath:       "/waf/apps/{ep_id}/crl_certificate",
		SecretFields:     []string{"certificate"},
		ReviewedEvidence: "the pinned OpenAPI keeps GET and PUT as SingleJsonObject",
		Reason:           "client-authentication CRL content upload is outside the provider goal",
		ScopeDecision:    "do not serve a client-authentication CRL resource",
	},
	{
		Module: "dns_resolve", TerraformName: "fortiappseccloud_waf_dns_resolve",
		PublicPath:       "/waf/apps/{ep_id}/dns_resolve",
		SecretFields:     nil,
		ReviewedEvidence: "the pinned OpenAPI 26.4 exposes the app-scoped dns_resolve GET/PUT pair",
		Reason:           "the API owner has not requested Terraform support for DNS resolve settings yet",
		ScopeDecision:    "do not serve a dns_resolve resource until the owner requests it",
	},
	{
		Module: "cert_proxy", TerraformName: "fortiappseccloud_waf_cert_proxy",
		PublicPath:       "/waf/apps/{ep_id}/cert_proxy",
		SecretFields:     []string{"certificate", "private_key", "passwd"},
		ReviewedEvidence: "the typed action API accepts CA certificate, private-key, and optional password content with an import/delete action shape while GET returns a paginated numeric-ID certificate list",
		Reason:           "origin-server CA certificate content upload is outside the provider goal",
		ScopeDecision:    "do not serve an origin-server certificate-proxy upload resource",
	},
}

// ReviewedUnsupportedCustomModuleContracts returns a deep copy of the
// explicit product-scope exclusions.
func ReviewedUnsupportedCustomModuleContracts() []UnsupportedCustomModuleContract {
	result := make([]UnsupportedCustomModuleContract, len(reviewedUnsupportedCustomModuleContracts))
	for index, contract := range reviewedUnsupportedCustomModuleContracts {
		result[index] = contract
		result[index].SecretFields = append([]string(nil), contract.SecretFields...)
	}
	return result
}
