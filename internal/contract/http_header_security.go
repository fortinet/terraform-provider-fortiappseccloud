package contract

// HttpHeaderSecurityScope classifies the app-level HTTP header security resource and manages the corresponding template operations.
var HttpHeaderSecurityScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/http_header_security",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_http_header_security",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/http_header_security",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_http_header_security",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/http_header_security",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_http_header_security",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/http_header_security",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_http_header_security",
		ClientMethod: "PutWAFTemplateModule",
	},
}

var HttpHeaderSecurityResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_http_header_security",
	GoName:              "HttpHeaderSecurity",
	TypeNameSuffix:      "waf_http_header_security",
	OperationName:       "HTTP header security",
	Path:                "/waf/apps/{ep_id}/http_header_security",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetHttpHeaderSecurity",
		PutRequest:  "#/components/schemas/PutHttpHeaderSecurity",
		Configs:     "#/components/schemas/HttpHeaderSecurity",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "content_security_policy", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "header_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 1023},
			{Name: "referrer_policy", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "referrer_policy_header_value", Kind: "string", Required: false, HasDefault: true, Default: "strict-origin-when-cross-origin", Enum: []string{"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}, MaxLength: 64, AllowNull: true},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "x_content_type_options", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "x_frame_options", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "x_xss_protection", Kind: "boolean", Required: true, HasDefault: true, Default: true},
		},
	},
	Provenance: "Implemented as the fifth reviewed generated app-module resource. Pure scalar config (6 booleans, 2 strings) with no collections. The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. All config defaults and the referrer_policy_header_value enum are pinned from OpenAPI 26.3.a. Destroy remains unverified forget behavior; lifecycle behavior is locally tested rather than live-verified.",
}
