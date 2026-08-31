package contract

// MobileAPIProtectionScope classifies the app-level mobile API protection
// resource and manages the corresponding template operations.
var MobileAPIProtectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/mobile_api_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_mobile_api_protection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/mobile_api_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_mobile_api_protection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/mobile_api_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_mobile_api_protection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/mobile_api_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_mobile_api_protection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// MobileAPIProtectionResource records the implemented twenty-first generated
// resource. It pairs a required status boolean (default false) with a required
// action string enum (default alert_deny), a required token_secret string
// (max 127, default TOKEN_SECRET) marked sensitive in the reviewed Terraform
// policy, a required token_header string (max 63, default Jwt_Token), and one
// object-item collection reusing the already-reviewed UrlList item schema
// (max 12, required url string max 255, wire-only idx default 1).
//
// This resource exercises the generator's sensitive-scalar capability for the
// first time: the reviewed profile marks configs.token_secret sensitive, so the
// generated schema attribute emits Sensitive: true and the docs argument text
// notes the field is sensitive. The token_secret value is never printed in
// generated examples or diagnostics. The contract pins the source fact
// (required string max 127 with default TOKEN_SECRET); sensitivity is a
// reviewed Terraform-policy overlay pinned in the profile, not a source fact.
var MobileAPIProtectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_mobile_api_protection",
	GoName:              "MobileAPIProtection",
	TypeNameSuffix:      "waf_mobile_api_protection",
	OperationName:       "mobile API protection",
	Path:                "/waf/apps/{ep_id}/mobile_api_protection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetMobileAPIProtection",
		PutRequest:  "#/components/schemas/PutMobileAPIProtection",
		Configs:     "#/components/schemas/MobileAPIProtection",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "token_header", Kind: "string", Required: true, HasDefault: true, Default: "Jwt_Token", MaxLength: 63},
			{Name: "token_secret", Kind: "string", Required: true, HasDefault: true, Default: "TOKEN_SECRET", MaxLength: 127},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "url_list", MaxItems: 12, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"url_list": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "url", Kind: "string", Required: true, HasDefault: false, MaxLength: 255},
			},
		},
	},
	Provenance: "Implemented as the twenty-first reviewed generated app-module resource and the mobile-API-protection shape (pinned config object MobileAPIProtection): " +
		"a required status boolean (default false), a required action string enum (default alert_deny), " +
		"a required token_secret string (max 127, default TOKEN_SECRET) marked sensitive in the reviewed Terraform policy, " +
		"a required token_header string (max 63, default Jwt_Token), " +
		"and one object-item collection reusing the already-reviewed UrlList item schema. " +
		"url_list (max 12) uses the UrlList item schema: required url string (max 255) and the wire-only positional idx (default 1). " +
		"This resource exercises the generator's sensitive-scalar capability for the first time: the reviewed profile marks configs.token_secret sensitive, so the generated schema attribute emits Sensitive: true and the docs argument text notes the field is sensitive. The token_secret value is never printed in generated examples or diagnostics. The contract pins the source fact (required string max 127 with default TOKEN_SECRET); sensitivity is a reviewed Terraform-policy overlay pinned in the profile, not a source fact. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action enum, every config default, the token_secret 127-character and token_header 63-character maximums, the 12-item url_list bound, the url 255-character maximum, and the idx default are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
