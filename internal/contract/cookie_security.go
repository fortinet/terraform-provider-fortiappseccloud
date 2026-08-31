package contract

// CookieSecurityScope classifies the app-level cookie security resource and
// manages the corresponding template operations.
var CookieSecurityScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/cookie_security",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_cookie_security",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/cookie_security",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_cookie_security",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/cookie_security",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_cookie_security",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/cookie_security",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_cookie_security",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// CookieSecurityResource records the implemented twelfth generated resource.
// It pairs nine config scalars (eight required booleans/enums/bounded
// integers plus one optional string enum, samesite_value) with one object-item
// collection (cookie_except_list, max 64) whose item schema carries a required
// string (name, max 127), an optional boolean (wildcard, default false), and
// the wire-only positional idx. The shape reuses the object-item ownership
// wrapper, the required item string maxLength, the optional item boolean
// provider-default filter, the bounded integer config scalar, and the optional
// config string enum already exercised by earlier resources. No new generator
// construct is introduced.
var CookieSecurityResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_cookie_security",
	GoName:              "CookieSecurity",
	TypeNameSuffix:      "waf_cookie_security",
	OperationName:       "cookie security",
	Path:                "/waf/apps/{ep_id}/cookie_security",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetCookieSecurity",
		PutRequest:     "#/components/schemas/PutCookieSecurity",
		Configs:        "#/components/schemas/CookieSecurity",
		CollectionItem: "#/components/schemas/CookieSecurityEexception",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log", "remove_cookie"}},
			{Name: "http_only", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "max_age", Kind: "integer", Required: true, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(65535)},
			{Name: "mode", Kind: "string", Required: true, HasDefault: true, Default: "signed", Enum: []string{"encrypted", "no", "signed"}},
			{Name: "replay_protection", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "samesite", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "samesite_value", Kind: "string", Required: false, HasDefault: true, Default: "Lax", Enum: []string{"Lax", "None", "Strict"}},
			{Name: "secure_cookie", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "cookie_except_list", MaxItems: 64},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
			{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 127},
			{Name: "wildcard", Kind: "boolean", Required: false, HasDefault: true, Default: false},
		},
	},
	Provenance: "Implemented as the twelfth reviewed generated app-module resource and the cookie-security shape: " +
		"nine config scalars (eight required plus the optional samesite_value string enum, default Lax) " +
		"and one object-item collection (cookie_except_list, max 64) whose item schema carries the required name string (max 127), " +
		"the optional wildcard boolean (default false), and the wire-only positional idx. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action/mode/samesite_value string enums, the max_age integer range (0..65535), every config default, the 64-item collection bound, " +
		"the 127-character name maximum, and the wildcard provider-default filter are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
