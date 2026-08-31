package contract

// MITBProtectionScope classifies the app-level MITB protection resource and
// manages the corresponding template operations.
var MITBProtectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/mitb_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_mitb_protection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/mitb_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_mitb_protection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/mitb_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_mitb_protection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/mitb_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_mitb_protection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// MITBProtectionResource records the implemented seventeenth generated resource.
// It pairs two required config scalars (status boolean and action string enum,
// both with reviewed defaults) with two optional URL strings (request_url and
// post_url, each max 255 with the ^/.*$ pattern) and two object-item collections
// that use new all-scalar indexed bounded item schemas: param_list (max 256,
// ProtectParamter item: required type string enum with default regular-input
// and required name string max 63, optional obfuscate/encrypt/anti_key_logger
// booleans default false, wire-only idx default 1) and domain_list (max 256,
// AllowedDomain item: required domain string max 255, wire-only idx default 1).
// No new generator construct is introduced: the per-collection item schemas
// reuse the indexed bounded object-item ownership wrapper and the all-scalar
// item-field shapes already exercised by earlier resources.
var MITBProtectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_mitb_protection",
	GoName:              "MITBProtection",
	TypeNameSuffix:      "waf_mitb_protection",
	OperationName:       "MITB protection",
	Path:                "/waf/apps/{ep_id}/mitb_protection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetMITBProtection",
		PutRequest:  "#/components/schemas/PutMITBProtection",
		Configs:     "#/components/schemas/MITBProtection",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny"}},
			{Name: "post_url", Kind: "string", Required: true, HasDefault: false, MaxLength: 255, Pattern: `^/.*$`},
			{Name: "request_url", Kind: "string", Required: true, HasDefault: false, MaxLength: 255, Pattern: `^/.*$`},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "param_list", MaxItems: 256, Unindexed: false},
			{Name: "domain_list", MaxItems: 256, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"param_list": {
				{Name: "anti_key_logger", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				{Name: "encrypt", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 63},
				{Name: "obfuscate", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				{Name: "type", Kind: "string", Required: true, HasDefault: true, Default: "regular-input", Enum: []string{"password-input", "regular-input"}},
			},
			"domain_list": {
				{Name: "domain", Kind: "string", Required: true, HasDefault: false, MaxLength: 255},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
			},
		},
	},
	Provenance: "Implemented as the seventeenth reviewed generated app-module resource and the MITB-protection shape: " +
		"two required config scalars (status boolean default false and action string enum default alert_deny), " +
		"two optional URL strings (request_url and post_url, each max 255 with the ^/.*$ pattern), " +
		"and two object-item collections with all-scalar indexed bounded item schemas. " +
		"param_list (max 256) uses the ProtectParamter item schema: required type string enum (default regular-input) and required name string (max 63), optional obfuscate/encrypt/anti_key_logger booleans (default false), and the wire-only positional idx (default 1). " +
		"domain_list (max 256) uses the AllowedDomain item schema: required domain string (max 255) and the wire-only positional idx (default 1). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action enum, every config default, the request_url/post_url 255-character maximum and ^/.*$ pattern, the 256-item param_list bound, the 256-item domain_list bound, the ProtectParamter type enum and name 63-character maximum, the obfuscate/encrypt/anti_key_logger defaults, the AllowedDomain domain 255-character maximum, and the idx defaults are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
