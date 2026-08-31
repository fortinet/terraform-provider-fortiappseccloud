package contract

// BotDeceptionScope classifies the app-level bot deception resource and manages
// the corresponding template operations.
var BotDeceptionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/bot_deception",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_bot_deception",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/bot_deception",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_bot_deception",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/bot_deception",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_bot_deception",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/bot_deception",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_bot_deception",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// BotDeceptionResource records the implemented fourteenth generated resource.
// It pairs two required config scalars (status boolean and action string enum,
// both with reviewed defaults) with two object-item collections that reuse
// already-reviewed item schemas: url_list (max 12, UrlList item: required url
// string max 255, wire-only idx default 1) and exception_list (max 128,
// BotExceptionRuleList item: required concatenate_type/match_target/operator
// string enums, optional ip_range/value/value_name strings and value_check
// boolean default false, wire-only idx default 1). A single optional
// deception_url string (max 255, default /url.html) rounds out the configs.
// No new generator construct is introduced: the per-collection item schemas
// reuse the indexed bounded object-item ownership wrapper and the item-field
// shapes already exercised by known_bots.exception_list and earlier resources.
var BotDeceptionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_bot_deception",
	GoName:              "BotDeception",
	TypeNameSuffix:      "waf_bot_deception",
	OperationName:       "bot deception",
	Path:                "/waf/apps/{ep_id}/bot_deception",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetBotDeception",
		PutRequest:  "#/components/schemas/PutBotDeception",
		Configs:     "#/components/schemas/BotDeception",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "deception_url", Kind: "string", Required: false, HasDefault: true, Default: "/url.html", MaxLength: 255},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "url_list", MaxItems: 12, Unindexed: false},
			{Name: "exception_list", MaxItems: 128, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"url_list": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "url", Kind: "string", Required: true, HasDefault: false, MaxLength: 255},
			},
			"exception_list": {
				{Name: "concatenate_type", Kind: "string", Required: true, HasDefault: false, Enum: []string{"AND", "OR"}},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "ip_range", Kind: "string", Required: false, HasDefault: false},
				{Name: "match_target", Kind: "string", Required: true, HasDefault: false, Enum: []string{"CLIENT_IP", "COOKIE", "FULL_URL", "HOST", "PARAMETER", "URI"}},
				{Name: "operator", Kind: "string", Required: true, HasDefault: false, Enum: []string{"EQ", "NE", "REGEXP_MATCH", "STRING_MATCH"}},
				{Name: "value", Kind: "string", Required: false, HasDefault: false},
				{Name: "value_check", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				{Name: "value_name", Kind: "string", Required: false, HasDefault: false},
			},
		},
	},
	Provenance: "Implemented as the fourteenth reviewed generated app-module resource and the bot-deception shape: " +
		"two required config scalars (status boolean default false and action string enum default alert_deny) plus the optional deception_url string (max 255, default /url.html), " +
		"and two object-item collections reusing already-reviewed indexed bounded item schemas. " +
		"url_list (max 12) uses the UrlList item schema: required url string (max 255) and the wire-only positional idx (default 1). " +
		"exception_list (max 128) uses the BotExceptionRuleList item schema: required concatenate_type/match_target/operator string enums and the optional ip_range/value/value_name strings and value_check boolean (default false), plus the wire-only positional idx (default 1). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action string enum, every config default, the deception_url 255-character maximum, the 12-item url_list bound, the 128-item exception_list bound, the url 255-character maximum, the BotExceptionRuleList enums, and the value_check default are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
