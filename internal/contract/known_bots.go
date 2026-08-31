package contract

// KnownBotsScope classifies the app-level known bots resource and manages the
// corresponding template operations.
var KnownBotsScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/known_bots",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_known_bots",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/known_bots",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_known_bots",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/known_bots",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_known_bots",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/known_bots",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_known_bots",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// KnownBotsResource records the implemented thirteenth generated resource. It
// is the first resource exercising three new generator capabilities together:
// unbounded object-item collections, unindexed item schemas, and item-level
// scalar-string-array fields. bad_bots_list and good_bots_list are unbounded
// (no maxItems in the pinned OpenAPI), unindexed
// (BadBotRule and GoodBotRule carry no positional idx), and each carries an
// item-level scalar-string-array (allow_list / deny_list). exception_list
// reuses the existing indexed bounded shape (BotExceptionRuleList, max 128,
// idx default 1, all-scalar items).
var KnownBotsResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_known_bots",
	GoName:              "KnownBots",
	TypeNameSuffix:      "waf_known_bots",
	OperationName:       "known bots",
	Path:                "/waf/apps/{ep_id}/known_bots",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetKnownBots",
		PutRequest:  "#/components/schemas/PutKnownBots",
		Configs:     "#/components/schemas/KnownBots",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "bad_bots", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "bad_bots_action", Kind: "string", Required: true, HasDefault: true, Default: "block_period", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "good_bots_action", Kind: "string", Required: true, HasDefault: true, Default: "bypass", Enum: []string{"alert", "alert_deny", "block_period", "bypass", "deny_no_log"}},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: true},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "bad_bots_list", MaxItems: 0, Unindexed: true},
			{Name: "good_bots_list", MaxItems: 0, Unindexed: true},
			{Name: "exception_list", MaxItems: 128, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"bad_bots_list": {
				{Name: "allow_list", Kind: "string_array", Required: false, HasDefault: false, StringArray: &CandidateItemStringArrayConstraint{
					Name:          "allow_list",
					ItemAttribute: "value",
					Enum:          nil,
					MaxItems:      0,
					Required:      false,
				}},
				{Name: "cat", Kind: "string", Required: false, HasDefault: false, Enum: []string{"Crawler", "DoS", "Scanner", "Spam", "Trojan"}},
				{Name: "status", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			},
			"good_bots_list": {
				{Name: "cat", Kind: "string", Required: false, HasDefault: false, Enum: []string{"Known Search Engines"}},
				{Name: "deny_list", Kind: "string_array", Required: false, HasDefault: false, StringArray: &CandidateItemStringArrayConstraint{
					Name:          "deny_list",
					ItemAttribute: "value",
					Enum:          nil,
					MaxItems:      0,
					Required:      false,
				}},
				{Name: "status", Kind: "boolean", Required: false, HasDefault: true, Default: true},
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
	Provenance: "Implemented as the thirteenth reviewed generated app-module resource and the first to exercise three new generator capabilities together: " +
		"unbounded object-item collections (bad_bots_list, good_bots_list have no maxItems in OpenAPI 26.3.a, so MaxItems is pinned 0 = unbounded), " +
		"unindexed item schemas (BadBotRule and GoodBotRule carry no positional idx, so Unindexed is pinned true; items send in Terraform order with no idx and decode in order without idx validation/sort), " +
		"and item-level scalar-string-array fields (BadBotRule.allow_list, GoodBotRule.deny_list render as ownership wrappers inside the item). " +
		"exception_list reuses the existing indexed bounded shape (BotExceptionRuleList, max 128, idx default 1). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The bad_bots_action/good_bots_action string enums, the cat enums, the BotExceptionRuleList enums, every config default, the 128-item exception_list bound, and the item string-array ownership wrappers are pinned from OpenAPI 26.3.a. " +
		"Item `status` booleans (reviewed default true) use a reviewed provider-default-false/true modifier pattern: the generator emits a DefaultTrueModifier so an omitted item status defaults to true on first create (mirroring the backend default) rather than sending false. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
