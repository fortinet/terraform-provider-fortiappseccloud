package contract

// BiometricsBasedDetectionScope classifies the app-level biometrics-based
// detection resource and manages the corresponding template operations.
var BiometricsBasedDetectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/biometrics_based_detection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_biometrics_based_detection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/biometrics_based_detection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_biometrics_based_detection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/biometrics_based_detection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_biometrics_based_detection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/biometrics_based_detection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_biometrics_based_detection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// BiometricsBasedDetectionResource records the implemented fifteenth generated
// resource. It pairs seven required config scalars (action string enum default
// alert_deny plus six booleans: click/keyboard/mouse_movement default true,
// screen_touch/scroll/status default false) with two optional bounded integer
// config scalars (bot_effect_time 1..5 default 5, event_collect_time 10..60
// default 15) and the same two object-item collections as bot_deception:
// url_list (max 12, UrlList item) and exception_list (max 128,
// BotExceptionRuleList item). No new generator construct is introduced; the
// bounded integer config scalars and the per-collection item schemas reuse
// already-reviewed shapes.
var BiometricsBasedDetectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_biometrics_based_detection",
	GoName:              "BiometricsBasedDetection",
	TypeNameSuffix:      "waf_biometrics_based_detection",
	OperationName:       "biometrics based detection",
	Path:                "/waf/apps/{ep_id}/biometrics_based_detection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetBiometricsBasedDetection",
		PutRequest:  "#/components/schemas/PutBiometricsBasedDetection",
		Configs:     "#/components/schemas/BiometricsBasedDetection",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "bot_effect_time", Kind: "integer", Required: true, HasDefault: true, Default: 5, Minimum: ptrFloat(1), Maximum: ptrFloat(5)},
			{Name: "click", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "event_collect_time", Kind: "integer", Required: true, HasDefault: true, Default: 15, Minimum: ptrFloat(10), Maximum: ptrFloat(60)},
			{Name: "keyboard", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "mouse_movement", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "screen_touch", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "scroll", Kind: "boolean", Required: true, HasDefault: true, Default: false},
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
	Provenance: "Implemented as the fifteenth reviewed generated app-module resource and the biometrics-based-detection shape: " +
		"seven required config scalars (action string enum default alert_deny plus the click/keyboard/mouse_movement booleans default true and the screen_touch/scroll/status booleans default false) " +
		"and two required bounded integer config scalars (bot_effect_time 1..5 default 5, event_collect_time 10..60 default 15), " +
		"plus the same two object-item collections as bot_deception: url_list (max 12, UrlList item with required url max 255 and wire-only idx default 1) " +
		"and exception_list (max 128, BotExceptionRuleList item with required concatenate_type/match_target/operator enums, optional ip_range/value/value_name strings and value_check default false, and wire-only idx default 1). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action string enum, the bot_effect_time/event_collect_time integer ranges and defaults, every boolean default, the 12-item url_list bound, the 128-item exception_list bound, the url 255-character maximum, the BotExceptionRuleList enums, and the value_check default are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
