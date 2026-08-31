package contract

// ThresholdDetectionScope classifies the app-level threshold detection resource
// and manages the corresponding template operations. The module path is
// threshold_detection; the pinned config object schema is BotDetection.
var ThresholdDetectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/threshold_detection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_threshold_detection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/threshold_detection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_threshold_detection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/threshold_detection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_threshold_detection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/threshold_detection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_threshold_detection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// ThresholdDetectionResource records the implemented eighteenth generated
// resource. It pairs two required config-scalar string enums (action default
// block_period and challenge default RBE) with a required status boolean
// (default false), five required detection booleans (crawler,
// vulnerability_scan, slow_attack, content_scraping, credential_brute_force,
// all default false), an optional request_url string (max 127), two optional
// integer config scalars with reviewed ranges (occurrence default 10 range
// 1..100 and range default 60 range 1..60), and one object-item collection
// reusing the already-reviewed BotExceptionRuleList item schema (max 128,
// required concatenate_type/match_target/operator string enums, optional
// ip_range/value/value_name strings and value_check boolean default false,
// wire-only idx default 1). No new generator construct is introduced: the
// integer config-scalar range and the indexed bounded object-item ownership
// wrapper are already exercised by earlier resources.
var ThresholdDetectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_threshold_detection",
	GoName:              "ThresholdDetection",
	TypeNameSuffix:      "waf_threshold_detection",
	OperationName:       "threshold detection",
	Path:                "/waf/apps/{ep_id}/threshold_detection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetBotDetection",
		PutRequest:  "#/components/schemas/PutBotDetection",
		Configs:     "#/components/schemas/BotDetection",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "block_period", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "challenge", Kind: "string", Required: true, HasDefault: true, Default: "RBE", Enum: []string{"CAPTCHA", "RBE", "disable"}},
			{Name: "content_scraping", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "crawler", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "credential_brute_force", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "occurrence", Kind: "integer", Required: false, HasDefault: true, Default: 10, Minimum: ptrFloat(1), Maximum: ptrFloat(100)},
			{Name: "range", Kind: "integer", Required: false, HasDefault: true, Default: 60, Minimum: ptrFloat(1), Maximum: ptrFloat(60)},
			{Name: "request_url", Kind: "string", Required: false, HasDefault: false, MaxLength: 127},
			{Name: "slow_attack", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "vulnerability_scan", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "exception_list", MaxItems: 128, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
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
	Provenance: "Implemented as the eighteenth reviewed generated app-module resource and the threshold-detection shape (pinned config object BotDetection): " +
		"two required config-scalar string enums (action default block_period and challenge default RBE), a required status boolean (default false), " +
		"five required detection booleans (crawler, vulnerability_scan, slow_attack, content_scraping, credential_brute_force, all default false), " +
		"an optional request_url string (max 127), two optional integer config scalars with reviewed ranges (occurrence default 10 range 1..100 and range default 60 range 1..60), " +
		"and one object-item collection reusing the already-reviewed BotExceptionRuleList item schema. " +
		"exception_list (max 128) uses the BotExceptionRuleList item schema: required concatenate_type/match_target/operator string enums and the optional ip_range/value/value_name strings and value_check boolean (default false), plus the wire-only positional idx (default 1). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action and challenge enums, every config default, the request_url 127-character maximum, the occurrence 1..100 and range 1..60 integer bounds, the 128-item exception_list bound, the BotExceptionRuleList enums, the value_check default, and the idx default are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
