package contract

// MLBotDetectionScope classifies the app-level machine-learning bot detection
// resource and manages the corresponding template operations.
var MLBotDetectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/ml_bot_detection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_ml_bot_detection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/ml_bot_detection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_ml_bot_detection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/ml_bot_detection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_ml_bot_detection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/ml_bot_detection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_ml_bot_detection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// MLBotDetectionResource records the implemented nineteenth generated resource.
// It pairs a required status boolean (default false) with five required
// config-scalar string enums (action default block_period, identification_method
// default IP-and-User-Agent, model_type default Strict, challenge default
// Real-Browser-Enforcement) and one required integer config scalar (anomaly_count
// default 1, range 1..3), plus one optional integer config scalar (block_duration
// default 600, range 1..3600). Three object-item collections reuse already-
// reviewed indexed bounded item schemas: ip_list (max 30, IpList item: required
// ip string, wire-only idx default 1), url_list (max 30, UrlPattern item:
// optional url string max 127 with the ^/.*$ pattern, wire-only idx default 1),
// and exception_list (max 128, BotExceptionRuleList item: required
// concatenate_type/match_target/operator string enums, optional
// ip_range/value/value_name strings and value_check boolean default false,
// wire-only idx default 1). No new generator construct is introduced.
//
// The pinned OpenAPI references UrlPattern for url_list items and pins its URL
// maximum at 127 characters, so the contract follows that canonical graph.
var MLBotDetectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_ml_bot_detection",
	GoName:              "MLBotDetection",
	TypeNameSuffix:      "waf_ml_bot_detection",
	OperationName:       "ML bot detection",
	Path:                "/waf/apps/{ep_id}/ml_bot_detection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetMLBotDetection",
		PutRequest:  "#/components/schemas/PutMLBotDetection",
		Configs:     "#/components/schemas/MLBotDetection",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "client-id-block-period", Enum: []string{"alert", "alert_deny", "client-id-block-period", "deny_no_log"}},
			{Name: "anomaly_count", Kind: "integer", Required: true, HasDefault: true, Default: 1, Minimum: ptrFloat(1), Maximum: ptrFloat(3)},
			{Name: "block_duration", Kind: "integer", Required: false, HasDefault: true, Default: 600, Minimum: ptrFloat(1), Maximum: ptrFloat(3600)},
			{Name: "challenge", Kind: "string", Required: true, HasDefault: true, Default: "Real-Browser-Enforcement", Enum: []string{"Captcha-Enforcement", "Real-Browser-Enforcement"}},
			{Name: "identification_method", Kind: "string", Required: true, HasDefault: true, Default: "IP-and-User-Agent", Enum: []string{"Cookie", "IP", "IP-and-User-Agent"}},
			{Name: "model_type", Kind: "string", Required: true, HasDefault: true, Default: "Strict", Enum: []string{"Loose", "Strict"}},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "ip_list", MaxItems: 30, Unindexed: false},
			{Name: "url_list", MaxItems: 30, Unindexed: false},
			{Name: "exception_list", MaxItems: 128, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"ip_list": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "ip", Kind: "string", Required: true, HasDefault: false},
			},
			"url_list": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "url", Kind: "string", Required: false, HasDefault: false, MaxLength: 127, Pattern: `^/.*$`},
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
	Provenance: "Implemented as the nineteenth reviewed generated app-module resource and the ML-bot-detection shape (pinned config object MLBotDetection): " +
		"a required status boolean (default false), five required config-scalar string enums (action default block_period, identification_method default IP-and-User-Agent, model_type default Strict, challenge default Real-Browser-Enforcement), " +
		"a required integer config scalar anomaly_count (default 1, range 1..3), an optional integer config scalar block_duration (default 600, range 1..3600), " +
		"and three object-item collections reusing already-reviewed indexed bounded item schemas. " +
		"ip_list (max 30) uses the IpList item schema: required ip string and the wire-only positional idx (default 1). " +
		"url_list (max 30) uses the UrlPattern item schema: optional url string (max 127, ^/.*$ pattern) and the wire-only positional idx (default 1). " +
		"exception_list (max 128) uses the BotExceptionRuleList item schema: required concatenate_type/match_target/operator string enums and the optional ip_range/value/value_name strings and value_check boolean (default false), plus the wire-only positional idx (default 1). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action/identification_method/model_type/challenge enums, every config default, the anomaly_count 1..3 and block_duration 1..3600 integer bounds, the 30-item ip_list and url_list bounds, the 128-item exception_list bound, the UrlPattern url 127-character maximum and ^/.*$ pattern, the BotExceptionRuleList enums, the value_check default, and the idx defaults are pinned from OpenAPI 26.3.a. " +
		"The pinned OpenAPI references UrlPattern for url_list items and pins its URL maximum at 127 characters, so the contract follows UrlPattern. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
