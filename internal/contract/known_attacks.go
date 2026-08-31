package contract

// KnownAttacksScope classifies the app-level known attacks resource and manages
// the corresponding template operations.
var KnownAttacksScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/known_attacks",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_known_attacks",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/known_attacks",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_known_attacks",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/known_attacks",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_known_attacks",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/known_attacks",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_known_attacks",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// KnownAttacksResource records the implemented fourth generated resource. It is
// the first generated resource with two collections that have different item
// schemas and the first whose item fields include nested objects (one level
// deep). The pinned OpenAPI KnownAttacks schema carries 20 boolean config
// scalars, one string enum (action), one integer enum (sensitivity_level), and
// two ordered object-item arrays (sig_except_rules, stx_except_rules, max 100
// each) whose items reference distinct sub-schemas with nested sub-objects.
var KnownAttacksResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_known_attacks",
	GoName:              "KnownAttacks",
	TypeNameSuffix:      "waf_known_attacks",
	OperationName:       "known attacks",
	Path:                "/waf/apps/{ep_id}/known_attacks",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetKnownAttacks",
		PutRequest:  "#/components/schemas/PutKnownAttacks",
		Configs:     "#/components/schemas/KnownAttacks",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "arithmetic_sql_inject", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "condition_sql_inject", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "cross_site_script", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "cross_site_script_ext", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "embed_sql_inject", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "generic_attacks", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "generic_attacks_ext", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "html_attr_xss_inject", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "html_css_xss_inject", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "html_tag_xss_inject", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "js_func_xss_inject", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "js_var_xss_inject", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "known_exploits", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "line_comments", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "sensitivity_level", Kind: "integer", Required: true, HasDefault: true, Default: 1, IntEnum: []int64{1, 2, 3, 4}},
			{Name: "sql_func_inject", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "sql_inject", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "sql_inject_ext", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "stack_sql_inject", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "trojans", Kind: "boolean", Required: true, HasDefault: true, Default: true},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "sig_except_rules", MaxItems: 100},
			{Name: "stx_except_rules", MaxItems: 100},
		},
		ItemFields: []CandidateFieldConstraint{},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"sig_except_rules": {
				{Name: "cookie", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "check_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
					{Name: "check_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
				{Name: "host", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
				}},
				{Name: "http_header", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "check_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
					{Name: "check_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "json", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "check_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
					{Name: "check_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
				{Name: "param", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "check_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
					{Name: "check_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
				{Name: "sig_id", Kind: "string", Required: true, HasDefault: false, MinLength: 9, MaxLength: 9},
				{Name: "sig_name", Kind: "string", Required: true, HasDefault: false},
				{Name: "url", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
			},
			"stx_except_rules": {
				{Name: "attack_cat", Kind: "string", Required: true, HasDefault: false, Enum: []string{"Cross Site Scripting (Syntax Based Detection)", "SQL Injection (Syntax Based Detection)"}},
				{Name: "attack_name", Kind: "string", Required: true, HasDefault: false, Enum: []string{"Arithmetic Operation Based Boolean Injection", "Condition Based Boolean Injection", "Embedded Queries SQL Injection", "HTML Attribute Based XSS Injection", "HTML CSS Based XSS Injection", "HTML Tag Based XSS Injection", "Javascript Function Based XSS Injection", "Javascript Variable Based XSS Injection", "Line Comments", "SQL Function Based Boolean Injection", "Stacked Queries SQL Injection"}},
				{Name: "cookie", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "param", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
				{Name: "url", Kind: "object", Required: true, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
					{Name: "status", Kind: "boolean", Required: false, HasDefault: false},
					{Name: "type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
					{Name: "value", Kind: "string", Required: false, HasDefault: false, MaxLength: 64},
				}},
			},
		},
	},
	Provenance: "Implemented as the fourth reviewed generated app-module resource and the first with two collections that have different item schemas and nested-object item fields. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Every config default, the action string enum, the sensitivity_level integer enum, the nested sub-object string/boolean fields, and the 100-item collection bounds are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
