package contract

// WaitingRoomScope classifies the app-level waiting room resource and manages
// the corresponding template operations. The waiting_room_overview read-only
// endpoint is separately excluded (it is not a durable GET/PUT config pair).
var WaitingRoomScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/waiting_room",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_waiting_room",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/waiting_room",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_waiting_room",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/waiting_room",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_waiting_room",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/waiting_room",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_waiting_room",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// WaitingRoomResource records the implemented sixteenth generated resource. It
// pairs two required config scalars (status boolean default false and path
// string default /.*) with six optional config scalars carrying reviewed
// defaults: enable_total_active_users (boolean default true), x-forwarded-for
// style booleans aside, the integers total_active_users (default 1000),
// new_users_per_min (default 60), session_duration (default 5), the boolean
// enable_new_users_per_min (default false), and the custom_wt_page string
// (default Predefined). One object-item collection bypass_rules (max 100)
// reuses the indexed bounded ownership wrapper with the WRBypassRule item
// schema: required rule_type string enum [source-ip] (max 64) and required
// rule_value string, plus the wire-only positional idx (default 1). No new
// generator construct is introduced.
var WaitingRoomResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_waiting_room",
	GoName:              "WaitingRoom",
	TypeNameSuffix:      "waf_waiting_room",
	OperationName:       "waiting room",
	Path:                "/waf/apps/{ep_id}/waiting_room",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetWaitingRoom",
		PutRequest:  "#/components/schemas/PutWaitingRoom",
		Configs:     "#/components/schemas/WaitingRoom",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "custom_wt_page", Kind: "string", Required: false, HasDefault: true, Default: "Predefined"},
			{Name: "enable_new_users_per_min", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "enable_total_active_users", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "new_users_per_min", Kind: "integer", Required: false, HasDefault: true, Default: 60},
			{Name: "path", Kind: "string", Required: true, HasDefault: true, Default: "/.*"},
			{Name: "session_duration", Kind: "integer", Required: false, HasDefault: true, Default: 5, Minimum: ptrFloat(1), Maximum: ptrFloat(30)},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "total_active_users", Kind: "integer", Required: false, HasDefault: true, Default: 1000},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "bypass_rules", MaxItems: 100, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"bypass_rules": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "rule_type", Kind: "string", Required: true, HasDefault: false, Enum: []string{"source-ip"}, MaxLength: 64, Pattern: "source-ip"},
				{Name: "rule_value", Kind: "string", Required: true, HasDefault: false},
			},
		},
	},
	Provenance: "Implemented as the sixteenth reviewed generated app-module resource and the waiting-room shape: " +
		"two required config scalars (status boolean default false and path string default /.*) plus six optional config scalars carrying reviewed defaults " +
		"(enable_total_active_users boolean default true, enable_new_users_per_min boolean default false, total_active_users integer default 1000, new_users_per_min integer default 60, session_duration integer default 5, custom_wt_page string default Predefined), " +
		"and one object-item collection bypass_rules (max 100) using the WRBypassRule item schema: required rule_type string enum [source-ip] (max 64) and required rule_value string, plus the wire-only positional idx (default 1). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The rule_type single-value enum, the rule_type 64-character maximum, every config default, the 100-item bypass_rules bound, and the WRBypassRule required fields are pinned from OpenAPI 26.3.a. " +
		"OpenAPI 26.3.a pins session_duration as an unconditional 1..30 range and expresses the enable-gated total_active_users/new_users_per_min ranges plus their comparison through x-fortinet-cross-field-v1. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
