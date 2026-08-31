package contract

// DDoSPreventionScope classifies the app-level DDoS prevention resource and
// manages the corresponding template operations.
var DDoSPreventionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/ddos_prevention",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_ddos_prevention",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/ddos_prevention",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_ddos_prevention",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/ddos_prevention",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_ddos_prevention",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/ddos_prevention",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_ddos_prevention",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// DDoSPreventionResource records the implemented eleventh generated resource.
// It is a collectionless configs shape: twelve config scalars (eleven required
// booleans/enums/bounded integers plus one optional bounded integer,
// block_period) and one optional free-form scalar-string-array (ip_exception).
// No object-item ordered collection is present. The shape reuses the integer
// config scalar minimum/maximum rendering, the optional config scalar default
// + use_state_for_unknown behavior, and the scalar-string-array ownership
// wrapper (omission/empty/populated) already exercised by request_limits and
// information_leakage. No new generator construct is introduced.
var DDoSPreventionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_ddos_prevention",
	GoName:              "DDoSPrevention",
	TypeNameSuffix:      "waf_ddos_prevention",
	OperationName:       "DDoS prevention",
	Path:                "/waf/apps/{ep_id}/ddos_prevention",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetDDoSPrevention",
		PutRequest:  "#/components/schemas/PutDDoSPrevention",
		Configs:     "#/components/schemas/DDoSPrevention",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "block_period", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "block_period", Kind: "integer", Required: false, HasDefault: true, Default: 600, Minimum: ptrFloat(1), Maximum: ptrFloat(3600)},
			{Name: "challenge", Kind: "string", Required: true, HasDefault: true, Default: "real-browser-enforcement", Enum: []string{"captcha-enforcement", "disabled", "real-browser-enforcement"}},
			{Name: "conn_flood_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "conn_flood_limit", Kind: "integer", Required: true, HasDefault: true, Default: 100, Minimum: ptrFloat(1), Maximum: ptrFloat(1024)},
			{Name: "http_access_limit", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "http_flood_prevent", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "http_request_limit", Kind: "integer", Required: true, HasDefault: true, Default: 1000, Minimum: ptrFloat(1), Maximum: ptrFloat(65535)},
			{Name: "http_session_limit", Kind: "integer", Required: true, HasDefault: true, Default: 500, Minimum: ptrFloat(0), Maximum: ptrFloat(4096)},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "tcp_conn_num_limit", Kind: "integer", Required: true, HasDefault: true, Default: 10, Minimum: ptrFloat(10), Maximum: ptrFloat(65535)},
			{Name: "tcp_flood_prevent", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{},
		ItemFields:  []CandidateFieldConstraint{},
		ScalarStringArrays: []CandidateScalarStringArrayConstraint{
			{
				Name:          "ip_exception",
				ItemAttribute: "ip",
				Enum:          nil,
				MaxItems:      0,
				Required:      false,
			},
		},
	},
	Provenance: "Implemented as the eleventh reviewed generated app-module resource and the first collectionless DDoS-prevention shape: " +
		"twelve config scalars (eleven required plus the optional bounded integer block_period, default 600, range 1-3600) " +
		"and one optional free-form scalar-string-array (ip_exception, no enum, unbounded). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Integer range bounds, the action and challenge string enums, every config default, and the ip_exception ownership wrapper are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
