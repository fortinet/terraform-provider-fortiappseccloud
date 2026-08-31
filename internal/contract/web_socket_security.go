package contract

// WebSocketSecurityScope classifies the app-level WebSocket security resource
// and manages the corresponding template operations.
var WebSocketSecurityScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/web_socket_security",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_web_socket_security",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/web_socket_security",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_web_socket_security",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/web_socket_security",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_web_socket_security",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/web_socket_security",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_web_socket_security",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// WebSocketSecurityResource records the implemented ninth generated resource. It
// reuses the nested array-of-objects-in-item capability (origin_list) added for
// parameter_validation. The pinned OpenAPI WebSocketSecurity schema carries two
// config scalars (action string enum, status boolean) and one ordered
// object-item array (rule_list, max 12) whose items reference WebSocketRule;
// WebSocketRule references AllowedOrigin for the nested origin_list (max 256).
var WebSocketSecurityResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_web_socket_security",
	GoName:              "WebSocketSecurity",
	TypeNameSuffix:      "waf_web_socket_security",
	OperationName:       "WebSocket security",
	Path:                "/waf/apps/{ep_id}/web_socket_security",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetWebSocketSecurity",
		PutRequest:     "#/components/schemas/PutWebSocketSecurity",
		Configs:        "#/components/schemas/WebSocketSecurity",
		CollectionItem: "#/components/schemas/WebSocketRule",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "rule_list", MaxItems: 12},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "allow_binary_text", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "allow_plain_text", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "allow_websocket", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "block_attacks", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "block_extensions", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "max_frm_size", Kind: "integer", Required: true, HasDefault: true, Default: 64, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "max_msg_size", Kind: "integer", Required: true, HasDefault: true, Default: 1024, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 39},
			{Name: "origin_list", Kind: "array", Required: false, HasDefault: false, SubItemArray: &CandidateSubItemArrayConstraint{
				Name:     "origin_list",
				MaxItems: 256,
				ItemName: "AllowedOrigin",
				ItemFields: []CandidateFieldConstraint{
					{Name: "origin", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
				},
			}},
			{Name: "url", Kind: "string", Required: true, HasDefault: false, MaxLength: 255, Pattern: `^/.*$`},
		},
	},
	Provenance: "Implemented as the ninth reviewed generated app-module resource and the second to use the nested array-of-objects-in-item capability (origin_list), reusing the shape added for parameter_validation. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Every config default, the action string enum, the required boolean/integer item fields, the name (39) and url (255) length limits, the 12-item rule_list bound, the 256-item origin_list bound, and the nested AllowedOrigin origin (255) field are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
