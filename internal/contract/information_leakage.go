package contract

// InformationLeakageScope classifies the app-level information leakage resource
// and manages the corresponding template operations.
var InformationLeakageScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/information_leakage",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_information_leakage",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/information_leakage",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_information_leakage",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/information_leakage",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_information_leakage",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/information_leakage",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_information_leakage",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// InformationLeakageResource records the implemented tenth generated resource. It
// is the combined-shape confidence check: a scalar-string-array (http_headers,
// free-form strings, max 26) alongside an object-item collection (sig_except_rules,
// max 100) reusing the SignatureBasedExceptionRule item schema already implemented
// for known_attacks. No new generator construct is introduced.
var InformationLeakageResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_information_leakage",
	GoName:              "InformationLeakage",
	TypeNameSuffix:      "waf_information_leakage",
	OperationName:       "information leakage",
	Path:                "/waf/apps/{ep_id}/information_leakage",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetInformationLeakage",
		PutRequest:     "#/components/schemas/PutInformationLeakage",
		Configs:        "#/components/schemas/InformationLeakage",
		CollectionItem: "#/components/schemas/SignatureBasedExceptionRule",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "deny_erase_no_log", Enum: []string{"alert", "alert_erase", "deny_erase_no_log"}},
			{Name: "cloak_error_pages", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "erase_http_headers", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "personal_info", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "server_info_disclose", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "sig_except_rules", MaxItems: 100},
		},
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
		},
		ScalarStringArrays: []CandidateScalarStringArrayConstraint{
			{
				Name:          "http_headers",
				ItemAttribute: "header",
				Enum:          nil,
				MaxItems:      26,
				Required:      false,
			},
		},
	},
	Provenance: "Implemented as the tenth reviewed generated app-module resource and the combined-shape confidence check: a free-form scalar-string-array (http_headers, max 26, no enum) alongside an object-item collection (sig_except_rules, max 100) reusing the SignatureBasedExceptionRule item schema already implemented for known_attacks. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Every config default, the action string enum, the nested sub-object fields, the nine-character sig_id minimum, and the 100-item collection bound are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
