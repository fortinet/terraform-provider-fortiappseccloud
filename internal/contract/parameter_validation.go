package contract

// ParameterValidationScope classifies the app-level parameter validation
// resource and manages the corresponding template operations.
var ParameterValidationScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/parameter_validation",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_parameter_validation",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/parameter_validation",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_parameter_validation",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/parameter_validation",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_parameter_validation",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/parameter_validation",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_parameter_validation",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// ParameterValidationResource records the implemented eighth generated
// resource. It is the first generated resource whose collection item contains
// a nested array-of-objects (sub_rule_list), exercising the two-level nesting
// capability. The pinned OpenAPI ParameterValidation schema carries one boolean
// config scalar (status) and one ordered object-item array (rule_list, max 12)
// whose items reference InputRule; InputRule references InputSubRule for the
// nested sub_rule_list (max 60).
var ParameterValidationResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_parameter_validation",
	GoName:              "ParameterValidation",
	TypeNameSuffix:      "waf_parameter_validation",
	OperationName:       "parameter validation",
	Path:                "/waf/apps/{ep_id}/parameter_validation",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetParameterValidation",
		PutRequest:     "#/components/schemas/PutParameterValidation",
		Configs:        "#/components/schemas/ParameterValidation",
		CollectionItem: "#/components/schemas/InputRule",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "rule_list", MaxItems: 12},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "block_period", Kind: "integer", Required: false, HasDefault: true, Default: 60, Minimum: ptrFloat(1), Maximum: ptrFloat(3600)},
			{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 49},
			{Name: "sub_rule_list", Kind: "array", Required: false, HasDefault: false, SubItemArray: &CandidateSubItemArrayConstraint{
				Name:     "sub_rule_list",
				MaxItems: 60,
				ItemName: "InputSubRule",
				ItemFields: []CandidateFieldConstraint{
					{Name: "arg_type", Kind: "string", Required: false, HasDefault: true, Default: "data-type", Enum: []string{"data-type", "regular-expression"}},
					{Name: "arg_val", Kind: "string", Required: false, HasDefault: false},
					{Name: "max_len", Kind: "integer", Required: false, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(1024)},
					{Name: "name", Kind: "string", Required: false, HasDefault: false, MaxLength: 63},
					{Name: "required", Kind: "boolean", Required: false, HasDefault: true, Default: false},
					{Name: "type_check", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				},
			}},
			{Name: "url", Kind: "string", Required: true, HasDefault: false, MaxLength: 2071, Pattern: `^/.*$`},
		},
	},
	Provenance: "Implemented as the eighth reviewed generated app-module resource and the first whose collection item contains a nested array-of-objects (sub_rule_list), exercising the two-level nesting capability. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Every config default, the action string enum, the block_period integer range (1..3600), the url ^/.*$ pattern, the 12-item rule_list bound, the 60-item sub_rule_list bound, and the nested InputSubRule fields are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
