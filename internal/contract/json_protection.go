package contract

// JsonProtectionScope classifies the app-level JSON protection resource and manages the corresponding template operations.
var JsonProtectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/json_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_json_protection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/json_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_json_protection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/json_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_json_protection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/json_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_json_protection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

var JsonProtectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_json_protection",
	GoName:              "JSONProtection",
	TypeNameSuffix:      "waf_json_protection",
	OperationName:       "JSON protection",
	Path:                "/waf/apps/{ep_id}/json_protection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetJsonProtection",
		PutRequest:     "#/components/schemas/PutJsonProtection",
		Configs:        "#/components/schemas/JsonProtection",
		CollectionItem: "#/components/schemas/JsonFile",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "bucket", Kind: "string", Required: false, HasDefault: false},
			{Name: "prefix", Kind: "string", Required: false, HasDefault: false},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "file_list", MaxItems: 10},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "filename", Kind: "string", Required: true, HasDefault: false},
			{Name: "limit_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "md5", Kind: "string", Required: false, HasDefault: false},
			{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 40},
			{Name: "schema_valid", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "url", Kind: "string", Required: true, HasDefault: false, MaxLength: 255},
		},
	},
	Provenance: "Implemented as the seventh reviewed generated app-module resource. Single object-item collection (file_list, max 10) with string/boolean item fields and no nested objects. The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. All config defaults and item field constraints are pinned from OpenAPI 26.3.a. Destroy remains unverified forget behavior; lifecycle behavior is locally tested rather than live-verified.",
}
