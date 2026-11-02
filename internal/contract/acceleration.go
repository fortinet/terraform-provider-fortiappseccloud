package contract

// AccelerationScope classifies the app-level web content acceleration
// resource and manages the corresponding template operations.
var AccelerationScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/acceleration",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_acceleration",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/acceleration",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_acceleration",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/acceleration",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_acceleration",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/acceleration",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_acceleration",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// AccelerationResource records the implemented twenty-sixth generated
// resource. The configs object pins an optional status boolean (default
// false) and five optional boolean minify/combine switches (css_minify,
// html_minify, html_css2head, html_combine_heads, js_minify, each default
// false), plus one object-item collection: exception_list (max 256,
// AccelerationException: required host_status bool default false, required
// url_pattern max 255, required url_type enum string|regex default string,
// optional host max 255, idx default 0 described as starting from 1).
var AccelerationResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_acceleration",
	GoName:              "Acceleration",
	TypeNameSuffix:      "waf_acceleration",
	OperationName:       "web content acceleration",
	Path:                "/waf/apps/{ep_id}/acceleration",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetAcceleration",
		PutRequest:     "#/components/schemas/PutAcceleration",
		Configs:        "#/components/schemas/Acceleration",
		CollectionItem: "#/components/schemas/AccelerationException",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "css_minify", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "html_combine_heads", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "html_css2head", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "html_minify", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "js_minify", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "exception_list", MaxItems: 256},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "host", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "host_status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 0},
			{Name: "url_pattern", Kind: "string", Required: true, HasDefault: false, MaxLength: 255},
			{Name: "url_type", Kind: "string", Required: true, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
		},
	},
	Provenance: "Implemented as the twenty-sixth reviewed generated app-module resource. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The template-scoped GET/PUT pair reuses the exact app GetAcceleration/PutAcceleration schema graph. " +
		"Every config and item default, the exception_list 256-item bound, the host/url_pattern 255-char maximums, the string|regex url_type enum, and the host_status/url_pattern/url_type required markers are pinned from OpenAPI 26.4. " +
		"The accepted dev1 lifecycle verified the disable-on-destroy configs.status=false write with normalized verification and exact restoration; " +
		"the template-scoped disable write was verified on a disposable template.",
}
