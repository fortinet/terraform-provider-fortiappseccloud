package contract

// GraphQLProtectionScope classifies the app-level GraphQL protection resource and manages the corresponding template operations.
var GraphQLProtectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/graphql_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_graphql_protection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/graphql_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_graphql_protection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/graphql_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_graphql_protection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/graphql_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_graphql_protection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

var GraphQLProtectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_graphql_protection",
	GoName:              "GraphQLProtection",
	TypeNameSuffix:      "waf_graphql_protection",
	OperationName:       "GraphQL protection",
	Path:                "/waf/apps/{ep_id}/graphql_protection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetGraphQLProtection",
		PutRequest:     "#/components/schemas/PutGraphQLProtection",
		Configs:        "#/components/schemas/GraphQLProtection",
		CollectionItem: "#/components/schemas/GraphQLProtectionRule",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "rule_list", MaxItems: 10},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "alias_batch_query", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "alias_batch_query_number", Kind: "integer", Required: false, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "array_batch_query", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "array_batch_query_number", Kind: "integer", Required: false, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "field_number", Kind: "integer", Required: false, HasDefault: true, Default: 256, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "fragment", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "graphql_data_size", Kind: "integer", Required: false, HasDefault: true, Default: 1024, Minimum: ptrFloat(0), Maximum: ptrFloat(10240)},
			{Name: "introspection", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 40},
			{Name: "object_depth", Kind: "integer", Required: false, HasDefault: true, Default: 32, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "request_url", Kind: "string", Required: true, HasDefault: false},
			{Name: "value_size", Kind: "integer", Required: false, HasDefault: true, Default: 256, Minimum: ptrFloat(0), Maximum: ptrFloat(10240)},
		},
	},
	Provenance: "Implemented as the sixth reviewed generated app-module resource. Single object-item collection (rule_list, max 10) with string/boolean/integer item fields and no nested objects. The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. All config defaults and item field constraints are pinned from OpenAPI 26.3.a. Destroy remains unverified forget behavior; lifecycle behavior is locally tested rather than live-verified.",
}
