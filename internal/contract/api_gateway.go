package contract

// APIGatewayScope classifies the app-level API gateway resource and manages the
// corresponding template operations.
var APIGatewayScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/api_gateway",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_api_gateway",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/api_gateway",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_api_gateway",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/api_gateway",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_api_gateway",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/api_gateway",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_api_gateway",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// APIGatewayResource records the implemented twenty-fourth generated resource.
// It introduces three reviewed generator capabilities: computed-only item fields
// (APIUser uuid/api_key/create_time), multiple sibling sub-item arrays in one
// parent item (APIUser ip_list + referer_list), and item-level sensitivity
// (api_key).
//
// The configs object pins a required status boolean (default false) and a
// required action string enum (default alert_deny). Two ordered object-item
// collections use different item schemas: rule_list (max 8, APIPolicy) and
// user_list (max 12, APIUser).
//
// APIPolicy (rule_list item) pins all-optional fields: name (max 40),
// api_key_loc (enum http-parameter|http-header), api_key_verify (bool default
// false), field_name (max 255), rate_limit_period/rate_limit_req (int default
// 0, range 0..600 / 0..100000), one nested array-of-objects url_list
// (MatchURLPrefix max 8: frontend/backend max 255 with ^/.*$ pattern), one
// item-level scalar-string-array user_list (unbounded), and the wire-only idx
// (default 1).
//
// APIUser (user_list item) pins all-optional writable fields: name (max 40),
// email, comments (free strings), two nested array-of-objects ip_list (IpList
// max 16: required ip) and referer_list (RefererList max 16: required
// referer), and the wire-only idx (default 1). It also pins three reviewed
// computed-only (backend-managed) item fields — uuid, api_key, create_time —
// decoded from GET into Terraform state (Computed) and carried from the fresh
// GET into the replacement PUT (PreserveFromGet), never read from config.
// api_key is additionally Sensitive (redacted in plan/output; still stored in
// state). OpenAPI 26.3.a now marks all three fields readOnly.
var APIGatewayResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_api_gateway",
	GoName:              "APIGateway",
	TypeNameSuffix:      "waf_api_gateway",
	OperationName:       "API gateway",
	Path:                "/waf/apps/{ep_id}/api_gateway",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetAPIGateway",
		PutRequest:  "#/components/schemas/PutAPIGateway",
		Configs:     "#/components/schemas/APIGateway",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "rule_list", MaxItems: 8},
			{Name: "user_list", MaxItems: 12},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"rule_list": {
				{Name: "api_key_loc", Kind: "string", Required: false, HasDefault: false, Enum: []string{"http-header", "http-parameter"}},
				{Name: "api_key_verify", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				{Name: "field_name", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "name", Kind: "string", Required: false, HasDefault: false, MaxLength: 40},
				{Name: "rate_limit_period", Kind: "integer", Required: false, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(600)},
				{Name: "rate_limit_req", Kind: "integer", Required: false, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(100000)},
				{Name: "url_list", Kind: "array", Required: false, HasDefault: false, SubItemArray: &CandidateSubItemArrayConstraint{
					Name:     "url_list",
					MaxItems: 8,
					ItemName: "MatchURLPrefix",
					ItemFields: []CandidateFieldConstraint{
						{Name: "backend", Kind: "string", Required: false, HasDefault: false, MaxLength: 255, Pattern: `^/.*$`},
						{Name: "frontend", Kind: "string", Required: false, HasDefault: false, MaxLength: 255, Pattern: `^/.*$`},
					},
				}},
				{Name: "user_list", Kind: "string_array", Required: false, HasDefault: false, StringArray: &CandidateItemStringArrayConstraint{
					Name:          "user_list",
					ItemAttribute: "user",
					MaxItems:      0,
					Required:      false,
				}},
			},
			"user_list": {
				{Name: "comments", Kind: "string", Required: false, HasDefault: false},
				{Name: "email", Kind: "string", Required: false, HasDefault: false},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "ip_list", Kind: "array", Required: false, HasDefault: false, SubItemArray: &CandidateSubItemArrayConstraint{
					Name:     "ip_list",
					MaxItems: 16,
					ItemName: "IpList",
					ItemFields: []CandidateFieldConstraint{
						{Name: "ip", Kind: "string", Required: true, HasDefault: false},
					},
				}},
				{Name: "name", Kind: "string", Required: false, HasDefault: false, MaxLength: 40},
				{Name: "referer_list", Kind: "array", Required: false, HasDefault: false, SubItemArray: &CandidateSubItemArrayConstraint{
					Name:     "referer_list",
					MaxItems: 16,
					ItemName: "RefererList",
					ItemFields: []CandidateFieldConstraint{
						{Name: "referer", Kind: "string", Required: true, HasDefault: false},
					},
				}},
			},
		},
		ComputedOnlyItemFields: []CandidateComputedOnlyItemFieldConstraint{
			{Path: "configs.user_list.item.uuid", ReadOnly: true, PreserveFromGet: true, Sensitive: false, Provenance: "OpenAPI 26.3.a marks APIUser.uuid readOnly. It is decoded from GET and preserved from the fresh GET into replacement PUT arrays."},
			{Path: "configs.user_list.item.api_key", ReadOnly: true, PreserveFromGet: true, Sensitive: true, Provenance: "OpenAPI 26.3.a marks APIUser.api_key readOnly. It is decoded from GET, preserved from the fresh GET into replacement PUT arrays, and marked Sensitive in Terraform."},
			{Path: "configs.user_list.item.create_time", ReadOnly: true, PreserveFromGet: true, Sensitive: false, Provenance: "OpenAPI 26.3.a marks APIUser.create_time readOnly. It is decoded from GET and preserved from the fresh GET into replacement PUT arrays."},
		},
	},
	Provenance: "Implemented as the twenty-fourth reviewed generated app-module resource and the API gateway shape, introducing three reviewed generator capabilities: computed-only item fields (APIUser uuid/api_key/create_time), multiple sibling sub-item arrays in one parent item (APIUser ip_list + referer_list), and item-level sensitivity (api_key). " +
		"The configs object pins a required status boolean (default false) and a required action string enum (default alert_deny). Two ordered object-item collections use different item schemas: rule_list (max 8, APIPolicy) and user_list (max 12, APIUser). " +
		"APIPolicy pins all-optional fields (name max 40, api_key_loc enum, api_key_verify default false, field_name max 255, rate_limit_period/rate_limit_req default 0 range 0..600/0..100000), one nested url_list (MatchURLPrefix max 8, frontend/backend max 255 ^/.*$), one item-level scalar-string-array user_list (unbounded), and idx default 1. " +
		"APIUser pins all-optional writable fields (name max 40, email, comments), two sibling nested ip_list (IpList max 16, required ip) and referer_list (RefererList max 16, required referer), idx default 1, and three computed-only backend-managed fields (uuid, api_key, create_time) decoded from GET into state and carried from the fresh GET into the PUT, never read from config; api_key is additionally Sensitive. " +
		"OpenAPI 26.3.a marks the computed-only fields readOnly. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Every config and item default, the action/protocol enums, the rule_list 8-item and user_list 12-item bounds, the url_list 8-item and ip_list/referer_list 16-item bounds, the rate_limit_period 0..600 and rate_limit_req 0..100000 ranges, every string maxLength, the ^/.*$ patterns, and the idx defaults are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; lifecycle behavior is locally tested rather than live-verified. Computed-only PUT echo behavior (whether the backend accepts unchanged GET values and whether omission clears them) is a live-verification question not proven locally; the generator preserves the reviewed GET values on PUT.",
}
