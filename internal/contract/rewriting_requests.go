package contract

// RewritingRequestsScope classifies the app-level rewriting requests resource
// and manages the corresponding template operations.
var RewritingRequestsScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/rewriting_requests",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_rewriting_requests",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/rewriting_requests",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_rewriting_requests",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/rewriting_requests",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_rewriting_requests",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/rewriting_requests",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_rewriting_requests",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// RewritingRequestsResource records the implemented twenty-third generated
// resource and introduces one reviewed generator capability: string-typed idx.
//
// The configs object pins a required status boolean (default false), three
// optional booleans that default true (x_forwarded_for, identify_original_ip),
// three optional booleans that default false (source_port, x_forwarded_port,
// x_real_ip), and an optional x_header string (default X-Forwarded-For).
// One ordered object-item array rule_list (max 12) references RewritingRule.
//
// RewritingRule pins a wire-only positional idx that is a STRING on the wire
// (default "1", "start from '1'"), the first reviewed item schema whose idx is
// not an integer. Every existing reviewed item schema pins integer idx (default
// 1, or 0 for file_protection custom_file_types, or none for GraphQL). The
// OpenAPI 26.3.a pins idx type=string with default="1", and its GET/PUT
// examples use string-encoded sequential positive integers
// ("idx":"1".."8"). The generator treats the
// string idx as a string-encoded positive integer: the internal sort/key type
// stays int (parsed from the string), so sort, match, and duplicate detection
// remain numeric and avoid the lexicographic "10" < "2" trap. The wire JSON
// type differs (string vs number); the semantic invariant is identical to
// integer-idx resources.
//
// RewritingRule's other item fields are all optional: name (string max 39),
// action (string enum of 8, no default), protocol (string enum HTTP|HTTPS
// default HTTP), twelve boolean flags (all default false: protocol_filter,
// url_translation, host_filter, url_filter, referer_filter, location_filter,
// host_status, url_status, referer_status, header_status), eleven string
// fields (max 255 except rewrite_from/rewrite_to max 127: host_expression,
// url_expression, referer_expression, location_expression, rewrite_host,
// rewrite_url, rewrite_referer, rewrite_location, insert_header_name,
// insert_header_value, rewrite_from, rewrite_to), and one item-level
// scalar-string-array remove_header (max 10, item string max 63).
var RewritingRequestsResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_rewriting_requests",
	GoName:              "RewritingRequests",
	TypeNameSuffix:      "waf_rewriting_requests",
	OperationName:       "rewriting requests",
	Path:                "/waf/apps/{ep_id}/rewriting_requests",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetRewritingRequests",
		PutRequest:     "#/components/schemas/PutRewritingRequests",
		Configs:        "#/components/schemas/RewritingRequests",
		CollectionItem: "#/components/schemas/RewritingRule",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "identify_original_ip", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "source_port", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "x_forwarded_for", Kind: "boolean", Required: false, HasDefault: true, Default: true},
			{Name: "x_forwarded_port", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "x_header", Kind: "string", Required: false, HasDefault: true, Default: "X-Forwarded-For"},
			{Name: "x_real_ip", Kind: "boolean", Required: false, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "rule_list", MaxItems: 12},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: false, HasDefault: false, Enum: []string{"redirect-301", "redirect-301-advanced", "redirect-host", "rewrite-header-advanced", "rewrite-host", "rewrite-refer", "rewrite-response-header", "rewrite-url"}},
			{Name: "header_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "host_expression", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "host_filter", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "host_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "idx", Kind: "string", Required: false, HasDefault: true, Default: "1"},
			{Name: "insert_header_name", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "insert_header_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 1023},
			{Name: "location_expression", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "location_filter", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "location_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "name", Kind: "string", Required: false, HasDefault: false, MaxLength: 39},
			{Name: "protocol", Kind: "string", Required: false, HasDefault: true, Default: "HTTP", Enum: []string{"HTTP", "HTTPS"}},
			{Name: "protocol_filter", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "referer_expression", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "referer_filter", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "referer_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "remove_header", Kind: "string_array", Required: false, HasDefault: false, StringArray: &CandidateItemStringArrayConstraint{
				Name:          "remove_header",
				ItemAttribute: "header",
				MaxItems:      10,
				Required:      false,
				ItemMaxLength: 63,
			}},
			{Name: "rewrite_from", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "rewrite_host", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "rewrite_location", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "rewrite_referer", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "rewrite_to", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "rewrite_url", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "url_expression", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			{Name: "url_filter", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "url_status", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "url_translation", Kind: "boolean", Required: false, HasDefault: true, Default: false},
		},
	},
	Provenance: "Implemented as the twenty-third reviewed generated app-module resource and the first exercising string-typed idx. " +
		"The configs object pins a required status boolean (default false), three optional booleans defaulting true (x_forwarded_for, identify_original_ip), " +
		"three optional booleans defaulting false (source_port, x_forwarded_port, x_real_ip), and an optional x_header string (default X-Forwarded-For). " +
		"One ordered object-item array rule_list (max 12) references RewritingRule. " +
		"RewritingRule pins the wire-only positional idx as a STRING on the wire (default \"1\", \"start from '1'\") — the first reviewed item schema whose idx is not an integer. " +
		"OpenAPI 26.3.a pins idx type=string default=\"1\", and its GET/PUT examples use string-encoded sequential positive integers (\"idx\":\"1\"..\"8\"). " +
		"The generator treats the string idx as a string-encoded positive integer: the internal sort/key type stays int (parsed from the string), so sort, match, and duplicate detection remain numeric and avoid the lexicographic \"10\" < \"2\" trap. The wire JSON type differs (string vs number); the semantic invariant is identical to integer-idx resources. " +
		"RewritingRule's other item fields are all optional: name (max 39), action (enum of 8, no default), protocol (enum HTTP|HTTPS default HTTP), twelve boolean flags (all default false), eleven string fields (max 255 except rewrite_from/rewrite_to max 127), and one item-level scalar-string-array remove_header (max 10, item string max 63). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Every config and item default, the action/protocol enums, the rule_list 12-item bound, the remove_header 10-item bound and 63-character item maximum, every string maxLength, and the idx string default are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified. String-idx echo behavior (whether the backend ever returns an integer-encoded idx) is a live-verification question not proven locally; the generator decodes the reviewed string idx.",
}
