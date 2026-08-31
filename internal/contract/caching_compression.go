package contract

// CachingCompressionScope classifies the app-level caching and compression
// resource and manages the corresponding template operations.
var CachingCompressionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/caching_compression",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_caching_compression",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/caching_compression",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_caching_compression",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/caching_compression",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_caching_compression",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/caching_compression",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_caching_compression",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// CachingCompressionResource records the implemented twenty-fifth generated
// resource and introduces one reviewed generator capability: nested composite
// config objects. The configs object pins a required status boolean (default
// false) and two nested-object config fields: cache (CachingConfig) and
// compress (CompressionConfig).
//
// CachingConfig pins: status (bool, required, default false), cache_timeout
// (int, default 60), timeout_type (enum minutes|hours, default minutes),
// allow_method (enum, default GET,HEAD), allow_return_code (enum, default
// 200), two scalar-string-arrays (allow_file_type, key_factor — unbounded
// arrays of enum strings), and two object-item collections: cookie_list
// (max 32, CookieList: required name max 126, idx default 1) and rule_list
// (max 32, BypassRule: optional method enum default any, optional url max
// 255, optional bypass_arg/bypass_cookie bools default false, optional
// bypass_arg_value/bypass_cookie_value strings max 128, idx default 1).
//
// CompressionConfig pins: status (bool, required, default false) and one
// object-item collection: content_type_list (max 10, ContentType: required
// type enum of 10, idx default 1).
var CachingCompressionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_caching_compression",
	GoName:              "CachingCompression",
	TypeNameSuffix:      "waf_caching_compression",
	OperationName:       "caching and compression",
	Path:                "/waf/apps/{ep_id}/caching_compression",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetCachingAndCompression",
		PutRequest:  "#/components/schemas/PutCachingAndCompression",
		Configs:     "#/components/schemas/CachingAndCompression",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "cache", Kind: "object", Required: false, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
				{Name: "allow_method", Kind: "string", Required: false, HasDefault: true, Default: "GET,HEAD", Enum: []string{"GET,HEAD", "GET,HEAD,OPTIONS", "GET,HEAD,OPTIONS,PUT,POST,PATCH,DELETE"}},
				{Name: "allow_return_code", Kind: "string", Required: false, HasDefault: true, Default: "200", Enum: []string{"200", "200,206", "200,206,301,302"}},
				{Name: "cache_timeout", Kind: "integer", Required: false, HasDefault: true, Default: 60},
				{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
				{Name: "timeout_type", Kind: "string", Required: false, HasDefault: true, Default: "minutes", Enum: []string{"hours", "minutes"}},
			}},
			{Name: "compress", Kind: "object", Required: false, HasDefault: false, ObjectFields: []CandidateFieldConstraint{
				{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			}},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "cache.cookie_list", MaxItems: 32},
			{Name: "cache.rule_list", MaxItems: 32},
			{Name: "compress.content_type_list", MaxItems: 10},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"cache.cookie_list": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 126},
			},
			"cache.rule_list": {
				{Name: "bypass_arg", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				{Name: "bypass_arg_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 128},
				{Name: "bypass_cookie", Kind: "boolean", Required: false, HasDefault: true, Default: false},
				{Name: "bypass_cookie_value", Kind: "string", Required: false, HasDefault: false, MaxLength: 128},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "method", Kind: "string", Required: false, HasDefault: true, Default: "any", Enum: []string{"any", "connect", "delete", "get", "head", "options", "patch", "post", "put", "trace"}},
				{Name: "url", Kind: "string", Required: false, HasDefault: false, MaxLength: 255},
			},
			"compress.content_type_list": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "type", Kind: "string", Required: true, HasDefault: false, Enum: []string{"application/javascript", "application/json", "application/rss+xml", "application/soap+xml", "application/x-javascript", "application/xml(or)text/xml", "text/css", "text/html", "text/javascript", "text/plain"}},
			},
		},
		ScalarStringArrays: []CandidateScalarStringArrayConstraint{
			{Name: "cache.allow_file_type", ItemAttribute: "file_type", Enum: []string{"binary", "media", "picture", "text", "other"}, MaxItems: 0, Required: false},
			{Name: "cache.key_factor", ItemAttribute: "factor", Enum: []string{"arguments", "host", "method", "protocol", "url", "cookies"}, MaxItems: 0, Required: false},
		},
	},
	Provenance: "Implemented as the twenty-fifth reviewed generated app-module resource and the caching-and-compression shape, introducing one reviewed generator capability: nested composite config objects. " +
		"The configs object pins a required status boolean (default false) and two nested-object config fields: cache (CachingConfig) and compress (CompressionConfig). " +
		"CachingConfig pins: status (required, default false), cache_timeout (default 60), timeout_type (enum minutes|hours, default minutes), allow_method (enum, default GET,HEAD), allow_return_code (enum, default 200), two scalar-string-arrays (allow_file_type, key_factor — unbounded arrays of enum strings), and two object-item collections (cookie_list max 32, rule_list max 32). " +
		"CompressionConfig pins: status (required, default false) and one object-item collection (content_type_list max 10). " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Every config and item default, the enums, the cookie_list/rule_list 32-item and content_type_list 10-item bounds, the name 126-char, URL 255-char, bypass_*_value 128-char maximums, the allow_file_type/key_factor enum values, and the idx defaults are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
