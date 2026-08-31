package contract

// RequestLimitsScope classifies the app-level request limits resource and
// manages the corresponding template operations.
var RequestLimitsScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/request_limits",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_request_limits",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/request_limits",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_request_limits",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/request_limits",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_request_limits",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/request_limits",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_request_limits",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// ptrFloat returns a pointer to v so integer range bounds can be pinned in
// CandidateFieldConstraint literals without a per-callsite helper.
func ptrFloat(v float64) *float64 {
	return &v
}

// RequestLimitsResource records the implemented third generated resource. It
// is the first generated resource that uses integer config scalars, a
// scalar-string-array collection (allow_methods), and no object-item ordered
// collection. The pinned OpenAPI RequestLimits schema carries 61 scalar config
// fields plus the
// allow_methods array of 12 HTTP-method enum strings.
var RequestLimitsResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_request_limits",
	GoName:              "RequestLimits",
	TypeNameSuffix:      "waf_request_limits",
	OperationName:       "request limits",
	Path:                "/waf/apps/{ep_id}/request_limits",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetRequestLimits",
		PutRequest:  "#/components/schemas/PutRequestLimits",
		Configs:     "#/components/schemas/RequestLimits",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "body_param_len", Kind: "integer", Required: true, HasDefault: true, Default: 8192, Minimum: ptrFloat(0), Maximum: ptrFloat(16384)},
			{Name: "chunk_size_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "cl_te_coexist_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "content_length_action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "content_length_num", Kind: "integer", Required: true, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(65536)},
			{Name: "cookie_num", Kind: "integer", Required: true, HasDefault: true, Default: 128, Minimum: ptrFloat(0), Maximum: ptrFloat(1023)},
			{Name: "duplicate_param_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "header_len", Kind: "integer", Required: true, HasDefault: true, Default: 8192, Minimum: ptrFloat(0), Maximum: ptrFloat(12288)},
			{Name: "header_line_num", Kind: "integer", Required: true, HasDefault: true, Default: 200, Minimum: ptrFloat(0), Maximum: ptrFloat(500)},
			{Name: "header_line_num_action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "header_name_len", Kind: "integer", Required: true, HasDefault: true, Default: 50, Minimum: ptrFloat(0), Maximum: ptrFloat(255)},
			{Name: "header_value_len", Kind: "integer", Required: true, HasDefault: true, Default: 4096, Minimum: ptrFloat(0), Maximum: ptrFloat(12288)},
			{Name: "http2_max_req_action", Kind: "string", Required: true, HasDefault: true, Default: "block_period", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "http2_max_requests_check", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "http2_max_requests_num", Kind: "integer", Required: true, HasDefault: true, Default: 1000, Minimum: ptrFloat(0), Maximum: ptrFloat(65535)},
			{Name: "http2_rst_action", Kind: "string", Required: true, HasDefault: true, Default: "block_period", Enum: []string{"alert", "alert_deny", "block_period", "deny_no_log"}},
			{Name: "http2_rst_stream_check", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "http2_rst_stream_frq_check", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "http2_rst_stream_frq_num", Kind: "integer", Required: true, HasDefault: true, Default: 20, Minimum: ptrFloat(1), Maximum: ptrFloat(65535)},
			{Name: "http2_rst_stream_num", Kind: "integer", Required: true, HasDefault: true, Default: 50, Minimum: ptrFloat(1), Maximum: ptrFloat(65535)},
			{Name: "http_header_action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "http_param_action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "http_req_action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "http_req_len", Kind: "integer", Required: true, HasDefault: true, Default: 2048, Minimum: ptrFloat(0), Maximum: ptrFloat(65536)},
			{Name: "illegal_char_check", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "illegal_cl_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_ctype_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_header_name_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_header_value_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_host_name_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_http_req_method_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_http_ver_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_param_name_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_param_value_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "illegal_res_code_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "inconsistent_cl_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "malformed_req_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "malformed_url_check", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "max_http_body_length", Kind: "integer", Required: true, HasDefault: true, Default: 16384, Minimum: ptrFloat(0), Maximum: ptrFloat(65536)},
			{Name: "max_setting_current_streams_num", Kind: "integer", Required: true, HasDefault: true, Default: 1000, Minimum: ptrFloat(0), Maximum: ptrFloat(100000)},
			{Name: "max_setting_frame_size", Kind: "integer", Required: true, HasDefault: true, Default: 4194303, Minimum: ptrFloat(0), Maximum: ptrFloat(16777215)},
			{Name: "max_setting_header_list_size", Kind: "integer", Required: true, HasDefault: true, Default: 65536, Minimum: ptrFloat(0), Maximum: ptrFloat(16777215)},
			{Name: "max_setting_header_table_size", Kind: "integer", Required: true, HasDefault: true, Default: 65535, Minimum: ptrFloat(0), Maximum: ptrFloat(16777215)},
			{Name: "max_setting_initial_window_size", Kind: "integer", Required: false, HasDefault: true, Default: 33554432, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647), ReadOnly: true},
			{Name: "multipart_formdata_bad_request_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "null_char_check", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "odd_and_even_space_attack_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "others_action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "param_name_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "param_value_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "post_req_ctype_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "range_num", Kind: "integer", Required: true, HasDefault: true, Default: 5, Minimum: ptrFloat(0), Maximum: ptrFloat(64)},
			{Name: "range_overlapping_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "redundant_header_check", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "req_filename_len", Kind: "integer", Required: true, HasDefault: true, Default: 2048, Minimum: ptrFloat(0), Maximum: ptrFloat(12288)},
			{Name: "rg_max_setting_initial_window_size", Kind: "integer", Required: true, HasDefault: true, Default: 33554432, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "rg_min_setting_initial_window_size", Kind: "integer", Required: true, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(2147483647)},
			{Name: "rpc_protocol_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: true},
			{Name: "url_param_len", Kind: "integer", Required: true, HasDefault: true, Default: 8192, Minimum: ptrFloat(0), Maximum: ptrFloat(12288)},
			{Name: "url_param_name_len", Kind: "integer", Required: true, HasDefault: true, Default: 4096, Minimum: ptrFloat(0), Maximum: ptrFloat(8192)},
			{Name: "url_param_num", Kind: "integer", Required: true, HasDefault: true, Default: 128, Minimum: ptrFloat(0), Maximum: ptrFloat(1023)},
			{Name: "url_param_value_len", Kind: "integer", Required: true, HasDefault: true, Default: 4096, Minimum: ptrFloat(0), Maximum: ptrFloat(8192)},
			{Name: "web_socket_protocol_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{},
		ItemFields:  []CandidateFieldConstraint{},
		ScalarStringArrays: []CandidateScalarStringArrayConstraint{
			{
				Name:          "allow_methods",
				ItemAttribute: "method",
				Enum:          []string{"connect", "delete", "get", "head", "options", "others", "patch", "post", "put", "rpc", "trace", "webdav"},
				MaxItems:      0,
				Required:      true,
			},
		},
	},
	Provenance: "Implemented as the third reviewed generated app-module resource and the first to use integer config scalars, a scalar-string-array collection, and no object-item ordered collection. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"Integer range bounds, the 12 HTTP-method allow_methods enum, and every config default are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
