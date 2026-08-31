package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const (
	CSRFResourceName                     = "fortiappseccloud_waf_csrf_protection"
	CSRFPath                             = "/waf/apps/{ep_id}/csrf_protection"
	URLAccessResourceName                = "fortiappseccloud_waf_url_access"
	URLAccessPath                        = "/waf/apps/{ep_id}/url_access"
	RequestLimitsResourceName            = "fortiappseccloud_waf_request_limits"
	RequestLimitsPath                    = "/waf/apps/{ep_id}/request_limits"
	KnownAttacksResourceName             = "fortiappseccloud_waf_known_attacks"
	KnownAttacksPath                     = "/waf/apps/{ep_id}/known_attacks"
	HttpHeaderSecurityResourceName       = "fortiappseccloud_waf_http_header_security"
	HttpHeaderSecurityPath               = "/waf/apps/{ep_id}/http_header_security"
	GraphQLProtectionResourceName        = "fortiappseccloud_waf_graphql_protection"
	GraphQLProtectionPath                = "/waf/apps/{ep_id}/graphql_protection"
	JSONProtectionResourceName           = "fortiappseccloud_waf_json_protection"
	JSONProtectionPath                   = "/waf/apps/{ep_id}/json_protection"
	ParameterValidationResourceName      = "fortiappseccloud_waf_parameter_validation"
	ParameterValidationPath              = "/waf/apps/{ep_id}/parameter_validation"
	WebSocketSecurityResourceName        = "fortiappseccloud_waf_web_socket_security"
	WebSocketSecurityPath                = "/waf/apps/{ep_id}/web_socket_security"
	InformationLeakageResourceName       = "fortiappseccloud_waf_information_leakage"
	InformationLeakagePath               = "/waf/apps/{ep_id}/information_leakage"
	DDoSPreventionResourceName           = "fortiappseccloud_waf_ddos_prevention"
	DDoSPreventionPath                   = "/waf/apps/{ep_id}/ddos_prevention"
	CookieSecurityResourceName           = "fortiappseccloud_waf_cookie_security"
	CookieSecurityPath                   = "/waf/apps/{ep_id}/cookie_security"
	KnownBotsResourceName                = "fortiappseccloud_waf_known_bots"
	KnownBotsPath                        = "/waf/apps/{ep_id}/known_bots"
	BotDeceptionResourceName             = "fortiappseccloud_waf_bot_deception"
	BotDeceptionPath                     = "/waf/apps/{ep_id}/bot_deception"
	BiometricsBasedDetectionResourceName = "fortiappseccloud_waf_biometrics_based_detection"
	BiometricsBasedDetectionPath         = "/waf/apps/{ep_id}/biometrics_based_detection"
	WaitingRoomResourceName              = "fortiappseccloud_waf_waiting_room"
	WaitingRoomPath                      = "/waf/apps/{ep_id}/waiting_room"
	MITBProtectionResourceName           = "fortiappseccloud_waf_mitb_protection"
	MITBProtectionPath                   = "/waf/apps/{ep_id}/mitb_protection"
	ThresholdDetectionResourceName       = "fortiappseccloud_waf_threshold_detection"
	ThresholdDetectionPath               = "/waf/apps/{ep_id}/threshold_detection"
	MLBotDetectionResourceName           = "fortiappseccloud_waf_ml_bot_detection"
	MLBotDetectionPath                   = "/waf/apps/{ep_id}/ml_bot_detection"
	FileProtectionResourceName           = "fortiappseccloud_waf_file_protection"
	FileProtectionPath                   = "/waf/apps/{ep_id}/file_protection"
	MobileAPIProtectionResourceName      = "fortiappseccloud_waf_mobile_api_protection"
	MobileAPIProtectionPath              = "/waf/apps/{ep_id}/mobile_api_protection"
	XMLProtectionPolicyResourceName      = "fortiappseccloud_waf_xml_protection_policy"
	XMLProtectionPolicyPath              = "/waf/apps/{ep_id}/xml_protection_policy"
	RewritingRequestsResourceName        = "fortiappseccloud_waf_rewriting_requests"
	RewritingRequestsPath                = "/waf/apps/{ep_id}/rewriting_requests"
	APIGatewayResourceName               = "fortiappseccloud_waf_api_gateway"
	APIGatewayPath                       = "/waf/apps/{ep_id}/api_gateway"
	CachingCompressionResourceName       = "fortiappseccloud_waf_caching_compression"
	CachingCompressionPath               = "/waf/apps/{ep_id}/caching_compression"

	forgetDestroyReason                     = "No DELETE operation exists and status=false disable semantics have not been live-verified"
	noSafeStatusDestroyReason               = "No DELETE operation exists and no safe standalone writable boolean status is available for disable-on-destroy"
	templateDestroyVerifiedReason           = "Template module configs.status=false disable behavior was verified in the accepted complete dev1 template matrix and confirmed as the module disable API behavior"
	templateCachingCompressionDestroyReason = "Direct dev1 curl control verified that template caching/compression disable requires configs.status, configs.cache.status, and configs.compress.status to be false together"
)

var (
	terraformNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	goNamePattern        = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

	// reviewedBackendAdditions pins the exact reviewed backend field additions
	// per resource. The map value keys are dotted item-field leaf paths. An
	// empty (nil) slice means the reviewed resource has no backend additions.
	// The generator rejects any addition whose path/kind/required/enum/
	// max-length/pattern does not match this reviewed contract.
	//
	reviewedBackendAdditions = map[string]map[string]backendAdditionExpectation{
		CSRFResourceName:      nil,
		URLAccessResourceName: nil,
	}

	// reviewedBackendConfigScalarConstraints pins the reviewed integer
	// config-scalar numeric enrichments per resource. A nil entry means the
	// reviewed resource has no config-scalar constraint enrichments. The
	// generator rejects any profile enrichment that does not match this map
	// exactly, and requires the matching contract
	// BackendEnrichedConfigScalarConstraints marker.
	reviewedBackendConfigScalarConstraints = map[string]map[string]backendConfigScalarConstraintExpectation{}

	reviewedResourceExpectations = map[string]resourceExpectation{
		CSRFResourceName: {
			goName:         "CSRFProtection",
			typeNameSuffix: "waf_csrf_protection",
			operationName:  "CSRF protection",
			path:           CSRFPath,
			fields: map[string]fieldExpectation{
				"ep_id":                         {terraformPolicy: "required"},
				"template":                      {terraformPolicy: "required"},
				"configs.action":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
				"configs.status":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
				"configs.page_list.item.filter": {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
				"configs.page_list.item.url":    {terraformPolicy: "required"},
				"configs.page_list.item.name":   {terraformPolicy: "optional_computed", allowWireNull: true},
				"configs.page_list.item.value":  {terraformPolicy: "optional_computed", allowWireNull: true},
				"configs.page_list.item.idx":    {terraformPolicy: "wire_only", wireOnly: true},
				"configs.url_list.item.filter":  {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
				"configs.url_list.item.url":     {terraformPolicy: "required"},
				"configs.url_list.item.name":    {terraformPolicy: "optional_computed", allowWireNull: true},
				"configs.url_list.item.value":   {terraformPolicy: "optional_computed", allowWireNull: true},
				"configs.url_list.item.idx":     {terraformPolicy: "wire_only", wireOnly: true},
			},
			collections: map[string]string{
				"configs.page_list": "page_list",
				"configs.url_list":  "url_list",
			},
		},
		URLAccessResourceName: {
			goName:         "URLAccess",
			typeNameSuffix: "waf_url_access",
			operationName:  "URL access",
			path:           URLAccessPath,
			fields: map[string]fieldExpectation{
				"ep_id":                           {terraformPolicy: "required"},
				"template":                        {terraformPolicy: "required"},
				"configs.status":                  {terraformPolicy: "optional_computed", useStateForUnknown: true},
				"configs.rule_list.item.action":   {terraformPolicy: "required"},
				"configs.rule_list.item.name":     {terraformPolicy: "required"},
				"configs.rule_list.item.url":      {terraformPolicy: "required"},
				"configs.rule_list.item.url_type": {terraformPolicy: "required"},
				"configs.rule_list.item.idx":      {terraformPolicy: "wire_only", wireOnly: true},
			},
			collections: map[string]string{
				"configs.rule_list": "rule_list",
			},
		},
		RequestLimitsResourceName: {
			goName:         "RequestLimits",
			typeNameSuffix: "waf_request_limits",
			operationName:  "request limits",
			path:           RequestLimitsPath,
			fields:         requestLimitsFieldExpectations(),
			collections:    map[string]string{},
			scalarStringArrays: map[string]scalarStringArrayExpectation{
				"configs.allow_methods": {
					wrapperBlock:  "allow_methods",
					itemAttribute: "method",
					enum:          []string{"connect", "delete", "get", "head", "options", "others", "patch", "post", "put", "rpc", "trace", "webdav"},
					maxItems:      0,
					required:      true,
					provenance:    "Reviewed from OpenAPI 26.3.a: allow_methods is a required array of HTTP-method enum strings with no maxItems. The pinned schema lists allow_methods in the RequestLimits required array. It is encoded as an ownership wrapper of item blocks carrying a synthetic method string attribute, reusing the object-item omission/empty/populated semantics. A missing remote array fails closed when Terraform owns it instead of being silently coerced to []. Local-only; live behavior unverified.",
				},
			},
		},
		KnownAttacksResourceName: {
			goName:         "KnownAttacks",
			typeNameSuffix: "waf_known_attacks",
			operationName:  "known attacks",
			path:           KnownAttacksPath,
			fields:         knownAttacksFieldExpectations(),
			collections: map[string]string{
				"configs.sig_except_rules": "sig_except_rules",
				"configs.stx_except_rules": "stx_except_rules",
			},
		},
		HttpHeaderSecurityResourceName: {
			goName:         "HttpHeaderSecurity",
			typeNameSuffix: "waf_http_header_security",
			operationName:  "HTTP header security",
			path:           HttpHeaderSecurityPath,
			fields:         httpHeaderSecurityFieldExpectations(),
			collections:    map[string]string{},
		},
		GraphQLProtectionResourceName: {
			goName:         "GraphQLProtection",
			typeNameSuffix: "waf_graphql_protection",
			operationName:  "GraphQL protection",
			path:           GraphQLProtectionPath,
			fields:         graphqlProtectionFieldExpectations(),
			collections: map[string]string{
				"configs.rule_list": "rule_list",
			},
		},
		JSONProtectionResourceName: {
			goName:         "JSONProtection",
			typeNameSuffix: "waf_json_protection",
			operationName:  "JSON protection",
			path:           JSONProtectionPath,
			fields:         jsonProtectionFieldExpectations(),
			collections: map[string]string{
				"configs.file_list": "file_list",
			},
		},
		ParameterValidationResourceName: {
			goName:         "ParameterValidation",
			typeNameSuffix: "waf_parameter_validation",
			operationName:  "parameter validation",
			path:           ParameterValidationPath,
			fields:         parameterValidationFieldExpectations(),
			collections: map[string]string{
				"configs.rule_list": "rule_list",
			},
		},
		WebSocketSecurityResourceName: {
			goName:         "WebSocketSecurity",
			typeNameSuffix: "waf_web_socket_security",
			operationName:  "WebSocket security",
			path:           WebSocketSecurityPath,
			fields:         webSocketSecurityFieldExpectations(),
			collections: map[string]string{
				"configs.rule_list": "rule_list",
			},
		},
		InformationLeakageResourceName: {
			goName:         "InformationLeakage",
			typeNameSuffix: "waf_information_leakage",
			operationName:  "information leakage",
			path:           InformationLeakagePath,
			fields:         informationLeakageFieldExpectations(),
			collections: map[string]string{
				"configs.sig_except_rules": "sig_except_rules",
			},
			scalarStringArrays: map[string]scalarStringArrayExpectation{
				"configs.http_headers": {
					wrapperBlock:  "http_headers",
					itemAttribute: "header",
					enum:          nil,
					maxItems:      26,
					required:      false,
					provenance:    "Reviewed from OpenAPI 26.3.a: http_headers is a free-form array of header name strings (no enum) with maxItems 26. It is encoded as an ownership wrapper of item blocks carrying a synthetic header string attribute. Local-only; live behavior unverified.",
				},
			},
		},
		DDoSPreventionResourceName: {
			goName:         "DDoSPrevention",
			typeNameSuffix: "waf_ddos_prevention",
			operationName:  "DDoS prevention",
			path:           DDoSPreventionPath,
			fields:         ddosPreventionFieldExpectations(),
			collections:    map[string]string{},
			scalarStringArrays: map[string]scalarStringArrayExpectation{
				"configs.ip_exception": {
					wrapperBlock:  "ip_exception",
					itemAttribute: "ip",
					enum:          nil,
					maxItems:      0,
					required:      false,
					provenance:    "Reviewed from OpenAPI 26.3.a: ip_exception is a free-form array of IP/IP-range strings (no enum, no maxItems) and is not in the DDoSPrevention required array. It is encoded as an ownership wrapper of item blocks carrying a synthetic ip string attribute, reusing the object-item omission/empty/populated semantics. Local-only; live behavior unverified.",
				},
			},
		},
		CookieSecurityResourceName: {
			goName:         "CookieSecurity",
			typeNameSuffix: "waf_cookie_security",
			operationName:  "cookie security",
			path:           CookieSecurityPath,
			fields:         cookieSecurityFieldExpectations(),
			collections: map[string]string{
				"configs.cookie_except_list": "cookie_except_list",
			},
		},
		KnownBotsResourceName: {
			goName:         "KnownBots",
			typeNameSuffix: "waf_known_bots",
			operationName:  "known bots",
			path:           KnownBotsPath,
			fields:         knownBotsFieldExpectations(),
			collections: map[string]string{
				"configs.bad_bots_list":  "bad_bots_list",
				"configs.good_bots_list": "good_bots_list",
				"configs.exception_list": "exception_list",
			},
			collectionUnindexed: map[string]bool{
				"configs.bad_bots_list":  true,
				"configs.good_bots_list": true,
				"configs.exception_list": false,
			},
			itemStringArrays: knownBotsItemStringArrayExpectations(),
		},
		BotDeceptionResourceName: {
			goName:         "BotDeception",
			typeNameSuffix: "waf_bot_deception",
			operationName:  "bot deception",
			path:           BotDeceptionPath,
			fields:         botDeceptionFieldExpectations(),
			collections: map[string]string{
				"configs.url_list":       "url_list",
				"configs.exception_list": "exception_list",
			},
		},
		BiometricsBasedDetectionResourceName: {
			goName:         "BiometricsBasedDetection",
			typeNameSuffix: "waf_biometrics_based_detection",
			operationName:  "biometrics based detection",
			path:           BiometricsBasedDetectionPath,
			fields:         biometricsBasedDetectionFieldExpectations(),
			collections: map[string]string{
				"configs.url_list":       "url_list",
				"configs.exception_list": "exception_list",
			},
		},
		WaitingRoomResourceName: {
			goName:         "WaitingRoom",
			typeNameSuffix: "waf_waiting_room",
			operationName:  "waiting room",
			path:           WaitingRoomPath,
			fields:         waitingRoomFieldExpectations(),
			collections: map[string]string{
				"configs.bypass_rules": "bypass_rules",
			},
		},
		MITBProtectionResourceName: {
			goName:         "MITBProtection",
			typeNameSuffix: "waf_mitb_protection",
			operationName:  "MITB protection",
			path:           MITBProtectionPath,
			fields:         mitbProtectionFieldExpectations(),
			collections: map[string]string{
				"configs.param_list":  "param_list",
				"configs.domain_list": "domain_list",
			},
		},
		ThresholdDetectionResourceName: {
			goName:         "ThresholdDetection",
			typeNameSuffix: "waf_threshold_detection",
			operationName:  "threshold detection",
			path:           ThresholdDetectionPath,
			fields:         thresholdDetectionFieldExpectations(),
			collections: map[string]string{
				"configs.exception_list": "exception_list",
			},
		},
		MLBotDetectionResourceName: {
			goName:         "MLBotDetection",
			typeNameSuffix: "waf_ml_bot_detection",
			operationName:  "ML bot detection",
			path:           MLBotDetectionPath,
			fields:         mlBotDetectionFieldExpectations(),
			collections: map[string]string{
				"configs.ip_list":        "ip_list",
				"configs.url_list":       "url_list",
				"configs.exception_list": "exception_list",
			},
		},
		FileProtectionResourceName: {
			goName:         "FileProtection",
			typeNameSuffix: "waf_file_protection",
			operationName:  "file protection",
			path:           FileProtectionPath,
			fields:         fileProtectionFieldExpectations(),
			collections: map[string]string{
				"configs.file_types":        "file_types",
				"configs.custom_file_types": "custom_file_types",
			},
		},
		MobileAPIProtectionResourceName: {
			goName:         "MobileAPIProtection",
			typeNameSuffix: "waf_mobile_api_protection",
			operationName:  "mobile API protection",
			path:           MobileAPIProtectionPath,
			fields:         mobileAPIProtectionFieldExpectations(),
			collections: map[string]string{
				"configs.url_list": "url_list",
			},
		},
		XMLProtectionPolicyResourceName: {
			goName:         "XMLProtectionPolicy",
			typeNameSuffix: "waf_xml_protection_policy",
			operationName:  "XML protection policy",
			path:           XMLProtectionPolicyPath,
			fields:         xmlProtectionPolicyFieldExpectations(),
			collections: map[string]string{
				"configs.file_list": "file_list",
			},
		},
		RewritingRequestsResourceName: {
			goName:         "RewritingRequests",
			typeNameSuffix: "waf_rewriting_requests",
			operationName:  "rewriting requests",
			path:           RewritingRequestsPath,
			fields:         rewritingRequestsFieldExpectations(),
			collections: map[string]string{
				"configs.rule_list": "rule_list",
			},
			itemStringArrays: rewritingRequestsItemStringArrayExpectations(),
		},
		APIGatewayResourceName: {
			goName:         "APIGateway",
			typeNameSuffix: "waf_api_gateway",
			operationName:  "API gateway",
			path:           APIGatewayPath,
			fields:         apiGatewayFieldExpectations(),
			collections: map[string]string{
				"configs.rule_list": "rule_list",
				"configs.user_list": "user_list",
			},
			itemStringArrays: apiGatewayItemStringArrayExpectations(),
		},
		CachingCompressionResourceName: {
			goName:         "CachingCompression",
			typeNameSuffix: "waf_caching_compression",
			operationName:  "caching and compression",
			path:           CachingCompressionPath,
			fields:         cachingCompressionFieldExpectations(),
			collections: map[string]string{
				"configs.cache.cookie_list":          "cookie_list",
				"configs.cache.rule_list":            "rule_list",
				"configs.compress.content_type_list": "content_type_list",
			},
			scalarStringArrays: cachingCompressionScalarStringArrayExpectations(),
		},
	}
)

// cachingCompressionFieldExpectations pins the reviewed field policy for the
// caching and compression envelope, its config scalars, the nested-object
// config fields (cache, compress), and the per-collection item fields.
func cachingCompressionFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                            {terraformPolicy: "required"},
		"template":                                         {terraformPolicy: "required"},
		"configs.status":                                   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.allow_method":                       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.allow_return_code":                  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.cache_timeout":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.status":                             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.timeout_type":                       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.cookie_list":                        {terraformPolicy: "optional_computed"},
		"configs.cache.rule_list":                          {terraformPolicy: "optional_computed"},
		"configs.compress.status":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.compress.content_type_list":               {terraformPolicy: "optional_computed"},
		"configs.cache.cookie_list.item.idx":               {terraformPolicy: "wire_only", wireOnly: true},
		"configs.cache.cookie_list.item.name":              {terraformPolicy: "required"},
		"configs.cache.rule_list.item.bypass_arg":          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.rule_list.item.bypass_arg_value":    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.rule_list.item.bypass_cookie":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.rule_list.item.bypass_cookie_value": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.rule_list.item.idx":                 {terraformPolicy: "wire_only", wireOnly: true},
		"configs.cache.rule_list.item.method":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cache.rule_list.item.url":                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.compress.content_type_list.item.idx":      {terraformPolicy: "wire_only", wireOnly: true},
		"configs.compress.content_type_list.item.type":     {terraformPolicy: "required"},
	}
	return expectations
}

// cachingCompressionScalarStringArrayExpectations pins the two configs-level
// scalar-string-array fields inside the cache nested object.
func cachingCompressionScalarStringArrayExpectations() map[string]scalarStringArrayExpectation {
	return map[string]scalarStringArrayExpectation{
		"configs.cache.allow_file_type": {
			wrapperBlock:  "allow_file_type",
			itemAttribute: "file_type",
			enum:          []string{"binary", "media", "picture", "text", "other"},
			maxItems:      0,
			required:      false,
			provenance:    "Reviewed from OpenAPI 26.3.a: allow_file_type is a free-form array of file-type enum strings inside the cache nested config object (no maxItems, optional). It is encoded as an ownership wrapper of item blocks carrying a synthetic file_type string attribute, reusing the scalar-string-array omission/empty/populated semantics. Local-only; live behavior unverified.",
		},
		"configs.cache.key_factor": {
			wrapperBlock:  "key_factor",
			itemAttribute: "factor",
			enum:          []string{"arguments", "host", "method", "protocol", "url", "cookies"},
			maxItems:      0,
			required:      false,
			provenance:    "Reviewed from OpenAPI 26.3.a: key_factor is a free-form array of key-factor enum strings inside the cache nested config object (no maxItems, optional). It is encoded as an ownership wrapper of item blocks carrying a synthetic factor string attribute, reusing the scalar-string-array omission/empty/populated semantics. Local-only; live behavior unverified.",
		},
	}
}

// apiGatewayFieldExpectations pins the reviewed field policy for the API
// gateway envelope, its two config scalars, and every per-collection item
// field (rule_list APIPolicy + user_list APIUser, including the three
// computed-only backend-managed user_list.item fields).
func apiGatewayFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":          {terraformPolicy: "required"},
		"template":       {terraformPolicy: "required"},
		"configs.action": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status": {terraformPolicy: "optional_computed", useStateForUnknown: true},

		// rule_list item (APIPolicy) — all optional writable fields.
		"configs.rule_list.item.api_key_loc":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.api_key_verify":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.field_name":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.idx":                    {terraformPolicy: "wire_only", wireOnly: true},
		"configs.rule_list.item.name":                   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.rate_limit_period":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.rate_limit_req":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.url_list":               {terraformPolicy: "optional_computed"},
		"configs.rule_list.item.url_list.item.backend":  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.url_list.item.frontend": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.url_list.item.idx":      {terraformPolicy: "wire_only", wireOnly: true},

		// user_list item (APIUser) — writable fields.
		"configs.user_list.item.comments":                  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.user_list.item.email":                     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.user_list.item.idx":                       {terraformPolicy: "wire_only", wireOnly: true},
		"configs.user_list.item.ip_list":                   {terraformPolicy: "optional_computed"},
		"configs.user_list.item.name":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.user_list.item.referer_list":              {terraformPolicy: "optional_computed"},
		"configs.user_list.item.ip_list.item.ip":           {terraformPolicy: "required"},
		"configs.user_list.item.ip_list.item.idx":          {terraformPolicy: "wire_only", wireOnly: true},
		"configs.user_list.item.referer_list.item.referer": {terraformPolicy: "required"},
		"configs.user_list.item.referer_list.item.idx":     {terraformPolicy: "wire_only", wireOnly: true},

		// user_list item — computed-only backend-managed fields. Computed (never
		// config), PreserveFromGet (carried from the fresh GET into the PUT),
		// never read from config/plan/state. api_key is additionally Sensitive.
		"configs.user_list.item.uuid":        {terraformPolicy: "computed", preserveFromGet: true},
		"configs.user_list.item.api_key":     {terraformPolicy: "computed", preserveFromGet: true, sensitive: true},
		"configs.user_list.item.create_time": {terraformPolicy: "computed", preserveFromGet: true},
	}
	return expectations
}

// apiGatewayItemStringArrayExpectations pins the one item-level scalar-string-
// array field (rule_list.item.user_list, unbounded).
func apiGatewayItemStringArrayExpectations() map[string]itemStringArrayExpectation {
	return map[string]itemStringArrayExpectation{
		"configs.rule_list.item.user_list": {
			wrapperBlock:  "user_list",
			itemAttribute: "user",
			enum:          nil,
			maxItems:      0,
			required:      false,
			provenance:    "Reviewed from OpenAPI 26.3.a: user_list is a free-form array of API-user-name strings inside a rule_list item (no enum, no maxItems, optional). It is encoded as an ownership wrapper of item blocks carrying a synthetic user string attribute inside the parent item, reusing the scalar-string-array omission/empty/populated semantics. Local-only; live behavior unverified.",
		},
	}
}

// knownBotsItemStringArrayExpectations pins the two item-level scalar-string-
// array fields (bad_bots_list.item.allow_list, good_bots_list.item.deny_list).
func knownBotsItemStringArrayExpectations() map[string]itemStringArrayExpectation {
	return map[string]itemStringArrayExpectation{
		"configs.bad_bots_list.item.allow_list": {
			wrapperBlock:  "allow_list",
			itemAttribute: "value",
			enum:          nil,
			maxItems:      0,
			required:      false,
			provenance:    "Reviewed from OpenAPI 26.3.a: allow_list is a free-form array of bot-identifier strings inside a bad_bots_list item (no enum, no maxItems, optional). It is encoded as an ownership wrapper of item blocks carrying a synthetic value string attribute inside the parent item, reusing the scalar-string-array omission/empty/populated semantics. Local-only; live behavior unverified.",
		},
		"configs.good_bots_list.item.deny_list": {
			wrapperBlock:  "deny_list",
			itemAttribute: "value",
			enum:          nil,
			maxItems:      0,
			required:      false,
			provenance:    "Reviewed from OpenAPI 26.3.a: deny_list is a free-form array of bot-identifier strings inside a good_bots_list item (no enum, no maxItems, optional). It is encoded as an ownership wrapper of item blocks carrying a synthetic value string attribute inside the parent item, reusing the scalar-string-array omission/empty/populated semantics. Local-only; live behavior unverified.",
		},
	}
}

// botDeceptionFieldExpectations returns the reviewed field policy for the
// bot deception envelope, its three config scalars, and the per-collection
// item fields. url_list and exception_list reuse the indexed bounded item
// schemas (UrlList and BotExceptionRuleList) already exercised by earlier
// resources.
func botDeceptionFieldExpectations() map[string]fieldExpectation {
	return sharedExceptionURLListExpectations(
		map[string]fieldExpectation{
			"configs.action":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.deception_url": {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.status":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		},
	)
}

// biometricsBasedDetectionFieldExpectations returns the reviewed field policy
// for the biometrics based detection envelope, its nine config scalars, and
// the per-collection item fields reusing UrlList and BotExceptionRuleList.
func biometricsBasedDetectionFieldExpectations() map[string]fieldExpectation {
	return sharedExceptionURLListExpectations(
		map[string]fieldExpectation{
			"configs.action":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.bot_effect_time":    {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.click":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.event_collect_time": {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.keyboard":           {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.mouse_movement":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.screen_touch":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.scroll":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
			"configs.status":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		},
	)
}

// sharedExceptionURLListExpectations returns the common envelope plus the
// shared url_list/exception_list item-field expectations used by both bot
// deception and biometrics based detection. configFields is the resource's
// own configs-scalar map; the shared item-field expectations cover UrlList
// (required url, wire-only idx) and BotExceptionRuleList (required
// concatenate_type/match_target/operator, optional ip_range/value/value_name,
// value_check provider default false, wire-only idx).
func sharedExceptionURLListExpectations(configFields map[string]fieldExpectation) map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                           {terraformPolicy: "required"},
		"template":                        {terraformPolicy: "required"},
		"configs.url_list.item.idx":       {terraformPolicy: "wire_only", wireOnly: true},
		"configs.url_list.item.url":       {terraformPolicy: "required"},
		"configs.exception_list.item.idx": {terraformPolicy: "wire_only", wireOnly: true},
		"configs.exception_list.item.concatenate_type": {terraformPolicy: "required"},
		"configs.exception_list.item.match_target":     {terraformPolicy: "required"},
		"configs.exception_list.item.operator":         {terraformPolicy: "required"},
		"configs.exception_list.item.ip_range":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value_check":      {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
		"configs.exception_list.item.value_name":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	for path, want := range configFields {
		expectations[path] = want
	}
	return expectations
}

// waitingRoomFieldExpectations returns the reviewed field policy for the
// waiting room envelope, its eight config scalars, and the bypass_rules item
// fields (WRBypassRule: required rule_type/rule_value, wire-only idx).
func waitingRoomFieldExpectations() map[string]fieldExpectation {
	return map[string]fieldExpectation{
		"ep_id":                                {terraformPolicy: "required"},
		"template":                             {terraformPolicy: "required"},
		"configs.custom_wt_page":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.enable_new_users_per_min":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.enable_total_active_users":    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.new_users_per_min":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.path":                         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.session_duration":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.total_active_users":           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.bypass_rules.item.idx":        {terraformPolicy: "wire_only", wireOnly: true},
		"configs.bypass_rules.item.rule_type":  {terraformPolicy: "required"},
		"configs.bypass_rules.item.rule_value": {terraformPolicy: "required"},
	}
}

// mitbProtectionFieldExpectations returns the reviewed field policy for the
// MITB protection envelope, its four config scalars, and the per-collection
// item fields. param_list uses the ProtectParamter item schema (required type
// enum default regular-input and required name max 63, optional
// obfuscate/encrypt/anti_key_logger booleans default false, wire-only idx
// default 1). domain_list uses the AllowedDomain item schema (required domain
// max 255, wire-only idx default 1).
func mitbProtectionFieldExpectations() map[string]fieldExpectation {
	return map[string]fieldExpectation{
		"ep_id":                                   {terraformPolicy: "required"},
		"template":                                {terraformPolicy: "required"},
		"configs.action":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.post_url":                        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.request_url":                     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.param_list.item.idx":             {terraformPolicy: "wire_only", wireOnly: true},
		"configs.param_list.item.type":            {terraformPolicy: "required"},
		"configs.param_list.item.name":            {terraformPolicy: "required"},
		"configs.param_list.item.obfuscate":       {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
		"configs.param_list.item.encrypt":         {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
		"configs.param_list.item.anti_key_logger": {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
		"configs.domain_list.item.idx":            {terraformPolicy: "wire_only", wireOnly: true},
		"configs.domain_list.item.domain":         {terraformPolicy: "required"},
	}
}

// thresholdDetectionFieldExpectations returns the reviewed field policy for
// the threshold detection envelope (pinned config object BotDetection), its
// eleven config scalars, and the exception_list item fields. exception_list
// reuses the BotExceptionRuleList item schema already exercised by bot
// deception, biometrics based detection, and known bots.
func thresholdDetectionFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                        {terraformPolicy: "required"},
		"template":                                     {terraformPolicy: "required"},
		"configs.action":                               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.challenge":                            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.content_scraping":                     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.crawler":                              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.credential_brute_force":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.occurrence":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.range":                                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.request_url":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.slow_attack":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.vulnerability_scan":                   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.idx":              {terraformPolicy: "wire_only", wireOnly: true},
		"configs.exception_list.item.concatenate_type": {terraformPolicy: "required"},
		"configs.exception_list.item.match_target":     {terraformPolicy: "required"},
		"configs.exception_list.item.operator":         {terraformPolicy: "required"},
		"configs.exception_list.item.ip_range":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value_check":      {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
		"configs.exception_list.item.value_name":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

// mlBotDetectionFieldExpectations returns the reviewed field policy for the
// ML bot detection envelope (pinned config object MLBotDetection), its seven
// config scalars, and the per-collection item fields. ip_list uses the IpList
// item schema (required ip, wire-only idx default 1), url_list uses the
// UrlPattern item schema (optional url max 127 with the ^/.*$ pattern,
// wire-only idx default 1), and exception_list reuses the BotExceptionRuleList
// item schema already exercised by bot deception, biometrics based detection,
// known bots, and threshold detection.
func mlBotDetectionFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                        {terraformPolicy: "required"},
		"template":                                     {terraformPolicy: "required"},
		"configs.action":                               {terraformPolicy: "optional_computed", useStateForUnknown: true, wireAliases: map[string]string{"client-id-block-period": "block_period"}},
		"configs.anomaly_count":                        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.block_duration":                       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.challenge":                            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.identification_method":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.model_type":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.ip_list.item.idx":                     {terraformPolicy: "wire_only", wireOnly: true},
		"configs.ip_list.item.ip":                      {terraformPolicy: "required"},
		"configs.url_list.item.idx":                    {terraformPolicy: "wire_only", wireOnly: true},
		"configs.url_list.item.url":                    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.idx":              {terraformPolicy: "wire_only", wireOnly: true},
		"configs.exception_list.item.concatenate_type": {terraformPolicy: "required"},
		"configs.exception_list.item.match_target":     {terraformPolicy: "required"},
		"configs.exception_list.item.operator":         {terraformPolicy: "required"},
		"configs.exception_list.item.ip_range":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value_check":      {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
		"configs.exception_list.item.value_name":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

// fileProtectionFieldExpectations returns the reviewed field policy for the
// file protection envelope, its eleven config scalars, and the per-collection
// item fields. file_types uses the FileType item schema (optional type enum and
// optional tid with the ^\d{5}$ pattern, wire-only idx default 1).
// custom_file_types uses the CustomFileType item schema (required name max 52
// and required file_extension max 63, a nested file_content_match_rule
// SubItemArray, wire-only idx default 0). The file_content_match_rule sub-item
// carries required data_value max 127, optional offset integer range 0..4096,
// optional offset_from/operation/data_type/concatenate_type enums, and a
// wire-only idx default 0.
func fileProtectionFieldExpectations() map[string]fieldExpectation {
	return map[string]fieldExpectation{
		"ep_id":                                               {terraformPolicy: "required"},
		"template":                                            {terraformPolicy: "required"},
		"configs.action":                                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.av_scan":                                     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_action":                                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_size":                                   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.json_file_support":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.json_key_field":                              {terraformPolicy: "optional_computed", useStateForUnknown: true, allowWireNull: true},
		"configs.json_key_for_filename":                       {terraformPolicy: "optional_computed", useStateForUnknown: true, allowWireNull: true},
		"configs.sandbox":                                     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.trojan":                                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.url":                                         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_types.item.idx":                         {terraformPolicy: "wire_only", wireOnly: true},
		"configs.file_types.item.type":                        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_types.item.tid":                         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.custom_file_types.item.idx":                  {terraformPolicy: "wire_only", wireOnly: true},
		"configs.custom_file_types.item.name":                 {terraformPolicy: "required"},
		"configs.custom_file_types.item.file_extension":       {terraformPolicy: "required"},
		"configs.custom_file_types.item.match_rules":          {terraformPolicy: "optional_computed", terraformName: "file_content_match_rule"},
		"configs.custom_file_types.item.match_rules.item.idx": {terraformPolicy: "wire_only", wireOnly: true},
		"configs.custom_file_types.item.match_rules.item.concatenate_type": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.custom_file_types.item.match_rules.item.data_type":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.custom_file_types.item.match_rules.item.data_value":       {terraformPolicy: "required"},
		"configs.custom_file_types.item.match_rules.item.offset":           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.custom_file_types.item.match_rules.item.offset_from":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.custom_file_types.item.match_rules.item.operation":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
}

// mobileAPIProtectionFieldExpectations returns the reviewed field policy for
// the mobile API protection envelope, its four config scalars, and the
// url_list item fields. url_list reuses the UrlList item schema (required url
// max 255, wire-only idx default 1). configs.token_secret is marked sensitive:
// it carries the JWT signing secret, so the generated schema attribute emits
// Sensitive: true and the docs argument text notes the field is sensitive. The
// token_secret value is never printed in generated examples or diagnostics.
func mobileAPIProtectionFieldExpectations() map[string]fieldExpectation {
	return map[string]fieldExpectation{
		"ep_id":                     {terraformPolicy: "required"},
		"template":                  {terraformPolicy: "required"},
		"configs.action":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.token_header":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.token_secret":      {terraformPolicy: "optional_computed", useStateForUnknown: true, sensitive: true},
		"configs.url_list.item.idx": {terraformPolicy: "wire_only", wireOnly: true},
		"configs.url_list.item.url": {terraformPolicy: "required"},
	}
}

// requestLimitsFieldExpectations returns the reviewed field policy for the
func requestLimitsFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":    {terraformPolicy: "required"},
		"template": {terraformPolicy: "required"},
	}
	for _, name := range requestLimitsScalarFields {
		expectations["configs."+name] = fieldExpectation{
			terraformPolicy:    "optional_computed",
			useStateForUnknown: true,
		}
	}
	expectations["configs.max_setting_initial_window_size"] = fieldExpectation{
		terraformPolicy: "computed",
	}
	return expectations
}

func knownAttacksFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                                  {terraformPolicy: "required"},
		"template":                                               {terraformPolicy: "required"},
		"configs.action":                                         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.arithmetic_sql_inject":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.condition_sql_inject":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cross_site_script":                              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cross_site_script_ext":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.embed_sql_inject":                               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.generic_attacks":                                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.generic_attacks_ext":                            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.html_attr_xss_inject":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.html_css_xss_inject":                            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.html_tag_xss_inject":                            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.js_func_xss_inject":                             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.js_var_xss_inject":                              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.known_exploits":                                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.line_comments":                                  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sensitivity_level":                              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sql_func_inject":                                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sql_inject":                                     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sql_inject_ext":                                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stack_sql_inject":                               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                                         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.trojans":                                        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.cookie.check_status":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.cookie.check_value":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.cookie.status":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.cookie.type":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.cookie.value":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.host.status":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.host.type":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.host.value":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.http_header.check_status": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.http_header.check_value":  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.http_header.status":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.http_header.type":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.http_header.value":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.idx":                      {terraformPolicy: "wire_only", wireOnly: true},
		"configs.sig_except_rules.item.json.check_status":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.json.check_value":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.json.status":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.json.type":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.json.value":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.param.check_status":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.param.check_value":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.param.status":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.param.type":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.param.value":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.sig_id":                   {terraformPolicy: "required"},
		"configs.sig_except_rules.item.sig_name":                 {terraformPolicy: "required"},
		"configs.sig_except_rules.item.url.status":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.url.type":                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.sig_except_rules.item.url.value":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.attack_cat":               {terraformPolicy: "required"},
		"configs.stx_except_rules.item.attack_name":              {terraformPolicy: "required"},
		"configs.stx_except_rules.item.cookie.status":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.cookie.type":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.cookie.value":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.idx":                      {terraformPolicy: "wire_only", wireOnly: true},
		"configs.stx_except_rules.item.param.status":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.param.type":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.param.value":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.url.status":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.url.type":                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.stx_except_rules.item.url.value":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

func httpHeaderSecurityFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                {terraformPolicy: "required"},
		"template":                             {terraformPolicy: "required"},
		"configs.content_security_policy":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.header_value":                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.referrer_policy":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.referrer_policy_header_value": {terraformPolicy: "optional_computed", useStateForUnknown: true, allowNull: true},
		"configs.status":                       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.x_content_type_options":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.x_frame_options":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.x_xss_protection":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

func graphqlProtectionFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":          {terraformPolicy: "required"},
		"template":       {terraformPolicy: "required"},
		"configs.action": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.alias_batch_query":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.alias_batch_query_number": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.array_batch_query":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.array_batch_query_number": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.field_number":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.fragment":                 {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.graphql_data_size":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.idx":                      {terraformPolicy: "wire_only", wireOnly: true},
		"configs.rule_list.item.introspection":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.name":                     {terraformPolicy: "required"},
		"configs.rule_list.item.object_depth":             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.request_url":              {terraformPolicy: "required"},
		"configs.rule_list.item.value_size":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

func jsonProtectionFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                               {terraformPolicy: "required"},
		"template":                            {terraformPolicy: "required"},
		"configs.action":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.bucket":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.prefix":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_list.item.filename":     {terraformPolicy: "required"},
		"configs.file_list.item.idx":          {terraformPolicy: "wire_only", wireOnly: true},
		"configs.file_list.item.limit_check":  {terraformPolicy: "required"},
		"configs.file_list.item.md5":          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_list.item.name":         {terraformPolicy: "required"},
		"configs.file_list.item.schema_valid": {terraformPolicy: "required"},
		"configs.file_list.item.url":          {terraformPolicy: "required"},
	}
	return expectations
}

func xmlProtectionPolicyFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                               {terraformPolicy: "required"},
		"template":                            {terraformPolicy: "required"},
		"configs.action":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.bucket":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.prefix":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_list.item.entity_check": {terraformPolicy: "required"},
		"configs.file_list.item.filename":     {terraformPolicy: "required"},
		"configs.file_list.item.idx":          {terraformPolicy: "wire_only", wireOnly: true},
		"configs.file_list.item.limit_check":  {terraformPolicy: "required"},
		"configs.file_list.item.md5":          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.file_list.item.name":         {terraformPolicy: "required"},
		"configs.file_list.item.schema_valid": {terraformPolicy: "required"},
		"configs.file_list.item.url":          {terraformPolicy: "required"},
	}
	return expectations
}

func rewritingRequestsFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                      {terraformPolicy: "required"},
		"template":                                   {terraformPolicy: "required"},
		"configs.identify_original_ip":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.source_port":                        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.x_forwarded_for":                    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.x_forwarded_port":                   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.x_header":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.x_real_ip":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.action":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.header_status":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.host_expression":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.host_filter":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.host_status":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.idx":                 {terraformPolicy: "wire_only", wireOnly: true},
		"configs.rule_list.item.insert_header_name":  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.insert_header_value": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.location_expression": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.location_filter":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.location_status":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.name":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.protocol":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.protocol_filter":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.referer_expression":  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.referer_filter":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.referer_status":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.remove_header":       {terraformPolicy: "optional_computed"},
		"configs.rule_list.item.rewrite_from":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.rewrite_host":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.rewrite_location":    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.rewrite_referer":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.rewrite_to":          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.rewrite_url":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.url_expression":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.url_filter":          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.url_status":          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.url_translation":     {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

// rewritingRequestsItemStringArrayExpectations pins the one item-level
// scalar-string-array field (rule_list.item.remove_header).
func rewritingRequestsItemStringArrayExpectations() map[string]itemStringArrayExpectation {
	return map[string]itemStringArrayExpectation{
		"configs.rule_list.item.remove_header": {
			wrapperBlock:  "remove_header",
			itemAttribute: "header",
			enum:          nil,
			maxItems:      10,
			required:      false,
			itemMaxLength: 63,
			provenance:    "Reviewed from OpenAPI 26.3.a: remove_header is a free-form array of header-name strings inside a rule_list item (no enum, maxItems 10, item string maxLength 63, optional). It is encoded as an ownership wrapper of item blocks carrying a synthetic header string attribute inside the parent item, reusing the scalar-string-array omission/empty/populated semantics. Local-only; live behavior unverified.",
		},
	}
}

func parameterValidationFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                                {terraformPolicy: "required"},
		"template":                                             {terraformPolicy: "required"},
		"configs.status":                                       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.action":                        {terraformPolicy: "required"},
		"configs.rule_list.item.block_period":                  {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.idx":                           {terraformPolicy: "wire_only", wireOnly: true},
		"configs.rule_list.item.name":                          {terraformPolicy: "required"},
		"configs.rule_list.item.sub_rule_list":                 {terraformPolicy: "optional_computed"},
		"configs.rule_list.item.url":                           {terraformPolicy: "required"},
		"configs.rule_list.item.sub_rule_list.item.arg_type":   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.sub_rule_list.item.arg_val":    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.sub_rule_list.item.idx":        {terraformPolicy: "wire_only", wireOnly: true},
		"configs.rule_list.item.sub_rule_list.item.max_len":    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.sub_rule_list.item.name":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.sub_rule_list.item.required":   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.sub_rule_list.item.type_check": {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

func webSocketSecurityFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":          {terraformPolicy: "required"},
		"template":       {terraformPolicy: "required"},
		"configs.action": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.rule_list.item.allow_binary_text":       {terraformPolicy: "required"},
		"configs.rule_list.item.allow_plain_text":        {terraformPolicy: "required"},
		"configs.rule_list.item.allow_websocket":         {terraformPolicy: "required"},
		"configs.rule_list.item.block_attacks":           {terraformPolicy: "required"},
		"configs.rule_list.item.block_extensions":        {terraformPolicy: "required"},
		"configs.rule_list.item.idx":                     {terraformPolicy: "wire_only", wireOnly: true},
		"configs.rule_list.item.max_frm_size":            {terraformPolicy: "required"},
		"configs.rule_list.item.max_msg_size":            {terraformPolicy: "required"},
		"configs.rule_list.item.name":                    {terraformPolicy: "required"},
		"configs.rule_list.item.origin_list":             {terraformPolicy: "optional_computed"},
		"configs.rule_list.item.url":                     {terraformPolicy: "required"},
		"configs.rule_list.item.origin_list.item.origin": {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

func informationLeakageFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                        {terraformPolicy: "required"},
		"template":                     {terraformPolicy: "required"},
		"configs.action":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cloak_error_pages":    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.erase_http_headers":   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.personal_info":        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.server_info_disclose": {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	// Reuse the reviewed sig_except_rules item-field policies from known_attacks.
	for path, policy := range knownAttacksFieldExpectations() {
		if strings.HasPrefix(path, "configs.sig_except_rules.item.") {
			expectations[path] = policy
		}
	}
	return expectations
}

func ddosPreventionFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":    {terraformPolicy: "required"},
		"template": {terraformPolicy: "required"},
	}
	for _, name := range ddosPreventionScalarFields {
		expectations["configs."+name] = fieldExpectation{
			terraformPolicy:    "optional_computed",
			useStateForUnknown: true,
		}
	}
	return expectations
}

// ddosPreventionScalarFields lists the twelve DDoSPrevention config scalar
// field names pinned from OpenAPI 26.3.a.
// ip_exception is handled separately as a scalar-string-array collection and
// is intentionally absent here. block_period is the only optional scalar; it
// is omission-preserving optional_computed like every other config scalar.
var ddosPreventionScalarFields = []string{
	"action", "block_period", "challenge", "conn_flood_check",
	"conn_flood_limit", "http_access_limit", "http_flood_prevent",
	"http_request_limit", "http_session_limit", "status",
	"tcp_conn_num_limit", "tcp_flood_prevent",
}

func cookieSecurityFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                    {terraformPolicy: "required"},
		"template":                                 {terraformPolicy: "required"},
		"configs.action":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.http_only":                        {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.max_age":                          {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.mode":                             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.replay_protection":                {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.samesite":                         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.samesite_value":                   {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.secure_cookie":                    {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.status":                           {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.cookie_except_list.item.idx":      {terraformPolicy: "wire_only", wireOnly: true},
		"configs.cookie_except_list.item.name":     {terraformPolicy: "required"},
		"configs.cookie_except_list.item.wildcard": {terraformPolicy: "optional_computed", providerDefault: boolPointer(false)},
	}
	return expectations
}

// knownBotsFieldExpectations returns the reviewed field policy for the known
// bots envelope, config scalars, and per-collection item fields. bad_bots_list
// and good_bots_list are unindexed (no idx); exception_list is indexed.
// Item `status` booleans are omission-preserving optional_computed.
func knownBotsFieldExpectations() map[string]fieldExpectation {
	expectations := map[string]fieldExpectation{
		"ep_id":                                        {terraformPolicy: "required"},
		"template":                                     {terraformPolicy: "required"},
		"configs.status":                               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.bad_bots":                             {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.bad_bots_action":                      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.good_bots_action":                     {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.bad_bots_list.item.cat":               {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.bad_bots_list.item.status":            {terraformPolicy: "optional_computed", providerDefault: boolPointer(true)},
		"configs.good_bots_list.item.cat":              {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.good_bots_list.item.status":           {terraformPolicy: "optional_computed", providerDefault: boolPointer(true)},
		"configs.exception_list.item.idx":              {terraformPolicy: "wire_only", wireOnly: true},
		"configs.exception_list.item.concatenate_type": {terraformPolicy: "required"},
		"configs.exception_list.item.match_target":     {terraformPolicy: "required"},
		"configs.exception_list.item.operator":         {terraformPolicy: "required"},
		"configs.exception_list.item.ip_range":         {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value":            {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value_check":      {terraformPolicy: "optional_computed", useStateForUnknown: true},
		"configs.exception_list.item.value_name":       {terraformPolicy: "optional_computed", useStateForUnknown: true},
	}
	return expectations
}

// requestLimitsScalarFields lists the 61 RequestLimits config scalar field
// names pinned from OpenAPI 26.3.a. allow_methods is handled separately as a
// scalar-string-array collection and is intentionally absent here.
var requestLimitsScalarFields = []string{
	"body_param_len", "chunk_size_check", "cl_te_coexist_check",
	"content_length_action", "content_length_num", "cookie_num",
	"duplicate_param_check", "header_len", "header_line_num", "header_line_num_action",
	"header_name_len", "header_value_len", "http2_max_req_action",
	"http2_max_requests_check", "http2_max_requests_num", "http2_rst_action",
	"http2_rst_stream_check", "http2_rst_stream_frq_check",
	"http2_rst_stream_frq_num", "http2_rst_stream_num", "http_header_action",
	"http_param_action", "http_req_action", "http_req_len",
	"illegal_char_check", "illegal_cl_check", "illegal_ctype_check",
	"illegal_header_name_check", "illegal_header_value_check",
	"illegal_host_name_check", "illegal_http_req_method_check",
	"illegal_http_ver_check", "illegal_param_name_check",
	"illegal_param_value_check", "illegal_res_code_check",
	"inconsistent_cl_check", "malformed_req_check", "malformed_url_check",
	"max_http_body_length", "max_setting_current_streams_num",
	"max_setting_frame_size", "max_setting_header_list_size",
	"max_setting_header_table_size", "max_setting_initial_window_size",
	"multipart_formdata_bad_request_check", "null_char_check",
	"odd_and_even_space_attack_check", "others_action", "param_name_check",
	"param_value_check", "post_req_ctype_check", "range_num",
	"range_overlapping_check", "redundant_header_check", "req_filename_len",
	"rg_max_setting_initial_window_size", "rg_min_setting_initial_window_size",
	"rpc_protocol_check", "status", "url_param_len", "url_param_name_len",
	"url_param_num", "url_param_value_len", "web_socket_protocol_check",
}

// Overrides is the human-reviewed policy input for generated app modules.
type Overrides struct {
	Resources []ResourceOverride `json:"resources"`
}

// ResourceOverride contains decisions that cannot be inferred safely from the
// OpenAPI document.
type ResourceOverride struct {
	TerraformName         string                    `json:"terraform_name"`
	GoName                string                    `json:"go_name"`
	TypeNameSuffix        string                    `json:"type_name_suffix"`
	OperationName         string                    `json:"operation_name"`
	GetPath               string                    `json:"get_path"`
	PutPath               string                    `json:"put_path"`
	Mode                  string                    `json:"mode"`
	Identity              IdentityPolicy            `json:"identity"`
	Template              TemplateConfigsPolicy     `json:"template_configs"`
	Fields                []FieldPolicy             `json:"fields"`
	Collections           []CollectionPolicy        `json:"collections"`
	ScalarStringArrays    []ScalarStringArrayPolicy `json:"scalar_string_arrays,omitempty"`
	ItemStringArrays      []ItemStringArrayPolicy   `json:"item_string_arrays,omitempty"`
	BackendFieldAdditions []BackendFieldAddition    `json:"backend_field_additions,omitempty"`
	// BackendConfigScalarConstraints pins reviewed integer config-scalar
	// Minimum/Maximum bounds that the pinned OpenAPI omits but the production
	// separately reviewed external contract enforces. Each entry is keyed by the config
	// field name (Path is "configs.<field>"). The generator applies the bound
	// to the in-memory SchemaIR and the contract authorizes the enrichment.
	BackendConfigScalarConstraints []BackendConfigScalarConstraint `json:"backend_config_scalar_constraints,omitempty"`
	Destroy                        DestroyPolicy                   `json:"destroy"`
	TemplateDestroy                DestroyPolicy                   `json:"template_destroy"`
	Provenance                     string                          `json:"provenance"`
}

// BackendConfigScalarConstraint pins one reviewed integer config-scalar
// numeric bound absent from the pinned OpenAPI. Minimum/Maximum are the
// reviewed effective values (both finite integers). A zero value for either
// means that facet is not enriched for this field; at least one facet must be
// non-zero. Provenance records the backend schema source.
type BackendConfigScalarConstraint struct {
	Path       string `json:"path"`
	Minimum    *int64 `json:"minimum,omitempty"`
	Maximum    *int64 `json:"maximum,omitempty"`
	Provenance string `json:"provenance"`
}

type IdentityPolicy struct {
	Attribute       string `json:"attribute"`
	ImportFormat    string `json:"import_format"`
	RequiresReplace bool   `json:"requires_replace"`
	Provenance      string `json:"provenance"`
}

type TemplateConfigsPolicy struct {
	TemplateAttribute                string `json:"template_attribute"`
	ConfigsBlock                     string `json:"configs_block"`
	RequiredWhenTemplateFalse        bool   `json:"required_when_template_false"`
	ForbiddenWhenTemplateTrue        bool   `json:"forbidden_when_template_true"`
	SuppressConfigsStateWhenTemplate bool   `json:"suppress_configs_state_when_template_true"`
	Provenance                       string `json:"provenance"`
}

type FieldPolicy struct {
	Path               string `json:"path"`
	TerraformPolicy    string `json:"terraform_policy"`
	UseStateForUnknown bool   `json:"use_state_for_unknown"`
	ProviderDefault    *bool  `json:"provider_default,omitempty"`
	AllowWireNull      bool   `json:"allow_wire_null,omitempty"`
	// TerraformName preserves an established Terraform attribute/block name
	// when the canonical OpenAPI wire property was renamed. Path continues to
	// identify the canonical source property.
	TerraformName string `json:"terraform_name,omitempty"`
	// WireName keeps a stable Terraform field/block name while reading and
	// writing a reviewed API key that differs from the pinned source schema.
	// It is currently used for the file-protection nested match-rule array,
	// whose 26.3.a wire key is "match_rules".
	WireName string `json:"wire_name,omitempty"`
	// WireAliases maps narrowly reviewed wire enum values to stable Terraform
	// values. Reads normalize wire -> Terraform, while explicitly configured
	// Terraform values encode back to the wire literal. Configured values must
	// still belong to the pinned Terraform-facing enum.
	WireAliases map[string]string `json:"wire_aliases,omitempty"`
	// RemoteMaximum is a read-side compatibility ceiling for a production
	// integer value that exceeds the pinned configurable maximum. It never
	// broadens Terraform configuration validation or the PUT patch contract.
	RemoteMaximum *int64 `json:"remote_maximum,omitempty"`
	// AllowNull records that the pinned OpenAPI marks the scalar wire field
	// nullable. The generated read path treats a null remote value as stable
	// null state instead of a malformed-result error. It is reviewed only for
	// optional config scalars; required scalars must still fail closed.
	AllowNull bool `json:"allow_null,omitempty"`
	WireOnly  bool `json:"wire_only"`
	// Sensitive records that the reviewed Terraform policy marks this scalar
	// or item field sensitive (e.g. a token secret or backend credential).
	// The generated schema attribute emits Sensitive: true so Terraform redacts
	// the value in plan output and state diffs, and the docs argument text notes
	// the field is sensitive. The value is never printed in generated examples
	// or diagnostics. Sensitive redacts in plan/output but does NOT omit the
	// value from Terraform state.
	Sensitive bool `json:"sensitive,omitempty"`
	// PreserveFromGet records that this item field is backend-managed
	// (computed-only): decoded from the fresh GET into Terraform state and
	// carried from the fresh GET into the replacement PUT, but never read from
	// config/plan/state. Used only with TerraformPolicy "computed".
	PreserveFromGet bool   `json:"preserve_from_get,omitempty"`
	Provenance      string `json:"provenance"`
}

type CollectionPolicy struct {
	Path              string `json:"path"`
	Encoding          string `json:"encoding"`
	WrapperBlock      string `json:"wrapper_block"`
	ItemBlock         string `json:"item_block"`
	Ordered           bool   `json:"ordered"`
	OmittedBehavior   string `json:"omitted_behavior"`
	EmptyBehavior     string `json:"empty_behavior"`
	PopulatedBehavior string `json:"populated_behavior"`
	HiddenIndex       string `json:"hidden_index"`
	UnknownItemKeys   string `json:"unknown_item_keys"`
	// Unindexed pins that the collection's item schema has no positional idx.
	// An unindexed collection sends items in Terraform order with no idx, decodes
	// the remote array in order, and treats item identity as the whole object.
	// HiddenIndex must be "none" when Unindexed is true.
	Unindexed  bool   `json:"unindexed,omitempty"`
	Provenance string `json:"provenance"`
}

// ScalarStringArrayPolicy pins one reviewed configs field that is an array of
// bare enum strings (no object item schema, no positional idx). It is encoded
// as an ownership wrapper of item blocks carrying a single synthetic string
// attribute named by ItemAttribute. OmittedBehavior/EmptyBehavior/
// PopulatedBehavior mirror the object-item ownership semantics so an omitted
// wrapper preserves the raw remote array and a present empty wrapper sends [].
type ScalarStringArrayPolicy struct {
	Path          string   `json:"path"`
	WrapperBlock  string   `json:"wrapper_block"`
	ItemAttribute string   `json:"item_attribute"`
	Enum          []string `json:"enum"`
	MaxItems      int      `json:"max_items"`
	// Required pins whether the pinned OpenAPI marks the array required. When
	// true, the generated read path fails closed if Terraform owns the array
	// and the remote key is absent, rather than silently coercing it to [].
	Required          bool   `json:"required"`
	OmittedBehavior   string `json:"omitted_behavior"`
	EmptyBehavior     string `json:"empty_behavior"`
	PopulatedBehavior string `json:"populated_behavior"`
	UnknownItemKeys   string `json:"unknown_item_keys"`
	Provenance        string `json:"provenance"`
}

// ItemStringArrayPolicy pins one reviewed item-level scalar-string-array field
// (one level deep), e.g. known_bots bad_bots_list.item.allow_list. It reuses
// the scalar-string-array ownership semantics inside a collection item.
type ItemStringArrayPolicy struct {
	Path              string   `json:"path"`
	WrapperBlock      string   `json:"wrapper_block"`
	ItemAttribute     string   `json:"item_attribute"`
	Enum              []string `json:"enum"`
	MaxItems          int      `json:"max_items"`
	Required          bool     `json:"required"`
	ItemMaxLength     int      `json:"item_max_length,omitempty"`
	OmittedBehavior   string   `json:"omitted_behavior"`
	EmptyBehavior     string   `json:"empty_behavior"`
	PopulatedBehavior string   `json:"populated_behavior"`
	UnknownItemKeys   string   `json:"unknown_item_keys"`
	Provenance        string   `json:"provenance"`
}

type DestroyPolicy struct {
	Mode          string   `json:"mode"`
	Verified      bool     `json:"verified"`
	Field         string   `json:"field,omitempty"`
	CoupledFields []string `json:"coupled_fields,omitempty"`
	Reason        string   `json:"reason"`
	Provenance    string   `json:"provenance"`
}

// BackendFieldAddition pins one reviewed backend field that the generator
// injects into the Terraform schema even though the field is absent from the
// pinned OpenAPI document. The pinned OpenAPI bytes and checksum remain
// unchanged; additions are provenance-backed and validated against the
// reviewed contract before injection.
//
// Path is a dotted reviewed leaf path, e.g.
// "configs.rule_list.item.url_type". Only collection-item scalar fields are
// supported. Kind is the JSON schema kind ("string" or "boolean"). Required,
// Enum, MaxLength, and Pattern mirror the CandidateFieldConstraint shape and
// must match the reviewed backend-enriched item field contract. Provenance is
// mandatory and records why the addition is reviewed.
type BackendFieldAddition struct {
	Path       string   `json:"path"`
	Kind       string   `json:"kind"`
	Required   bool     `json:"required"`
	Enum       []string `json:"enum,omitempty"`
	MaxLength  int      `json:"max_length,omitempty"`
	Pattern    string   `json:"pattern,omitempty"`
	Provenance string   `json:"provenance"`
}

type resourceExpectation struct {
	goName         string
	typeNameSuffix string
	operationName  string
	path           string
	fields         map[string]fieldExpectation
	collections    map[string]string
	// collectionUnindexed pins the reviewed Unindexed flag per collection path.
	// A collection absent from the map expects Unindexed false (indexed). This
	// prevents a profile/JSON inconsistency where unindexed and hidden_index
	// disagree: the profile Unindexed must match the reviewed contract Unindexed.
	collectionUnindexed map[string]bool
	scalarStringArrays  map[string]scalarStringArrayExpectation
	itemStringArrays    map[string]itemStringArrayExpectation
	// backendConfigScalarConstraints pins the reviewed integer config-scalar
	// numeric enrichments per field path. nil means the reviewed resource has
	// no config-scalar constraint enrichments.
	backendConfigScalarConstraints map[string]backendConfigScalarConstraintExpectation
}

// backendConfigScalarConstraintExpectation pins one reviewed integer
// config-scalar numeric enrichment so profile/JSON drift is rejected.
type backendConfigScalarConstraintExpectation struct {
	minimum    *int64
	maximum    *int64
	provenance string
}

type fieldExpectation struct {
	terraformPolicy    string
	useStateForUnknown bool
	providerDefault    *bool
	allowWireNull      bool
	terraformName      string
	wireName           string
	wireAliases        map[string]string
	remoteMaximum      *int64
	allowNull          bool
	wireOnly           bool
	sensitive          bool
	preserveFromGet    bool
}

// backendAdditionExpectation pins one reviewed backend field addition. The
// generator's generic injection rejects any addition that does not match.
type backendAdditionExpectation struct {
	kind       string
	required   bool
	enum       []string
	maxLength  int
	pattern    string
	provenance string
}

// scalarStringArrayExpectation pins one reviewed scalar-string-array collection
// so the generator's profile validation rejects any drift.
type scalarStringArrayExpectation struct {
	wrapperBlock  string
	itemAttribute string
	enum          []string
	maxItems      int
	required      bool
	provenance    string
}

// itemStringArrayExpectation pins one reviewed item-level scalar-string-array
// so the generator's profile validation rejects any drift.
type itemStringArrayExpectation struct {
	wrapperBlock  string
	itemAttribute string
	enum          []string
	maxItems      int
	required      bool
	itemMaxLength int
	provenance    string
}

// DecodeOverrides strictly decodes and validates the reviewed JSON policy.
func DecodeOverrides(data []byte) (Overrides, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var overrides Overrides
	if err := decoder.Decode(&overrides); err != nil {
		return Overrides{}, fmt.Errorf("decode WAF generator overrides: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Overrides{}, err
	}
	if err := validateOverrides(overrides); err != nil {
		return Overrides{}, err
	}
	return overrides, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode WAF generator overrides: unexpected trailing JSON value")
		}
		return fmt.Errorf("decode WAF generator overrides: %w", err)
	}
	return nil
}

func validateOverrides(overrides Overrides) error {
	terraformNames := make(map[string]struct{}, len(overrides.Resources))
	goNames := make(map[string]struct{}, len(overrides.Resources))
	for index := range overrides.Resources {
		resource := &overrides.Resources[index]
		if !terraformNamePattern.MatchString(resource.TerraformName) {
			return fmt.Errorf("resource %d has invalid Terraform name %q", index, resource.TerraformName)
		}
		if _, exists := terraformNames[resource.TerraformName]; exists {
			return fmt.Errorf("Terraform resource name collision %q", resource.TerraformName)
		}
		terraformNames[resource.TerraformName] = struct{}{}
		if !goNamePattern.MatchString(resource.GoName) {
			return fmt.Errorf("resource %q has invalid Go name %q", resource.TerraformName, resource.GoName)
		}
		if _, exists := goNames[resource.GoName]; exists {
			return fmt.Errorf("Go resource name collision %q", resource.GoName)
		}
		goNames[resource.GoName] = struct{}{}
		expected, ok := reviewedResourceExpectations[resource.TerraformName]
		if !ok {
			return fmt.Errorf("resource %q is not in the reviewed generated-resource set", resource.TerraformName)
		}
		if err := validateResource(*resource, expected); err != nil {
			return fmt.Errorf("resource %q: %w", resource.TerraformName, err)
		}
	}
	return exactKeys(terraformNames, sortedExpectationKeys(reviewedResourceExpectations), "reviewed generated resources")
}

func validateResource(resource ResourceOverride, expected resourceExpectation) error {
	require := func(name, value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must not be empty", name)
		}
		return nil
	}
	for name, value := range map[string]string{
		"type_name_suffix": resource.TypeNameSuffix,
		"operation_name":   resource.OperationName,
		"get_path":         resource.GetPath,
		"put_path":         resource.PutPath,
		"mode":             resource.Mode,
		"provenance":       resource.Provenance,
	} {
		if err := require(name, value); err != nil {
			return err
		}
	}
	if resource.GoName != expected.goName || resource.TypeNameSuffix != expected.typeNameSuffix ||
		resource.OperationName != expected.operationName || resource.GetPath != expected.path || resource.PutPath != expected.path {
		return fmt.Errorf("resource metadata does not match the reviewed generated-resource contract")
	}
	if resource.Mode != "generated" {
		return fmt.Errorf("mode must be generated")
	}
	if resource.Identity.Attribute != "ep_id" || resource.Identity.ImportFormat != "ep_id" || !resource.Identity.RequiresReplace {
		return fmt.Errorf("identity policy must use replace-only ep_id imports")
	}
	if err := require("identity.provenance", resource.Identity.Provenance); err != nil {
		return err
	}
	if resource.Template.TemplateAttribute != "template" || resource.Template.ConfigsBlock != "configs" ||
		!resource.Template.RequiredWhenTemplateFalse || !resource.Template.ForbiddenWhenTemplateTrue ||
		!resource.Template.SuppressConfigsStateWhenTemplate {
		return fmt.Errorf("template/configs policy does not match the reviewed lifecycle")
	}
	if err := require("template_configs.provenance", resource.Template.Provenance); err != nil {
		return err
	}

	fieldPaths := make(map[string]struct{}, len(resource.Fields))
	for _, field := range resource.Fields {
		if err := require("field.path", field.Path); err != nil {
			return err
		}
		if _, exists := fieldPaths[field.Path]; exists {
			return fmt.Errorf("duplicate field policy %q", field.Path)
		}
		fieldPaths[field.Path] = struct{}{}
		want, ok := expected.fields[field.Path]
		if !ok {
			return fmt.Errorf("field %q is not part of the reviewed policy", field.Path)
		}
		if err := validateFieldPolicy(field, want); err != nil {
			return err
		}
		if err := require("field.provenance", field.Provenance); err != nil {
			return fmt.Errorf("field %q: %w", field.Path, err)
		}
	}
	if err := exactKeys(fieldPaths, sortedExpectationKeys(expected.fields), "field policies"); err != nil {
		return err
	}

	collectionPaths := make(map[string]struct{}, len(resource.Collections))
	for _, collection := range resource.Collections {
		if _, exists := collectionPaths[collection.Path]; exists {
			return fmt.Errorf("duplicate collection policy %q", collection.Path)
		}
		collectionPaths[collection.Path] = struct{}{}
		wantWrapper, ok := expected.collections[collection.Path]
		if !ok {
			return fmt.Errorf("unsupported collection policy %q", collection.Path)
		}
		// Unindexed must match the reviewed expectation (default false = indexed)
		// so a profile/JSON inconsistency between unindexed and hidden_index, or
		// between the profile and the reviewed contract, is rejected.
		wantUnindexed := false
		if expected.collectionUnindexed != nil {
			wantUnindexed = expected.collectionUnindexed[collection.Path]
		}
		if collection.Unindexed != wantUnindexed {
			return fmt.Errorf("collection %q unindexed = %v, want %v", collection.Path, collection.Unindexed, wantUnindexed)
		}
		if collection.Encoding != "single_nested_ownership_wrapper_with_list_nested_block" ||
			collection.WrapperBlock != wantWrapper || collection.ItemBlock != "item" || !collection.Ordered ||
			collection.OmittedBehavior != "preserve_raw_and_keep_state_null" ||
			collection.EmptyBehavior != "replace_with_empty_array" ||
			collection.PopulatedBehavior != "replace_complete_ordered_array" ||
			collection.UnknownItemKeys != "fail_closed_when_owned_or_imported" {
			return fmt.Errorf("collection %q does not match the reviewed protocol-5 ownership policy", collection.Path)
		}
		// HiddenIndex is "sequential_one_based_idx" for indexed collections and
		// "none" for unindexed collections (no positional idx).
		wantHiddenIndex := "sequential_one_based_idx"
		if collection.Unindexed {
			wantHiddenIndex = "none"
		}
		if collection.HiddenIndex != wantHiddenIndex {
			return fmt.Errorf("collection %q hidden_index = %q, want %q", collection.Path, collection.HiddenIndex, wantHiddenIndex)
		}
		if err := require("collection.provenance", collection.Provenance); err != nil {
			return fmt.Errorf("collection %q: %w", collection.Path, err)
		}
	}
	if err := exactKeys(collectionPaths, sortedExpectationKeys(expected.collections), "collection policies"); err != nil {
		return err
	}

	if err := validateScalarStringArrays(resource, expected); err != nil {
		return err
	}

	if err := validateItemStringArrays(resource, expected); err != nil {
		return err
	}

	if err := validateBackendAdditions(resource, expected); err != nil {
		return err
	}

	if err := validateBackendConfigScalarConstraints(resource, expected); err != nil {
		return err
	}

	standaloneStatusCandidate := resource.TerraformName != CachingCompressionResourceName
	if standaloneStatusCandidate && resource.Destroy.Field != "status" {
		return fmt.Errorf("reviewed standalone disable candidate must declare configs.status")
	}
	if !standaloneStatusCandidate && resource.Destroy.Field != "" {
		return fmt.Errorf("resource has no reviewed safe standalone disable field")
	}
	switch resource.Destroy.Mode {
	case "forget":
		if resource.Destroy.Verified {
			return fmt.Errorf("forget destroy policy must not be marked verified")
		}
		switch resource.Destroy.Field {
		case "status":
			if resource.Destroy.Reason != forgetDestroyReason {
				return fmt.Errorf("status disable candidate must retain the reviewed unverified forget reason")
			}
		case "":
			if resource.Destroy.Reason != noSafeStatusDestroyReason {
				return fmt.Errorf("non-candidate destroy policy must record the absence of a safe standalone status")
			}
		default:
			return fmt.Errorf("unsupported destroy candidate field %q", resource.Destroy.Field)
		}
	case "disable":
		if !resource.Destroy.Verified {
			return fmt.Errorf("disable destroy policy must be individually live verified")
		}
		if resource.Destroy.Field != "status" {
			return fmt.Errorf("disable destroy policy must own configs.status")
		}
		if strings.TrimSpace(resource.Destroy.Reason) == "" || resource.Destroy.Reason == forgetDestroyReason {
			return fmt.Errorf("disable destroy policy must record exact live-verification provenance")
		}
	default:
		return fmt.Errorf("unsupported destroy policy mode %q", resource.Destroy.Mode)
	}
	if err := require("destroy.provenance", resource.Destroy.Provenance); err != nil {
		return err
	}
	if resource.TemplateDestroy.Mode != "disable" || !resource.TemplateDestroy.Verified ||
		resource.TemplateDestroy.Field != "status" {
		return fmt.Errorf("template destroy policy must be a verified configs.status disable")
	}
	templateDestroyReason := templateDestroyVerifiedReason
	wantCoupledFields := []string(nil)
	if resource.TerraformName == CachingCompressionResourceName {
		templateDestroyReason = templateCachingCompressionDestroyReason
		wantCoupledFields = []string{"cache.status", "compress.status"}
	}
	if !orderedStringsEqual(resource.TemplateDestroy.CoupledFields, wantCoupledFields) {
		return fmt.Errorf("template destroy policy has unreviewed coupled disable fields")
	}
	if resource.TemplateDestroy.Reason != templateDestroyReason {
		return fmt.Errorf("template destroy policy must retain the reviewed verification reason")
	}
	if err := require("template_destroy.provenance", resource.TemplateDestroy.Provenance); err != nil {
		return err
	}
	return nil
}

func orderedStringsEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateFieldPolicy(field FieldPolicy, want fieldExpectation) error {
	defaultMatches := field.ProviderDefault == nil && want.providerDefault == nil
	if field.ProviderDefault != nil && want.providerDefault != nil {
		defaultMatches = *field.ProviderDefault == *want.providerDefault
	}
	if field.TerraformPolicy != want.terraformPolicy ||
		field.UseStateForUnknown != want.useStateForUnknown || !defaultMatches ||
		field.AllowWireNull != want.allowWireNull || field.TerraformName != want.terraformName || field.WireName != want.wireName ||
		!stringMapEqual(field.WireAliases, want.wireAliases) ||
		!int64PointerEqual(field.RemoteMaximum, want.remoteMaximum) || field.AllowNull != want.allowNull || field.WireOnly != want.wireOnly ||
		field.Sensitive != want.sensitive || field.PreserveFromGet != want.preserveFromGet {
		return fmt.Errorf("field %q does not match the reviewed Terraform and wire policy", field.Path)
	}
	// AllowNull is only meaningful for optional config scalars. A required
	// scalar must never accept a null wire value.
	if field.AllowNull && field.TerraformPolicy == "required" {
		return fmt.Errorf("field %q cannot be both required and nullable", field.Path)
	}
	// Computed-only values must never read from config/plan/state. Item fields
	// additionally preserve the fresh GET value into replacement PUT arrays;
	// configs-level readOnly scalars are omitted from the patch and therefore
	// do not need preserve_from_get.
	if field.TerraformPolicy == "computed" {
		if strings.Contains(field.Path, ".item.") && !field.PreserveFromGet {
			return fmt.Errorf("field %q has computed policy but preserve_from_get is not set", field.Path)
		}
		if field.UseStateForUnknown {
			return fmt.Errorf("field %q has computed policy but carries use_state_for_unknown", field.Path)
		}
		if field.ProviderDefault != nil || field.AllowWireNull || len(field.WireAliases) != 0 || field.RemoteMaximum != nil || field.AllowNull || field.WireOnly {
			return fmt.Errorf("field %q has computed policy but carries a non-computed facet", field.Path)
		}
	}
	return nil
}

func stringMapEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

// validateScalarStringArrays validates reviewed scalar-string-array collection
// policies against the reviewed expectation map. It enforces exact path/wrapper
// block/item attribute/enum/max-items/behavior/provenance matches and rejects
// duplicates, so a resource that declares no scalar-string-array in its
// reviewed contract must not carry one in policy and vice-versa.
func validateScalarStringArrays(resource ResourceOverride, expected resourceExpectation) error {
	gotPaths := make(map[string]struct{}, len(resource.ScalarStringArrays))
	for _, array := range resource.ScalarStringArrays {
		if strings.TrimSpace(array.Path) == "" {
			return fmt.Errorf("scalar string array policy has an empty path")
		}
		if strings.TrimSpace(array.Provenance) == "" {
			return fmt.Errorf("scalar string array %q is missing provenance", array.Path)
		}
		if _, exists := gotPaths[array.Path]; exists {
			return fmt.Errorf("duplicate scalar string array policy %q", array.Path)
		}
		gotPaths[array.Path] = struct{}{}
		want, ok := expected.scalarStringArrays[array.Path]
		if !ok {
			return fmt.Errorf("scalar string array %q is not part of the reviewed policy", array.Path)
		}
		if array.WrapperBlock != want.wrapperBlock || array.ItemAttribute != want.itemAttribute ||
			array.MaxItems != want.maxItems || array.Required != want.required ||
			array.OmittedBehavior != "preserve_raw_and_keep_state_null" ||
			array.EmptyBehavior != "replace_with_empty_array" ||
			array.PopulatedBehavior != "replace_complete_ordered_array" ||
			array.UnknownItemKeys != "fail_closed_when_owned_or_imported" {
			return fmt.Errorf("scalar string array %q does not match the reviewed ownership policy", array.Path)
		}
		if !sortedStringsEqual(array.Enum, want.enum) {
			return fmt.Errorf("scalar string array %q enum = %v, want %v", array.Path, array.Enum, want.enum)
		}
		if array.Provenance != want.provenance {
			return fmt.Errorf("scalar string array %q provenance does not match the reviewed policy", array.Path)
		}
	}
	return exactKeys(gotPaths, sortedExpectationKeys(expected.scalarStringArrays), "scalar string array policies")
}

// validateItemStringArrays validates reviewed item-level scalar-string-array
// policies against the reviewed expectation map. It enforces exact path/wrapper
// block/item attribute/enum/max-items/behavior/provenance matches and rejects
// duplicates, so a resource that declares no item string array in its reviewed
// contract must not carry one in policy and vice-versa.
func validateItemStringArrays(resource ResourceOverride, expected resourceExpectation) error {
	gotPaths := make(map[string]struct{}, len(resource.ItemStringArrays))
	for _, array := range resource.ItemStringArrays {
		if strings.TrimSpace(array.Path) == "" {
			return fmt.Errorf("item string array policy has an empty path")
		}
		if strings.TrimSpace(array.Provenance) == "" {
			return fmt.Errorf("item string array %q is missing provenance", array.Path)
		}
		if _, exists := gotPaths[array.Path]; exists {
			return fmt.Errorf("duplicate item string array policy %q", array.Path)
		}
		gotPaths[array.Path] = struct{}{}
		want, ok := expected.itemStringArrays[array.Path]
		if !ok {
			return fmt.Errorf("item string array %q is not part of the reviewed policy", array.Path)
		}
		if array.WrapperBlock != want.wrapperBlock || array.ItemAttribute != want.itemAttribute ||
			array.MaxItems != want.maxItems || array.Required != want.required ||
			array.ItemMaxLength != want.itemMaxLength ||
			array.OmittedBehavior != "preserve_raw_and_keep_state_null" ||
			array.EmptyBehavior != "replace_with_empty_array" ||
			array.PopulatedBehavior != "replace_complete_ordered_array" ||
			array.UnknownItemKeys != "fail_closed_when_owned_or_imported" {
			return fmt.Errorf("item string array %q does not match the reviewed ownership policy", array.Path)
		}
		if !sortedStringsEqual(array.Enum, want.enum) {
			return fmt.Errorf("item string array %q enum = %v, want %v", array.Path, array.Enum, want.enum)
		}
		if array.Provenance != want.provenance {
			return fmt.Errorf("item string array %q provenance does not match the reviewed policy", array.Path)
		}
	}
	return exactKeys(gotPaths, sortedExpectationKeys(expected.itemStringArrays), "item string array policies")
}

// validateBackendAdditions validates reviewed backend field additions against
// the reviewed expectation map. It enforces exact path/kind/required/enum/
// max-length/pattern/provenance matches, rejects duplicates, and requires each
// addition to have a matching reviewed field policy (the field policy records
// the Terraform behavior; the backend addition records the reviewed backend
// origin and contract). The generator separately rejects any addition that
// collides with a pure OpenAPI item field.
func validateBackendAdditions(resource ResourceOverride, expected resourceExpectation) error {
	want := reviewedBackendAdditions[resource.TerraformName]
	fieldPolicyPaths := make(map[string]struct{}, len(resource.Fields))
	for _, field := range resource.Fields {
		fieldPolicyPaths[field.Path] = struct{}{}
	}
	gotPaths := make(map[string]struct{}, len(resource.BackendFieldAdditions))
	for _, addition := range resource.BackendFieldAdditions {
		if strings.TrimSpace(addition.Path) == "" {
			return fmt.Errorf("backend field addition has an empty path")
		}
		if strings.TrimSpace(addition.Provenance) == "" {
			return fmt.Errorf("backend field addition %q is missing provenance", addition.Path)
		}
		if _, exists := gotPaths[addition.Path]; exists {
			return fmt.Errorf("duplicate backend field addition %q", addition.Path)
		}
		gotPaths[addition.Path] = struct{}{}
		if _, exists := fieldPolicyPaths[addition.Path]; !exists {
			return fmt.Errorf("backend field addition %q has no matching reviewed field policy", addition.Path)
		}
		fieldPolicy, ok := expected.fields[addition.Path]
		if !ok {
			return fmt.Errorf("backend field addition %q is not part of the reviewed field policy set", addition.Path)
		}
		if fieldPolicy.wireOnly {
			return fmt.Errorf("backend field addition %q must not be wire-only", addition.Path)
		}
		if fieldPolicy.providerDefault != nil {
			return fmt.Errorf("backend field addition %q must not carry a provider default", addition.Path)
		}
		wantAddition, ok := want[addition.Path]
		if !ok {
			return fmt.Errorf("backend field addition %q is not part of the reviewed backend additions", addition.Path)
		}
		if addition.Kind != wantAddition.kind {
			return fmt.Errorf("backend field addition %q kind = %q, want %q", addition.Path, addition.Kind, wantAddition.kind)
		}
		if addition.Required != wantAddition.required {
			return fmt.Errorf("backend field addition %q required = %v, want %v", addition.Path, addition.Required, wantAddition.required)
		}
		if !sortedStringsEqual(addition.Enum, wantAddition.enum) {
			return fmt.Errorf("backend field addition %q enum = %v, want %v", addition.Path, addition.Enum, wantAddition.enum)
		}
		if addition.MaxLength != wantAddition.maxLength {
			return fmt.Errorf("backend field addition %q max_length = %d, want %d", addition.Path, addition.MaxLength, wantAddition.maxLength)
		}
		if addition.Pattern != wantAddition.pattern {
			return fmt.Errorf("backend field addition %q pattern = %q, want %q", addition.Path, addition.Pattern, wantAddition.pattern)
		}
		if addition.Provenance != wantAddition.provenance {
			return fmt.Errorf("backend field addition %q provenance does not match the reviewed backend additions", addition.Path)
		}
	}
	if err := exactKeys(gotPaths, sortedExpectationKeys(want), "backend field additions"); err != nil {
		return err
	}
	return nil
}

// validateBackendConfigScalarConstraints validates reviewed integer
// config-scalar numeric enrichments against the reviewed expectation map. It
// enforces exact path/minimum/maximum/provenance matches, rejects duplicates,
// requires each enrichment to target a reviewed configs integer field policy,
// requires at least one facet (minimum or maximum) per entry, and requires
// minimum <= maximum. The generator separately rejects any enrichment that
// collides with a pure OpenAPI bound or lacks a matching contract marker.
func validateBackendConfigScalarConstraints(resource ResourceOverride, expected resourceExpectation) error {
	want := reviewedBackendConfigScalarConstraints[resource.TerraformName]
	fieldPolicyPaths := make(map[string]struct{}, len(resource.Fields))
	for _, field := range resource.Fields {
		fieldPolicyPaths[field.Path] = struct{}{}
	}
	gotPaths := make(map[string]struct{}, len(resource.BackendConfigScalarConstraints))
	for _, constraint := range resource.BackendConfigScalarConstraints {
		if strings.TrimSpace(constraint.Path) == "" {
			return fmt.Errorf("backend config scalar constraint has an empty path")
		}
		if strings.TrimSpace(constraint.Provenance) == "" {
			return fmt.Errorf("backend config scalar constraint %q is missing provenance", constraint.Path)
		}
		if _, exists := gotPaths[constraint.Path]; exists {
			return fmt.Errorf("duplicate backend config scalar constraint %q", constraint.Path)
		}
		gotPaths[constraint.Path] = struct{}{}
		if _, exists := fieldPolicyPaths[constraint.Path]; !exists {
			return fmt.Errorf("backend config scalar constraint %q has no matching reviewed field policy", constraint.Path)
		}
		if constraint.Minimum == nil && constraint.Maximum == nil {
			return fmt.Errorf("backend config scalar constraint %q pins neither minimum nor maximum", constraint.Path)
		}
		if constraint.Minimum != nil && constraint.Maximum != nil && *constraint.Minimum > *constraint.Maximum {
			return fmt.Errorf("backend config scalar constraint %q minimum %d > maximum %d", constraint.Path, *constraint.Minimum, *constraint.Maximum)
		}
		wantConstraint, ok := want[constraint.Path]
		if !ok {
			return fmt.Errorf("backend config scalar constraint %q is not part of the reviewed backend config scalar constraints", constraint.Path)
		}
		if !int64PointerEqual(constraint.Minimum, wantConstraint.minimum) {
			return fmt.Errorf("backend config scalar constraint %q minimum does not match the reviewed backend config scalar constraints", constraint.Path)
		}
		if !int64PointerEqual(constraint.Maximum, wantConstraint.maximum) {
			return fmt.Errorf("backend config scalar constraint %q maximum does not match the reviewed backend config scalar constraints", constraint.Path)
		}
		if constraint.Provenance != wantConstraint.provenance {
			return fmt.Errorf("backend config scalar constraint %q provenance does not match the reviewed backend config scalar constraints", constraint.Path)
		}
	}
	if err := exactKeys(gotPaths, sortedExpectationKeys(want), "backend config scalar constraints"); err != nil {
		return err
	}
	return nil
}

// int64PointerEqual compares two optional int64 bounds for equality.
func int64PointerEqual(got, want *int64) bool {
	if got == nil && want == nil {
		return true
	}
	if got == nil || want == nil {
		return false
	}
	return *got == *want
}

func sortedStringsEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gotCopy := append([]string(nil), got...)
	wantCopy := append([]string(nil), want...)
	sort.Strings(gotCopy)
	sort.Strings(wantCopy)
	for i := range gotCopy {
		if gotCopy[i] != wantCopy[i] {
			return false
		}
	}
	return true
}

func exactKeys(got map[string]struct{}, want []string, label string) error {
	missing := make([]string, 0)
	for _, key := range want {
		if _, ok := got[key]; !ok {
			missing = append(missing, key)
		}
	}
	extra := make([]string, 0)
	wantSet := make(map[string]struct{}, len(want))
	for _, key := range want {
		wantSet[key] = struct{}{}
	}
	for key := range got {
		if _, ok := wantSet[key]; !ok {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) != 0 || len(extra) != 0 {
		return fmt.Errorf("%s do not match the reviewed generated-resource graph (missing=%v extra=%v)", label, missing, extra)
	}
	return nil
}

func sortedExpectationKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func boolPointer(value bool) *bool {
	return &value
}

func int64Pointer(value int64) *int64 {
	return &value
}
