package contract

import (
	"fmt"
	"sort"
	"strings"
)

// EndpointFamily groups operations in the reviewed public WAF matrix.
type EndpointFamily string

const (
	FamilyCoreCRUD        EndpointFamily = "core_crud"
	FamilyAppModule       EndpointFamily = "app_module"
	FamilyTemplateModule  EndpointFamily = "template_module"
	FamilyAppGetOnly      EndpointFamily = "app_get_only"
	FamilyAppPutOnly      EndpointFamily = "app_put_only"
	FamilyNestedAppGetPut EndpointFamily = "nested_app_get_put"
	FamilyAppPost         EndpointFamily = "app_post"
	FamilyBlockedIP       EndpointFamily = "blocked_ip"
	FamilyMisc            EndpointFamily = "misc"
	FamilySettings        EndpointFamily = "settings"
	FamilyTemplateExport  EndpointFamily = "template_export"
)

// ImplementationMode records how Terraform will deliver an operation.
type ImplementationMode string

const (
	ModeHandWritten     ImplementationMode = "hand_written"
	ModeGenerated       ImplementationMode = "generated"
	ModeSDKv2           ImplementationMode = "sdkv2"
	ModeCustom          ImplementationMode = "custom"
	ModeDataSource      ImplementationMode = "data_source"
	ModeSharedReference ImplementationMode = "shared_reference"
	ModeNone            ImplementationMode = "none"
)

// CoverageStatus records the implementation state of an operation.
type CoverageStatus string

const (
	// CoverageLocallyImplemented means a Terraform-facing implementation and
	// deterministic local lifecycle coverage exist, but the endpoint has not
	// passed the revised design's live acceptance gate.
	CoverageLocallyImplemented CoverageStatus = "locally_implemented"
	// CoverageLiveVerified means the Terraform-facing implementation has also
	// completed a recorded live lifecycle with restoration/no-op verification.
	CoverageLiveVerified CoverageStatus = "live_verified"
	CoverageSelectedNext CoverageStatus = "selected_next"
	CoveragePlanned      CoverageStatus = "planned"
	CoverageDeferred     CoverageStatus = "deferred"
	CoverageExcluded     CoverageStatus = "excluded"
)

// OperationClassification is one row of the public WAF operation matrix.
type OperationClassification struct {
	Method       string             `json:"method"`
	Path         string             `json:"path"`
	Family       EndpointFamily     `json:"family"`
	Disposition  Disposition        `json:"disposition"`
	Mode         ImplementationMode `json:"mode"`
	Coverage     CoverageStatus     `json:"coverage"`
	Owner        string             `json:"owner"`
	ClientMethod string             `json:"client_method"`
	Provenance   string             `json:"provenance"`
}

// IsImplementedCoverage reports whether a classification has a real local
// Terraform implementation. Live verification is a stricter implemented
// state, not a replacement for local implementation.
func IsImplementedCoverage(status CoverageStatus) bool {
	return status == CoverageLocallyImplemented || status == CoverageLiveVerified
}

var handWrittenAppModules = stringSet(
	"account_takeover",
)

var generatedAppModules = stringSet(
	"csrf_protection",
	"url_access",
	"request_limits",
	"known_attacks",
	"http_header_security",
	"graphql_protection",
	"json_protection",
	"parameter_validation",
	"web_socket_security",
	"information_leakage",
	"ddos_prevention",
	"cookie_security",
	"known_bots",
	"bot_deception",
	"biometrics_based_detection",
	"waiting_room",
	"mitb_protection",
	"threshold_detection",
	"ml_bot_detection",
	"file_protection",
	"mobile_api_protection",
	"xml_protection_policy",
	"rewriting_requests",
	"api_gateway",
	"caching_compression",
)

// implementedTemplateModules is the reviewed intersection of public template
// GET/PUT pairs and Terraform module resources. api_protection remains
// deferred pending a typed template-specific review, and the bulk modules
// endpoint remains excluded from resource ownership.
var implementedTemplateModules = stringSet(
	"account_takeover",
	"anomaly_detection",
	"api_gateway",
	"biometrics_based_detection",
	"bot_deception",
	"caching_compression",
	"cookie_security",
	"cors_protection",
	"csrf_protection",
	"custom_rule",
	"ddos_prevention",
	"file_protection",
	"graphql_protection",
	"http_header_security",
	"information_leakage",
	"ip_protection",
	"json_protection",
	"known_attacks",
	"known_bots",
	"mitb_protection",
	"ml_api_protection",
	"ml_bot_detection",
	"mobile_api_protection",
	"parameter_validation",
	"request_limits",
	"rewriting_requests",
	"threshold_detection",
	"url_access",
	"waiting_room",
	"web_socket_security",
	"xml_protection_policy",
)

// liveVerifiedTemplateModules contains all template-scoped modules that
// completed the exact disposable-template Terraform
// apply/update/no-op/import lifecycle, including live status=false and
// status=true writes, in the accepted complete dev1 matrix. Keep this separate
// from app-module evidence.
var liveVerifiedTemplateModules = stringSet(
	"account_takeover",
	"anomaly_detection",
	"api_gateway",
	"biometrics_based_detection",
	"bot_deception",
	"caching_compression",
	"cookie_security",
	"cors_protection",
	"csrf_protection",
	"custom_rule",
	"ddos_prevention",
	"file_protection",
	"graphql_protection",
	"http_header_security",
	"information_leakage",
	"ip_protection",
	"json_protection",
	"known_attacks",
	"known_bots",
	"mitb_protection",
	"ml_api_protection",
	"ml_bot_detection",
	"mobile_api_protection",
	"parameter_validation",
	"request_limits",
	"rewriting_requests",
	"threshold_detection",
	"url_access",
	"waiting_room",
	"web_socket_security",
	"xml_protection_policy",
)

// liveVerifiedGeneratedAppModules contains the complete generated set after
// the target-bound July 22, 2026 disposable-app campaign passed serial
// apply/update/no-op/import/forget/restore lifecycles for all 25 modules.
// Keep this list explicit so later generated additions still require their own
// recorded live evidence before promotion.
var liveVerifiedGeneratedAppModules = stringSet(
	"csrf_protection",
	"url_access",
	"request_limits",
	"known_attacks",
	"http_header_security",
	"graphql_protection",
	"json_protection",
	"parameter_validation",
	"web_socket_security",
	"information_leakage",
	"ddos_prevention",
	"cookie_security",
	"known_bots",
	"bot_deception",
	"biometrics_based_detection",
	"waiting_room",
	"mitb_protection",
	"threshold_detection",
	"ml_bot_detection",
	"file_protection",
	"mobile_api_protection",
	"xml_protection_policy",
	"rewriting_requests",
	"api_gateway",
	"caching_compression",
)

var frameworkCustomImplementedAppModules = stringSet(
	"api_protection",
)

// frameworkCustomLiveVerifiedAppModules records the custom app modules that
// passed their served Terraform lifecycle in the accepted complete dev1
// matrix. Keep this list explicit so later custom modules still require their
// own recorded live evidence.
var frameworkCustomLiveVerifiedAppModules = stringSet(
	"global_trust_list_parameter",
	"anomaly_detection",
	"cors_protection",
	"ip_protection",
	"routings",
	"custom_rule",
	"ml_api_protection",
)

// explicitlyUnsupportedAppModules records reviewed product-scope decisions,
// not temporary implementation blockers. Neither log settings nor any
// certificate/CRL content upload or attachment family is served.
var explicitlyUnsupportedAppModules = stringSet(
	"log_settings",
	"inter_certificate",
	"sni_certificate",
	"server_ca",
	"server_crl",
	"ca_certificate",
	"crl_certificate",
)

var generatedPlannedAppModules = stringSet()

var designCustomAppModules = stringSet(
	"anomaly_detection",
	"custom_rule",
	"ml_api_protection",
	"inter_certificate",
)

var schemaCustomAppModules = stringSet(
	"ca_certificate",
	"cors_protection",
	"crl_certificate",
	"endpoint",
	"global_trust_list_parameter",
	"inter_certificate",
	"ip_protection",
	"log_settings",
	"modules",
	"routings",
	"server_ca",
	"server_crl",
	"servers",
	"signature_exception",
	"sni_certificate",
)

var selectedNextAppModules = stringSet()

var allAppModuleSet = mergeStringSets(
	handWrittenAppModules,
	generatedAppModules,
	frameworkCustomImplementedAppModules,
	selectedNextAppModules,
	generatedPlannedAppModules,
	designCustomAppModules,
	schemaCustomAppModules,
)

var templateModulePairs = stringSet(
	"account_takeover",
	"anomaly_detection",
	"api_gateway",
	"api_protection",
	"biometrics_based_detection",
	"bot_deception",
	"caching_compression",
	"cookie_security",
	"cors_protection",
	"csrf_protection",
	"custom_rule",
	"ddos_prevention",
	"file_protection",
	"graphql_protection",
	"http_header_security",
	"information_leakage",
	"ip_protection",
	"json_protection",
	"known_attacks",
	"known_bots",
	"mitb_protection",
	"ml_api_protection",
	"ml_bot_detection",
	"mobile_api_protection",
	"modules",
	"parameter_validation",
	"request_limits",
	"rewriting_requests",
	"threshold_detection",
	"url_access",
	"waiting_room",
	"web_socket_security",
	"xml_protection_policy",
)

var coreOperations = map[string][]string{
	"/waf/apps":                   {"GET", "POST"},
	"/waf/apps/{ep_id}":           {"DELETE", "GET", "PUT"},
	"/waf/template":               {"GET", "POST"},
	"/waf/template/clone":         {"POST"},
	"/waf/template/{template_id}": {"DELETE", "GET", "PUT"},
}

var appGetOnlySegments = stringSet(
	"ca_cert_detail",
	"crl_cert_detail",
	"dashboard",
	"dashboard/owasp_top10",
	"dashboard/pserver_status",
	"dashboard/threat_level_history",
	"dashboard/threat_levels",
	"dashboard/traffic_stat",
	"ddos_prevention_ip_exception_export",
	"geo_ip_exception_list",
	"inter_cert_detail",
	"ip_protection_list",
	"ml_ad_overview",
	"ml_ad_treeview",
	"ml_ad_url_stats",
	"ml_api_protection_download",
	"ml_api_protection_schemafile",
	"ml_api_protection_timeline",
	"ml_api_protection_url",
	"server_ca_detail",
	"server_crl_detail",
	"sni_cert_detail",
	"threat_view/statistics",
	"threat_view/threat_map",
	"traffic_summary/ip_statistics",
	"traffic_summary/method_statistics",
	"traffic_summary/retcode_statistics",
	"traffic_summary/url_statistics",
	"waiting_room_overview",
)

var certificateDetailSegments = stringSet(
	"ca_cert_detail",
	"crl_cert_detail",
	"inter_cert_detail",
	"server_ca_detail",
	"server_crl_detail",
	"sni_cert_detail",
)

var appPutOnlySegments = stringSet(
	"block",
	"ml_ad_discard_arg",
	"ml_ad_rebuild_arg",
	"ml_ad_rebuild_dic",
	"ml_ad_rebuild_url",
	"ml_api_protection_url_config",
	"ml_api_protection_url_model",
	"ml_api_protection_url_refresh",
	"server_lock",
)

var nestedAppOperations = map[string][]string{
	"authentication_proxy/settings": {"GET", "PUT"},
	"vs/{action}":                   {"GET", "PUT"},
}

var appPostSegments = stringSet(
	"authentication_proxy/settings/download_sp_metadata",
	"cache_purge",
	"log_settings/server_connect_test",
	"server/test",
)

var miscOperations = map[string][]string{
	"/waf/misc/backend-ip-test": {"GET"},
	"/waf/misc/dns-lookup":      {"POST"},
	"/waf/misc/knownbot-info":   {"GET"},
	"/waf/misc/management_ip":   {"GET"},
}

var settingsOperations = map[string][]string{
	"/waf/settings":                             {"GET", "PUT"},
	"/waf/settings/cbp/images":                  {"DELETE", "GET", "POST", "PUT"},
	"/waf/settings/cbp/messages":                {"DELETE", "GET", "POST", "PUT"},
	"/waf/settings/cbp/messages/clone":          {"POST"},
	"/waf/settings/cbp/messages/{message_name}": {"GET"},
	"/waf/settings/connectors":                  {"DELETE", "GET", "POST", "PUT"},
	"/waf/settings/connectors/filter_options":   {"GET"},
	"/waf/settings/connectors/public_ip_test":   {"PUT"},
	"/waf/settings/connectors/test":             {"POST"},
	"/waf/settings/fabric/status":               {"GET", "POST"},
	"/waf/settings/fabric/status/{ip}":          {"DELETE", "PUT"},
	"/waf/settings/idps":                        {"GET", "POST"},
	"/waf/settings/idps/{idp_name}":             {"DELETE", "PUT"},
	"/waf/settings/socaas":                      {"GET"},
	"/waf/settings/wrp/pages":                   {"DELETE", "GET", "POST", "PUT"},
	"/waf/settings/wrp/pages/clone":             {"POST"},
	"/waf/settings/wrp/pages/{page_name}":       {"GET"},
}

var excludedSettingsPaths = stringSet(
	"/waf/settings/cbp/messages/clone",
	"/waf/settings/connectors/public_ip_test",
	"/waf/settings/connectors/test",
	"/waf/settings/idps",
	"/waf/settings/idps/{idp_name}",
	"/waf/settings/wrp/pages/clone",
)

var templateExportSegments = stringSet(
	"ddos_prevention_ip_exception_export",
	"geo_ip_exception_list",
	"ip_protection_list",
)

const (
	provenanceFrameworkLocal    = "Framework resource and typed client lifecycle are implemented and locally tested; live acceptance remains pending."
	provenanceFrameworkLive     = "Framework resource and typed client operation completed the recorded disposable live apply/no-op/import/destroy lifecycle."
	provenanceGeneratedLocal    = "Generated Framework resource has pinned app GET/PUT contracts and deterministic local lifecycle coverage; live acceptance remains pending."
	provenanceGeneratedLive     = "Generated Framework resource completed a recorded live lifecycle with convergence and restoration verification."
	provenanceHandWrittenLive   = "Hand-written Framework resource completed a recorded live lifecycle with convergence and restoration verification."
	provenanceGeneratedPlanned  = "Pinned app GET/PUT contract is assigned to the generated family; field policy and lifecycle verification remain pending."
	provenanceDesignCustom      = "Reviewed revised-design custom family due to conditional or specialized ownership despite an app GET/PUT envelope."
	provenanceSchemaCustom      = "Pinned schema or lifecycle disqualifier requires a custom implementation instead of the uniform generator."
	provenanceTemplateDeferred  = "Template ownership is deferred pending a dedicated lifecycle design and live probe."
	provenanceExcluded          = "Reviewed exclusion: the operation has no durable Terraform configuration ownership."
	provenanceCustomPlanned     = "Reviewed custom implementation for non-uniform durable configuration ownership."
	provenanceDataSourcePlanned = "Reviewed read-only data-source target; typed public state implementation remains pending."
	provenanceDataSourceLocal   = "Framework data source and typed client read are implemented and deterministically locally tested; live acceptance remains pending."
	provenanceSharedReference   = "Shared provider reference or precheck operation, not an independently owned Terraform object."
)

// ClassifyPublicWAF returns one deterministic row for every public WAF operation.
func ClassifyPublicWAF(document Document) ([]OperationClassification, error) {
	if err := validateReviewedPublicOperations(document); err != nil {
		return nil, err
	}

	operations := append([]Operation(nil), document.Operations...)
	sort.Slice(operations, func(i, j int) bool {
		if operations[i].Path == operations[j].Path {
			return operations[i].Method < operations[j].Method
		}
		return operations[i].Path < operations[j].Path
	})

	classifications := make([]OperationClassification, 0, len(operations))
	for _, operation := range operations {
		if !operation.Public {
			continue
		}
		classification, ok := classifyPublicWAFOperation(operation)
		if !ok {
			return nil, fmt.Errorf("unclassified public WAF operation %s %s", operation.Method, operation.Path)
		}
		classifications = append(classifications, classification)
	}
	return classifications, nil
}

func validateReviewedPublicOperations(document Document) error {
	expected, err := reviewedPublicOperationKeys()
	if err != nil {
		return err
	}
	actual := make(map[string]struct{})
	for _, operation := range document.Operations {
		if !operation.Public {
			continue
		}
		key := operationKey(operation.Method, operation.Path)
		if _, duplicate := actual[key]; duplicate {
			return fmt.Errorf("duplicate public WAF operation %s", key)
		}
		actual[key] = struct{}{}
	}

	unclassified := differenceKeys(actual, expected)
	stale := differenceKeys(expected, actual)
	if len(unclassified) != 0 || len(stale) != 0 {
		return fmt.Errorf("public WAF classification mismatch (unclassified=%v stale=%v)", unclassified, stale)
	}
	return nil
}

func reviewedPublicOperationKeys() (map[string]struct{}, error) {
	keys := make(map[string]struct{})
	add := func(method, path string) error {
		key := operationKey(method, path)
		if _, duplicate := keys[key]; duplicate {
			return fmt.Errorf("duplicate reviewed WAF operation %s", key)
		}
		keys[key] = struct{}{}
		return nil
	}
	addMethods := func(path string, methods []string) error {
		for _, method := range methods {
			if err := add(method, path); err != nil {
				return err
			}
		}
		return nil
	}

	for module := range allAppModuleSet {
		if err := addMethods("/waf/apps/{ep_id}/"+module, []string{"GET", "PUT"}); err != nil {
			return nil, err
		}
	}
	for module := range templateModulePairs {
		if err := addMethods("/waf/template/{template_id}/"+module, []string{"GET", "PUT"}); err != nil {
			return nil, err
		}
	}
	for path, methods := range coreOperations {
		if err := addMethods(path, methods); err != nil {
			return nil, err
		}
	}
	for segment := range appGetOnlySegments {
		if err := add("GET", "/waf/apps/{ep_id}/"+segment); err != nil {
			return nil, err
		}
	}
	for segment := range appPutOnlySegments {
		if err := add("PUT", "/waf/apps/{ep_id}/"+segment); err != nil {
			return nil, err
		}
	}
	for segment, methods := range nestedAppOperations {
		if err := addMethods("/waf/apps/{ep_id}/"+segment, methods); err != nil {
			return nil, err
		}
	}
	for segment := range appPostSegments {
		if err := add("POST", "/waf/apps/{ep_id}/"+segment); err != nil {
			return nil, err
		}
	}
	if err := addMethods("/waf/apps/{ep_id}/blocked_ip", []string{"DELETE", "GET"}); err != nil {
		return nil, err
	}
	for path, methods := range miscOperations {
		if err := addMethods(path, methods); err != nil {
			return nil, err
		}
	}
	for path, methods := range settingsOperations {
		if err := addMethods(path, methods); err != nil {
			return nil, err
		}
	}
	for segment := range templateExportSegments {
		if err := add("GET", "/waf/template/{template_id}/"+segment); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

func classifyPublicWAFOperation(operation Operation) (OperationClassification, bool) {
	if classification, ok := classifyCoreOperation(operation); ok {
		return classification, true
	}
	if classification, ok := classifyTemplateOperation(operation); ok {
		return classification, true
	}
	if classification, ok := classifyAppOperation(operation); ok {
		return classification, true
	}
	if classification, ok := classifySettingsOperation(operation); ok {
		return classification, true
	}
	if classification, ok := classifyMiscOperation(operation); ok {
		return classification, true
	}
	return OperationClassification{}, false
}

func classifyCoreOperation(operation Operation) (OperationClassification, bool) {
	c := baseClassification(operation, FamilyCoreCRUD)
	switch operation.Path {
	case "/waf/apps":
		switch operation.Method {
		case "GET":
			c.Disposition = DispositionDataSource
			c.Mode = ModeDataSource
			c.Coverage = CoveragePlanned
			c.Owner = "fortiappseccloud_waf_apps"
			c.ClientMethod = "ListApplications/ListAllApplications/ListApplicationSummaries"
			c.Provenance = provenanceDataSourcePlanned
		case "POST":
			c.Disposition = DispositionResourceWrite
			c.Mode = ModeCustom
			c.Coverage = CoverageLiveVerified
			c.Owner = "fortiappseccloud_waf_app"
			c.ClientMethod = "CreateApplication"
			c.Provenance = provenanceFrameworkLive
		default:
			return OperationClassification{}, false
		}
	case "/waf/apps/{ep_id}":
		c.Owner = "fortiappseccloud_waf_app"
		switch operation.Method {
		case "GET":
			c.Disposition = DispositionResourceRead
			c.Mode = ModeCustom
			c.Coverage = CoverageLocallyImplemented
			c.ClientMethod = "GetApplication/FindApplicationByEPID"
			c.Provenance = provenanceFrameworkLocal
		case "PUT":
			c.Disposition = DispositionResourceWrite
			c.Mode = ModeCustom
			c.Coverage = CoverageLocallyImplemented
			c.ClientMethod = "UpdateApplication"
			c.Provenance = provenanceFrameworkLocal
		case "DELETE":
			c.Disposition = DispositionResourceWrite
			c.Mode = ModeCustom
			c.Coverage = CoverageLiveVerified
			c.ClientMethod = "DeleteApplication"
			c.Provenance = provenanceFrameworkLive
		default:
			return OperationClassification{}, false
		}
	case "/waf/template":
		c.Owner = "fortiappseccloud_waf_template"
		if operation.Method == "GET" {
			c.Disposition = DispositionDataSource
			c.Mode = ModeDataSource
			c.Coverage = CoveragePlanned
			c.Owner = "fortiappseccloud_waf_templates"
			c.ClientMethod = "ListTemplates"
			c.Provenance = provenanceDataSourcePlanned
		} else if operation.Method == "POST" {
			c.Disposition = DispositionResourceWrite
			c.Mode = ModeCustom
			c.Coverage = CoverageLiveVerified
			c.ClientMethod = "CreateTemplate"
			c.Provenance = provenanceFrameworkLive
		} else {
			return OperationClassification{}, false
		}
	case "/waf/template/{template_id}":
		c.Mode = ModeCustom
		switch operation.Method {
		case "GET":
			c.Disposition = DispositionResourceRead
			c.ClientMethod = "GetTemplate"
			c.Coverage = CoverageLiveVerified
			c.Owner = "fortiappseccloud_waf_template, fortiappseccloud_waf_template_attachment"
			c.Provenance = provenanceFrameworkLive
		case "PUT":
			c.Disposition = DispositionResourceWrite
			c.ClientMethod = "PutTemplateEndpoints"
			c.Coverage = CoverageLiveVerified
			c.Owner = "fortiappseccloud_waf_template_attachment"
			c.Provenance = provenanceFrameworkLive
		case "DELETE":
			c.Disposition = DispositionResourceWrite
			c.ClientMethod = "DeleteTemplate"
			c.Coverage = CoverageLiveVerified
			c.Owner = "fortiappseccloud_waf_template"
			c.Provenance = provenanceFrameworkLive
		default:
			return OperationClassification{}, false
		}
	case "/waf/template/clone":
		if operation.Method != "POST" {
			return OperationClassification{}, false
		}
		c.Disposition = DispositionAction
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
	default:
		return OperationClassification{}, false
	}
	return c, true
}

func classifyTemplateOperation(operation Operation) (OperationClassification, bool) {
	const prefix = "/waf/template/{template_id}/"
	if !strings.HasPrefix(operation.Path, prefix) {
		return OperationClassification{}, false
	}
	segment := strings.TrimPrefix(operation.Path, prefix)
	if _, ok := templateModulePairs[segment]; ok {
		if operation.Method != "GET" && operation.Method != "PUT" {
			return OperationClassification{}, false
		}
		c := baseClassification(operation, FamilyTemplateModule)
		c.Owner = "fortiappseccloud_waf_template_" + segment
		if has(implementedTemplateModules, segment) {
			c.Disposition = DispositionResourceRead
			c.ClientMethod = "GetWAFTemplateModule"
			if operation.Method == "PUT" {
				c.Disposition = DispositionResourceWrite
				c.ClientMethod = "PutWAFTemplateModule"
			}
			c.Mode = ModeCustom
			if has(generatedAppModules, segment) {
				c.Mode = ModeGenerated
			}
			if has(liveVerifiedTemplateModules, segment) {
				c.Coverage = CoverageLiveVerified
				c.Provenance = provenanceGeneratedLive
			} else {
				c.Coverage = CoverageLocallyImplemented
				c.Provenance = provenanceFrameworkLocal
			}
			return c, true
		}
		c.Disposition = DispositionDeferred
		c.Mode = ModeNone
		c.Coverage = CoverageDeferred
		c.Provenance = provenanceTemplateDeferred
		return c, true
	}
	if _, ok := templateExportSegments[segment]; ok && operation.Method == "GET" {
		c := baseClassification(operation, FamilyTemplateExport)
		c.Disposition = DispositionExplicitExclusion
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
		return c, true
	}
	return OperationClassification{}, false
}

func classifyAppOperation(operation Operation) (OperationClassification, bool) {
	const prefix = "/waf/apps/{ep_id}/"
	if !strings.HasPrefix(operation.Path, prefix) {
		return OperationClassification{}, false
	}
	segment := strings.TrimPrefix(operation.Path, prefix)
	if segment == "block" && operation.Method == "PUT" {
		c := baseClassification(operation, FamilyAppPutOnly)
		c.Disposition = DispositionResourceWrite
		c.Mode = ModeCustom
		c.Coverage = CoverageLiveVerified
		c.Owner = "fortiappseccloud_waf_app"
		c.ClientMethod = "UpdateApplicationBlockMode"
		c.Provenance = provenanceFrameworkLive
		return c, true
	}

	if _, ok := allAppModuleSet[segment]; ok && (operation.Method == "GET" || operation.Method == "PUT") {
		c := baseClassification(operation, FamilyAppModule)
		c.Disposition = DispositionResourceRead
		if operation.Method == "PUT" {
			c.Disposition = DispositionResourceWrite
		}
		c.Mode, c.Coverage = appModuleMode(segment, operation.Method)
		c.Owner = appModuleOwner(segment)
		c.ClientMethod = appModuleClientMethod(segment, operation.Method)
		c.Provenance = appModuleProvenance(segment, operation.Method)
		// Reviewed contract decisions override the default resource read/write
		// disposition for operations intentionally outside provider scope and
		// for two asymmetric modules whose GET is served as a data source:
		//   - log_settings and all certificate/CRL upload or attachment
		//     families are explicit product-scope exclusions.
		//   - signature_exception: GET returns only an optional template id for
		//     one signature and is served as a narrow read-only data source; PUT
		//     accepts exception rules that GET cannot reconstruct and remains an
		//     explicit exclusion.
		//   - modules: bulk array[ApplicationModuleStatus]; PUT changes module
		//     statuses without complete configs (overlapping ownership) -> explicit
		//     exclusion; GET is served by a read-only status data source.
		if has(explicitlyUnsupportedAppModules, segment) {
			c.Disposition = DispositionExplicitExclusion
			c.Mode = ModeNone
			c.Coverage = CoverageExcluded
			c.Provenance = provenanceExcluded
			c.ClientMethod = ""
		} else if segment == "signature_exception" {
			if operation.Method == "PUT" {
				c.Disposition = DispositionExplicitExclusion
				c.Mode = ModeNone
				c.Coverage = CoverageExcluded
				c.Provenance = provenanceExcluded
				c.ClientMethod = ""
			} else {
				c.Disposition = DispositionDataSource
				c.Mode = ModeDataSource
				c.Coverage = CoverageLocallyImplemented
				c.Provenance = provenanceDataSourceLocal
				c.ClientMethod = "GetSignatureException"
			}
		} else if segment == "modules" {
			if operation.Method == "PUT" {
				c.Disposition = DispositionExplicitExclusion
				c.Mode = ModeNone
				c.Coverage = CoverageExcluded
				c.Provenance = provenanceExcluded
				c.ClientMethod = ""
			} else {
				c.Disposition = DispositionDataSource
				c.Mode = ModeDataSource
				c.Coverage = CoverageLocallyImplemented
				c.Provenance = provenanceDataSourceLocal
				c.ClientMethod = "GetApplicationModules"
			}
		}
		return c, true
	}
	if segment == "blocked_ip" && (operation.Method == "GET" || operation.Method == "DELETE") {
		c := baseClassification(operation, FamilyBlockedIP)
		c.Disposition = DispositionExplicitExclusion
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
		return c, true
	}
	if methods, ok := nestedAppOperations[segment]; ok && contains(methods, operation.Method) {
		c := baseClassification(operation, FamilyNestedAppGetPut)
		if segment == "authentication_proxy/settings" {
			c.Disposition = DispositionResourceRead
			if operation.Method == "PUT" {
				c.Disposition = DispositionResourceWrite
			}
			c.Mode = ModeCustom
			c.Coverage = CoveragePlanned
			c.Owner = "fortiappseccloud_waf_authentication_proxy"
			c.Provenance = provenanceCustomPlanned
		} else {
			c.Disposition = DispositionAction
			c.Mode = ModeNone
			c.Coverage = CoverageExcluded
			c.Provenance = provenanceExcluded
		}
		return c, true
	}
	if _, ok := appGetOnlySegments[segment]; ok && operation.Method == "GET" {
		c := baseClassification(operation, FamilyAppGetOnly)
		if _, detail := certificateDetailSegments[segment]; detail {
			c.Disposition = DispositionReadOnly
			c.Mode = ModeDataSource
			c.Coverage = CoveragePlanned
			c.Owner = "fortiappseccloud_waf_" + segment
			c.Provenance = provenanceDataSourcePlanned
		} else {
			c.Disposition = DispositionExplicitExclusion
			c.Mode = ModeNone
			c.Coverage = CoverageExcluded
			c.Provenance = provenanceExcluded
		}
		return c, true
	}
	if _, ok := appPutOnlySegments[segment]; ok && operation.Method == "PUT" {
		c := baseClassification(operation, FamilyAppPutOnly)
		c.Disposition = DispositionAction
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
		return c, true
	}
	if _, ok := appPostSegments[segment]; ok && operation.Method == "POST" {
		c := baseClassification(operation, FamilyAppPost)
		c.Disposition = DispositionAction
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
		return c, true
	}
	return OperationClassification{}, false
}

func classifySettingsOperation(operation Operation) (OperationClassification, bool) {
	methods, reviewed := settingsOperations[operation.Path]
	if !reviewed || !contains(methods, operation.Method) {
		return OperationClassification{}, false
	}
	c := baseClassification(operation, FamilySettings)
	c.Owner = settingsOwner(operation.Path)

	if operation.Path == "/waf/settings" {
		if operation.Method == "GET" {
			c.Disposition = DispositionSharedReference
			c.Mode = ModeSharedReference
			// The typed client read exists, but no served Framework resource or
			// data source consumes it yet. Client-only code is not local Terraform
			// implementation coverage.
			c.Coverage = CoveragePlanned
			c.Owner = "fortiappseccloud_waf_settings, fortiappseccloud_waf_regions"
			c.ClientMethod = "GetWAFSettings"
			c.Provenance = provenanceDataSourcePlanned
		} else {
			c.Disposition = DispositionResourceWrite
			c.Mode = ModeCustom
			c.Coverage = CoveragePlanned
			c.Provenance = provenanceCustomPlanned
		}
		return c, true
	}
	if operation.Path == "/waf/settings/socaas" {
		c.Disposition = DispositionReadOnly
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
		return c, true
	}
	if _, excluded := excludedSettingsPaths[operation.Path]; excluded {
		c.Disposition = DispositionAction
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
		return c, true
	}
	if operation.Method == "GET" {
		c.Disposition = DispositionReadOnly
		c.Mode = ModeCustom
		c.Coverage = CoveragePlanned
		c.Provenance = provenanceCustomPlanned
		return c, true
	}
	c.Disposition = DispositionResourceWrite
	c.Mode = ModeCustom
	c.Coverage = CoveragePlanned
	c.Provenance = provenanceCustomPlanned
	return c, true
}

func classifyMiscOperation(operation Operation) (OperationClassification, bool) {
	methods, reviewed := miscOperations[operation.Path]
	if !reviewed || !contains(methods, operation.Method) {
		return OperationClassification{}, false
	}
	c := baseClassification(operation, FamilyMisc)
	if operation.Path == "/waf/misc/backend-ip-test" || operation.Path == "/waf/misc/dns-lookup" {
		c.Disposition = DispositionSharedReference
		c.Mode = ModeSharedReference
		c.Coverage = CoverageLocallyImplemented
		c.Owner = "fortiappseccloud_waf_app"
		if operation.Path == "/waf/misc/backend-ip-test" {
			c.ClientMethod = "TestBackendConnectivity"
		} else {
			c.ClientMethod = "DNSLookup"
		}
		c.Provenance = provenanceSharedReference
	} else {
		c.Disposition = DispositionExplicitExclusion
		c.Mode = ModeNone
		c.Coverage = CoverageExcluded
		c.Provenance = provenanceExcluded
	}
	return c, true
}

func appModuleMode(module, method string) (ImplementationMode, CoverageStatus) {
	switch {
	case module == "api_protection" || module == "servers" || module == "endpoint":
		return ModeCustom, CoverageLiveVerified
	case has(frameworkCustomLiveVerifiedAppModules, module):
		return ModeCustom, CoverageLiveVerified
	case has(handWrittenAppModules, module):
		return ModeHandWritten, CoverageLiveVerified
	case has(liveVerifiedGeneratedAppModules, module):
		return ModeGenerated, CoverageLiveVerified
	case has(generatedAppModules, module):
		return ModeGenerated, CoverageLocallyImplemented
	case has(selectedNextAppModules, module):
		return ModeGenerated, CoverageSelectedNext
	case has(generatedPlannedAppModules, module):
		return ModeGenerated, CoveragePlanned
	default:
		return ModeCustom, CoveragePlanned
	}
}

func appModuleOwner(module string) string {
	switch module {
	case "api_protection":
		return "fortiappseccloud_waf_openapi_validation"
	case "endpoint":
		return "fortiappseccloud_waf_app"
	case "servers":
		return "fortiappseccloud_waf_origin_servers"
	case "routings":
		return "fortiappseccloud_waf_content_routing"
	default:
		return "fortiappseccloud_waf_" + module
	}
}

func appModuleClientMethod(module, method string) string {
	switch module {
	case "account_takeover":
		if method == "GET" {
			return "GetAccountTakeover"
		}
		return "PutAccountTakeover"
	case "csrf_protection", "url_access", "request_limits", "known_attacks", "http_header_security", "graphql_protection", "json_protection", "parameter_validation", "web_socket_security", "information_leakage", "ddos_prevention", "cookie_security", "known_bots", "bot_deception", "biometrics_based_detection", "waiting_room", "mitb_protection", "threshold_detection", "ml_bot_detection", "file_protection", "mobile_api_protection", "xml_protection_policy", "rewriting_requests", "api_gateway", "caching_compression":
		if method == "GET" {
			return "GetWAFModule"
		}
		return "PutWAFModule"
	case "api_protection":
		if method == "GET" {
			return "GetOpenAPIValidation"
		}
		return "PutOpenAPIValidation"
	case "endpoint":
		if method == "GET" {
			return "GetApplicationEndpoint"
		}
		return "PutApplicationEndpoint"
	case "servers":
		if method == "GET" {
			return "GetOriginServers"
		}
		return "PutOriginServers"
	case "global_trust_list_parameter":
		if method == "GET" {
			return "GetGlobalTrustList"
		}
		return "PutGlobalTrustList"
	case "anomaly_detection":
		if method == "GET" {
			return "GetAnomalyDetection"
		}
		return "PutAnomalyDetection"
	case "cors_protection":
		if method == "GET" {
			return "GetCorsProtection"
		}
		return "PutCorsProtection"
	case "ip_protection":
		if method == "GET" {
			return "GetIPProtection"
		}
		return "PutIPProtection"
	case "routings":
		if method == "GET" {
			return "GetContentRouting"
		}
		return "PutContentRouting"
	case "custom_rule":
		if method == "GET" {
			return "GetCustomRule"
		}
		return "PutCustomRule"
	case "ml_api_protection":
		if method == "GET" {
			return "GetMlApiProtection"
		}
		return "PutMlApiProtection"
	default:
		return ""
	}
}

func appModuleProvenance(module, method string) string {
	mode, coverage := appModuleMode(module, method)
	if coverage == CoverageLiveVerified {
		switch mode {
		case ModeGenerated:
			return provenanceGeneratedLive
		case ModeHandWritten:
			return provenanceHandWrittenLive
		default:
			return provenanceFrameworkLive
		}
	}
	switch {
	case mode == ModeGenerated && coverage == CoverageLocallyImplemented:
		return provenanceGeneratedLocal
	case mode == ModeCustom && coverage == CoverageLocallyImplemented:
		return provenanceFrameworkLocal
	case has(generatedPlannedAppModules, module):
		return provenanceGeneratedPlanned
	case has(designCustomAppModules, module):
		return provenanceDesignCustom
	default:
		return provenanceSchemaCustom
	}
}

func settingsOwner(path string) string {
	switch {
	case strings.HasPrefix(path, "/waf/settings/cbp/images"):
		return "fortiappseccloud_waf_cbp_images"
	case strings.HasPrefix(path, "/waf/settings/cbp/messages"):
		return "fortiappseccloud_waf_cbp_messages"
	case strings.HasPrefix(path, "/waf/settings/connectors"):
		return "fortiappseccloud_waf_connectors"
	case strings.HasPrefix(path, "/waf/settings/fabric"):
		return "fortiappseccloud_waf_fabric"
	case path == "/waf/settings/socaas":
		return "fortiappseccloud_waf_socaas"
	case strings.HasPrefix(path, "/waf/settings/wrp/pages"):
		return "fortiappseccloud_waf_wrp_pages"
	default:
		return "fortiappseccloud_waf_settings"
	}
}

func mergeStringSets(sources ...map[string]struct{}) map[string]struct{} {
	capacity := 0
	for _, source := range sources {
		capacity += len(source)
	}
	result := make(map[string]struct{}, capacity)
	for _, source := range sources {
		for value := range source {
			result[value] = struct{}{}
		}
	}
	return result
}

func baseClassification(operation Operation, family EndpointFamily) OperationClassification {
	return OperationClassification{Method: operation.Method, Path: operation.Path, Family: family}
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func has(values map[string]struct{}, value string) bool {
	_, ok := values[value]
	return ok
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func operationKey(method, path string) string {
	return method + " " + path
}

func differenceKeys(left, right map[string]struct{}) []string {
	result := make([]string, 0)
	for key := range left {
		if _, ok := right[key]; !ok {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}
