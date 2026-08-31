package contract

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestClassifyPublicWAFCoverage(t *testing.T) {
	t.Parallel()

	document := loadPinnedWAFDocument(t)
	publicCount, nonPublicCount := 0, 0
	for _, operation := range document.Operations {
		if operation.Public {
			publicCount++
		} else {
			nonPublicCount++
		}
	}
	if len(document.Operations) != 262 || publicCount != 256 || nonPublicCount != 6 {
		t.Fatalf("operation counts = total:%d public:%d non-public:%d", len(document.Operations), publicCount, nonPublicCount)
	}

	classifications, err := ClassifyPublicWAF(document)
	if err != nil {
		t.Fatalf("ClassifyPublicWAF() error = %v", err)
	}
	if len(classifications) != publicCount {
		t.Fatalf("classification count = %d, want %d", len(classifications), publicCount)
	}

	byKey := make(map[string]OperationClassification, len(classifications))
	for index, classification := range classifications {
		key := operationKey(classification.Method, classification.Path)
		if _, duplicate := byKey[key]; duplicate {
			t.Fatalf("duplicate classification %s", key)
		}
		byKey[key] = classification
		if classification.Family == "" || classification.Disposition == "" || classification.Mode == "" ||
			classification.Coverage == "" || strings.TrimSpace(classification.Provenance) == "" {
			t.Errorf("classification %s has incomplete policy metadata: %#v", key, classification)
		}
		if IsImplementedCoverage(classification.Coverage) &&
			(classification.Owner == "" || classification.ClientMethod == "") {
			t.Errorf("implemented classification %s lacks owner/client metadata", key)
		}
		if index > 0 {
			previous := classifications[index-1]
			if previous.Path > classification.Path ||
				(previous.Path == classification.Path && previous.Method >= classification.Method) {
				t.Errorf("classification order is not deterministic at %s", key)
			}
		}
	}

	for _, operation := range document.Operations {
		key := operationKey(operation.Method, operation.Path)
		_, classified := byKey[key]
		if operation.Public != classified {
			t.Errorf("classification coverage for %s = %t, public = %t", key, classified, operation.Public)
		}
	}
}

func TestClassifyPublicWAFFamilyCounts(t *testing.T) {
	t.Parallel()

	classifications, err := ClassifyPublicWAF(loadPinnedWAFDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[EndpointFamily]int{
		FamilyAppModule:       90,
		FamilyTemplateModule:  66,
		FamilyCoreCRUD:        11,
		FamilyAppGetOnly:      29,
		FamilyAppPutOnly:      9,
		FamilyNestedAppGetPut: 4,
		FamilyAppPost:         4,
		FamilyBlockedIP:       2,
		FamilyMisc:            4,
		FamilySettings:        34,
		FamilyTemplateExport:  3,
	}
	got := make(map[EndpointFamily]int)
	for _, classification := range classifications {
		got[classification.Family]++
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("family counts = %#v, want %#v", got, want)
	}
}

func TestClassifyPublicWAFCoverageCounts(t *testing.T) {
	t.Parallel()

	classifications, err := ClassifyPublicWAF(loadPinnedWAFDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[CoverageStatus]int{
		CoverageLiveVerified:       141,
		CoverageLocallyImplemented: 6,
		CoveragePlanned:            35,
		CoverageDeferred:           4,
		CoverageExcluded:           70,
	}
	got := make(map[CoverageStatus]int)
	for _, classification := range classifications {
		got[classification.Coverage]++
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("coverage counts = %#v, want %#v", got, want)
	}
}

func TestClassifyPublicWAFAppModulePartition(t *testing.T) {
	t.Parallel()

	wantGeneratedPlanned := []string{}
	wantCustom := []string{
		"anomaly_detection", "ca_certificate", "cors_protection", "crl_certificate",
		"custom_rule", "endpoint", "global_trust_list_parameter",
		"inter_certificate", "ip_protection",
		"log_settings", "ml_api_protection", "modules", "routings", "server_ca",
		"server_crl", "servers", "signature_exception", "sni_certificate",
	}
	if got := sortedKeys(generatedPlannedAppModules); !reflect.DeepEqual(got, wantGeneratedPlanned) {
		t.Fatalf("generated planned modules = %#v, want %#v", got, wantGeneratedPlanned)
	}
	custom := unionSets(designCustomAppModules, schemaCustomAppModules)
	if got := sortedKeys(custom); !reflect.DeepEqual(got, wantCustom) {
		t.Fatalf("custom modules = %#v, want %#v", got, wantCustom)
	}
	for module := range generatedAppModules {
		if has(custom, module) {
			t.Errorf("app module %q is classified as both generated and custom", module)
		}
		if !has(liveVerifiedGeneratedAppModules, module) {
			t.Errorf("generated app module %q lacks recorded live evidence", module)
		}
	}
	for module := range liveVerifiedGeneratedAppModules {
		if !has(generatedAppModules, module) {
			t.Errorf("live-verified app module %q is not generated", module)
		}
	}

	all := unionSets(handWrittenAppModules, generatedAppModules, frameworkCustomImplementedAppModules,
		selectedNextAppModules, generatedPlannedAppModules, custom)
	if len(all) != 45 || len(handWrittenAppModules) != 1 || len(generatedAppModules) != 25 ||
		len(frameworkCustomImplementedAppModules) != 1 || len(selectedNextAppModules) != 0 ||
		len(generatedPlannedAppModules) != 0 || len(custom) != 18 {
		t.Fatalf("app module set sizes = all:%d handwritten:%d generated:%d framework-custom:%d selected:%d planned:%d custom:%d",
			len(all), len(handWrittenAppModules), len(generatedAppModules), len(frameworkCustomImplementedAppModules),
			len(selectedNextAppModules), len(generatedPlannedAppModules), len(custom))
	}

	classifications, err := ClassifyPublicWAF(loadPinnedWAFDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	methodsByModule := make(map[string][]string)
	for _, classification := range classifications {
		if classification.Family != FamilyAppModule {
			continue
		}
		module := strings.TrimPrefix(classification.Path, "/waf/apps/{ep_id}/")
		methodsByModule[module] = append(methodsByModule[module], classification.Method)
		switch module {
		case "account_takeover":
			if classification.Mode != ModeHandWritten || classification.Coverage != CoverageLiveVerified {
				t.Errorf("account takeover classification = %#v", classification)
			}
		case "csrf_protection":
			if classification.Mode != ModeGenerated || classification.Coverage != CoverageLiveVerified {
				t.Errorf("CSRF classification = %#v", classification)
			}
		case "url_access":
			if classification.Mode != ModeGenerated || classification.Coverage != CoverageLiveVerified ||
				classification.ClientMethod != map[string]string{"GET": "GetWAFModule", "PUT": "PutWAFModule"}[classification.Method] {
				t.Errorf("URL access classification = %#v", classification)
			}
		case "api_protection":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_openapi_validation" {
				t.Errorf("API protection classification = %#v", classification)
			}
		case "global_trust_list_parameter":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_global_trust_list_parameter" ||
				classification.ClientMethod != map[string]string{"GET": "GetGlobalTrustList", "PUT": "PutGlobalTrustList"}[classification.Method] {
				t.Errorf("global trust list parameter classification = %#v", classification)
			}
		case "anomaly_detection":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_anomaly_detection" ||
				classification.ClientMethod != map[string]string{"GET": "GetAnomalyDetection", "PUT": "PutAnomalyDetection"}[classification.Method] {
				t.Errorf("anomaly detection classification = %#v", classification)
			}
		case "cors_protection":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_cors_protection" ||
				classification.ClientMethod != map[string]string{"GET": "GetCorsProtection", "PUT": "PutCorsProtection"}[classification.Method] {
				t.Errorf("cors protection classification = %#v", classification)
			}
		case "ip_protection":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_ip_protection" ||
				classification.ClientMethod != map[string]string{"GET": "GetIPProtection", "PUT": "PutIPProtection"}[classification.Method] {
				t.Errorf("ip protection classification = %#v", classification)
			}
		case "routings":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_content_routing" ||
				classification.ClientMethod != map[string]string{"GET": "GetContentRouting", "PUT": "PutContentRouting"}[classification.Method] {
				t.Errorf("routings classification = %#v", classification)
			}
		case "custom_rule":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_custom_rule" ||
				classification.ClientMethod != map[string]string{"GET": "GetCustomRule", "PUT": "PutCustomRule"}[classification.Method] {
				t.Errorf("custom rule classification = %#v", classification)
			}
		case "ml_api_protection":
			if classification.Mode != ModeCustom || classification.Coverage != CoverageLiveVerified ||
				classification.Owner != "fortiappseccloud_waf_ml_api_protection" ||
				classification.ClientMethod != map[string]string{"GET": "GetMlApiProtection", "PUT": "PutMlApiProtection"}[classification.Method] {
				t.Errorf("ml api protection classification = %#v", classification)
			}
		case "log_settings", "inter_certificate", "sni_certificate",
			"server_ca", "server_crl", "ca_certificate", "crl_certificate":
			if classification.Disposition != DispositionExplicitExclusion ||
				classification.Mode != ModeNone ||
				classification.Coverage != CoverageExcluded ||
				classification.Owner != appModuleOwner(module) ||
				classification.ClientMethod != "" {
				t.Errorf("unsupported custom module %s classification = %#v", module, classification)
			}
		case "signature_exception":
			// Slice 8 decision: PUT is an imperative exclusion (GET cannot
			// reconstruct the rules PUT accepts); GET is a narrow served
			// data-source view of the optional template ID.
			if classification.Owner != "fortiappseccloud_waf_signature_exception" {
				t.Errorf("signature_exception classification = %#v", classification)
			}
			if classification.Method == "PUT" {
				if classification.Disposition != DispositionExplicitExclusion || classification.Mode != ModeNone ||
					classification.Coverage != CoverageExcluded || classification.ClientMethod != "" {
					t.Errorf("signature_exception PUT = %#v, want explicit exclusion", classification)
				}
			} else {
				if classification.Disposition != DispositionDataSource || classification.Mode != ModeDataSource ||
					classification.Coverage != CoverageLocallyImplemented ||
					classification.ClientMethod != "GetSignatureException" {
					t.Errorf("signature_exception GET = %#v, want locally implemented data source", classification)
				}
			}
		case "modules":
			// Slice 10 decision: PUT is an explicit exclusion (overlapping
			// bulk status ownership); GET is a served data-source status view.
			if classification.Owner != "fortiappseccloud_waf_modules" {
				t.Errorf("modules classification = %#v", classification)
			}
			if classification.Method == "PUT" {
				if classification.Disposition != DispositionExplicitExclusion || classification.Mode != ModeNone ||
					classification.Coverage != CoverageExcluded || classification.ClientMethod != "" {
					t.Errorf("modules PUT = %#v, want explicit exclusion", classification)
				}
			} else {
				if classification.Disposition != DispositionDataSource || classification.Mode != ModeDataSource ||
					classification.Coverage != CoverageLocallyImplemented ||
					classification.ClientMethod != "GetApplicationModules" {
					t.Errorf("modules GET = %#v, want locally implemented data source", classification)
				}
			}
		default:
			if has(liveVerifiedGeneratedAppModules, module) && classification.Coverage != CoverageLiveVerified {
				t.Errorf("live-verified generated module %s coverage = %q", module, classification.Coverage)
			}
			if has(generatedAppModules, module) && !has(liveVerifiedGeneratedAppModules, module) &&
				classification.Coverage != CoverageLocallyImplemented {
				t.Errorf("locally implemented generated module %s coverage = %q", module, classification.Coverage)
			}
			if has(generatedPlannedAppModules, module) && classification.Coverage != CoveragePlanned {
				t.Errorf("planned generated module %s coverage = %q", module, classification.Coverage)
			}
		}
	}
	if len(methodsByModule) != 45 {
		t.Fatalf("classified app modules = %d, want 45", len(methodsByModule))
	}
	for module, methods := range methodsByModule {
		sort.Strings(methods)
		if !reflect.DeepEqual(methods, []string{"GET", "PUT"}) {
			t.Errorf("module %s methods = %#v", module, methods)
		}
	}
}

func TestClassifyPublicWAFReviewedPolicy(t *testing.T) {
	t.Parallel()

	classifications, err := ClassifyPublicWAF(loadPinnedWAFDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	byKey := make(map[string]OperationClassification, len(classifications))
	for _, classification := range classifications {
		byKey[operationKey(classification.Method, classification.Path)] = classification
	}

	for _, scope := range [][]Classification{InitialScope, AccountTakeoverScope, CSRFProtectionScope, URLAccessScope} {
		for _, expected := range scope {
			key := operationKey(expected.Method, expected.Path)
			actual, ok := byKey[key]
			if !ok {
				t.Errorf("focused scope operation %s is absent", key)
				continue
			}
			if actual.Disposition != expected.Disposition || actual.Owner != expected.Owner ||
				actual.ClientMethod != expected.ClientMethod {
				t.Errorf("focused scope mismatch for %s: %#v / %#v", key, actual, expected)
			}
		}
	}

	selected := make([]OperationClassification, 0)
	for _, classification := range classifications {
		if classification.Coverage == CoverageSelectedNext {
			selected = append(selected, classification)
		}
	}
	if len(selected) != 0 {
		t.Fatalf("selected-next classifications = %#v, want none", selected)
	}

	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}/ca_cert_detail", DispositionReadOnly, ModeDataSource, CoveragePlanned)
	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}/dashboard", DispositionExplicitExclusion, ModeNone, CoverageExcluded)
	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}/authentication_proxy/settings", DispositionResourceRead, ModeCustom, CoveragePlanned)
	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}/vs/{action}", DispositionAction, ModeNone, CoverageExcluded)
	assertClassification(t, byKey, "GET", "/waf/settings", DispositionSharedReference, ModeSharedReference, CoveragePlanned)
	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}", DispositionResourceRead, ModeCustom, CoverageLocallyImplemented)
	assertClassification(t, byKey, "PUT", "/waf/apps/{ep_id}", DispositionResourceWrite, ModeCustom, CoverageLocallyImplemented)
	assertClassification(t, byKey, "POST", "/waf/apps", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "DELETE", "/waf/apps/{ep_id}", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "PUT", "/waf/apps/{ep_id}/block", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}/endpoint", DispositionResourceRead, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "PUT", "/waf/apps/{ep_id}/endpoint", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}/servers", DispositionResourceRead, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "PUT", "/waf/apps/{ep_id}/servers", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "GET", "/waf/apps/{ep_id}/api_protection", DispositionResourceRead, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "PUT", "/waf/apps/{ep_id}/api_protection", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "POST", "/waf/template", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "GET", "/waf/template/{template_id}", DispositionResourceRead, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "PUT", "/waf/template/{template_id}", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "DELETE", "/waf/template/{template_id}", DispositionResourceWrite, ModeCustom, CoverageLiveVerified)
	assertClassification(t, byKey, "GET", "/waf/template/{template_id}/known_attacks", DispositionResourceRead, ModeGenerated, CoverageLiveVerified)
	assertClassification(t, byKey, "PUT", "/waf/template/{template_id}/known_attacks", DispositionResourceWrite, ModeGenerated, CoverageLiveVerified)
	assertClassification(t, byKey, "PUT", "/waf/settings", DispositionResourceWrite, ModeCustom, CoveragePlanned)
	assertClassification(t, byKey, "GET", "/waf/settings/cbp/messages", DispositionReadOnly, ModeCustom, CoveragePlanned)
	assertClassification(t, byKey, "PUT", "/waf/settings/connectors/public_ip_test", DispositionAction, ModeNone, CoverageExcluded)
	assertClassification(t, byKey, "POST", "/waf/apps/{ep_id}/authentication_proxy/settings/download_sp_metadata", DispositionAction, ModeNone, CoverageExcluded)
	assertClassification(t, byKey, "GET", "/waf/settings/idps", DispositionAction, ModeNone, CoverageExcluded)
	assertClassification(t, byKey, "PUT", "/waf/settings/idps/{idp_name}", DispositionAction, ModeNone, CoverageExcluded)
	assertClassification(t, byKey, "GET", "/waf/settings/socaas", DispositionReadOnly, ModeNone, CoverageExcluded)
	assertClassification(t, byKey, "GET", "/waf/template/{template_id}/url_access", DispositionResourceRead, ModeGenerated, CoverageLiveVerified)
}

func TestClassifyPublicWAFRejectsContractDrift(t *testing.T) {
	t.Parallel()

	document := loadPinnedWAFDocument(t)
	document.Operations = append(document.Operations, Operation{
		Method: "GET", Path: "/waf/new-public-operation", Public: true,
	})
	if _, err := ClassifyPublicWAF(document); err == nil || !strings.Contains(err.Error(), "unclassified") {
		t.Fatalf("new public operation error = %v", err)
	}

	document = loadPinnedWAFDocument(t)
	for index, operation := range document.Operations {
		if operation.Method == "GET" && operation.Path == URLAccessCandidate.Path {
			document.Operations = append(document.Operations[:index], document.Operations[index+1:]...)
			break
		}
	}
	if _, err := ClassifyPublicWAF(document); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("missing reviewed operation error = %v", err)
	}
}

func TestClassifyPublicWAFNonPublicOperations(t *testing.T) {
	t.Parallel()

	want := []string{
		"DELETE /waf/apps/diagnostics/{ep_id}/reports/{report_id}",
		"GET /waf/apps/diagnostics/{ep_id}/reports",
		"GET /waf/apps/diagnostics/{ep_id}/reports/{report_id}",
		"GET /waf/misc/check-ip-region",
		"POST /waf/apps/diagnostics/{ep_id}/reports",
		"POST /waf/misc/check-ip-region",
	}
	var got []string
	for _, operation := range loadPinnedWAFDocument(t).Operations {
		if !operation.Public {
			got = append(got, operationKey(operation.Method, operation.Path))
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("non-public operations = %#v, want %#v", got, want)
	}
}

func assertClassification(
	t *testing.T,
	byKey map[string]OperationClassification,
	method, path string,
	disposition Disposition,
	mode ImplementationMode,
	coverage CoverageStatus,
) {
	t.Helper()
	classification, ok := byKey[operationKey(method, path)]
	if !ok {
		t.Fatalf("classification is absent: %s %s", method, path)
	}
	if classification.Disposition != disposition || classification.Mode != mode || classification.Coverage != coverage {
		t.Errorf("classification %s %s = %#v", method, path, classification)
	}
}

func loadPinnedWAFDocument(t *testing.T) Document {
	t.Helper()
	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func unionSets(sets ...map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{})
	for _, set := range sets {
		for value := range set {
			result[value] = struct{}{}
		}
	}
	return result
}
