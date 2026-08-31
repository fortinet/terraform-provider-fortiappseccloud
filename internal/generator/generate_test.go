package generator

import (
	"bytes"
	"encoding/json"
	"go/format"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"terraform-provider-fortiappseccloud/internal/contract"
	profile "terraform-provider-fortiappseccloud/internal/generator/profile/waf"
)

func TestGenerateIsDeterministic(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	first, err := Generate(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("Generate(first) error = %v", err)
	}
	second, err := Generate(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("Generate(second) error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Generate() returned different bytes for identical inputs")
	}

	paths := OutputPaths(first)
	wantPaths := []string{
		manifestOutputPath,
		registerOutputPath,
		resourceOutputPath("waf_api_gateway"),
		resourceOutputPath("waf_biometrics_based_detection"),
		resourceOutputPath("waf_bot_deception"),
		resourceOutputPath("waf_caching_compression"),
		resourceOutputPath("waf_cookie_security"),
		resourceOutputPath("waf_csrf_protection"),
		resourceOutputPath("waf_ddos_prevention"),
		resourceOutputPath("waf_file_protection"),
		resourceOutputPath("waf_graphql_protection"),
		resourceOutputPath("waf_http_header_security"),
		resourceOutputPath("waf_information_leakage"),
		resourceOutputPath("waf_json_protection"),
		resourceOutputPath("waf_known_attacks"),
		resourceOutputPath("waf_known_bots"),
		resourceOutputPath("waf_mitb_protection"),
		resourceOutputPath("waf_ml_bot_detection"),
		resourceOutputPath("waf_mobile_api_protection"),
		resourceOutputPath("waf_parameter_validation"),
		resourceOutputPath("waf_request_limits"),
		resourceOutputPath("waf_rewriting_requests"),
		resourceOutputPath("waf_threshold_detection"),
		resourceOutputPath("waf_url_access"),
		resourceOutputPath("waf_waiting_room"),
		resourceOutputPath("waf_web_socket_security"),
		resourceOutputPath("waf_xml_protection_policy"),
		docsOutputPath("waf_api_gateway"),
		docsOutputPath("waf_biometrics_based_detection"),
		docsOutputPath("waf_bot_deception"),
		docsOutputPath("waf_caching_compression"),
		docsOutputPath("waf_cookie_security"),
		docsOutputPath("waf_csrf_protection"),
		docsOutputPath("waf_ddos_prevention"),
		docsOutputPath("waf_file_protection"),
		docsOutputPath("waf_graphql_protection"),
		docsOutputPath("waf_http_header_security"),
		docsOutputPath("waf_information_leakage"),
		docsOutputPath("waf_json_protection"),
		docsOutputPath("waf_known_attacks"),
		docsOutputPath("waf_known_bots"),
		docsOutputPath("waf_mitb_protection"),
		docsOutputPath("waf_ml_bot_detection"),
		docsOutputPath("waf_mobile_api_protection"),
		docsOutputPath("waf_parameter_validation"),
		docsOutputPath("waf_request_limits"),
		docsOutputPath("waf_rewriting_requests"),
		docsOutputPath("waf_threshold_detection"),
		docsOutputPath("waf_url_access"),
		docsOutputPath("waf_waiting_room"),
		docsOutputPath("waf_web_socket_security"),
		docsOutputPath("waf_xml_protection_policy"),
		templateDocsOutputPath("waf_api_gateway"),
		templateDocsOutputPath("waf_biometrics_based_detection"),
		templateDocsOutputPath("waf_bot_deception"),
		templateDocsOutputPath("waf_caching_compression"),
		templateDocsOutputPath("waf_cookie_security"),
		templateDocsOutputPath("waf_csrf_protection"),
		templateDocsOutputPath("waf_ddos_prevention"),
		templateDocsOutputPath("waf_file_protection"),
		templateDocsOutputPath("waf_graphql_protection"),
		templateDocsOutputPath("waf_http_header_security"),
		templateDocsOutputPath("waf_information_leakage"),
		templateDocsOutputPath("waf_json_protection"),
		templateDocsOutputPath("waf_known_attacks"),
		templateDocsOutputPath("waf_known_bots"),
		templateDocsOutputPath("waf_mitb_protection"),
		templateDocsOutputPath("waf_ml_bot_detection"),
		templateDocsOutputPath("waf_mobile_api_protection"),
		templateDocsOutputPath("waf_parameter_validation"),
		templateDocsOutputPath("waf_request_limits"),
		templateDocsOutputPath("waf_rewriting_requests"),
		templateDocsOutputPath("waf_threshold_detection"),
		templateDocsOutputPath("waf_url_access"),
		templateDocsOutputPath("waf_waiting_room"),
		templateDocsOutputPath("waf_web_socket_security"),
		templateDocsOutputPath("waf_xml_protection_policy"),
	}
	sort.Strings(wantPaths)
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("OutputPaths() = %#v, want %#v", paths, wantPaths)
	}
	wantCount := 2 + 3*numResourcesFromManifest(t, first[manifestOutputPath])
	if len(paths) != wantCount {
		t.Fatalf("OutputPaths() count = %d, want %d", len(paths), wantCount)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, ".go") {
			if !bytes.HasPrefix(first[path], []byte("// "+generatedMarker+"\n")) {
				t.Fatalf("generated %s is missing its generated header", path)
			}
			formatted, err := format.Source(first[path])
			if err != nil {
				t.Fatalf("format generated %s: %v", path, err)
			}
			if !bytes.Equal(formatted, first[path]) {
				t.Fatalf("generated %s is not gofmt-clean", path)
			}
		}
		text := string(first[path])
		if strings.HasSuffix(path, ".markdown") {
			// The generated marker is an HTML comment. It must be present, but
			// it must NOT be the first line: a leading marker would push the YAML
			// frontmatter's opening "---" off line 1, so the Terraform Registry
			// would fail to parse the frontmatter and drop the subcategory.
			if !strings.HasPrefix(text, "---\n") {
				t.Fatalf("generated %s must start with YAML frontmatter \"---\", got: %q", path, strings.SplitN(text, "\n", 2)[0])
			}
			if !strings.Contains(text, "<!-- "+generatedMarker+" -->") {
				t.Fatalf("generated %s is missing its generated marker", path)
			}
			for _, internalText := range []string{"dev1", "live lifecycle", "live-verified", "Promotion is backed", "Reviewed evidence:"} {
				if strings.Contains(text, internalText) {
					t.Fatalf("generated public documentation %s contains internal verification text %q", path, internalText)
				}
			}
		}
		for _, forbidden := range []string{"/home/", "2026-", "time.Now(", "ListNestedAttribute"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("generated %s contains forbidden nondeterministic or protocol-6 text %q", path, forbidden)
			}
		}
	}
}

// OpenAPI 26.3.a expresses waiting-room conditional bounds natively, so no
// resource should retain a 26.2 backend numeric overlay.
func TestGenerateHasNoObsoleteBackendConfigScalarConstraints(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var overrides profile.Overrides
	if err := json.Unmarshal(profile.DefaultOverridesJSON, &overrides); err != nil {
		t.Fatalf("decode overrides: %v", err)
	}
	for _, resource := range overrides.Resources {
		if len(resource.BackendConfigScalarConstraints) != 0 {
			t.Fatalf("%s retains backend config scalar constraints", resource.TerraformName)
		}
	}
	if _, err := Generate(openAPI, profile.DefaultOverridesJSON); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
}

func numResourcesFromManifest(t *testing.T, manifestBytes []byte) int {
	t.Helper()
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode generated manifest: %v", err)
	}
	return len(manifest.Resources)
}

func TestGenerateMatchesCommittedOutputs(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := Generate(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range OutputPaths(outputs) {
		committed, err := os.ReadFile(filepath.Join("../..", filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read committed %s: %v", path, err)
		}
		if !bytes.Equal(outputs[path], committed) {
			t.Fatalf("generated %s differs from the committed output; run go generate ./...", path)
		}
	}
}

func TestGeneratedManifestProvenanceAndVerticalSlice(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := Generate(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(outputs[manifestOutputPath], &manifest); err != nil {
		t.Fatalf("decode generated manifest: %v", err)
	}
	if manifest.Generated != generatedMarker || manifest.OpenAPI.Version != "26.3.a" || manifest.OpenAPI.SHA256 != "463015364e7d4d7cbd8f346a2e238928d1c7c741271656fec06bd8ed87e58e63" {
		t.Fatalf("manifest source/header = %#v / %q", manifest.OpenAPI, manifest.Generated)
	}
	if !manifest.Scope.FullWAFClassification || manifest.Scope.Classification != "complete_public_waf_operation_matrix" ||
		manifest.Scope.PublicOperationCount != 256 || manifest.Scope.NonPublicOperationCount != 6 ||
		len(manifest.Scope.Operations) != 256 {
		t.Fatalf("manifest scope = %#v", manifest.Scope)
	}
	if manifest.Scope.SelectedResourceCount != 25 || len(manifest.Resources) != 25 {
		t.Fatalf("selected resource count = %d, resources = %d", manifest.Scope.SelectedResourceCount, len(manifest.Resources))
	}
	if manifest.Scope.NextGeneratedResource != nil {
		t.Fatalf("next generated resource should be nil after generalization, got %#v", manifest.Scope.NextGeneratedResource)
	}
	seenResources := make(map[string]struct{}, len(manifest.Resources))
	disableCandidates := 0
	activeDisables := 0
	for _, resource := range manifest.Resources {
		seenResources[resource.TerraformName] = struct{}{}
		if resource.Disposition != "generated" {
			t.Fatalf("manifest resource %q disposition = %q", resource.TerraformName, resource.Disposition)
		}
		if strings.TrimSpace(resource.Reviewed.Provenance) == "" || strings.TrimSpace(resource.Reviewed.Destroy.Provenance) == "" {
			t.Fatalf("manifest resource %q omitted provenance", resource.TerraformName)
		}
		if resource.Reviewed.Destroy.Field == "status" {
			disableCandidates++
		}
		if resource.Reviewed.Destroy.Mode == "disable" {
			activeDisables++
		}
		for _, field := range resource.Reviewed.Fields {
			if strings.TrimSpace(field.Provenance) == "" {
				t.Fatalf("field %q omitted provenance", field.Path)
			}
		}
		for _, collection := range resource.Reviewed.Collections {
			if strings.TrimSpace(collection.Provenance) == "" {
				t.Fatalf("collection %q omitted provenance", collection.Path)
			}
		}
		switch resource.TerraformName {
		case contract.CSRFProtectionResource.TerraformName:
			if !strings.Contains(resource.Reviewed.Provenance, "Live GET and Terraform apply/import/restore probes verified") {
				t.Fatalf("CSRF provenance omitted verified live facts: %q", resource.Reviewed.Provenance)
			}
		case contract.URLAccessCandidate.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("URL access provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.RequestLimitsResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("request limits provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.ScalarStringArrays) != 1 {
				t.Fatalf("request limits scalar string arrays = %d, want 1", len(resource.Reviewed.ScalarStringArrays))
			}
		case contract.KnownAttacksResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("known attacks provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.HttpHeaderSecurityResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("HTTP header security provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.GraphQLProtectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("GraphQL protection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.JsonProtectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("JSON protection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.ParameterValidationResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("parameter validation provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.WebSocketSecurityResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("WebSocket security provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.InformationLeakageResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("parameter validation provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
		case contract.DDoSPreventionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("DDoS prevention provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.ScalarStringArrays) != 1 {
				t.Fatalf("DDoS prevention scalar string arrays = %d, want 1", len(resource.Reviewed.ScalarStringArrays))
			}
			if len(resource.Reviewed.Collections) != 0 {
				t.Fatalf("DDoS prevention collections = %d, want 0", len(resource.Reviewed.Collections))
			}
		case contract.CookieSecurityResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("cookie security provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 1 {
				t.Fatalf("cookie security collections = %d, want 1", len(resource.Reviewed.Collections))
			}
			if len(resource.Reviewed.ScalarStringArrays) != 0 {
				t.Fatalf("cookie security scalar string arrays = %d, want 0", len(resource.Reviewed.ScalarStringArrays))
			}
		case contract.KnownBotsResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("known bots provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 3 {
				t.Fatalf("known bots collections = %d, want 3", len(resource.Reviewed.Collections))
			}
			if len(resource.Reviewed.ItemStringArrays) != 2 {
				t.Fatalf("known bots item string arrays = %d, want 2", len(resource.Reviewed.ItemStringArrays))
			}
		case contract.BotDeceptionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("bot deception provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 2 {
				t.Fatalf("bot deception collections = %d, want 2", len(resource.Reviewed.Collections))
			}
		case contract.BiometricsBasedDetectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("biometrics based detection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 2 {
				t.Fatalf("biometrics based detection collections = %d, want 2", len(resource.Reviewed.Collections))
			}
		case contract.WaitingRoomResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("waiting room provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 1 {
				t.Fatalf("waiting room collections = %d, want 1", len(resource.Reviewed.Collections))
			}
		case contract.MITBProtectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("MITB protection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 2 {
				t.Fatalf("MITB protection collections = %d, want 2", len(resource.Reviewed.Collections))
			}
		case contract.ThresholdDetectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("threshold detection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 1 {
				t.Fatalf("threshold detection collections = %d, want 1", len(resource.Reviewed.Collections))
			}
		case contract.MLBotDetectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("ML bot detection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 3 {
				t.Fatalf("ML bot detection collections = %d, want 3", len(resource.Reviewed.Collections))
			}
		case contract.FileProtectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("file protection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 2 {
				t.Fatalf("file protection collections = %d, want 2", len(resource.Reviewed.Collections))
			}
		case contract.MobileAPIProtectionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("mobile API protection provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 1 {
				t.Fatalf("mobile API protection collections = %d, want 1", len(resource.Reviewed.Collections))
			}
		case contract.XMLProtectionPolicyResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("XML protection policy provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 1 {
				t.Fatalf("XML protection policy collections = %d, want 1", len(resource.Reviewed.Collections))
			}
		case contract.RewritingRequestsResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("rewriting requests provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 1 {
				t.Fatalf("rewriting requests collections = %d, want 1", len(resource.Reviewed.Collections))
			}
		case contract.APIGatewayResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("API gateway provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 2 {
				t.Fatalf("API gateway collections = %d, want 2", len(resource.Reviewed.Collections))
			}
		case contract.CachingCompressionResource.TerraformName:
			if strings.Contains(resource.Reviewed.Provenance, "Live GET") ||
				strings.Contains(resource.Reviewed.Provenance, "apply/import/restore probes verified") {
				t.Fatalf("caching compression provenance overclaims live verification: %q", resource.Reviewed.Provenance)
			}
			if len(resource.Reviewed.Collections) != 3 {
				t.Fatalf("caching compression collections = %d, want 3", len(resource.Reviewed.Collections))
			}
		default:
			t.Fatalf("unexpected generated resource %q", resource.TerraformName)
		}
	}
	if disableCandidates != 24 || activeDisables != 24 {
		t.Fatalf("generated destroy policies: candidates=%d active=%d, want 24/24", disableCandidates, activeDisables)
	}
	for _, name := range []string{contract.CSRFProtectionResource.TerraformName, contract.URLAccessCandidate.TerraformName, contract.RequestLimitsResource.TerraformName} {
		if _, ok := seenResources[name]; !ok {
			t.Fatalf("manifest resources = %#v, missing %q", seenResources, name)
		}
	}
	urlAccessOutput := string(outputs[resourceOutputPath("waf_url_access")])
	if !strings.Contains(urlAccessOutput, "func NewURLAccessResource") ||
		!strings.Contains(string(outputs[docsOutputPath("waf_url_access")]), contract.URLAccessCandidate.TerraformName) {
		t.Fatal("URL access generated resource or documentation is missing")
	}
	csrfOutput := string(outputs[resourceOutputPath("waf_csrf_protection")])
	if strings.Count(csrfOutput, "listvalidator.SizeAtMost(") != 1 ||
		!strings.Contains(csrfOutput, `ownershipWrapper("page_list", 256, false,`) ||
		!strings.Contains(csrfOutput, `ownershipWrapper("url_list", 256, false,`) {
		t.Fatal("generated ownership wrappers do not apply maxItems independently")
	}
	if !strings.Contains(csrfOutput, "csrfProtectionConfigActionValues") ||
		!strings.Contains(urlAccessOutput, "urlAccessRuleListActionValues") {
		t.Fatal("generated enum symbols are not scope-qualified")
	}
	urlAccessMethods := make([]string, 0, 2)
	for _, classification := range manifest.Scope.Operations {
		if classification.Coverage == contract.CoverageSelectedNext {
			t.Fatalf("public WAF matrix still contains selected-next operation %s %s", classification.Method, classification.Path)
		}
		if classification.Path == contract.URLAccessCandidate.Path {
			if classification.Mode != contract.ModeGenerated || classification.Coverage != contract.CoverageLiveVerified ||
				classification.Owner != contract.URLAccessCandidate.TerraformName {
				t.Fatalf("URL access classification = %#v", classification)
			}
			urlAccessMethods = append(urlAccessMethods, classification.Method)
		}
	}
	if !reflect.DeepEqual(urlAccessMethods, []string{"GET", "PUT"}) {
		t.Fatalf("URL access methods = %#v", urlAccessMethods)
	}
}

func TestGenerateRendersReviewedDestroyPromotion(t *testing.T) {
	t.Parallel()

	openAPI, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := Generate(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("Generate() rejected the reviewed promotions: %v", err)
	}
	resourceOutput := string(outputs["internal/resources/generated/waf/resource_csrf_protection.go"])
	if !strings.Contains(resourceOutput, "Mode:     wafmodule.DestroyDisable") ||
		!strings.Contains(resourceOutput, `Field:    "status"`) ||
		!strings.Contains(resourceOutput, "Verified: true") {
		t.Fatalf("promoted generated descriptor omitted disable policy:\n%s", resourceOutput)
	}
	appDocs := string(outputs["website/docs/r/waf_csrf_protection.html.markdown"])
	if !strings.Contains(appDocs, "fresh GET") || !strings.Contains(appDocs, "configs.status=false") {
		t.Fatalf("promoted app documentation omitted disable lifecycle:\n%s", appDocs)
	}
	templateDocs := string(outputs["website/docs/r/waf_template_csrf_protection.html.markdown"])
	if !strings.Contains(templateDocs, "fresh GET") || !strings.Contains(templateDocs, "configs.status=false") ||
		strings.Contains(templateDocs, "Destroy forgets") {
		t.Fatalf("promoted template documentation omitted disable lifecycle:\n%s", templateDocs)
	}
	cachingOutput := string(outputs["internal/resources/generated/waf/resource_caching_compression.go"])
	for _, coupled := range []string{`CoupledFields: []string{`, `"cache.status"`, `"compress.status"`} {
		if !strings.Contains(cachingOutput, coupled) {
			t.Fatalf("caching/compression generated descriptor omitted %q", coupled)
		}
	}
	cachingAppDocs := string(outputs["website/docs/r/waf_caching_compression.html.markdown"])
	wantCachingAppDestroy := "Destroy forgets this app-scoped resource without sending a disabling PUT. The remote application caching and compression configuration remains unchanged and Terraform emits a warning. This behavior does not apply to `fortiappseccloud_waf_template_caching_compression`, which disables the template module by setting its reviewed top-level, cache, and compression statuses false together."
	if !strings.Contains(cachingAppDocs, wantCachingAppDestroy) {
		t.Fatalf("caching/compression app documentation omitted the distinct template destroy behavior:\n%s", cachingAppDocs)
	}
	cachingTemplateDocs := string(outputs["website/docs/r/waf_template_caching_compression.html.markdown"])
	for _, status := range []string{"configs.status=false", "configs.cache.status=false", "configs.compress.status=false"} {
		if !strings.Contains(cachingTemplateDocs, status) {
			t.Fatalf("caching/compression template documentation omitted %q", status)
		}
	}
}

func TestValidateDestroyPolicySchemaFailsClosed(t *testing.T) {
	t.Parallel()

	boolField := SchemaIR{Name: "status", Kind: "boolean"}
	readOnly := true
	tests := map[string]SchemaIR{
		"missing configs": {Kind: "object"},
		"missing status": {
			Kind: "object", Fields: []SchemaIR{{Name: "configs", Kind: "object"}},
		},
		"non boolean status": {
			Kind: "object", Fields: []SchemaIR{{Name: "configs", Kind: "object", Fields: []SchemaIR{{Name: "status", Kind: "string"}}}},
		},
		"read only status": {
			Kind: "object", Fields: []SchemaIR{{Name: "configs", Kind: "object", Fields: []SchemaIR{{Name: "status", Kind: "boolean", ReadOnly: &readOnly}}}},
		},
	}
	for name, root := range tests {
		root := root
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateDestroyPolicySchema(root, profile.DestroyPolicy{Mode: "forget", Field: "status"}); err == nil {
				t.Fatal("validateDestroyPolicySchema() accepted an unsafe status candidate")
			}
		})
	}
	valid := SchemaIR{Kind: "object", Fields: []SchemaIR{{Name: "configs", Kind: "object", Fields: []SchemaIR{boolField}}}}
	if err := validateDestroyPolicySchema(valid, profile.DestroyPolicy{Mode: "forget", Field: "status"}); err != nil {
		t.Fatalf("validateDestroyPolicySchema() rejected writable boolean status: %v", err)
	}
	coupled := SchemaIR{
		Kind: "object",
		Fields: []SchemaIR{{
			Name: "configs",
			Kind: "object",
			Fields: []SchemaIR{
				boolField,
				{Name: "cache", Kind: "object", Fields: []SchemaIR{{Name: "status", Kind: "boolean"}}},
				{Name: "compress", Kind: "object", Fields: []SchemaIR{{Name: "status", Kind: "boolean"}}},
			},
		}},
	}
	policy := profile.DestroyPolicy{Mode: "disable", Field: "status", CoupledFields: []string{"cache.status", "compress.status"}}
	if err := validateDestroyPolicySchema(coupled, policy); err != nil {
		t.Fatalf("validateDestroyPolicySchema() rejected reviewed coupled fields: %v", err)
	}
	for _, invalid := range [][]string{{"missing.status"}, {"cache"}, {"cache.status", "cache.status"}} {
		invalidPolicy := policy
		invalidPolicy.CoupledFields = invalid
		if err := validateDestroyPolicySchema(coupled, invalidPolicy); err == nil {
			t.Fatalf("validateDestroyPolicySchema() accepted coupled fields %#v", invalid)
		}
	}
}
