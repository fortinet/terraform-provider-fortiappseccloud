package provider

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/contract"
)

type moduleResourceContract struct {
	module       string
	pathModule   string
	typeName     string
	schemaShape  string
	identityName string
}

func TestAllAppModuleResourceContracts(t *testing.T) {
	t.Parallel()

	cases := []moduleResourceContract{
		appModuleContract("account_takeover", "standard"),
		appModuleContract("api_gateway", "standard"),
		appModuleContract("biometrics_based_detection", "standard"),
		appModuleContract("bot_deception", "standard"),
		appModuleContract("caching_compression", "standard"),
		appModuleContract("cookie_security", "standard"),
		appModuleContract("csrf_protection", "standard"),
		appModuleContract("ddos_prevention", "standard"),
		appModuleContract("file_protection", "standard"),
		appModuleContract("graphql_protection", "standard"),
		appModuleContract("http_header_security", "standard"),
		appModuleContract("information_leakage", "standard"),
		appModuleContract("json_protection", "standard"),
		appModuleContract("known_attacks", "standard"),
		appModuleContract("known_bots", "standard"),
		appModuleContract("mitb_protection", "standard"),
		appModuleContract("ml_bot_detection", "standard"),
		appModuleContract("mobile_api_protection", "standard"),
		appModuleContract("parameter_validation", "standard"),
		appModuleContract("request_limits", "standard"),
		appModuleContract("rewriting_requests", "standard"),
		appModuleContract("threshold_detection", "standard"),
		appModuleContract("url_access", "standard"),
		appModuleContract("waiting_room", "standard"),
		appModuleContract("web_socket_security", "standard"),
		appModuleContract("xml_protection_policy", "standard"),
		appModuleContract("global_trust_list_parameter", "configs_without_template"),
		appModuleContract("anomaly_detection", "standard"),
		appModuleContract("cors_protection", "standard"),
		appModuleContract("ip_protection", "standard"),
		{module: "routings", pathModule: "routings", typeName: "fortiappseccloud_waf_content_routing", schemaShape: "routing", identityName: "ep_id"},
		appModuleContract("custom_rule", "standard"),
		appModuleContract("ml_api_protection", "standard"),
		{module: "api_protection", pathModule: "api_protection", typeName: "fortiappseccloud_waf_openapi_validation", schemaShape: "openapi", identityName: "ep_id"},
	}
	if len(cases) != 34 {
		t.Fatalf("app module contracts = %d, want 34", len(cases))
	}

	constructors := registeredResourcesByType(t)
	operations := implementedOperations(t)
	seen := make(map[string]struct{}, len(cases))
	for _, testCase := range cases {
		if _, duplicate := seen[testCase.typeName]; duplicate {
			t.Fatalf("duplicate app resource contract %q", testCase.typeName)
		}
		seen[testCase.typeName] = struct{}{}
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.module, func(t *testing.T) {
			t.Parallel()
			constructor, ok := constructors[testCase.typeName]
			if !ok {
				t.Fatalf("registered provider is missing %q", testCase.typeName)
			}
			implementation := constructor()
			resourceSchema := verifyRealResourceContract(t, implementation, testCase)
			verifyImplementedOperation(t, operations, testCase.typeName, "/waf/apps/{ep_id}/"+testCase.pathModule, "GET")
			verifyImplementedOperation(t, operations, testCase.typeName, "/waf/apps/{ep_id}/"+testCase.pathModule, "PUT")
			verifyImportIdentity(t, implementation, resourceSchema, testCase.identityName)
		})
	}
}

func TestAllTemplateModuleResourceContracts(t *testing.T) {
	t.Parallel()

	modules := []string{
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
	}
	if len(modules) != 31 {
		t.Fatalf("template module contracts = %d, want 31", len(modules))
	}

	constructors := registeredResourcesByType(t)
	operations := implementedOperations(t)
	for _, module := range modules {
		module := module
		t.Run(module, func(t *testing.T) {
			t.Parallel()
			testCase := moduleResourceContract{
				module:       module,
				pathModule:   module,
				typeName:     "fortiappseccloud_waf_template_" + module,
				schemaShape:  "template",
				identityName: "template_id",
			}
			constructor, ok := constructors[testCase.typeName]
			if !ok {
				t.Fatalf("registered provider is missing %q", testCase.typeName)
			}
			implementation := constructor()
			resourceSchema := verifyRealResourceContract(t, implementation, testCase)
			if module == "caching_compression" && !strings.Contains(resourceSchema.Schema.MarkdownDescription, "coupled nested features") {
				t.Fatalf("caching/compression template schema does not describe its coupled destroy behavior")
			}
			verifyImplementedOperation(t, operations, testCase.typeName, "/waf/template/{template_id}/"+module, "GET")
			verifyImplementedOperation(t, operations, testCase.typeName, "/waf/template/{template_id}/"+module, "PUT")
			verifyImportIdentity(t, implementation, resourceSchema, testCase.identityName)
		})
	}

	for _, absent := range []string{
		"fortiappseccloud_waf_template_global_trust_list_parameter",
		"fortiappseccloud_waf_template_routings",
		"fortiappseccloud_waf_template_openapi_validation",
	} {
		if _, ok := constructors[absent]; ok {
			t.Errorf("unsupported template module %q is registered", absent)
		}
	}
}

func appModuleContract(module, shape string) moduleResourceContract {
	return moduleResourceContract{
		module:       module,
		pathModule:   module,
		typeName:     "fortiappseccloud_waf_" + module,
		schemaShape:  shape,
		identityName: "ep_id",
	}
}

func registeredResourcesByType(t *testing.T) map[string]func() resource.Resource {
	t.Helper()
	ctx := context.Background()
	configured := New("test", "test")()
	result := make(map[string]func() resource.Resource, len(configured.Resources(ctx)))
	for _, constructor := range configured.Resources(ctx) {
		var metadata resource.MetadataResponse
		constructor().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &metadata)
		if metadata.TypeName == "" {
			t.Fatal("registered resource returned an empty type name")
		}
		if _, duplicate := result[metadata.TypeName]; duplicate {
			t.Fatalf("duplicate registered resource %q", metadata.TypeName)
		}
		result[metadata.TypeName] = constructor
	}
	if len(result) != 69 {
		t.Fatalf("registered resources = %d, want 69", len(result))
	}
	return result
}

func verifyRealResourceContract(t *testing.T, implementation resource.Resource, testCase moduleResourceContract) resource.SchemaResponse {
	t.Helper()
	ctx := context.Background()

	var metadata resource.MetadataResponse
	implementation.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &metadata)
	if metadata.TypeName != testCase.typeName {
		t.Fatalf("metadata type name = %q, want %q", metadata.TypeName, testCase.typeName)
	}

	var schemaResponse resource.SchemaResponse
	implementation.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema() diagnostics = %v", schemaResponse.Diagnostics)
	}
	if _, ok := schemaResponse.Schema.Attributes[testCase.identityName]; !ok {
		t.Fatalf("schema is missing identity attribute %q", testCase.identityName)
	}

	switch testCase.schemaShape {
	case "standard":
		requireSchemaAttribute(t, schemaResponse, "ep_id", true)
		requireSchemaAttribute(t, schemaResponse, "template", true)
		requireSchemaBlock(t, schemaResponse, "configs", true)
	case "configs_without_template":
		requireSchemaAttribute(t, schemaResponse, "ep_id", true)
		requireSchemaAttribute(t, schemaResponse, "template", false)
		requireSchemaBlock(t, schemaResponse, "configs", true)
	case "routing":
		requireSchemaAttribute(t, schemaResponse, "ep_id", true)
		requireSchemaAttribute(t, schemaResponse, "status", true)
		requireSchemaAttribute(t, schemaResponse, "template", false)
		requireSchemaBlock(t, schemaResponse, "configs", false)
	case "openapi":
		for _, name := range []string{"ep_id", "enable", "action", "validation_files"} {
			requireSchemaAttribute(t, schemaResponse, name, true)
		}
		requireSchemaAttribute(t, schemaResponse, "template", false)
		requireSchemaBlock(t, schemaResponse, "configs", false)
	case "template":
		requireSchemaAttribute(t, schemaResponse, "template_id", true)
		requireSchemaAttribute(t, schemaResponse, "ep_id", false)
		requireSchemaAttribute(t, schemaResponse, "template", false)
		requireSchemaBlock(t, schemaResponse, "configs", true)
		if !strings.Contains(schemaResponse.Schema.MarkdownDescription, "Destroy disables the remote module") {
			t.Fatal("template module schema does not advertise disable-on-destroy")
		}
	default:
		t.Fatalf("unsupported schema shape %q", testCase.schemaShape)
	}

	configurable, ok := implementation.(resource.ResourceWithConfigure)
	if !ok {
		t.Fatal("resource does not implement ResourceWithConfigure")
	}
	var configureResponse resource.ConfigureResponse
	configurable.Configure(ctx, resource.ConfigureRequest{ProviderData: "wrong-provider-data"}, &configureResponse)
	if !configureResponse.Diagnostics.HasError() {
		t.Fatal("Configure() accepted provider data with the wrong type")
	}

	if _, ok := implementation.(resource.ResourceWithValidateConfig); !ok {
		t.Fatal("resource does not implement ResourceWithValidateConfig")
	}
	if _, ok := implementation.(resource.ResourceWithImportState); !ok {
		t.Fatal("resource does not implement ResourceWithImportState")
	}
	return schemaResponse
}

func requireSchemaAttribute(t *testing.T, response resource.SchemaResponse, name string, want bool) {
	t.Helper()
	_, got := response.Schema.Attributes[name]
	if got != want {
		t.Fatalf("schema attribute %q presence = %t, want %t", name, got, want)
	}
}

func requireSchemaBlock(t *testing.T, response resource.SchemaResponse, name string, want bool) {
	t.Helper()
	_, got := response.Schema.Blocks[name]
	if got != want {
		t.Fatalf("schema block %q presence = %t, want %t", name, got, want)
	}
}

func verifyImportIdentity(t *testing.T, implementation resource.Resource, schemaResponse resource.SchemaResponse, identityName string) {
	t.Helper()
	ctx := context.Background()
	importer := implementation.(resource.ResourceWithImportState)
	newState := func() tfsdk.State {
		return tfsdk.State{
			Schema: schemaResponse.Schema,
			Raw:    tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(ctx), nil),
		}
	}

	response := resource.ImportStateResponse{State: newState()}
	importer.ImportState(ctx, resource.ImportStateRequest{ID: "  unit-identity  "}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("ImportState() diagnostics = %v", response.Diagnostics)
	}
	var identity types.String
	if diagnostics := response.State.GetAttribute(ctx, path.Root(identityName), &identity); diagnostics.HasError() {
		t.Fatalf("read imported %s: %v", identityName, diagnostics)
	}
	if identity.ValueString() != "unit-identity" {
		t.Fatalf("imported %s = %q", identityName, identity.ValueString())
	}

	empty := resource.ImportStateResponse{State: newState()}
	importer.ImportState(ctx, resource.ImportStateRequest{ID: "   "}, &empty)
	if !empty.Diagnostics.HasError() {
		t.Fatal("ImportState() accepted an empty identity")
	}
}

type operationKey struct {
	owner  string
	path   string
	method string
}

func implementedOperations(t *testing.T) map[operationKey]struct{} {
	t.Helper()
	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read pinned OpenAPI: %v", err)
	}
	document, err := contract.ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("parse pinned OpenAPI: %v", err)
	}
	classifications, err := contract.ClassifyPublicWAF(document)
	if err != nil {
		t.Fatalf("classify public WAF contract: %v", err)
	}
	result := make(map[operationKey]struct{})
	for _, classification := range classifications {
		if !contract.IsImplementedCoverage(classification.Coverage) {
			continue
		}
		result[operationKey{owner: classification.Owner, path: classification.Path, method: classification.Method}] = struct{}{}
	}
	return result
}

func verifyImplementedOperation(t *testing.T, operations map[operationKey]struct{}, owner, publicPath, method string) {
	t.Helper()
	if _, ok := operations[operationKey{owner: owner, path: publicPath, method: method}]; !ok {
		keys := make([]string, 0)
		for key := range operations {
			if key.owner == owner {
				keys = append(keys, key.method+" "+key.path)
			}
		}
		sort.Strings(keys)
		t.Fatalf("implemented contract is missing %s %s for %s; owner operations = %v", method, publicPath, owner, keys)
	}
}
