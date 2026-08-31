package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/contract"
	frameworkprovider "terraform-provider-fortiappseccloud/internal/provider"
)

func TestFrameworkProviderSchema(t *testing.T) {
	t.Parallel()

	factory := providerserver.NewProtocol5(frameworkprovider.New("test", "test")())
	response, err := factory().GetProviderSchema(context.Background(), &tfprotov5.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema() error = %v", err)
	}
	for _, diagnostic := range response.Diagnostics {
		if diagnostic.Severity == tfprotov5.DiagnosticSeverityError {
			t.Fatalf("GetProviderSchema() diagnostic: %s: %s", diagnostic.Summary, diagnostic.Detail)
		}
	}

	var resources []string
	for name := range response.ResourceSchemas {
		resources = append(resources, name)
	}
	sort.Strings(resources)
	want := []string{
		"fortiappseccloud_waf_account_takeover",
		"fortiappseccloud_waf_anomaly_detection",
		"fortiappseccloud_waf_api_gateway",
		"fortiappseccloud_waf_app",
		"fortiappseccloud_waf_biometrics_based_detection",
		"fortiappseccloud_waf_bot_deception",
		"fortiappseccloud_waf_caching_compression",
		"fortiappseccloud_waf_content_routing",
		"fortiappseccloud_waf_cookie_security",
		"fortiappseccloud_waf_cors_protection",
		"fortiappseccloud_waf_csrf_protection",
		"fortiappseccloud_waf_custom_rule",
		"fortiappseccloud_waf_ddos_prevention",
		"fortiappseccloud_waf_file_protection",
		"fortiappseccloud_waf_global_trust_list_parameter",
		"fortiappseccloud_waf_graphql_protection",
		"fortiappseccloud_waf_http_header_security",
		"fortiappseccloud_waf_information_leakage",
		"fortiappseccloud_waf_ip_protection",
		"fortiappseccloud_waf_json_protection",
		"fortiappseccloud_waf_known_attacks",
		"fortiappseccloud_waf_known_bots",
		"fortiappseccloud_waf_mitb_protection",
		"fortiappseccloud_waf_ml_api_protection",
		"fortiappseccloud_waf_ml_bot_detection",
		"fortiappseccloud_waf_mobile_api_protection",
		"fortiappseccloud_waf_openapi_validation",
		"fortiappseccloud_waf_origin_servers",
		"fortiappseccloud_waf_parameter_validation",
		"fortiappseccloud_waf_request_limits",
		"fortiappseccloud_waf_rewriting_requests",
		"fortiappseccloud_waf_template",
		"fortiappseccloud_waf_template_account_takeover",
		"fortiappseccloud_waf_template_anomaly_detection",
		"fortiappseccloud_waf_template_api_gateway",
		"fortiappseccloud_waf_template_attachment",
		"fortiappseccloud_waf_template_biometrics_based_detection",
		"fortiappseccloud_waf_template_bot_deception",
		"fortiappseccloud_waf_template_caching_compression",
		"fortiappseccloud_waf_template_cookie_security",
		"fortiappseccloud_waf_template_cors_protection",
		"fortiappseccloud_waf_template_csrf_protection",
		"fortiappseccloud_waf_template_custom_rule",
		"fortiappseccloud_waf_template_ddos_prevention",
		"fortiappseccloud_waf_template_file_protection",
		"fortiappseccloud_waf_template_graphql_protection",
		"fortiappseccloud_waf_template_http_header_security",
		"fortiappseccloud_waf_template_information_leakage",
		"fortiappseccloud_waf_template_ip_protection",
		"fortiappseccloud_waf_template_json_protection",
		"fortiappseccloud_waf_template_known_attacks",
		"fortiappseccloud_waf_template_known_bots",
		"fortiappseccloud_waf_template_mitb_protection",
		"fortiappseccloud_waf_template_ml_api_protection",
		"fortiappseccloud_waf_template_ml_bot_detection",
		"fortiappseccloud_waf_template_mobile_api_protection",
		"fortiappseccloud_waf_template_parameter_validation",
		"fortiappseccloud_waf_template_request_limits",
		"fortiappseccloud_waf_template_rewriting_requests",
		"fortiappseccloud_waf_template_threshold_detection",
		"fortiappseccloud_waf_template_url_access",
		"fortiappseccloud_waf_template_waiting_room",
		"fortiappseccloud_waf_template_web_socket_security",
		"fortiappseccloud_waf_template_xml_protection_policy",
		"fortiappseccloud_waf_threshold_detection",
		"fortiappseccloud_waf_url_access",
		"fortiappseccloud_waf_waiting_room",
		"fortiappseccloud_waf_web_socket_security",
		"fortiappseccloud_waf_xml_protection_policy",
	}
	if !reflect.DeepEqual(resources, want) {
		t.Fatalf("resources = %#v, want %#v", resources, want)
	}

	template := response.ResourceSchemas["fortiappseccloud_waf_template"]
	if template == nil || template.Block == nil {
		t.Fatal("template resource schema is missing its root block")
	}
	for _, name := range []string{"template_id", "name", "predefined", "features"} {
		if findProto5Attribute(template.Block, name) == nil {
			t.Fatalf("template resource is missing %s", name)
		}
	}

	templateCSRF := response.ResourceSchemas["fortiappseccloud_waf_template_csrf_protection"]
	if templateCSRF == nil || templateCSRF.Block == nil {
		t.Fatal("template CSRF resource schema is missing its root block")
	}
	if findProto5Attribute(templateCSRF.Block, "template_id") == nil {
		t.Fatal("template CSRF resource is missing template_id")
	}
	for _, absent := range []string{"ep_id", "template"} {
		if findProto5Attribute(templateCSRF.Block, absent) != nil {
			t.Fatalf("template CSRF resource unexpectedly exposes %s", absent)
		}
	}
	templateCSRFConfigs := requireProto5NestedBlock(t, templateCSRF.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	for _, name := range []string{"page_list", "url_list"} {
		requireProto5NestedBlock(t, templateCSRFConfigs.Block, name, tfprotov5.SchemaNestedBlockNestingModeSingle)
	}

	csrf := response.ResourceSchemas["fortiappseccloud_waf_csrf_protection"]
	if csrf == nil || csrf.Block == nil {
		t.Fatal("CSRF resource schema is missing its root block")
	}
	configs := requireProto5NestedBlock(t, csrf.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	for _, name := range []string{"page_list", "url_list"} {
		if findProto5Attribute(configs.Block, name) != nil {
			t.Fatalf("%s was exposed as an attribute instead of a protocol-5 ownership block", name)
		}
		wrapper := requireProto5NestedBlock(t, configs.Block, name, tfprotov5.SchemaNestedBlockNestingModeSingle)
		item := requireProto5NestedBlock(t, wrapper.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
		if findProto5Attribute(item.Block, "idx") != nil {
			t.Fatalf("%s.item exposes wire-only idx", name)
		}
		for _, attribute := range []string{"filter", "url", "name", "value"} {
			if findProto5Attribute(item.Block, attribute) == nil {
				t.Fatalf("%s.item is missing %s", name, attribute)
			}
		}
	}

	urlAccess := response.ResourceSchemas["fortiappseccloud_waf_url_access"]
	if urlAccess == nil || urlAccess.Block == nil {
		t.Fatal("URL access resource schema is missing its root block")
	}
	urlConfigs := requireProto5NestedBlock(t, urlAccess.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	if findProto5Attribute(urlConfigs.Block, "status") == nil {
		t.Fatal("URL access configs is missing status")
	}
	ruleList := requireProto5NestedBlock(t, urlConfigs.Block, "rule_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	ruleItem := requireProto5NestedBlock(t, ruleList.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(ruleItem.Block, "idx") != nil {
		t.Fatal("rule_list.item exposes wire-only idx")
	}
	for _, attribute := range []string{"action", "name", "url", "url_type"} {
		if findProto5Attribute(ruleItem.Block, attribute) == nil {
			t.Fatalf("rule_list.item is missing %s", attribute)
		}
	}

	// global_trust_list_parameter: hand-written custom resource with a configs
	// block (no template) and a trust_list ownership wrapper containing an item
	// ListNestedBlock. Wire-only idx must not be exposed.
	gtl := response.ResourceSchemas["fortiappseccloud_waf_global_trust_list_parameter"]
	if gtl == nil || gtl.Block == nil {
		t.Fatal("global trust list resource schema is missing its root block")
	}
	if findProto5Attribute(gtl.Block, "template") != nil {
		t.Fatal("global trust list exposes a template attribute; this endpoint has no template")
	}
	gtlConfigs := requireProto5NestedBlock(t, gtl.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	if findProto5Attribute(gtlConfigs.Block, "status") == nil {
		t.Fatal("global trust list configs is missing status")
	}
	gtlWrapper := requireProto5NestedBlock(t, gtlConfigs.Block, "trust_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	gtlItem := requireProto5NestedBlock(t, gtlWrapper.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(gtlItem.Block, "idx") != nil {
		t.Fatal("trust_list.item exposes wire-only idx")
	}
	gotAttrs := make([]string, 0, len(gtlItem.Block.Attributes))
	for _, attribute := range gtlItem.Block.Attributes {
		gotAttrs = append(gotAttrs, attribute.Name)
	}
	sort.Strings(gotAttrs)
	if !reflect.DeepEqual(gotAttrs, []string{"name", "status", "url"}) {
		t.Fatalf("trust_list.item attributes = %#v, want exactly [name status url]", gotAttrs)
	}

	// anomaly_detection: hand-written custom resource with the {template, configs}
	// envelope and an ip_list ownership wrapper containing an item ListNestedBlock.
	ad := response.ResourceSchemas["fortiappseccloud_waf_anomaly_detection"]
	if ad == nil || ad.Block == nil {
		t.Fatal("anomaly detection resource schema is missing its root block")
	}
	if findProto5Attribute(ad.Block, "template") == nil {
		t.Fatal("anomaly detection is missing the template attribute")
	}
	adConfigs := requireProto5NestedBlock(t, ad.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	for _, attribute := range []string{"status", "action", "ip_list_type"} {
		if findProto5Attribute(adConfigs.Block, attribute) == nil {
			t.Fatalf("anomaly detection configs is missing %s", attribute)
		}
	}
	adWrapper := requireProto5NestedBlock(t, adConfigs.Block, "ip_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	adItem := requireProto5NestedBlock(t, adWrapper.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(adItem.Block, "idx") != nil {
		t.Fatal("ip_list.item exposes wire-only idx")
	}
	adAttrs := make([]string, 0, len(adItem.Block.Attributes))
	for _, attribute := range adItem.Block.Attributes {
		adAttrs = append(adAttrs, attribute.Name)
	}
	sort.Strings(adAttrs)
	if !reflect.DeepEqual(adAttrs, []string{"ip"}) {
		t.Fatalf("ip_list.item attributes = %#v, want exactly [ip]", adAttrs)
	}

	// cors_protection: hand-written custom resource with the {template, configs}
	// envelope and four required nested policy SingleNestedBlocks.
	cors := response.ResourceSchemas["fortiappseccloud_waf_cors_protection"]
	if cors == nil || cors.Block == nil {
		t.Fatal("cors protection resource schema is missing its root block")
	}
	if findProto5Attribute(cors.Block, "template") == nil {
		t.Fatal("cors protection is missing the template attribute")
	}
	corsConfigs := requireProto5NestedBlock(t, cors.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	for _, block := range []string{"allowed_origins", "allowed_methods", "allowed_headers", "exposed_headers"} {
		if findProto5Attribute(corsConfigs.Block, block) != nil {
			t.Fatalf("cors protection %s was exposed as an attribute instead of a nested block", block)
		}
		requireProto5NestedBlock(t, corsConfigs.Block, block, tfprotov5.SchemaNestedBlockNestingModeSingle)
	}
	for _, attribute := range []string{"status", "block_cors_traffic", "url_pattern", "allowed_credentials", "allowed_maximum_age"} {
		if findProto5Attribute(corsConfigs.Block, attribute) == nil {
			t.Fatalf("cors protection configs is missing %s", attribute)
		}
	}
	corsOrigins := requireProto5NestedBlock(t, corsConfigs.Block, "allowed_origins", tfprotov5.SchemaNestedBlockNestingModeSingle)
	for _, attribute := range []string{"protocol", "origin_name", "port", "include_sub_domains"} {
		if findProto5Attribute(corsOrigins.Block, attribute) == nil {
			t.Fatalf("cors protection allowed_origins is missing %s", attribute)
		}
	}

	// ip_protection: hand-written custom resource with the {template, configs}
	// envelope, required status/ip_reputation scalars, optional geo_ip_mode/block_country_list,
	// and an ip_list ownership wrapper containing an item ListNestedBlock.
	ipp := response.ResourceSchemas["fortiappseccloud_waf_ip_protection"]
	if ipp == nil || ipp.Block == nil {
		t.Fatal("ip protection resource schema is missing its root block")
	}
	if findProto5Attribute(ipp.Block, "template") == nil {
		t.Fatal("ip protection is missing the template attribute")
	}
	ippConfigs := requireProto5NestedBlock(t, ipp.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	for _, attribute := range []string{"status", "ip_reputation", "geo_ip_mode", "block_country_list"} {
		if findProto5Attribute(ippConfigs.Block, attribute) == nil {
			t.Fatalf("ip protection configs is missing %s", attribute)
		}
	}
	ippWrapper := requireProto5NestedBlock(t, ippConfigs.Block, "ip_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	ippItem := requireProto5NestedBlock(t, ippWrapper.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(ippItem.Block, "idx") != nil {
		t.Fatal("ip_list.item exposes wire-only idx")
	}
	ippAttrs := make([]string, 0, len(ippItem.Block.Attributes))
	for _, attribute := range ippItem.Block.Attributes {
		ippAttrs = append(ippAttrs, attribute.Name)
	}
	sort.Strings(ippAttrs)
	if !reflect.DeepEqual(ippAttrs, []string{"ip", "type"}) {
		t.Fatalf("ip_list.item attributes = %#v, want exactly [ip type]", ippAttrs)
	}

	// content_routing: hand-written custom resource with a flat {status,
	// policy_list} envelope (no template/configs) and a nested policy_list
	// ownership wrapper containing rule_list inside each policy.
	cr := response.ResourceSchemas["fortiappseccloud_waf_content_routing"]
	if cr == nil || cr.Block == nil {
		t.Fatal("content routing resource schema is missing its root block")
	}
	if findProto5Attribute(cr.Block, "status") == nil {
		t.Fatal("content routing is missing the status attribute")
	}
	if findProto5Attribute(cr.Block, "template") != nil {
		t.Fatal("content routing exposes a template attribute; this endpoint has no template")
	}
	crWrapper := requireProto5NestedBlock(t, cr.Block, "policy_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	crItem := requireProto5NestedBlock(t, crWrapper.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(crItem.Block, "idx") != nil {
		t.Fatal("policy_list.item exposes wire-only idx")
	}
	for _, attribute := range []string{"name", "server_pool", "is_default"} {
		if findProto5Attribute(crItem.Block, attribute) == nil {
			t.Fatalf("content routing policy_list.item is missing %s", attribute)
		}
	}
	// rule_list is a nested ownership wrapper inside each policy item.
	crRuleList := requireProto5NestedBlock(t, crItem.Block, "rule_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	crRuleItem := requireProto5NestedBlock(t, crRuleList.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(crRuleItem.Block, "idx") != nil {
		t.Fatal("rule_list.item exposes wire-only idx")
	}
	for _, attribute := range []string{"match_object", "match_condition", "match_expression", "name", "value", "concatenate", "reverse", "start_ip", "end_ip", "ip_list", "name_match_condition", "value_match_condition", "x509_subject_name"} {
		if findProto5Attribute(crRuleItem.Block, attribute) == nil {
			t.Fatalf("content routing rule_list.item is missing %s", attribute)
		}
	}

	// custom_rule: hand-written custom resource with the {template, configs}
	// envelope, rule_list ownership wrapper (max 24), and nested filter_list
	// (max 200) with a type discriminator.
	crule := response.ResourceSchemas["fortiappseccloud_waf_custom_rule"]
	if crule == nil || crule.Block == nil {
		t.Fatal("custom rule resource schema is missing its root block")
	}
	if findProto5Attribute(crule.Block, "template") == nil {
		t.Fatal("custom rule is missing the template attribute")
	}
	cruleConfigs := requireProto5NestedBlock(t, crule.Block, "configs", tfprotov5.SchemaNestedBlockNestingModeSingle)
	if findProto5Attribute(cruleConfigs.Block, "status") == nil {
		t.Fatal("custom rule configs is missing status")
	}
	cruleWrapper := requireProto5NestedBlock(t, cruleConfigs.Block, "rule_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	cruleItem := requireProto5NestedBlock(t, cruleWrapper.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(cruleItem.Block, "idx") != nil {
		t.Fatal("rule_list.item exposes wire-only idx")
	}
	for _, attribute := range []string{"name", "action", "block_period", "challenge"} {
		if findProto5Attribute(cruleItem.Block, attribute) == nil {
			t.Fatalf("custom rule rule_list.item is missing %s", attribute)
		}
	}
	cruleFilterList := requireProto5NestedBlock(t, cruleItem.Block, "filter_list", tfprotov5.SchemaNestedBlockNestingModeSingle)
	cruleFilterItem := requireProto5NestedBlock(t, cruleFilterList.Block, "item", tfprotov5.SchemaNestedBlockNestingModeList)
	if findProto5Attribute(cruleFilterItem.Block, "idx") != nil {
		t.Fatal("filter_list.item exposes wire-only idx")
	}
	if findProto5Attribute(cruleFilterItem.Block, "type") == nil {
		t.Fatal("filter_list.item is missing type")
	}
	if findProto5Attribute(cruleFilterItem.Block, "idx") != nil {
		t.Fatal("filter_list.item exposes wire-only idx")
	}
	// Assert the exact filter key set (type + 32 optional fields, no idx).
	cruleFilterAttrs := make([]string, 0, len(cruleFilterItem.Block.Attributes))
	for _, attribute := range cruleFilterItem.Block.Attributes {
		cruleFilterAttrs = append(cruleFilterAttrs, attribute.Name)
	}
	sort.Strings(cruleFilterAttrs)
	wantFilterAttrs := []string{
		"content_types", "country_list", "cross_site_scripting", "end",
		"generic_attacks", "header_check", "header_name", "header_reverse_match",
		"header_type", "header_value", "http_hline_empty_check", "http_hline_missing_check",
		"ip", "known_exploits", "limit", "match_exclusively",
		"method_check", "method_reverse_match", "method_value", "name",
		"occurrence", "response_code", "reverse_match", "sql_injection",
		"start", "time_type", "timeout", "trojans", "type", "url",
		"username", "value", "within",
	}
	if !reflect.DeepEqual(cruleFilterAttrs, wantFilterAttrs) {
		t.Fatalf("filter_list.item attributes = %#v, want exactly %#v", cruleFilterAttrs, wantFilterAttrs)
	}
}

func TestImplementedInventoryOwnersAreServed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	openAPI, err := os.ReadFile(filepath.Join("openapi_spec", "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := contract.ParseOpenAPI(openAPI)
	if err != nil {
		t.Fatal(err)
	}
	classifications, err := contract.ClassifyPublicWAF(document)
	if err != nil {
		t.Fatal(err)
	}
	server := providerserver.NewProtocol5(frameworkprovider.New("test", "test")())()
	schemas, err := server.GetProviderSchema(ctx, &tfprotov5.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, classification := range classifications {
		if !contract.IsImplementedCoverage(classification.Coverage) {
			continue
		}
		for _, owner := range strings.Split(classification.Owner, ",") {
			owner = strings.TrimSpace(owner)
			if owner == "" {
				t.Fatalf("implemented %s %s has no Terraform owner", classification.Method, classification.Path)
			}
			if schemas.ResourceSchemas[owner] == nil && schemas.DataSourceSchemas[owner] == nil {
				t.Errorf("implemented %s %s names unserved owner %q", classification.Method, classification.Path, owner)
			}
		}
	}
}

func TestLegacyResourceStateUpgradesThroughProtocol5(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server := providerserver.NewProtocol5(frameworkprovider.New("test", "test")())()
	schemas, err := server.GetProviderSchema(ctx, &tfprotov5.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		resourceType string
		fixture      string
		legacyName   string
	}{
		{resourceType: "fortiappseccloud_waf_app", fixture: filepath.Join("internal", "resources", "app", "testdata", "v1.0.5-state.json"), legacyName: "legacy-demo"},
		{resourceType: "fortiappseccloud_waf_openapi_validation", fixture: filepath.Join("internal", "resources", "openapivalidation", "testdata", "v1.0.5-state.json"), legacyName: "legacy-demo"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.resourceType, func(t *testing.T) {
			raw, readErr := os.ReadFile(test.fixture)
			if readErr != nil {
				t.Fatal(readErr)
			}
			response, upgradeErr := server.UpgradeResourceState(ctx, &tfprotov5.UpgradeResourceStateRequest{
				TypeName: test.resourceType,
				Version:  0,
				RawState: &tfprotov5.RawState{JSON: raw},
			})
			if upgradeErr != nil {
				t.Fatal(upgradeErr)
			}
			for _, diagnostic := range response.Diagnostics {
				if diagnostic.Severity == tfprotov5.DiagnosticSeverityError {
					t.Fatalf("UpgradeResourceState diagnostic: %s: %s", diagnostic.Summary, diagnostic.Detail)
				}
			}
			if response.UpgradedState == nil {
				t.Fatal("UpgradeResourceState returned no state")
			}
			schema := schemas.ResourceSchemas[test.resourceType]
			value, unmarshalErr := response.UpgradedState.Unmarshal(schema.ValueType())
			if unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			attributes := map[string]tftypes.Value{}
			if asErr := value.As(&attributes); asErr != nil {
				t.Fatal(asErr)
			}
			var legacyName string
			if asErr := attributes["legacy_app_name"].As(&legacyName); asErr != nil {
				t.Fatal(asErr)
			}
			if legacyName != test.legacyName {
				t.Fatalf("legacy_app_name = %q, want %q", legacyName, test.legacyName)
			}
		})
	}
}

func requireProto5NestedBlock(t *testing.T, block *tfprotov5.SchemaBlock, name string, nesting tfprotov5.SchemaNestedBlockNestingMode) *tfprotov5.SchemaNestedBlock {
	t.Helper()
	if block == nil {
		t.Fatalf("parent block for %s is nil", name)
	}
	for _, nested := range block.BlockTypes {
		if nested.TypeName == name {
			if nested.Nesting != nesting {
				t.Fatalf("%s nesting = %v, want %v", name, nested.Nesting, nesting)
			}
			if nested.Block == nil {
				t.Fatalf("%s nested block is nil", name)
			}
			return nested
		}
	}
	t.Fatalf("nested block %s is missing", name)
	return nil
}

func findProto5Attribute(block *tfprotov5.SchemaBlock, name string) *tfprotov5.SchemaAttribute {
	if block == nil {
		return nil
	}
	for _, attribute := range block.Attributes {
		if attribute.Name == name {
			return attribute
		}
	}
	return nil
}
