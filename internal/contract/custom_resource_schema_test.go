package contract_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/contract"
	"terraform-provider-fortiappseccloud/internal/locking"
	"terraform-provider-fortiappseccloud/internal/resources/anomalydetection"
	"terraform-provider-fortiappseccloud/internal/resources/contentsrouting"
	"terraform-provider-fortiappseccloud/internal/resources/corsprotection"
	"terraform-provider-fortiappseccloud/internal/resources/customrule"
	"terraform-provider-fortiappseccloud/internal/resources/globaltrustlist"
	"terraform-provider-fortiappseccloud/internal/resources/ipprotection"
	"terraform-provider-fortiappseccloud/internal/resources/mlapiprotection"
)

func TestReviewedCustomDestroyCandidateSchemas(t *testing.T) {
	t.Parallel()

	schemas := reviewedConfigurationResourceSchemas(t)
	schemaNames := map[string]string{
		"anomaly_detection": "anomaly",
		"cors_protection":   "cors",
		"custom_rule":       "custom",
		"ip_protection":     "ip",
		"ml_api_protection": "ml",
	}
	checked := 0
	for _, reviewed := range contract.ReviewedCustomResourceContracts() {
		if reviewed.DestroyField == "" {
			continue
		}
		resourceSchema, ok := schemas[schemaNames[reviewed.Module]]
		if !ok {
			t.Errorf("%s destroy candidate has no reviewed schema", reviewed.Module)
			continue
		}
		template, ok := resourceSchema.Attributes["template"].(schema.BoolAttribute)
		if !ok || (!template.Required && !template.Optional) {
			t.Errorf("%s template must be a writable boolean attribute", reviewed.Module)
		}
		configs, ok := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
		if !ok {
			t.Errorf("%s configs must be a single nested block", reviewed.Module)
			continue
		}
		status, ok := configs.Attributes[reviewed.DestroyField].(schema.BoolAttribute)
		if !ok || (!status.Required && !status.Optional) {
			t.Errorf("%s configs.%s must be a writable boolean attribute", reviewed.Module, reviewed.DestroyField)
		}
		checked++
	}
	if checked != 5 {
		t.Fatalf("checked custom destroy candidate schemas = %d, want 5", checked)
	}
}

func TestReviewedCustomResourceStringValidators(t *testing.T) {
	t.Parallel()

	schemas := reviewedConfigurationResourceSchemas(t)
	tests := []struct {
		resource string
		path     string
		valid    string
		invalid  string
	}{
		{resource: "global", path: "configs.trust_list.item.name", valid: strings.Repeat("界", 63), invalid: strings.Repeat("界", 64)},
		{resource: "global", path: "configs.trust_list.item.url", valid: strings.Repeat("界", 255), invalid: strings.Repeat("界", 256)},
		{resource: "anomaly", path: "configs.action", valid: "alert", invalid: "deny"},
		{resource: "anomaly", path: "configs.ip_list_type", valid: "Block", invalid: "Allow"},
		{resource: "cors", path: "configs.allowed_credentials", valid: "TRUE", invalid: "true"},
		{resource: "cors", path: "configs.allowed_origins.protocol", valid: "HTTPS", invalid: "FTP"},
		{resource: "ip", path: "configs.geo_ip_mode", valid: "allow", invalid: "deny"},
		{resource: "ip", path: "configs.ip_list.item.type", valid: "allow-only-ip", invalid: "deny-ip"},
		{resource: "routing", path: "policy_list.item.rule_list.item.match_object", valid: "http-request", invalid: "path"},
		{resource: "routing", path: "policy_list.item.rule_list.item.match_condition", valid: "match-end", invalid: "contains"},
		{resource: "routing", path: "policy_list.item.rule_list.item.concatenate", valid: "or", invalid: "xor"},
		{resource: "routing", path: "policy_list.item.rule_list.item.name_match_condition", valid: "equal", invalid: "contains"},
		{resource: "routing", path: "policy_list.item.rule_list.item.value_match_condition", valid: "match-reg", invalid: "contains"},
		{resource: "custom", path: "configs.rule_list.item.name", valid: strings.Repeat("界", 40), invalid: strings.Repeat("界", 41)},
		{resource: "custom", path: "configs.rule_list.item.action", valid: "alert_deny", invalid: "deny"},
		{resource: "custom", path: "configs.rule_list.item.challenge", valid: "disabled", invalid: "unknown"},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.type", valid: "geo-filter", invalid: "future-filter"},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.username", valid: strings.Repeat("界", 63), invalid: strings.Repeat("界", 64)},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.header_type", valid: "custom", invalid: "other"},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.time_type", valid: "daily", invalid: "weekly"},
		{resource: "ml", path: "configs.threat_action", valid: "disable", invalid: "deny"},
		{resource: "ml", path: "configs.ip_list_type", valid: "Trust", invalid: "Allow"},
		{resource: "ml", path: "configs.path_list.item.type", valid: "regular", invalid: "regex"},
		{resource: "ml", path: "configs.path_list.item.pattern", valid: "/api", invalid: "api"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.resource+"."+test.path, func(t *testing.T) {
			t.Parallel()

			attribute := lookupSchemaElement(t, schemas[test.resource], test.path).(schema.StringAttribute)
			if len(attribute.Validators) == 0 {
				t.Fatal("attribute has no string validators")
			}
			if diagnostics := runStringValidators(attribute.Validators, test.path, test.valid); diagnostics.Diagnostics.HasError() {
				t.Fatalf("valid control diagnostics = %v", diagnostics)
			}
			if diagnostics := runStringValidators(attribute.Validators, test.path, test.invalid); !diagnostics.Diagnostics.HasError() {
				t.Fatalf("validators accepted invalid value %q", test.invalid)
			}
		})
	}
}

func TestReviewedCustomResourceIntegerValidators(t *testing.T) {
	t.Parallel()

	schemas := reviewedConfigurationResourceSchemas(t)
	tests := []struct {
		resource string
		path     string
		valid    int64
		invalid  []int64
	}{
		{resource: "cors", path: "configs.allowed_maximum_age", valid: 86400, invalid: []int64{-1, 86401}},
		{resource: "cors", path: "configs.allowed_origins.port", valid: 65535, invalid: []int64{-1, 65536}},
		{resource: "custom", path: "configs.rule_list.item.block_period", valid: 3600, invalid: []int64{0, 3601}},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.limit", valid: 65535, invalid: []int64{0, 65536}},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.occurrence", valid: 100000, invalid: []int64{0, 100001}},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.within", valid: 600, invalid: []int64{0, 601}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.resource+"."+test.path, func(t *testing.T) {
			t.Parallel()

			attribute := lookupSchemaElement(t, schemas[test.resource], test.path).(schema.Int64Attribute)
			if len(attribute.Validators) == 0 {
				t.Fatal("attribute has no integer validators")
			}
			if diagnostics := runInt64Validators(attribute.Validators, test.path, test.valid); diagnostics.Diagnostics.HasError() {
				t.Fatalf("valid control diagnostics = %v", diagnostics)
			}
			for _, invalid := range test.invalid {
				if diagnostics := runInt64Validators(attribute.Validators, test.path, invalid); !diagnostics.Diagnostics.HasError() {
					t.Fatalf("validators accepted invalid value %d", invalid)
				}
			}
		})
	}
}

func TestReviewedCustomResourceListValidators(t *testing.T) {
	t.Parallel()

	schemas := reviewedConfigurationResourceSchemas(t)
	stringListTests := []struct {
		resource string
		path     string
		valid    string
		invalid  string
	}{
		{resource: "cors", path: "configs.allowed_methods.methods", valid: "GET", invalid: "OPTIONS"},
		{resource: "ip", path: "configs.block_country_list", valid: "Taiwan", invalid: "Atlantis"},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item.content_types", valid: "application/json", invalid: "other/type"},
	}
	for _, test := range stringListTests {
		test := test
		t.Run(test.resource+"."+test.path, func(t *testing.T) {
			t.Parallel()

			attribute := lookupSchemaElement(t, schemas[test.resource], test.path).(schema.ListAttribute)
			if len(attribute.Validators) == 0 {
				t.Fatal("attribute has no list validators")
			}
			valid := types.ListValueMust(types.StringType, []attr.Value{types.StringValue(test.valid)})
			if diagnostics := runListValidators(attribute.Validators, test.path, valid); diagnostics.Diagnostics.HasError() {
				t.Fatalf("valid control diagnostics = %v", diagnostics)
			}
			invalid := types.ListValueMust(types.StringType, []attr.Value{types.StringValue(test.invalid)})
			if diagnostics := runListValidators(attribute.Validators, test.path, invalid); !diagnostics.Diagnostics.HasError() {
				t.Fatalf("validators accepted invalid list value %q", test.invalid)
			}
		})
	}

	sizeTests := []struct {
		resource string
		path     string
		max      int
	}{
		{resource: "global", path: "configs.trust_list.item", max: 30},
		{resource: "anomaly", path: "configs.ip_list.item", max: 30},
		{resource: "ip", path: "configs.ip_list.item", max: 256},
		{resource: "routing", path: "policy_list.item", max: 32},
		{resource: "routing", path: "policy_list.item.rule_list.item", max: 32},
		{resource: "custom", path: "configs.rule_list.item", max: 24},
		{resource: "custom", path: "configs.rule_list.item.filter_list.item", max: 200},
		{resource: "ml", path: "configs.ip_list.item", max: 30},
		{resource: "ml", path: "configs.path_list.item", max: 30},
	}
	for _, test := range sizeTests {
		test := test
		t.Run(test.resource+"."+test.path+".size", func(t *testing.T) {
			t.Parallel()

			block := lookupSchemaElement(t, schemas[test.resource], test.path).(schema.ListNestedBlock)
			if len(block.Validators) == 0 {
				t.Fatal("block has no list validators")
			}
			objectType := block.NestedObject.Type().(basetypes.ObjectType)
			element := types.ObjectNull(objectType.AttrTypes)
			valid := types.ListValueMust(objectType, repeatedValues(element, test.max))
			if diagnostics := runListValidators(block.Validators, test.path, valid); diagnostics.Diagnostics.HasError() {
				t.Fatalf("valid max-size control diagnostics = %v", diagnostics)
			}
			invalid := types.ListValueMust(objectType, repeatedValues(element, test.max+1))
			if diagnostics := runListValidators(block.Validators, test.path, invalid); !diagnostics.Diagnostics.HasError() {
				t.Fatalf("validators accepted %d items, max is %d", test.max+1, test.max)
			}
		})
	}
}

func reviewedConfigurationResourceSchemas(t *testing.T) map[string]schema.Schema {
	t.Helper()

	locks := locking.NewRegistry()
	return map[string]schema.Schema{
		"global":  resourceSchema(t, globaltrustlist.NewResource(locks)),
		"anomaly": resourceSchema(t, anomalydetection.NewResource(locks)),
		"cors":    resourceSchema(t, corsprotection.NewResource(locks)),
		"ip":      resourceSchema(t, ipprotection.NewResource(locks)),
		"routing": resourceSchema(t, contentsrouting.NewResource(locks)),
		"custom":  resourceSchema(t, customrule.NewResource(locks)),
		"ml":      resourceSchema(t, mlapiprotection.NewResource(locks)),
	}
}

func resourceSchema(t *testing.T, implementation resource.Resource) schema.Schema {
	t.Helper()

	var response resource.SchemaResponse
	implementation.Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Schema() diagnostics = %v", response.Diagnostics)
	}
	return response.Schema
}

func lookupSchemaElement(t *testing.T, root schema.Schema, dottedPath string) any {
	t.Helper()

	attributes := root.Attributes
	blocks := root.Blocks
	segments := strings.Split(dottedPath, ".")
	for index, segment := range segments {
		last := index == len(segments)-1
		if attribute, ok := attributes[segment]; ok {
			if !last {
				t.Fatalf("%s: attribute %q is not the final path element", dottedPath, segment)
			}
			return attribute
		}
		block, ok := blocks[segment]
		if !ok {
			t.Fatalf("%s: schema element %q not found", dottedPath, segment)
		}
		if last {
			return block
		}
		switch nested := block.(type) {
		case schema.SingleNestedBlock:
			attributes = nested.Attributes
			blocks = nested.Blocks
		case schema.ListNestedBlock:
			attributes = nested.NestedObject.Attributes
			blocks = nested.NestedObject.Blocks
		default:
			t.Fatalf("%s: unsupported nested block type %T", dottedPath, block)
		}
	}
	t.Fatalf("%s: no schema element found", dottedPath)
	return nil
}

func runStringValidators(implementations []validator.String, dottedPath, value string) validator.StringResponse {
	var response validator.StringResponse
	for _, implementation := range implementations {
		implementation.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root(dottedPath),
			ConfigValue: types.StringValue(value),
		}, &response)
	}
	return response
}

func runInt64Validators(implementations []validator.Int64, dottedPath string, value int64) validator.Int64Response {
	var response validator.Int64Response
	for _, implementation := range implementations {
		implementation.ValidateInt64(context.Background(), validator.Int64Request{
			Path:        path.Root(dottedPath),
			ConfigValue: types.Int64Value(value),
		}, &response)
	}
	return response
}

func runListValidators(implementations []validator.List, dottedPath string, value types.List) validator.ListResponse {
	var response validator.ListResponse
	for _, implementation := range implementations {
		implementation.ValidateList(context.Background(), validator.ListRequest{
			Path:        path.Root(dottedPath),
			ConfigValue: value,
		}, &response)
	}
	return response
}

func repeatedValues(value attr.Value, count int) []attr.Value {
	result := make([]attr.Value, count)
	for index := range result {
		result[index] = value
	}
	return result
}
