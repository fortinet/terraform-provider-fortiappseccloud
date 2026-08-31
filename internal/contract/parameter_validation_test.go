package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestParameterValidationScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/parameter_validation", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_parameter_validation", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/parameter_validation", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_parameter_validation", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/parameter_validation", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_parameter_validation", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/parameter_validation", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_parameter_validation", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(ParameterValidationScope, want) {
		t.Fatalf("ParameterValidationScope = %#v, want %#v", ParameterValidationScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range ParameterValidationScope {
		operation, ok := document.Find(classification.Method, classification.Path)
		if !ok {
			t.Errorf("classification missing from OpenAPI: %s %s", classification.Method, classification.Path)
			continue
		}
		if !operation.Public {
			t.Errorf("classification is non-public: %s %s", classification.Method, classification.Path)
		}
		if classification.Disposition != DispositionDeferred && classification.ClientMethod == "" {
			t.Errorf("managed classification lacks client method: %s %s", classification.Method, classification.Path)
		}
	}
}

func TestParameterValidationResourceContract(t *testing.T) {
	t.Parallel()

	if ParameterValidationResource.TerraformName != "fortiappseccloud_waf_parameter_validation" {
		t.Fatalf("TerraformName = %q", ParameterValidationResource.TerraformName)
	}
	if ParameterValidationResource.GoName != "ParameterValidation" || ParameterValidationResource.TypeNameSuffix != "waf_parameter_validation" {
		t.Fatalf("resource identity = %#v", ParameterValidationResource)
	}
	if ParameterValidationResource.ImplementationState != ImplementationStateImplemented {
		t.Fatalf("ImplementationState = %q", ParameterValidationResource.ImplementationState)
	}
	if !reflect.DeepEqual(ParameterValidationResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", ParameterValidationResource.ExpectedMethods)
	}
	if ParameterValidationResource.Refs.GetResponse != "#/components/schemas/GetParameterValidation" ||
		ParameterValidationResource.Refs.PutRequest != "#/components/schemas/PutParameterValidation" ||
		ParameterValidationResource.Refs.Configs != "#/components/schemas/ParameterValidation" ||
		ParameterValidationResource.Refs.CollectionItem != "#/components/schemas/InputRule" {
		t.Fatalf("Refs = %#v", ParameterValidationResource.Refs)
	}
	if len(ParameterValidationResource.Schema.ConfigFields) != 1 {
		t.Fatalf("ConfigFields = %d, want 1", len(ParameterValidationResource.Schema.ConfigFields))
	}
	if len(ParameterValidationResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(ParameterValidationResource.Schema.Collections))
	}
	if ParameterValidationResource.Schema.Collections[0].Name != "rule_list" || ParameterValidationResource.Schema.Collections[0].MaxItems != 12 {
		t.Fatalf("rule_list = %#v", ParameterValidationResource.Schema.Collections[0])
	}

	fields := make(map[string]CandidateFieldConstraint, len(ParameterValidationResource.Schema.ItemFields))
	for _, field := range ParameterValidationResource.Schema.ItemFields {
		fields[field.Name] = field
	}
	if len(ParameterValidationResource.Schema.ItemFields) != 5 {
		t.Fatalf("ItemFields = %d, want 5", len(ParameterValidationResource.Schema.ItemFields))
	}

	// action is required with a reviewed enum.
	action, ok := fields["action"]
	if !ok {
		t.Fatal("missing action item field")
	}
	if !action.Required || len(action.Enum) != 4 {
		t.Fatalf("action = %#v, want required enum of 4", action)
	}
	// url is required with the ^/.*$ pattern.
	urlField, ok := fields["url"]
	if !ok {
		t.Fatal("missing url item field")
	}
	if !urlField.Required || urlField.Pattern != `^/.*$` {
		t.Fatalf("url = %#v, want required with ^/.*$ pattern", urlField)
	}
	// block_period is optional with range 1..3600 and default 60.
	blockPeriod, ok := fields["block_period"]
	if !ok {
		t.Fatal("missing block_period item field")
	}
	if blockPeriod.Required || blockPeriod.Minimum == nil || *blockPeriod.Minimum != 1 || blockPeriod.Maximum == nil || *blockPeriod.Maximum != 3600 {
		t.Fatalf("block_period = %#v, want optional 1..3600", blockPeriod)
	}

	// sub_rule_list is the nested array-of-objects item field.
	subRuleList, ok := fields["sub_rule_list"]
	if !ok {
		t.Fatal("missing sub_rule_list item field")
	}
	if subRuleList.Kind != "array" || subRuleList.SubItemArray == nil {
		t.Fatalf("sub_rule_list = %#v, want an array with SubItemArray", subRuleList)
	}
	if subRuleList.SubItemArray.MaxItems != 60 {
		t.Fatalf("sub_rule_list MaxItems = %d, want 60", subRuleList.SubItemArray.MaxItems)
	}
	if len(subRuleList.SubItemArray.ItemFields) != 6 {
		t.Fatalf("sub_rule_list item fields = %d, want 6 (excluding idx)", len(subRuleList.SubItemArray.ItemFields))
	}
	// max_len sub-item field pins range 0..1024 and default 0.
	subFields := make(map[string]CandidateFieldConstraint, len(subRuleList.SubItemArray.ItemFields))
	for _, f := range subRuleList.SubItemArray.ItemFields {
		subFields[f.Name] = f
	}
	maxLen, ok := subFields["max_len"]
	if !ok {
		t.Fatal("missing max_len sub-item field")
	}
	if maxLen.Minimum == nil || *maxLen.Minimum != 0 || maxLen.Maximum == nil || *maxLen.Maximum != 1024 {
		t.Fatalf("max_len = %#v, want 0..1024", maxLen)
	}
}
