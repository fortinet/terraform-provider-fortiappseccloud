package contentsrouting

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
)

// validateCrossFields applies the reviewed rule matrix from the official
// FortiAppSec Cloud Content Routing guide. The pinned OpenAPI supplies the
// exact wire enums; the guide supplies which fields belong to each match
// object. Unknown values are deferred until apply.
func validateCrossFields(ctx context.Context, model resourceModel) error {
	if model.PolicyList.IsNull() || model.PolicyList.IsUnknown() {
		return nil
	}
	var policyWrapper policyListWrapperModel
	if diagnostics := model.PolicyList.As(ctx, &policyWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode policy_list for validation: %s", diagnostics)
	}
	if policyWrapper.Item.IsNull() || policyWrapper.Item.IsUnknown() {
		return nil
	}
	var policies []policyItemModel
	if diagnostics := policyWrapper.Item.ElementsAs(ctx, &policies, false); diagnostics.HasError() {
		return fmt.Errorf("decode policy_list items for validation: %s", diagnostics)
	}
	if len(policies) > client.ContentRoutingMaxPolicies {
		return fmt.Errorf("policy_list may contain at most %d items", client.ContentRoutingMaxPolicies)
	}

	defaultCount := 0
	for policyIndex, policy := range policies {
		if configuredRoutingValue(policy.IsDefault) && policy.IsDefault.ValueBool() {
			defaultCount++
		}
		if configuredRoutingValue(policy.ServerPool) && strings.TrimSpace(policy.ServerPool.ValueString()) == "" {
			return fmt.Errorf("policy_list item %d server_pool must not be empty", policyIndex+1)
		}
		if policy.RuleList.IsNull() || policy.RuleList.IsUnknown() {
			continue
		}
		var ruleWrapper ruleListWrapperModel
		if diagnostics := policy.RuleList.As(ctx, &ruleWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
			return fmt.Errorf("decode policy_list item %d rule_list for validation: %s", policyIndex+1, diagnostics)
		}
		if ruleWrapper.Item.IsNull() || ruleWrapper.Item.IsUnknown() {
			continue
		}
		var rules []ruleItemModel
		if diagnostics := ruleWrapper.Item.ElementsAs(ctx, &rules, false); diagnostics.HasError() {
			return fmt.Errorf("decode policy_list item %d rule_list items for validation: %s", policyIndex+1, diagnostics)
		}
		if len(rules) > client.ContentRoutingMaxRules {
			return fmt.Errorf("policy_list item %d rule_list may contain at most %d items", policyIndex+1, client.ContentRoutingMaxRules)
		}
		for ruleIndex, rule := range rules {
			if err := validateRoutingRule(rule, policyIndex+1, ruleIndex+1); err != nil {
				return err
			}
		}
	}
	if defaultCount > 1 {
		return fmt.Errorf("policy_list may contain at most one item with is_default = true")
	}
	return nil
}

func validateRoutingRule(rule ruleItemModel, policyIndex, ruleIndex int) error {
	location := fmt.Sprintf("policy_list item %d rule_list item %d", policyIndex, ruleIndex)
	if !configuredRoutingValue(rule.MatchObject) {
		return fmt.Errorf("%s requires match_object", location)
	}
	matchObject := rule.MatchObject.ValueString()

	base := routingTypeSet("concatenate", "reverse")
	allowed := routingTypeSet()
	required := []routingNamedValue{}
	switch matchObject {
	case "url-parameter", "http-cookie", "http-header":
		allowed = routingTypeSet("name_match_condition", "name", "value_match_condition", "value")
		required = []routingNamedValue{
			{"name_match_condition", rule.NameMatchCondition},
			{"name", rule.Name},
			{"value_match_condition", rule.ValueMatchCondition},
			{"value", rule.Value},
		}
	case "http-host", "http-request", "http-referer", "https-sni":
		allowed = routingTypeSet("match_condition", "match_expression")
		required = []routingNamedValue{
			{"match_condition", rule.MatchCondition},
			{"match_expression", rule.MatchExpression},
		}
	case "source-ip":
		allowed = routingTypeSet("match_condition", "start_ip", "end_ip", "ip_list")
		required = []routingNamedValue{{"match_condition", rule.MatchCondition}}
	case "x509-certificate-Subject":
		allowed = routingTypeSet("x509_subject_name", "value_match_condition", "match_expression")
		required = []routingNamedValue{
			{"x509_subject_name", rule.X509SubjectName},
			{"value_match_condition", rule.ValueMatchCondition},
			{"match_expression", rule.MatchExpression},
		}
	case "x509-certificate-Extension":
		allowed = routingTypeSet("value_match_condition", "value")
		required = []routingNamedValue{
			{"value_match_condition", rule.ValueMatchCondition},
			{"value", rule.Value},
		}
	default:
		// The schema enum validator reports unsupported match objects.
		return nil
	}
	for field := range base {
		allowed[field] = struct{}{}
	}

	for _, field := range routingRuleValues(rule) {
		if !configuredRoutingValue(field.value) {
			continue
		}
		if _, ok := allowed[field.name]; !ok {
			return fmt.Errorf("%s field %q does not belong to match_object %q", location, field.name, matchObject)
		}
	}
	for _, field := range required {
		if err := requireRoutingValue(location, matchObject, field); err != nil {
			return err
		}
	}

	switch matchObject {
	case "http-host", "http-request", "http-referer", "https-sni":
		if configuredRoutingValue(rule.MatchCondition) &&
			!routingContains([]string{"match-begin", "match-end", "match-sub", "match-domain", "match-dir", "match-reg", "equal"}, rule.MatchCondition.ValueString()) {
			return fmt.Errorf("%s match_condition %q is not valid for match_object %q", location, rule.MatchCondition.ValueString(), matchObject)
		}
	case "source-ip":
		if configuredRoutingValue(rule.MatchCondition) {
			switch rule.MatchCondition.ValueString() {
			case "ip-range", "ip-range6":
				if err := requireRoutingValue(location, matchObject, routingNamedValue{"start_ip", rule.StartIP}); err != nil {
					return err
				}
				if err := requireRoutingValue(location, matchObject, routingNamedValue{"end_ip", rule.EndIP}); err != nil {
					return err
				}
				if configuredRoutingValue(rule.IPList) {
					return fmt.Errorf("%s ip_list is valid only when match_condition is %q", location, "ip-list")
				}
			case "ip-list":
				if err := requireRoutingValue(location, matchObject, routingNamedValue{"ip_list", rule.IPList}); err != nil {
					return err
				}
				if configuredRoutingValue(rule.StartIP) || configuredRoutingValue(rule.EndIP) {
					return fmt.Errorf("%s start_ip/end_ip are valid only for ip-range or ip-range6", location)
				}
			default:
				return fmt.Errorf("%s match_condition %q is not valid for match_object %q", location, rule.MatchCondition.ValueString(), matchObject)
			}
		}
	}
	return nil
}

func routingRuleValues(rule ruleItemModel) []routingNamedValue {
	return []routingNamedValue{
		{"match_condition", rule.MatchCondition},
		{"match_expression", rule.MatchExpression},
		{"name", rule.Name},
		{"value", rule.Value},
		{"concatenate", rule.Concatenate},
		{"reverse", rule.Reverse},
		{"start_ip", rule.StartIP},
		{"end_ip", rule.EndIP},
		{"ip_list", rule.IPList},
		{"name_match_condition", rule.NameMatchCondition},
		{"value_match_condition", rule.ValueMatchCondition},
		{"x509_subject_name", rule.X509SubjectName},
	}
}

type routingNamedValue struct {
	name  string
	value attr.Value
}

func requireRoutingValue(location, matchObject string, field routingNamedValue) error {
	if !configuredRoutingValue(field.value) {
		return fmt.Errorf("%s match_object %q requires %s", location, matchObject, field.name)
	}
	if value, ok := field.value.(basetypes.StringValue); ok && strings.TrimSpace(value.ValueString()) == "" {
		return fmt.Errorf("%s match_object %q requires non-empty %s", location, matchObject, field.name)
	}
	return nil
}

func configuredRoutingValue(value attr.Value) bool {
	return value != nil && !value.IsNull() && !value.IsUnknown()
}

func routingTypeSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func routingContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
