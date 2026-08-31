package customrule

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	dailyTimePattern = regexp.MustCompile(`^\d{2}:\d{2}$`)
	onceTimePattern  = regexp.MustCompile(`^\d{2}:\d{2} \d{4}/\d{2}/\d{2}$`)
)

// validateCrossFields enforces relationships backed by the pinned
// CustomRuleFilter schema descriptions and the reviewed FortiAppSec Cloud
// Custom Rule guide. Unknown values are deferred until apply.
func validateCrossFields(ctx context.Context, model resourceModel) error {
	if model.Template.IsNull() || model.Template.IsUnknown() || model.Template.ValueBool() ||
		model.Configs.IsNull() || model.Configs.IsUnknown() {
		return nil
	}

	var configs configsModel
	if diagnostics := model.Configs.As(ctx, &configs, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode configs for validation: %s", diagnostics)
	}
	if configs.Status.IsNull() {
		return fmt.Errorf("configs.status must be configured")
	}
	if configs.RuleList.IsNull() || configs.RuleList.IsUnknown() {
		return nil
	}

	var ruleWrapper ruleListWrapperModel
	if diagnostics := configs.RuleList.As(ctx, &ruleWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode rule_list for validation: %s", diagnostics)
	}
	if ruleWrapper.Item.IsNull() || ruleWrapper.Item.IsUnknown() {
		return nil
	}

	var rules []ruleItemModel
	if diagnostics := ruleWrapper.Item.ElementsAs(ctx, &rules, false); diagnostics.HasError() {
		return fmt.Errorf("decode rule_list items for validation: %s", diagnostics)
	}
	for ruleIndex, rule := range rules {
		if err := validateRuleCrossFields(ctx, rule, ruleIndex+1); err != nil {
			return err
		}
	}
	return nil
}

func validateRuleCrossFields(ctx context.Context, rule ruleItemModel, ruleIndex int) error {
	if !rule.Action.IsNull() && !rule.Action.IsUnknown() {
		action := rule.Action.ValueString()
		hasBlockPeriod := configured(rule.BlockPeriod)
		if action == "block_period" && !hasBlockPeriod {
			return fmt.Errorf("rule_list item %d action %q requires block_period", ruleIndex, action)
		}
		if action != "block_period" && hasBlockPeriod {
			return fmt.Errorf("rule_list item %d block_period is valid only when action is %q", ruleIndex, "block_period")
		}
	}

	// The reviewed guide defines challenge independently of action, so no
	// action/challenge restriction is imposed.
	if rule.FilterList.IsNull() || rule.FilterList.IsUnknown() {
		return nil
	}
	var filterWrapper filterListWrapperModel
	if diagnostics := rule.FilterList.As(ctx, &filterWrapper, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode rule_list item %d filter_list for validation: %s", ruleIndex, diagnostics)
	}
	if filterWrapper.Item.IsNull() || filterWrapper.Item.IsUnknown() {
		return nil
	}
	var filters []filterItemModel
	if diagnostics := filterWrapper.Item.ElementsAs(ctx, &filters, false); diagnostics.HasError() {
		return fmt.Errorf("decode rule_list item %d filter_list items for validation: %s", ruleIndex, diagnostics)
	}
	for filterIndex, filter := range filters {
		if err := validateFilterCrossFields(filter, ruleIndex, filterIndex+1); err != nil {
			return err
		}
	}
	return nil
}

func validateFilterCrossFields(filter filterItemModel, ruleIndex, filterIndex int) error {
	if filter.Type.IsNull() || filter.Type.IsUnknown() {
		return nil
	}
	filterType := filter.Type.ValueString()

	fields := []struct {
		name    string
		value   attr.Value
		allowed map[string]struct{}
	}{
		{"reverse_match", filter.ReverseMatch, typeSet("source-ip-filter", "user-filter", "url-filter")},
		{"ip", filter.IP, typeSet("source-ip-filter")},
		{"username", filter.Username, typeSet("user-filter")},
		{"url", filter.URL, typeSet("url-filter")},
		{"name", filter.Name, typeSet("parameter")},
		{"value", filter.Value, typeSet("parameter")},
		{"header_check", filter.HeaderCheck, typeSet("http-header-filter")},
		{"header_type", filter.HeaderType, typeSet("http-header-filter")},
		{"header_name", filter.HeaderName, typeSet("http-header-filter")},
		{"header_value", filter.HeaderValue, typeSet("http-header-filter")},
		{"header_reverse_match", filter.HeaderReverseMatch, typeSet("http-header-filter")},
		{"method_check", filter.MethodCheck, typeSet("http-header-filter")},
		{"method_value", filter.MethodValue, typeSet("http-header-filter")},
		{"method_reverse_match", filter.MethodReverseMatch, typeSet("http-header-filter")},
		{"http_hline_missing_check", filter.HttpHlineMissing, typeSet("http-header-filter")},
		{"http_hline_empty_check", filter.HttpHlineEmpty, typeSet("http-header-filter")},
		{"content_types", filter.ContentTypes, typeSet("content-type")},
		{"response_code", filter.ResponseCode, typeSet("response-code")},
		{"cross_site_scripting", filter.CrossSiteScripting, typeSet("security-rules")},
		{"sql_injection", filter.SqlInjection, typeSet("security-rules")},
		{"generic_attacks", filter.GenericAttacks, typeSet("security-rules")},
		{"known_exploits", filter.KnownExploits, typeSet("security-rules")},
		{"trojans", filter.Trojans, typeSet("security-rules")},
		{"limit", filter.Limit, typeSet("access-limit-filter")},
		{"timeout", filter.Timeout, typeSet("packet-interval", "http-transaction")},
		{"occurrence", filter.Occurrence, typeSet("occurrence")},
		{"within", filter.Within, typeSet("occurrence")},
		{"time_type", filter.TimeType, typeSet("time-range-filter")},
		{"start", filter.Start, typeSet("time-range-filter")},
		{"end", filter.End, typeSet("time-range-filter")},
		// OpenAPI 26.3.a includes geo-filter in the discriminator and binds these
		// fields to that variant.
		{"country_list", filter.CountryList, typeSet("geo-filter")},
		{"match_exclusively", filter.MatchExclusively, typeSet("geo-filter")},
	}
	for _, field := range fields {
		if !configured(field.value) {
			continue
		}
		if _, ok := field.allowed[filterType]; !ok {
			return fmt.Errorf(
				"rule_list item %d filter_list item %d field %q does not belong to filter type %q",
				ruleIndex, filterIndex, field.name, filterType,
			)
		}
	}

	if err := validateRequiredFilterFields(filter, filterType); err != nil {
		return fmt.Errorf("rule_list item %d filter_list item %d: %w", ruleIndex, filterIndex, err)
	}
	if filterType == "http-header-filter" &&
		boolTrue(filter.HttpHlineMissing) && boolTrue(filter.HttpHlineEmpty) {
		return fmt.Errorf(
			"rule_list item %d filter_list item %d cannot enable both http_hline_missing_check and http_hline_empty_check",
			ruleIndex, filterIndex,
		)
	}
	if filterType == "time-range-filter" && configured(filter.TimeType) {
		layout := "15:04"
		pattern := dailyTimePattern
		if filter.TimeType.ValueString() == "once" {
			layout = "15:04 2006/01/02"
			pattern = onceTimePattern
		}
		for _, value := range []struct {
			name  string
			value types.String
		}{
			{"start", filter.Start},
			{"end", filter.End},
		} {
			if !configured(value.value) {
				continue
			}
			if !pattern.MatchString(value.value.ValueString()) {
				return fmt.Errorf(
					"rule_list item %d filter_list item %d %s must use format %q for time_type %q",
					ruleIndex, filterIndex, value.name, layout, filter.TimeType.ValueString(),
				)
			}
			if _, err := time.Parse(layout, value.value.ValueString()); err != nil {
				return fmt.Errorf(
					"rule_list item %d filter_list item %d %s is not a valid time for time_type %q",
					ruleIndex, filterIndex, value.name, filter.TimeType.ValueString(),
				)
			}
		}
	}
	return nil
}

func validateRequiredFilterFields(filter filterItemModel, filterType string) error {
	switch filterType {
	case "source-ip-filter":
		return requireConfigured(filterType, "ip", filter.IP)
	case "user-filter":
		return requireConfigured(filterType, "username", filter.Username)
	case "url-filter":
		return requireConfigured(filterType, "url", filter.URL)
	case "parameter":
		return requireAllConfigured(filterType,
			namedValue{"name", filter.Name},
			namedValue{"value", filter.Value},
		)
	case "http-header-filter":
		if !boolTrue(filter.HeaderCheck) && !boolTrue(filter.MethodCheck) {
			return fmt.Errorf("filter type %q requires header_check or method_check to be true", filterType)
		}
	case "content-type":
		if !configured(filter.ContentTypes) || len(filter.ContentTypes.Elements()) == 0 {
			return fmt.Errorf("filter type %q requires a non-empty content_types list", filterType)
		}
	case "response-code":
		return requireConfigured(filterType, "response_code", filter.ResponseCode)
	case "security-rules":
		if !boolTrue(filter.CrossSiteScripting) && !boolTrue(filter.SqlInjection) &&
			!boolTrue(filter.GenericAttacks) && !boolTrue(filter.KnownExploits) &&
			!boolTrue(filter.Trojans) {
			return fmt.Errorf("filter type %q requires at least one attack category to be true", filterType)
		}
	case "access-limit-filter":
		return requireConfigured(filterType, "limit", filter.Limit)
	case "packet-interval", "http-transaction":
		return requireConfigured(filterType, "timeout", filter.Timeout)
	case "occurrence":
		return requireAllConfigured(filterType,
			namedValue{"occurrence", filter.Occurrence},
			namedValue{"within", filter.Within},
		)
	case "time-range-filter":
		return requireAllConfigured(filterType,
			namedValue{"time_type", filter.TimeType},
			namedValue{"start", filter.Start},
			namedValue{"end", filter.End},
		)
	}
	return nil
}

type namedValue struct {
	name  string
	value attr.Value
}

func requireConfigured(filterType, name string, value attr.Value) error {
	if !configured(value) {
		return fmt.Errorf("filter type %q requires %s", filterType, name)
	}
	if stringValue, ok := value.(basetypes.StringValue); ok && strings.TrimSpace(stringValue.ValueString()) == "" {
		return fmt.Errorf("filter type %q requires non-empty %s", filterType, name)
	}
	return nil
}

func requireAllConfigured(filterType string, values ...namedValue) error {
	for _, value := range values {
		if err := requireConfigured(filterType, value.name, value.value); err != nil {
			return err
		}
	}
	return nil
}

func configured(value attr.Value) bool {
	return value != nil && !value.IsNull() && !value.IsUnknown()
}

func boolTrue(value types.Bool) bool {
	return configured(value) && value.ValueBool()
}

func typeSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
