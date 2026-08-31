package customrule

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
)

type resourceModel struct {
	EPID     types.String `tfsdk:"ep_id"`
	Template types.Bool   `tfsdk:"template"`
	Configs  types.Object `tfsdk:"configs"`
}

type configsModel struct {
	Status   types.Bool   `tfsdk:"status"`
	RuleList types.Object `tfsdk:"rule_list"`
}

type ruleListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

type ruleItemModel struct {
	Name        types.String `tfsdk:"name"`
	Action      types.String `tfsdk:"action"`
	BlockPeriod types.Int64  `tfsdk:"block_period"`
	Challenge   types.String `tfsdk:"challenge"`
	FilterList  types.Object `tfsdk:"filter_list"`
}

type filterListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

type filterItemModel struct {
	Type               types.String `tfsdk:"type"`
	ReverseMatch       types.Bool   `tfsdk:"reverse_match"`
	IP                 types.String `tfsdk:"ip"`
	Username           types.String `tfsdk:"username"`
	URL                types.String `tfsdk:"url"`
	Name               types.String `tfsdk:"name"`
	Value              types.String `tfsdk:"value"`
	HeaderCheck        types.Bool   `tfsdk:"header_check"`
	HeaderType         types.String `tfsdk:"header_type"`
	HeaderName         types.String `tfsdk:"header_name"`
	HeaderValue        types.String `tfsdk:"header_value"`
	HeaderReverseMatch types.Bool   `tfsdk:"header_reverse_match"`
	MethodCheck        types.Bool   `tfsdk:"method_check"`
	MethodValue        types.String `tfsdk:"method_value"`
	MethodReverseMatch types.Bool   `tfsdk:"method_reverse_match"`
	HttpHlineMissing   types.Bool   `tfsdk:"http_hline_missing_check"`
	HttpHlineEmpty     types.Bool   `tfsdk:"http_hline_empty_check"`
	ContentTypes       types.List   `tfsdk:"content_types"`
	ResponseCode       types.Int64  `tfsdk:"response_code"`
	CrossSiteScripting types.Bool   `tfsdk:"cross_site_scripting"`
	SqlInjection       types.Bool   `tfsdk:"sql_injection"`
	GenericAttacks     types.Bool   `tfsdk:"generic_attacks"`
	KnownExploits      types.Bool   `tfsdk:"known_exploits"`
	Trojans            types.Bool   `tfsdk:"trojans"`
	Limit              types.Int64  `tfsdk:"limit"`
	Timeout            types.Int64  `tfsdk:"timeout"`
	Occurrence         types.Int64  `tfsdk:"occurrence"`
	Within             types.Int64  `tfsdk:"within"`
	TimeType           types.String `tfsdk:"time_type"`
	Start              types.String `tfsdk:"start"`
	End                types.String `tfsdk:"end"`
	CountryList        types.List   `tfsdk:"country_list"`
	MatchExclusively   types.Bool   `tfsdk:"match_exclusively"`
}

var configsAttributeTypes = map[string]attr.Type{
	"status":    types.BoolType,
	"rule_list": ruleListWrapperObjectTypes(),
}

func ruleListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: ruleItemObjectTypes()},
	}}
}

func ruleItemObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":         types.StringType,
		"action":       types.StringType,
		"block_period": types.Int64Type,
		"challenge":    types.StringType,
		"filter_list":  filterListWrapperObjectTypes(),
	}}
}

func filterListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: filterItemObjectTypes()},
	}}
}

func filterItemObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"type":                     types.StringType,
		"reverse_match":            types.BoolType,
		"ip":                       types.StringType,
		"username":                 types.StringType,
		"url":                      types.StringType,
		"name":                     types.StringType,
		"value":                    types.StringType,
		"header_check":             types.BoolType,
		"header_type":              types.StringType,
		"header_name":              types.StringType,
		"header_value":             types.StringType,
		"header_reverse_match":     types.BoolType,
		"method_check":             types.BoolType,
		"method_value":             types.StringType,
		"method_reverse_match":     types.BoolType,
		"http_hline_missing_check": types.BoolType,
		"http_hline_empty_check":   types.BoolType,
		"content_types":            types.ListType{ElemType: types.StringType},
		"response_code":            types.Int64Type,
		"cross_site_scripting":     types.BoolType,
		"sql_injection":            types.BoolType,
		"generic_attacks":          types.BoolType,
		"known_exploits":           types.BoolType,
		"trojans":                  types.BoolType,
		"limit":                    types.Int64Type,
		"timeout":                  types.Int64Type,
		"occurrence":               types.Int64Type,
		"within":                   types.Int64Type,
		"time_type":                types.StringType,
		"start":                    types.StringType,
		"end":                      types.StringType,
		"country_list":             types.ListType{ElemType: types.StringType},
		"match_exclusively":        types.BoolType,
	}}
}

func validateTemplateConfigs(model resourceModel) error {
	if model.Template.IsUnknown() || model.Configs.IsUnknown() {
		return nil
	}
	if model.Template.IsNull() {
		return fmt.Errorf("template must be configured")
	}
	if model.Template.ValueBool() && !model.Configs.IsNull() {
		return fmt.Errorf("configs must be omitted when template is true")
	}
	if !model.Template.ValueBool() && model.Configs.IsNull() {
		return fmt.Errorf("configs must be configured when template is false")
	}
	return nil
}

func mergeCustomRule(ctx context.Context, document client.CustomRuleDocument, template bool, configConfigs, planConfigs types.Object) (client.WAFModuleResult, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	updated := document.Result.Clone()
	updated.Template = template
	if template {
		return updated, diagnostics
	}
	if planConfigs.IsNull() || planConfigs.IsUnknown() {
		diagnostics.AddError("Invalid custom rule configuration", "configs must be configured when template is false.")
		return updated, diagnostics
	}
	var planValues configsModel
	diagnostics.Append(planConfigs.As(ctx, &planValues, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if planValues.Status.IsNull() || planValues.Status.IsUnknown() {
		diagnostics.AddError("Invalid custom rule configuration", "configs.status must be known during apply.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("status", planValues.Status.ValueBool()); err != nil {
		diagnostics.AddError("Unable to merge custom rule status", err.Error())
		return updated, diagnostics
	}

	if planValues.RuleList.IsNull() {
		return updated, diagnostics
	}
	if planValues.RuleList.IsUnknown() {
		diagnostics.AddError("Unknown custom rule rule_list", "The rule_list ownership wrapper must be known during apply.")
		return updated, diagnostics
	}
	var wrapper ruleListWrapperModel
	diagnostics.Append(planValues.RuleList.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if wrapper.Item.IsUnknown() {
		diagnostics.AddError("Unknown custom rule rule_list", "The rule_list item blocks must be known during apply.")
		return updated, diagnostics
	}
	rules := buildRuleList(ctx, wrapper.Item, document.Config.RuleList, &diagnostics)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if err := updated.SetConfig("rule_list", rules); err != nil {
		diagnostics.AddError("Unable to merge custom rule rule_list", err.Error())
		return updated, diagnostics
	}
	return updated, diagnostics
}

func buildRuleList(ctx context.Context, list types.List, freshRuleList []json.RawMessage, diagnostics *diag.Diagnostics) []any {
	if list.IsNull() {
		return []any{}
	}
	var entries []ruleItemModel
	diagnostics.Append(list.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return nil
	}
	if len(entries) > client.CustomRuleRuleListMaxEntries {
		diagnostics.AddError("Invalid custom rule rule_list",
			fmt.Sprintf("rule_list may contain at most %d item blocks.", client.CustomRuleRuleListMaxEntries))
		return nil
	}
	// Build a map of fresh GET raw rule items by idx for grafting filter_list.
	freshRuleByIdx := map[int]map[string]json.RawMessage{}
	for _, raw := range freshRuleList {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err == nil {
			idx := 1
			if rawIdx, ok := obj["idx"]; ok && !isJSONNull(rawIdx) {
				_ = json.Unmarshal(rawIdx, &idx)
			}
			freshRuleByIdx[idx] = obj
		}
	}
	rules := make([]any, 0, len(entries))
	for index, entry := range entries {
		if entry.Name.IsNull() || entry.Name.IsUnknown() || entry.Name.ValueString() == "" {
			diagnostics.AddError("Invalid custom rule rule_list",
				fmt.Sprintf("rule_list item %d requires a non-empty name.", index+1))
			return nil
		}
		name := entry.Name.ValueString()
		if utf8.RuneCountInString(name) > client.CustomRuleNameMaxLen {
			diagnostics.AddError("Invalid custom rule rule_list",
				fmt.Sprintf("rule_list item %d name exceeds %d UTF-8 characters.", index+1, client.CustomRuleNameMaxLen))
			return nil
		}
		if entry.Action.IsNull() || entry.Action.IsUnknown() {
			diagnostics.AddError("Invalid custom rule rule_list",
				fmt.Sprintf("rule_list item %d requires an action.", index+1))
			return nil
		}
		ruleObj := map[string]any{
			"idx":    index + 1,
			"name":   name,
			"action": entry.Action.ValueString(),
		}
		if !entry.BlockPeriod.IsNull() && !entry.BlockPeriod.IsUnknown() {
			ruleObj["block_period"] = entry.BlockPeriod.ValueInt64()
		}
		if !entry.Challenge.IsNull() && !entry.Challenge.IsUnknown() {
			ruleObj["challenge"] = entry.Challenge.ValueString()
		}
		if !entry.FilterList.IsNull() && !entry.FilterList.IsUnknown() {
			filters, filterDiag := buildFilterList(ctx, entry.FilterList, index+1)
			diagnostics.Append(filterDiag...)
			if filterDiag.HasError() {
				return nil
			}
			ruleObj["filter_list"] = filters
		} else if fresh, ok := freshRuleByIdx[index+1]; ok {
			// filter_list wrapper omitted: preserve the remote filter_list.
			if rawFilters, ok := fresh["filter_list"]; ok && !isJSONNull(rawFilters) {
				var remoteFilters []any
				if err := json.Unmarshal(rawFilters, &remoteFilters); err == nil {
					ruleObj["filter_list"] = remoteFilters
				}
			}
		}
		rules = append(rules, ruleObj)
	}
	return rules
}

func buildFilterList(ctx context.Context, filterListObj types.Object, ruleIdx int) ([]any, diag.Diagnostics) {
	var filterDiag diag.Diagnostics
	if filterListObj.IsNull() || filterListObj.IsUnknown() {
		return []any{}, filterDiag
	}
	var wrapper filterListWrapperModel
	filterDiag.Append(filterListObj.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if filterDiag.HasError() {
		return nil, filterDiag
	}
	if wrapper.Item.IsNull() || wrapper.Item.IsUnknown() {
		return []any{}, filterDiag
	}
	var entries []filterItemModel
	filterDiag.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
	if filterDiag.HasError() {
		return nil, filterDiag
	}
	if len(entries) > client.CustomRuleFilterListMaxEntries {
		filterDiag.AddError("Invalid custom rule filter_list",
			fmt.Sprintf("filter_list may contain at most %d item blocks.", client.CustomRuleFilterListMaxEntries))
		return nil, filterDiag
	}
	filters := make([]any, 0, len(entries))
	for index, entry := range entries {
		if entry.Type.IsNull() || entry.Type.IsUnknown() || entry.Type.ValueString() == "" {
			filterDiag.AddError("Invalid custom rule filter_list",
				fmt.Sprintf("rule_list item %d filter_list item %d requires a type.", ruleIdx, index+1))
			return nil, filterDiag
		}
		filterObj := map[string]any{
			"idx":  index + 1,
			"type": entry.Type.ValueString(),
		}
		// All filter fields are optional; only set non-null/non-unknown ones.
		if !entry.ReverseMatch.IsNull() && !entry.ReverseMatch.IsUnknown() {
			filterObj["reverse_match"] = entry.ReverseMatch.ValueBool()
		}
		if !entry.IP.IsNull() && !entry.IP.IsUnknown() {
			filterObj["ip"] = entry.IP.ValueString()
		}
		if !entry.Username.IsNull() && !entry.Username.IsUnknown() {
			if utf8.RuneCountInString(entry.Username.ValueString()) > client.CustomRuleUsernameMaxLen {
				filterDiag.AddError("Invalid custom rule filter_list",
					fmt.Sprintf("rule_list item %d filter_list item %d username exceeds %d UTF-8 characters.", ruleIdx, index+1, client.CustomRuleUsernameMaxLen))
				return nil, filterDiag
			}
			filterObj["username"] = entry.Username.ValueString()
		}
		if !entry.URL.IsNull() && !entry.URL.IsUnknown() {
			filterObj["url"] = entry.URL.ValueString()
		}
		if !entry.Name.IsNull() && !entry.Name.IsUnknown() {
			filterObj["name"] = entry.Name.ValueString()
		}
		if !entry.Value.IsNull() && !entry.Value.IsUnknown() {
			filterObj["value"] = entry.Value.ValueString()
		}
		if !entry.HeaderCheck.IsNull() && !entry.HeaderCheck.IsUnknown() {
			filterObj["header_check"] = entry.HeaderCheck.ValueBool()
		}
		if !entry.HeaderType.IsNull() && !entry.HeaderType.IsUnknown() {
			filterObj["header_type"] = entry.HeaderType.ValueString()
		}
		if !entry.HeaderName.IsNull() && !entry.HeaderName.IsUnknown() {
			filterObj["header_name"] = entry.HeaderName.ValueString()
		}
		if !entry.HeaderValue.IsNull() && !entry.HeaderValue.IsUnknown() {
			filterObj["header_value"] = entry.HeaderValue.ValueString()
		}
		if !entry.HeaderReverseMatch.IsNull() && !entry.HeaderReverseMatch.IsUnknown() {
			filterObj["header_reverse_match"] = entry.HeaderReverseMatch.ValueBool()
		}
		if !entry.MethodCheck.IsNull() && !entry.MethodCheck.IsUnknown() {
			filterObj["method_check"] = entry.MethodCheck.ValueBool()
		}
		if !entry.MethodValue.IsNull() && !entry.MethodValue.IsUnknown() {
			filterObj["method_value"] = entry.MethodValue.ValueString()
		}
		if !entry.MethodReverseMatch.IsNull() && !entry.MethodReverseMatch.IsUnknown() {
			filterObj["method_reverse_match"] = entry.MethodReverseMatch.ValueBool()
		}
		if !entry.HttpHlineMissing.IsNull() && !entry.HttpHlineMissing.IsUnknown() {
			filterObj["http_hline_missing_check"] = entry.HttpHlineMissing.ValueBool()
		}
		if !entry.HttpHlineEmpty.IsNull() && !entry.HttpHlineEmpty.IsUnknown() {
			filterObj["http_hline_empty_check"] = entry.HttpHlineEmpty.ValueBool()
		}
		if !entry.ContentTypes.IsNull() && !entry.ContentTypes.IsUnknown() {
			ctypes := make([]string, 0, len(entry.ContentTypes.Elements()))
			for _, e := range entry.ContentTypes.Elements() {
				if s, ok := e.(basetypes.StringValue); ok {
					ctypes = append(ctypes, s.ValueString())
				}
			}
			filterObj["content_types"] = ctypes
		}
		if !entry.ResponseCode.IsNull() && !entry.ResponseCode.IsUnknown() {
			filterObj["code"] = strconv.FormatInt(entry.ResponseCode.ValueInt64(), 10)
		}
		if !entry.CrossSiteScripting.IsNull() && !entry.CrossSiteScripting.IsUnknown() {
			filterObj["cross_site_scripting"] = entry.CrossSiteScripting.ValueBool()
		}
		if !entry.SqlInjection.IsNull() && !entry.SqlInjection.IsUnknown() {
			filterObj["sql_injection"] = entry.SqlInjection.ValueBool()
		}
		if !entry.GenericAttacks.IsNull() && !entry.GenericAttacks.IsUnknown() {
			filterObj["generic_attacks"] = entry.GenericAttacks.ValueBool()
		}
		if !entry.KnownExploits.IsNull() && !entry.KnownExploits.IsUnknown() {
			filterObj["known_exploits"] = entry.KnownExploits.ValueBool()
		}
		if !entry.Trojans.IsNull() && !entry.Trojans.IsUnknown() {
			filterObj["trojans"] = entry.Trojans.ValueBool()
		}
		if !entry.Limit.IsNull() && !entry.Limit.IsUnknown() {
			filterObj["limit"] = entry.Limit.ValueInt64()
		}
		if !entry.Timeout.IsNull() && !entry.Timeout.IsUnknown() {
			filterObj["timeout"] = entry.Timeout.ValueInt64()
		}
		if !entry.Occurrence.IsNull() && !entry.Occurrence.IsUnknown() {
			filterObj["occurrence"] = entry.Occurrence.ValueInt64()
		}
		if !entry.Within.IsNull() && !entry.Within.IsUnknown() {
			filterObj["within"] = entry.Within.ValueInt64()
		}
		if !entry.TimeType.IsNull() && !entry.TimeType.IsUnknown() {
			filterObj["time_type"] = entry.TimeType.ValueString()
		}
		if !entry.Start.IsNull() && !entry.Start.IsUnknown() {
			filterObj["start"] = entry.Start.ValueString()
		}
		if !entry.End.IsNull() && !entry.End.IsUnknown() {
			filterObj["end"] = entry.End.ValueString()
		}
		if !entry.CountryList.IsNull() && !entry.CountryList.IsUnknown() {
			countries := make([]string, 0, len(entry.CountryList.Elements()))
			for _, e := range entry.CountryList.Elements() {
				if s, ok := e.(basetypes.StringValue); ok {
					countries = append(countries, s.ValueString())
				}
			}
			filterObj["country_list"] = countries
		}
		if !entry.MatchExclusively.IsNull() && !entry.MatchExclusively.IsUnknown() {
			filterObj["match_exclusively"] = entry.MatchExclusively.ValueBool()
		}
		filters = append(filters, filterObj)
	}
	return filters, filterDiag
}

type ownershipSource uint8

const (
	ownershipPriorState ownershipSource = iota
	ownershipImported
	ownershipConfigured
)

func stateModel(epID string, document client.CustomRuleDocument, source ownershipSource, priorConfigs types.Object) (resourceModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	model := resourceModel{
		EPID:     types.StringValue(epID),
		Template: types.BoolValue(document.Result.Template),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}
	if document.Result.Template {
		return model, nil
	}
	owned := ruleListOwned(source, priorConfigs, &diagnostics)
	// For PriorState/Configured reads, the per-rule filter_list wrapper should
	// only be hydrated if the prior/plan state had it present. For Imported,
	// always hydrate.
	hydrateNested := source == ownershipImported
	attributes := map[string]attr.Value{
		"status":    types.BoolPointerValue(document.Config.Status),
		"rule_list": stateRuleListWrapper(document.Config.RuleList, owned, hydrateNested, priorConfigs, &diagnostics),
	}
	configs, objectDiag := types.ObjectValue(configsAttributeTypes, attributes)
	diagnostics.Append(objectDiag...)
	model.Configs = configs
	return model, diagnostics
}

func ruleListOwned(source ownershipSource, priorConfigs types.Object, diagnostics *diag.Diagnostics) bool {
	if source == ownershipImported {
		return true
	}
	if priorConfigs.IsNull() || priorConfigs.IsUnknown() {
		return false
	}
	var configs configsModel
	diagnostics.Append(priorConfigs.As(context.Background(), &configs, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return false
	}
	return !configs.RuleList.IsNull() && !configs.RuleList.IsUnknown()
}

func stateRuleListWrapper(rawItems []json.RawMessage, owned bool, hydrateNested bool, priorConfigs types.Object, diagnostics *diag.Diagnostics) types.Object {
	if !owned {
		return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
	}
	if rawItems == nil {
		return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
	}
	decoded, err := client.DecodeCustomRuleRuleList(rawItems)
	if err != nil {
		diagnostics.AddError("Unable to decode owned rule_list", err.Error())
		return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
	}
	// For PriorState/Configured reads, determine which prior/plan rule items
	// had a non-null filter_list wrapper. For Imported, hydrate all.
	var priorRuleItems []ruleItemModel
	if !hydrateNested && !priorConfigs.IsNull() && !priorConfigs.IsUnknown() {
		var configs configsModel
		diagnostics.Append(priorConfigs.As(context.Background(), &configs, basetypes.ObjectAsOptions{})...)
		if !configs.RuleList.IsNull() && !configs.RuleList.IsUnknown() {
			var wrapper ruleListWrapperModel
			diagnostics.Append(configs.RuleList.As(context.Background(), &wrapper, basetypes.ObjectAsOptions{})...)
			if !wrapper.Item.IsNull() && !wrapper.Item.IsUnknown() {
				diagnostics.Append(wrapper.Item.ElementsAs(context.Background(), &priorRuleItems, false)...)
			}
		}
	}
	values := make([]attr.Value, 0, len(decoded))
	for idx, raw := range decoded {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			diagnostics.AddError("Unable to decode rule_list item", err.Error())
			return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
		}
		// Determine whether to hydrate this rule's filter_list.
		shouldHydrateFilter := hydrateNested
		if !hydrateNested && idx < len(priorRuleItems) {
			shouldHydrateFilter = !priorRuleItems[idx].FilterList.IsNull() && !priorRuleItems[idx].FilterList.IsUnknown()
		}
		var filterListVal types.Object
		if shouldHydrateFilter {
			filterListVal = stateFilterListWrapper(obj["filter_list"], diagnostics)
		} else {
			filterListVal = types.ObjectNull(filterListWrapperObjectTypes().AttrTypes)
		}
		attrs := map[string]attr.Value{
			"name":         stringFromRaw(obj, "name"),
			"action":       stringFromRaw(obj, "action"),
			"block_period": int64FromRaw(obj, "block_period"),
			"challenge":    stringFromRaw(obj, "challenge"),
			"filter_list":  filterListVal,
		}
		ruleObj, ruleDiag := types.ObjectValue(ruleItemObjectTypes().AttrTypes, attrs)
		diagnostics.Append(ruleDiag...)
		values = append(values, ruleObj)
	}
	list, listDiag := types.ListValue(ruleItemObjectTypes(), values)
	diagnostics.Append(listDiag...)
	wrapper, wrapperDiag := types.ObjectValue(ruleListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	diagnostics.Append(wrapperDiag...)
	return wrapper
}

func stateFilterListWrapper(rawFilters json.RawMessage, diagnostics *diag.Diagnostics) types.Object {
	if len(rawFilters) == 0 || string(rawFilters) == "null" {
		return types.ObjectNull(filterListWrapperObjectTypes().AttrTypes)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(rawFilters, &items); err != nil {
		diagnostics.AddError("Unable to decode filter_list", err.Error())
		return types.ObjectNull(filterListWrapperObjectTypes().AttrTypes)
	}
	// Strict decode: fail-closed unknown filter keys and 200-item bound.
	if err := client.DecodeCustomRuleFilterList(items); err != nil {
		diagnostics.AddError("Unable to decode owned filter_list", err.Error())
		return types.ObjectNull(filterListWrapperObjectTypes().AttrTypes)
	}
	type indexedFilter struct {
		idx int
		raw json.RawMessage
	}
	indexed := make([]indexedFilter, 0, len(items))
	for position, raw := range items {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			diagnostics.AddError("Unable to decode filter_list item", err.Error())
			return types.ObjectNull(filterListWrapperObjectTypes().AttrTypes)
		}
		idx := position + 1
		if rawIdx, ok := object["idx"]; ok && !isJSONNull(rawIdx) {
			_ = json.Unmarshal(rawIdx, &idx)
		}
		indexed = append(indexed, indexedFilter{idx: idx, raw: raw})
	}
	sort.SliceStable(indexed, func(i, j int) bool { return indexed[i].idx < indexed[j].idx })

	values := make([]attr.Value, 0, len(items))
	for _, indexedFilter := range indexed {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(indexedFilter.raw, &obj); err != nil {
			diagnostics.AddError("Unable to decode filter_list item", err.Error())
			return types.ObjectNull(filterListWrapperObjectTypes().AttrTypes)
		}
		attrs := map[string]attr.Value{
			"type":                     stringFromRaw(obj, "type"),
			"reverse_match":            boolFromRaw(obj, "reverse_match"),
			"ip":                       stringFromRaw(obj, "ip"),
			"username":                 stringFromRaw(obj, "username"),
			"url":                      stringFromRaw(obj, "url"),
			"name":                     stringFromRaw(obj, "name"),
			"value":                    stringFromRaw(obj, "value"),
			"header_check":             boolFromRaw(obj, "header_check"),
			"header_type":              stringFromRaw(obj, "header_type"),
			"header_name":              stringFromRaw(obj, "header_name"),
			"header_value":             stringFromRaw(obj, "header_value"),
			"header_reverse_match":     boolFromRaw(obj, "header_reverse_match"),
			"method_check":             boolFromRaw(obj, "method_check"),
			"method_value":             stringFromRaw(obj, "method_value"),
			"method_reverse_match":     boolFromRaw(obj, "method_reverse_match"),
			"http_hline_missing_check": boolFromRaw(obj, "http_hline_missing_check"),
			"http_hline_empty_check":   boolFromRaw(obj, "http_hline_empty_check"),
			"content_types":            stringListFromRaw(obj, "content_types", diagnostics),
			"response_code":            int64StringFromRaw(obj, "code"),
			"cross_site_scripting":     boolFromRaw(obj, "cross_site_scripting"),
			"sql_injection":            boolFromRaw(obj, "sql_injection"),
			"generic_attacks":          boolFromRaw(obj, "generic_attacks"),
			"known_exploits":           boolFromRaw(obj, "known_exploits"),
			"trojans":                  boolFromRaw(obj, "trojans"),
			"limit":                    int64FromRaw(obj, "limit"),
			"timeout":                  int64FromRaw(obj, "timeout"),
			"occurrence":               int64FromRaw(obj, "occurrence"),
			"within":                   int64FromRaw(obj, "within"),
			"time_type":                stringFromRaw(obj, "time_type"),
			"start":                    stringFromRaw(obj, "start"),
			"end":                      stringFromRaw(obj, "end"),
			"country_list":             stringListFromRaw(obj, "country_list", diagnostics),
			"match_exclusively":        boolFromRaw(obj, "match_exclusively"),
		}
		filterObj, filterDiag := types.ObjectValue(filterItemObjectTypes().AttrTypes, attrs)
		diagnostics.Append(filterDiag...)
		values = append(values, filterObj)
	}
	list, listDiag := types.ListValue(filterItemObjectTypes(), values)
	diagnostics.Append(listDiag...)
	wrapper, wrapperDiag := types.ObjectValue(filterListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	diagnostics.Append(wrapperDiag...)
	return wrapper
}

func isJSONNull(val json.RawMessage) bool {
	return len(val) == 0 || string(val) == "null"
}

func stringFromRaw(raw map[string]json.RawMessage, key string) types.String {
	val, ok := raw[key]
	if !ok || len(val) == 0 || string(val) == "null" {
		return types.StringNull()
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func boolFromRaw(raw map[string]json.RawMessage, key string) types.Bool {
	val, ok := raw[key]
	if !ok || len(val) == 0 || string(val) == "null" {
		return types.BoolNull()
	}
	var b bool
	if err := json.Unmarshal(val, &b); err != nil {
		return types.BoolNull()
	}
	return types.BoolValue(b)
}

func int64FromRaw(raw map[string]json.RawMessage, key string) types.Int64 {
	val, ok := raw[key]
	if !ok || len(val) == 0 || string(val) == "null" {
		return types.Int64Null()
	}
	var i int64
	if err := json.Unmarshal(val, &i); err != nil {
		return types.Int64Null()
	}
	return types.Int64Value(i)
}

func int64StringFromRaw(raw map[string]json.RawMessage, key string) types.Int64 {
	val, ok := raw[key]
	if !ok || len(val) == 0 || string(val) == "null" {
		return types.Int64Null()
	}
	var encoded string
	if err := json.Unmarshal(val, &encoded); err != nil {
		return types.Int64Null()
	}
	value, err := strconv.ParseInt(encoded, 10, 64)
	if err != nil {
		return types.Int64Null()
	}
	return types.Int64Value(value)
}

func stringListFromRaw(raw map[string]json.RawMessage, key string, diagnostics *diag.Diagnostics) types.List {
	val, ok := raw[key]
	if !ok || len(val) == 0 || string(val) == "null" {
		return types.ListNull(types.StringType)
	}
	var items []string
	if err := json.Unmarshal(val, &items); err != nil {
		return types.ListNull(types.StringType)
	}
	values := make([]attr.Value, 0, len(items))
	for _, s := range items {
		values = append(values, types.StringValue(s))
	}
	list, listDiag := types.ListValue(types.StringType, values)
	diagnostics.Append(listDiag...)
	return list
}
