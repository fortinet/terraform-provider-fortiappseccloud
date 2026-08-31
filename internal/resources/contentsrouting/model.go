package contentsrouting

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
)

type resourceModel struct {
	EPID       types.String `tfsdk:"ep_id"`
	Status     types.Bool   `tfsdk:"status"`
	PolicyList types.Object `tfsdk:"policy_list"`
}

// policyListWrapperModel models the policy_list ownership wrapper.
type policyListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

// policyItemModel models one policy_list item (a content-routing policy).
type policyItemModel struct {
	Name       types.String `tfsdk:"name"`
	ServerPool types.String `tfsdk:"server_pool"`
	IsDefault  types.Bool   `tfsdk:"is_default"`
	RuleList   types.Object `tfsdk:"rule_list"`
}

// ruleListWrapperModel models the rule_list ownership wrapper inside a policy.
type ruleListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

// ruleItemModel models one rule_list item (a routing rule). The known fields
// are typed; unknown fields are preserved by the reviewed ownership policy.
type ruleItemModel struct {
	MatchObject         types.String `tfsdk:"match_object"`
	MatchCondition      types.String `tfsdk:"match_condition"`
	MatchExpression     types.String `tfsdk:"match_expression"`
	Name                types.String `tfsdk:"name"`
	Value               types.String `tfsdk:"value"`
	Concatenate         types.String `tfsdk:"concatenate"`
	Reverse             types.Bool   `tfsdk:"reverse"`
	StartIP             types.String `tfsdk:"start_ip"`
	EndIP               types.String `tfsdk:"end_ip"`
	IPList              types.String `tfsdk:"ip_list"`
	NameMatchCondition  types.String `tfsdk:"name_match_condition"`
	ValueMatchCondition types.String `tfsdk:"value_match_condition"`
	X509SubjectName     types.String `tfsdk:"x509_subject_name"`
}

func policyListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: policyItemObjectTypes()},
	}}
}

func policyItemObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":        types.StringType,
		"server_pool": types.StringType,
		"is_default":  types.BoolType,
		"rule_list":   ruleListWrapperObjectTypes(),
	}}
}

func ruleListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: ruleItemObjectTypes()},
	}}
}

func ruleItemObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"match_object":          types.StringType,
		"match_condition":       types.StringType,
		"match_expression":      types.StringType,
		"name":                  types.StringType,
		"value":                 types.StringType,
		"concatenate":           types.StringType,
		"reverse":               types.BoolType,
		"start_ip":              types.StringType,
		"end_ip":                types.StringType,
		"ip_list":               types.StringType,
		"name_match_condition":  types.StringType,
		"value_match_condition": types.StringType,
		"x509_subject_name":     types.StringType,
	}}
}

// policyKnownKeys are the policy_list item keys Terraform models and owns.
// When Terraform owns the policy_list, these fields are authoritative from
// config: a null config value omits the key on the wire (cleared, not preserved
// from the remote). Only keys NOT in this set are grafted from the fresh GET
// (reviewed opaque preservation of unknown keys).
var policyKnownKeys = map[string]struct{}{
	"idx":         {},
	"name":        {},
	"server_pool": {},
	"is_default":  {},
	"rule_list":   {},
}

// ruleKnownKeys are the rule_list item keys Terraform models and owns. When
// Terraform owns the rule_list, these fields are authoritative from config: a
// null config value omits the key on the wire (the field is cleared, not
// preserved from the remote). Only keys NOT in this set are grafted from the
// fresh GET (reviewed opaque preservation of unknown keys).
var ruleKnownKeys = map[string]struct{}{
	"idx":                   {},
	"match_object":          {},
	"match_condition":       {},
	"match_expression":      {},
	"name":                  {},
	"value":                 {},
	"concatenate":           {},
	"reverse":               {},
	"start_ip":              {},
	"end_ip":                {},
	"ip_list":               {},
	"name_match_condition":  {},
	"value_match_condition": {},
	"x509_subject_name":     {},
}

// validateConfigs enforces that status is configured.
func validateConfigs(model resourceModel) error {
	if model.Status.IsUnknown() {
		return nil
	}
	if model.Status.IsNull() {
		return fmt.Errorf("status must be configured")
	}
	return nil
}

// mergeContentRouting overlays the Terraform-owned status and policy_list onto a
// fresh GET result, preserving unknown envelope fields. policy_list is overlaid
// only when the wrapper is present (omitted preserves the remote array opaquely).
// Unknown keys in policy/rule objects are preserved by policy.
func mergeContentRouting(ctx context.Context, document client.ContentRoutingDocument, plan resourceModel) (client.ContentRoutingResult, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	updated := document.Result.Clone()

	if plan.Status.IsNull() || plan.Status.IsUnknown() {
		diagnostics.AddError("Invalid content routing configuration", "status must be known during apply.")
		return updated, diagnostics
	}
	updated.Status = plan.Status.ValueBool()

	if plan.PolicyList.IsNull() {
		// Wrapper omitted: preserve the remote array opaquely.
		return updated, diagnostics
	}
	if plan.PolicyList.IsUnknown() {
		diagnostics.AddError("Unknown content routing policy_list", "The policy_list ownership wrapper must be known during apply.")
		return updated, diagnostics
	}

	var wrapper policyListWrapperModel
	diagnostics.Append(plan.PolicyList.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if wrapper.Item.IsUnknown() {
		diagnostics.AddError("Unknown content routing policy_list", "The policy_list item blocks must be known during apply.")
		return updated, diagnostics
	}

	// Build the wire policy_list from the Terraform-owned items. Each policy item
	// is encoded as a raw JSON object preserving unknown keys (INCLUDE semantics)
	// by grafting from the fresh GET's raw policy items (matched by idx).
	items := []json.RawMessage{}
	if !wrapper.Item.IsNull() {
		var entries []policyItemModel
		diagnostics.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
		if diagnostics.HasError() {
			return updated, diagnostics
		}
		// Build a map of fresh GET raw policy items by idx for grafting.
		freshByIdx := map[int]map[string]json.RawMessage{}
		for _, raw := range document.Config.PolicyList {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err == nil {
				idx := 1
				if rawIdx, ok := obj["idx"]; ok && !isJSONNull(rawIdx) {
					_ = json.Unmarshal(rawIdx, &idx)
				}
				freshByIdx[idx] = obj
			}
		}
		for index, entry := range entries {
			if entry.Name.IsNull() || entry.Name.IsUnknown() || entry.Name.ValueString() == "" {
				diagnostics.AddError("Invalid content routing policy_list",
					fmt.Sprintf("policy_list item %d requires a non-empty name.", index+1))
				return updated, diagnostics
			}
			// Graft only UNKNOWN keys from the fresh GET (reviewed opaque
			// preservation). Known policy keys are owned by Terraform: a
			// null config value omits the key on the wire (cleared, not preserved
			// from the remote), so they are NOT grafted and are written below only
			// when non-null.
			policyObj := map[string]any{}
			if fresh, ok := freshByIdx[index+1]; ok {
				for k, v := range fresh {
					if _, known := policyKnownKeys[k]; !known {
						var val any
						if err := json.Unmarshal(v, &val); err == nil {
							policyObj[k] = val
						}
					}
				}
			}
			// Overlay the Terraform-owned known fields.
			policyObj["idx"] = index + 1
			policyObj["name"] = entry.Name.ValueString()
			if !entry.ServerPool.IsNull() && !entry.ServerPool.IsUnknown() {
				policyObj["server_pool"] = entry.ServerPool.ValueString()
			}
			if !entry.IsDefault.IsNull() && !entry.IsDefault.IsUnknown() {
				policyObj["is_default"] = entry.IsDefault.ValueBool()
			}
			// rule_list: build from the nested wrapper, grafting unknown keys from
			// the fresh GET's raw rules (INCLUDE semantics).
			if !entry.RuleList.IsNull() && !entry.RuleList.IsUnknown() {
				var freshRules []json.RawMessage
				if fresh, ok := freshByIdx[index+1]; ok {
					if rawRules, ok := fresh["rule_list"]; ok && !isJSONNull(rawRules) {
						_ = json.Unmarshal(rawRules, &freshRules)
					}
				}
				ruleItems, ruleDiag := buildRuleList(ctx, entry.RuleList, index+1, freshRules)
				diagnostics.Append(ruleDiag...)
				if diagnostics.HasError() {
					return updated, diagnostics
				}
				policyObj["rule_list"] = ruleItems
			}
			encoded, err := json.Marshal(policyObj)
			if err != nil {
				diagnostics.AddError("Unable to encode policy_list item", err.Error())
				return updated, diagnostics
			}
			items = append(items, encoded)
		}
	}
	updated.PolicyList = items
	return updated, diagnostics
}

func buildRuleList(ctx context.Context, ruleListObj types.Object, policyIdx int, freshRules []json.RawMessage) ([]any, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if ruleListObj.IsNull() || ruleListObj.IsUnknown() {
		return []any{}, diagnostics
	}
	var wrapper ruleListWrapperModel
	diagnostics.Append(ruleListObj.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	if wrapper.Item.IsNull() || wrapper.Item.IsUnknown() {
		return []any{}, diagnostics
	}
	var entries []ruleItemModel
	diagnostics.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	rules := make([]any, 0, len(entries))
	// Build a map of fresh GET raw rule items by idx for grafting.
	freshRuleByIdx := map[int]map[string]any{}
	for _, rawRule := range freshRules {
		var obj map[string]any
		if err := json.Unmarshal(rawRule, &obj); err == nil {
			idx := 1
			if rawIdx, ok := obj["idx"]; ok {
				if f, ok := rawIdx.(float64); ok {
					idx = int(f)
				}
			}
			freshRuleByIdx[idx] = obj
		}
	}
	for index, entry := range entries {
		// Graft only UNKNOWN keys from the fresh GET (reviewed opaque
		// preservation). Known rule keys are owned by Terraform: a null
		// config value omits the key on the wire (the field is cleared, not
		// preserved from the remote), so they are NOT grafted and are written
		// below only when non-null.
		ruleObj := map[string]any{}
		if fresh, ok := freshRuleByIdx[index+1]; ok {
			for k, v := range fresh {
				if _, known := ruleKnownKeys[k]; !known {
					ruleObj[k] = v
				}
			}
		}
		ruleObj["idx"] = index + 1
		if !entry.MatchObject.IsNull() && !entry.MatchObject.IsUnknown() {
			ruleObj["match_object"] = entry.MatchObject.ValueString()
		}
		if !entry.MatchCondition.IsNull() && !entry.MatchCondition.IsUnknown() {
			ruleObj["match_condition"] = entry.MatchCondition.ValueString()
		}
		if !entry.MatchExpression.IsNull() && !entry.MatchExpression.IsUnknown() {
			ruleObj["match_expression"] = entry.MatchExpression.ValueString()
		}
		if !entry.Name.IsNull() && !entry.Name.IsUnknown() {
			ruleObj["name"] = entry.Name.ValueString()
		}
		if !entry.Value.IsNull() && !entry.Value.IsUnknown() {
			ruleObj["value"] = entry.Value.ValueString()
		}
		if !entry.Concatenate.IsNull() && !entry.Concatenate.IsUnknown() {
			ruleObj["concatenate"] = entry.Concatenate.ValueString()
		}
		if !entry.Reverse.IsNull() && !entry.Reverse.IsUnknown() {
			ruleObj["reverse"] = entry.Reverse.ValueBool()
		}
		if !entry.StartIP.IsNull() && !entry.StartIP.IsUnknown() {
			ruleObj["start_ip"] = entry.StartIP.ValueString()
		}
		if !entry.EndIP.IsNull() && !entry.EndIP.IsUnknown() {
			ruleObj["end_ip"] = entry.EndIP.ValueString()
		}
		if !entry.IPList.IsNull() && !entry.IPList.IsUnknown() {
			ruleObj["ip_list"] = entry.IPList.ValueString()
		}
		if !entry.NameMatchCondition.IsNull() && !entry.NameMatchCondition.IsUnknown() {
			ruleObj["name_match_condition"] = entry.NameMatchCondition.ValueString()
		}
		if !entry.ValueMatchCondition.IsNull() && !entry.ValueMatchCondition.IsUnknown() {
			ruleObj["value_match_condition"] = entry.ValueMatchCondition.ValueString()
		}
		if !entry.X509SubjectName.IsNull() && !entry.X509SubjectName.IsUnknown() {
			ruleObj["x509_subject_name"] = entry.X509SubjectName.ValueString()
		}
		rules = append(rules, ruleObj)
	}
	return rules, diagnostics
}

// ownershipSource tells stateModel whether Terraform owns the policy_list.
type ownershipSource uint8

const (
	ownershipPriorState ownershipSource = iota
	ownershipImported
	ownershipConfigured
)

func stateModel(epID string, document client.ContentRoutingDocument, source ownershipSource, priorPolicyList types.Object) (resourceModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	model := resourceModel{
		EPID:       types.StringValue(epID),
		Status:     types.BoolPointerValue(document.Config.Status),
		PolicyList: types.ObjectNull(policyListWrapperObjectTypes().AttrTypes),
	}
	owned := policyListOwned(source, priorPolicyList, &diagnostics)
	if !owned {
		return model, nil
	}
	// Flatten the remote policy_list into the wrapper (preserving unknown keys
	// opaquely — the raw items are decoded to typed known fields; unknown keys
	// are not surfaced in Terraform state but are carried forward through the
	// raw envelope on PUT).
	policyItems := flattenPolicyList(document.Config.PolicyList, &diagnostics)
	wrapper, wrapperDiag := types.ObjectValue(policyListWrapperObjectTypes().AttrTypes, map[string]attr.Value{
		"item": policyItems,
	})
	diagnostics.Append(wrapperDiag...)
	model.PolicyList = wrapper
	return model, diagnostics
}

func policyListOwned(source ownershipSource, priorPolicyList types.Object, diagnostics *diag.Diagnostics) bool {
	if source == ownershipImported {
		return true
	}
	if priorPolicyList.IsNull() || priorPolicyList.IsUnknown() {
		return false
	}
	return true
}

func flattenPolicyList(rawItems []json.RawMessage, diagnostics *diag.Diagnostics) types.List {
	if rawItems == nil {
		return types.ListNull(policyItemObjectTypes())
	}
	if err := client.ValidateContentRoutingPolicyList(rawItems); err != nil {
		diagnostics.AddError("Unable to decode owned policy_list", err.Error())
		return types.ListNull(policyItemObjectTypes())
	}
	values := make([]attr.Value, 0, len(rawItems))
	// Sort by idx for canonical ordering.
	type indexedItem struct {
		idx int
		raw map[string]json.RawMessage
	}
	items := make([]indexedItem, 0, len(rawItems))
	for position, raw := range rawItems {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			diagnostics.AddError("Unable to decode policy_list item", err.Error())
			return types.ListNull(policyItemObjectTypes())
		}
		idx := position + 1
		if rawIdx, ok := obj["idx"]; ok && !isJSONNull(rawIdx) {
			_ = json.Unmarshal(rawIdx, &idx)
		}
		items = append(items, indexedItem{idx: idx, raw: obj})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].idx < items[j].idx })
	for _, item := range items {
		attrs := map[string]attr.Value{
			"name":        stringFromRaw(item.raw, "name"),
			"server_pool": stringFromRaw(item.raw, "server_pool"),
			"is_default":  boolFromRaw(item.raw, "is_default"),
			"rule_list":   flattenRuleList(item.raw, diagnostics),
		}
		obj, objDiag := types.ObjectValue(policyItemObjectTypes().AttrTypes, attrs)
		diagnostics.Append(objDiag...)
		values = append(values, obj)
	}
	list, listDiag := types.ListValue(policyItemObjectTypes(), values)
	diagnostics.Append(listDiag...)
	return list
}

func flattenRuleList(policyRaw map[string]json.RawMessage, diagnostics *diag.Diagnostics) types.Object {
	ruleListRaw, ok := policyRaw["rule_list"]
	if !ok || isJSONNull(ruleListRaw) {
		return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
	}
	var rawRules []json.RawMessage
	if err := json.Unmarshal(ruleListRaw, &rawRules); err != nil {
		diagnostics.AddError("Unable to decode rule_list", err.Error())
		return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
	}
	type indexedRule struct {
		idx int
		raw json.RawMessage
	}
	indexed := make([]indexedRule, 0, len(rawRules))
	for position, rawRule := range rawRules {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawRule, &object); err != nil {
			diagnostics.AddError("Unable to decode rule_list item", err.Error())
			return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
		}
		idx := position + 1
		if rawIdx, ok := object["idx"]; ok && !isJSONNull(rawIdx) {
			_ = json.Unmarshal(rawIdx, &idx)
		}
		indexed = append(indexed, indexedRule{idx: idx, raw: rawRule})
	}
	sort.SliceStable(indexed, func(i, j int) bool { return indexed[i].idx < indexed[j].idx })

	values := make([]attr.Value, 0, len(indexed))
	for _, indexedRule := range indexed {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(indexedRule.raw, &obj); err != nil {
			diagnostics.AddError("Unable to decode rule_list item", err.Error())
			return types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
		}
		attrs := map[string]attr.Value{
			"match_object":          stringFromRaw(obj, "match_object"),
			"match_condition":       stringFromRaw(obj, "match_condition"),
			"match_expression":      stringFromRaw(obj, "match_expression"),
			"name":                  stringFromRaw(obj, "name"),
			"value":                 stringFromRaw(obj, "value"),
			"concatenate":           stringFromRaw(obj, "concatenate"),
			"reverse":               boolFromRaw(obj, "reverse"),
			"start_ip":              stringFromRaw(obj, "start_ip"),
			"end_ip":                stringFromRaw(obj, "end_ip"),
			"ip_list":               stringFromRaw(obj, "ip_list"),
			"name_match_condition":  stringFromRaw(obj, "name_match_condition"),
			"value_match_condition": stringFromRaw(obj, "value_match_condition"),
			"x509_subject_name":     stringFromRaw(obj, "x509_subject_name"),
		}
		ruleObj, ruleDiag := types.ObjectValue(ruleItemObjectTypes().AttrTypes, attrs)
		diagnostics.Append(ruleDiag...)
		values = append(values, ruleObj)
	}
	list, listDiag := types.ListValue(ruleItemObjectTypes(), values)
	diagnostics.Append(listDiag...)
	wrapper, wrapperDiag := types.ObjectValue(ruleListWrapperObjectTypes().AttrTypes, map[string]attr.Value{
		"item": list,
	})
	diagnostics.Append(wrapperDiag...)
	return wrapper
}

func stringFromRaw(raw map[string]json.RawMessage, key string) types.String {
	val, ok := raw[key]
	if !ok || isJSONNull(val) {
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
	if !ok || isJSONNull(val) {
		return types.BoolNull()
	}
	var b bool
	if err := json.Unmarshal(val, &b); err != nil {
		return types.BoolNull()
	}
	return types.BoolValue(b)
}

func isJSONNull(val json.RawMessage) bool {
	return len(val) == 0 || string(val) == "null"
}
