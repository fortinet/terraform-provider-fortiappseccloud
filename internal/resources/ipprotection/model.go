package ipprotection

import (
	"context"
	"encoding/json"
	"fmt"

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
	Status           types.Bool   `tfsdk:"status"`
	IPReputation     types.Bool   `tfsdk:"ip_reputation"`
	GeoIPMode        types.String `tfsdk:"geo_ip_mode"`
	BlockCountryList types.List   `tfsdk:"block_country_list"`
	IPList           types.Object `tfsdk:"ip_list"`
}

type ipListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

type ipEntryModel struct {
	Type types.String `tfsdk:"type"`
	IP   types.String `tfsdk:"ip"`
}

var configsAttributeTypes = map[string]attr.Type{
	"status":             types.BoolType,
	"ip_reputation":      types.BoolType,
	"geo_ip_mode":        types.StringType,
	"block_country_list": types.ListType{ElemType: types.StringType},
	"ip_list":            ipListWrapperObjectTypes(),
}

func ipListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: ipEntryObjectTypes()},
	}}
}

func ipEntryObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"type": types.StringType,
		"ip":   types.StringType,
	}}
}

// validateTemplateConfigs enforces the template/configs mutual exclusion.
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

// validateRequiredConfigs enforces IPProtectionPut's required fields while
// allowing Terraform to omit the complete configs block for template=true.
func validateRequiredConfigs(ctx context.Context, configs types.Object) error {
	if configs.IsNull() || configs.IsUnknown() {
		return nil
	}
	var values configsModel
	if diagnostics := configs.As(ctx, &values, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode configs for validation: %s", diagnostics)
	}
	switch {
	case values.Status.IsNull():
		return fmt.Errorf("configs.status must be configured")
	case values.IPReputation.IsNull():
		return fmt.Errorf("configs.ip_reputation must be configured")
	}
	return nil
}

// ownershipSource tells stateModel whether Terraform owns the ip_list for this
// read, controlling whether the remote array is flattened or preserved opaquely.
type ownershipSource uint8

const (
	ownershipPriorState ownershipSource = iota
	ownershipImported
	ownershipConfigured
)

// mergeIPProtection overlays the Terraform-owned config scalars and, when the
// ip_list wrapper is present, the ordered ip_list onto a fresh GET result,
// preserving unknown envelope/config fields. Optional scalars (geo_ip_mode,
// block_country_list) are overlaid only when present in config (configConfigs);
// an omitted optional preserves the fresh-GET value. The ip_list is overlaid
// only when the wrapper is present (planConfigs), preserving the remote array
// opaquely when omitted.
func mergeIPProtection(ctx context.Context, document client.IPProtectionDocument, template bool, configConfigs, planConfigs types.Object) (client.WAFModuleResult, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	updated := document.Result.Clone()
	updated.Template = template
	// The clone carries the fresh GET ip_list verbatim, including GET-only idx
	// and production's explicit-null inactive rule-type placeholders. Prepare
	// the carried-forward array for PUT before any path can return: drop only
	// exact reviewed placeholders, strip idx from active entries, and preserve
	// other active-entry fields opaquely. The owned path below replaces this
	// prepared array with Terraform's active PUT entries.
	if len(document.Config.IPList) > 0 {
		prepared, err := client.PrepareIPProtectionIPListForPut(document.Config.IPList)
		if err != nil {
			diagnostics.AddError("Unable to merge ip protection ip_list", err.Error())
			return updated, diagnostics
		}
		if err := updated.SetConfig("ip_list", prepared); err != nil {
			diagnostics.AddError("Unable to merge ip protection ip_list", err.Error())
			return updated, diagnostics
		}
	}
	if template {
		return updated, diagnostics
	}
	if planConfigs.IsNull() || planConfigs.IsUnknown() {
		diagnostics.AddError("Invalid ip protection configuration", "configs must be configured when template is false.")
		return updated, diagnostics
	}
	var planValues configsModel
	diagnostics.Append(planConfigs.As(ctx, &planValues, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	var configValues configsModel
	if !configConfigs.IsNull() && !configConfigs.IsUnknown() {
		diagnostics.Append(configConfigs.As(ctx, &configValues, basetypes.ObjectAsOptions{})...)
		if diagnostics.HasError() {
			return updated, diagnostics
		}
	} else {
		configValues = planValues
	}

	if planValues.Status.IsNull() || planValues.Status.IsUnknown() {
		diagnostics.AddError("Invalid ip protection configuration", "configs.status must be known during apply.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("status", planValues.Status.ValueBool()); err != nil {
		diagnostics.AddError("Unable to merge ip protection status", err.Error())
		return updated, diagnostics
	}
	if planValues.IPReputation.IsNull() || planValues.IPReputation.IsUnknown() {
		diagnostics.AddError("Invalid ip protection configuration", "configs.ip_reputation must be known during apply.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("ip_reputation", planValues.IPReputation.ValueBool()); err != nil {
		diagnostics.AddError("Unable to merge ip protection ip_reputation", err.Error())
		return updated, diagnostics
	}
	if !configValues.GeoIPMode.IsNull() && !configValues.GeoIPMode.IsUnknown() {
		if err := updated.SetConfig("geo_ip_mode", planValues.GeoIPMode.ValueString()); err != nil {
			diagnostics.AddError("Unable to merge ip protection geo_ip_mode", err.Error())
			return updated, diagnostics
		}
	}
	if !configValues.BlockCountryList.IsNull() && !configValues.BlockCountryList.IsUnknown() {
		countries := make([]string, 0, len(planValues.BlockCountryList.Elements()))
		for _, element := range planValues.BlockCountryList.Elements() {
			if s, ok := element.(basetypes.StringValue); ok {
				countries = append(countries, s.ValueString())
			}
		}
		if err := updated.SetConfig("block_country_list", countries); err != nil {
			diagnostics.AddError("Unable to merge ip protection block_country_list", err.Error())
			return updated, diagnostics
		}
	}

	owned, ownedDiag := buildOwnedIPList(ctx, planConfigs)
	diagnostics.Append(ownedDiag...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if owned.Set {
		// Owned wrapper: replace ip_list with the PUT shape (type/ip only, no
		// idx). This overrides the up-front strip, which already removed idx
		// from the carried-forward remote array for the omitted path.
		if err := updated.SetConfig("ip_list", owned.Items); err != nil {
			diagnostics.AddError("Unable to merge ip protection ip_list", err.Error())
			return updated, diagnostics
		}
	}
	return updated, diagnostics
}

// ownedIPList records whether the ip_list wrapper is present and the ordered
// entries Terraform owns, in the reviewed PUT/write shape that omits wire-only
// idx. Set=false preserves the raw remote array opaquely; Set=true with empty
// Items sends []; Set=true with populated Items replaces the array in Terraform
// order.
type ownedIPList struct {
	Set   bool
	Items []client.IPProtectionIPListPutEntry
}

// buildOwnedIPList produces the owned ip_list from the Terraform wrapper in the
// reviewed PUT/write shape (type and ip only; wire-only idx is GET-only and
// omitted on write per the pinned PutIPProtection schema), enforcing the
// reviewed 256-item bound and required non-empty ip. Wire-only idx is never in
// state.
func buildOwnedIPList(ctx context.Context, configs types.Object) (ownedIPList, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if configs.IsNull() || configs.IsUnknown() {
		return ownedIPList{}, diagnostics
	}
	var values configsModel
	diagnostics.Append(configs.As(ctx, &values, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return ownedIPList{}, diagnostics
	}
	if values.IPList.IsNull() {
		return ownedIPList{Set: false}, diagnostics
	}
	if values.IPList.IsUnknown() {
		diagnostics.AddError("Unknown ip protection ip_list", "The ip_list ownership wrapper must be known during apply.")
		return ownedIPList{}, diagnostics
	}
	var wrapper ipListWrapperModel
	diagnostics.Append(values.IPList.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return ownedIPList{}, diagnostics
	}
	if wrapper.Item.IsUnknown() {
		diagnostics.AddError("Unknown ip protection ip_list", "The ip_list item blocks must be known during apply.")
		return ownedIPList{}, diagnostics
	}
	owned := ownedIPList{Set: true, Items: []client.IPProtectionIPListPutEntry{}}
	if wrapper.Item.IsNull() {
		return owned, diagnostics
	}
	var entries []ipEntryModel
	diagnostics.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return ownedIPList{}, diagnostics
	}
	if len(entries) > client.IPProtectionIPListMaxEntries {
		diagnostics.AddError("Invalid ip protection ip_list",
			fmt.Sprintf("ip_list may contain at most %d item blocks.", client.IPProtectionIPListMaxEntries))
		return ownedIPList{}, diagnostics
	}
	items := make([]client.IPProtectionIPListPutEntry, 0, len(entries))
	for index, entry := range entries {
		if entry.IP.IsNull() || entry.IP.IsUnknown() || entry.IP.ValueString() == "" {
			diagnostics.AddError("Invalid ip protection ip_list",
				fmt.Sprintf("ip_list item %d requires a non-empty ip.", index+1))
			return ownedIPList{}, diagnostics
		}
		item := client.IPProtectionIPListPutEntry{IP: entry.IP.ValueString()}
		if !entry.Type.IsNull() && !entry.Type.IsUnknown() {
			item.Type = entry.Type.ValueString()
		}
		items = append(items, item)
	}
	owned.Items = items
	return owned, diagnostics
}

func stateModel(epID string, document client.IPProtectionDocument, source ownershipSource, priorConfigs types.Object) (resourceModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	model := resourceModel{
		EPID:     types.StringValue(epID),
		Template: types.BoolValue(document.Result.Template),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}
	if document.Result.Template {
		return model, nil
	}
	owned := ipListOwned(source, priorConfigs, &diagnostics)
	attributes := map[string]attr.Value{
		"status":             types.BoolPointerValue(document.Config.Status),
		"ip_reputation":      types.BoolPointerValue(document.Config.IPReputation),
		"geo_ip_mode":        types.StringPointerValue(document.Config.GeoIPMode),
		"block_country_list": stateStringList(document.Config.BlockCountryList, &diagnostics),
		"ip_list":            stateIPListWrapper(document.Config.IPList, owned, &diagnostics),
	}
	configs, objectDiag := types.ObjectValue(configsAttributeTypes, attributes)
	diagnostics.Append(objectDiag...)
	model.Configs = configs
	return model, diagnostics
}

func ipListOwned(source ownershipSource, priorConfigs types.Object, diagnostics *diag.Diagnostics) bool {
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
	return !configs.IPList.IsNull() && !configs.IPList.IsUnknown()
}

func stateStringList(values []string, diagnostics *diag.Diagnostics) types.List {
	if values == nil {
		return types.ListNull(types.StringType)
	}
	elemValues := make([]attr.Value, 0, len(values))
	for _, v := range values {
		elemValues = append(elemValues, types.StringValue(v))
	}
	list, listDiag := types.ListValue(types.StringType, elemValues)
	diagnostics.Append(listDiag...)
	return list
}

func stateIPListWrapper(rawItems []json.RawMessage, owned bool, diagnostics *diag.Diagnostics) types.Object {
	if !owned {
		return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
	}
	entries, err := client.DecodeIPProtectionIPList(rawItems)
	if err != nil {
		diagnostics.AddError("Unable to decode owned ip_list", err.Error())
		return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
	}
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		attributes := map[string]attr.Value{
			"type": types.StringValue(entry.Type),
			"ip":   types.StringValue(entry.IP),
		}
		object, objectDiag := types.ObjectValue(ipEntryObjectTypes().AttrTypes, attributes)
		diagnostics.Append(objectDiag...)
		values = append(values, object)
	}
	list, listDiag := types.ListValue(ipEntryObjectTypes(), values)
	diagnostics.Append(listDiag...)
	wrapper, wrapperDiag := types.ObjectValue(ipListWrapperObjectTypes().AttrTypes, map[string]attr.Value{
		"item": list,
	})
	diagnostics.Append(wrapperDiag...)
	return wrapper
}
