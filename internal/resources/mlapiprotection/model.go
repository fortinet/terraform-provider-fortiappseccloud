package mlapiprotection

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
	Status       types.Bool   `tfsdk:"status"`
	ThreatAction types.String `tfsdk:"threat_action"`
	IPListType   types.String `tfsdk:"ip_list_type"`
	IPList       types.Object `tfsdk:"ip_list"`
	PathList     types.Object `tfsdk:"path_list"`
}

type ipListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

type ipEntryModel struct {
	IP types.String `tfsdk:"ip"`
}

type pathListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

type pathEntryModel struct {
	Type    types.String `tfsdk:"type"`
	Pattern types.String `tfsdk:"pattern"`
}

var configsAttributeTypes = map[string]attr.Type{
	"status":        types.BoolType,
	"threat_action": types.StringType,
	"ip_list_type":  types.StringType,
	"ip_list":       ipListWrapperObjectTypes(),
	"path_list":     pathListWrapperObjectTypes(),
}

func ipListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: ipEntryObjectTypes()},
	}}
}

func ipEntryObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"ip": types.StringType}}
}

func pathListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: pathEntryObjectTypes()},
	}}
}

func pathEntryObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"type":    types.StringType,
		"pattern": types.StringType,
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

// validateRequiredConfigs enforces MlApiProtection's required request fields
// while allowing Terraform to omit the complete configs block for template=true.
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
	case values.ThreatAction.IsNull():
		return fmt.Errorf("configs.threat_action must be configured")
	case values.IPListType.IsNull():
		return fmt.Errorf("configs.ip_list_type must be configured")
	}
	return nil
}

func mergeMlApiProtection(ctx context.Context, document client.MlApiProtectionDocument, template bool, configConfigs, planConfigs types.Object) (client.WAFModuleResult, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	updated := document.Result.Clone()
	updated.Template = template
	if template {
		return updated, diagnostics
	}
	if planConfigs.IsNull() || planConfigs.IsUnknown() {
		diagnostics.AddError("Invalid ml api protection configuration", "configs must be configured when template is false.")
		return updated, diagnostics
	}
	var planValues configsModel
	diagnostics.Append(planConfigs.As(ctx, &planValues, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	// Required scalars: reject null/unknown
	if planValues.Status.IsNull() || planValues.Status.IsUnknown() {
		diagnostics.AddError("Invalid ml api protection configuration", "configs.status must be known during apply.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("status", planValues.Status.ValueBool()); err != nil {
		diagnostics.AddError("Unable to merge ml api protection status", err.Error())
		return updated, diagnostics
	}
	if planValues.ThreatAction.IsNull() || planValues.ThreatAction.IsUnknown() {
		diagnostics.AddError("Invalid ml api protection configuration", "configs.threat_action must be known during apply.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("threat_action", planValues.ThreatAction.ValueString()); err != nil {
		diagnostics.AddError("Unable to merge ml api protection threat_action", err.Error())
		return updated, diagnostics
	}
	if planValues.IPListType.IsNull() || planValues.IPListType.IsUnknown() {
		diagnostics.AddError("Invalid ml api protection configuration", "configs.ip_list_type must be known during apply.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("ip_list_type", planValues.IPListType.ValueString()); err != nil {
		diagnostics.AddError("Unable to merge ml api protection ip_list_type", err.Error())
		return updated, diagnostics
	}
	// ip_list ownership wrapper
	if !planValues.IPList.IsNull() && !planValues.IPList.IsUnknown() {
		owned, ownedDiag := buildOwnedIPList(ctx, planValues.IPList)
		diagnostics.Append(ownedDiag...)
		if diagnostics.HasError() {
			return updated, diagnostics
		}
		if owned.Set {
			if err := updated.SetConfig("ip_list", owned.Items); err != nil {
				diagnostics.AddError("Unable to merge ml api protection ip_list", err.Error())
				return updated, diagnostics
			}
		}
	}
	// path_list ownership wrapper
	if !planValues.PathList.IsNull() && !planValues.PathList.IsUnknown() {
		owned, ownedDiag := buildOwnedPathList(ctx, planValues.PathList)
		diagnostics.Append(ownedDiag...)
		if diagnostics.HasError() {
			return updated, diagnostics
		}
		if owned.Set {
			if err := updated.SetConfig("path_list", owned.Items); err != nil {
				diagnostics.AddError("Unable to merge ml api protection path_list", err.Error())
				return updated, diagnostics
			}
		}
	}
	return updated, diagnostics
}

type ownedIPList struct {
	Set   bool
	Items []client.MlApiProtectionIPListEntry
}

func buildOwnedIPList(ctx context.Context, ipListObj types.Object) (ownedIPList, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if ipListObj.IsNull() || ipListObj.IsUnknown() {
		return ownedIPList{}, diagnostics
	}
	var wrapper ipListWrapperModel
	diagnostics.Append(ipListObj.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return ownedIPList{}, diagnostics
	}
	if wrapper.Item.IsUnknown() {
		diagnostics.AddError("Unknown ml api protection ip_list", "The ip_list item blocks must be known during apply.")
		return ownedIPList{}, diagnostics
	}
	owned := ownedIPList{Set: true, Items: []client.MlApiProtectionIPListEntry{}}
	if wrapper.Item.IsNull() {
		return owned, diagnostics
	}
	var entries []ipEntryModel
	diagnostics.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return ownedIPList{}, diagnostics
	}
	if len(entries) > client.MlApiProtectionIPListMaxEntries {
		diagnostics.AddError("Invalid ml api protection ip_list",
			fmt.Sprintf("ip_list may contain at most %d item blocks.", client.MlApiProtectionIPListMaxEntries))
		return ownedIPList{}, diagnostics
	}
	items := make([]client.MlApiProtectionIPListEntry, 0, len(entries))
	for index, entry := range entries {
		if entry.IP.IsNull() || entry.IP.IsUnknown() || entry.IP.ValueString() == "" {
			diagnostics.AddError("Invalid ml api protection ip_list",
				fmt.Sprintf("ip_list item %d requires a non-empty ip.", index+1))
			return ownedIPList{}, diagnostics
		}
		items = append(items, client.MlApiProtectionIPListEntry{IDX: index + 1, IP: entry.IP.ValueString()})
	}
	owned.Items = items
	return owned, diagnostics
}

type ownedPathList struct {
	Set   bool
	Items []client.MlApiProtectionPathListEntry
}

func buildOwnedPathList(ctx context.Context, pathListObj types.Object) (ownedPathList, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if pathListObj.IsNull() || pathListObj.IsUnknown() {
		return ownedPathList{}, diagnostics
	}
	var wrapper pathListWrapperModel
	diagnostics.Append(pathListObj.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return ownedPathList{}, diagnostics
	}
	if wrapper.Item.IsUnknown() {
		diagnostics.AddError("Unknown ml api protection path_list", "The path_list item blocks must be known during apply.")
		return ownedPathList{}, diagnostics
	}
	owned := ownedPathList{Set: true, Items: []client.MlApiProtectionPathListEntry{}}
	if wrapper.Item.IsNull() {
		return owned, diagnostics
	}
	var entries []pathEntryModel
	diagnostics.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return ownedPathList{}, diagnostics
	}
	if len(entries) > client.MlApiProtectionPathListMaxEntries {
		diagnostics.AddError("Invalid ml api protection path_list",
			fmt.Sprintf("path_list may contain at most %d item blocks.", client.MlApiProtectionPathListMaxEntries))
		return ownedPathList{}, diagnostics
	}
	items := make([]client.MlApiProtectionPathListEntry, 0, len(entries))
	for index, entry := range entries {
		if entry.Type.IsNull() || entry.Type.IsUnknown() || entry.Type.ValueString() == "" {
			diagnostics.AddError("Invalid ml api protection path_list",
				fmt.Sprintf("path_list item %d requires a non-empty type.", index+1))
			return ownedPathList{}, diagnostics
		}
		if entry.Pattern.IsNull() || entry.Pattern.IsUnknown() || entry.Pattern.ValueString() == "" {
			diagnostics.AddError("Invalid ml api protection path_list",
				fmt.Sprintf("path_list item %d requires a non-empty pattern.", index+1))
			return ownedPathList{}, diagnostics
		}
		if entry.Pattern.ValueString()[0] != '/' {
			diagnostics.AddError("Invalid ml api protection path_list",
				fmt.Sprintf("path_list item %d pattern must start with /.", index+1))
			return ownedPathList{}, diagnostics
		}
		items = append(items, client.MlApiProtectionPathListEntry{IDX: index + 1, Type: entry.Type.ValueString(), Pattern: entry.Pattern.ValueString()})
	}
	owned.Items = items
	return owned, diagnostics
}

type ownershipSource uint8

const (
	ownershipPriorState ownershipSource = iota
	ownershipImported
	ownershipConfigured
)

func stateModel(epID string, document client.MlApiProtectionDocument, source ownershipSource, priorConfigs types.Object) (resourceModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	model := resourceModel{
		EPID:     types.StringValue(epID),
		Template: types.BoolValue(document.Result.Template),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}
	if document.Result.Template {
		return model, nil
	}
	ownedIP := ipListOwned(source, priorConfigs, &diagnostics)
	ownedPath := pathListOwned(source, priorConfigs, &diagnostics)
	attributes := map[string]attr.Value{
		"status":        types.BoolPointerValue(document.Config.Status),
		"threat_action": types.StringPointerValue(document.Config.ThreatAction),
		"ip_list_type":  types.StringPointerValue(document.Config.IPListType),
		"ip_list":       stateIPListWrapper(document.Config.IPList, ownedIP, &diagnostics),
		"path_list":     statePathListWrapper(document.Config.PathList, ownedPath, &diagnostics),
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

func pathListOwned(source ownershipSource, priorConfigs types.Object, diagnostics *diag.Diagnostics) bool {
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
	return !configs.PathList.IsNull() && !configs.PathList.IsUnknown()
}

func stateIPListWrapper(rawItems []json.RawMessage, owned bool, diagnostics *diag.Diagnostics) types.Object {
	if !owned {
		return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
	}
	if rawItems == nil {
		return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
	}
	entries, err := client.DecodeMlApiProtectionIPList(rawItems)
	if err != nil {
		diagnostics.AddError("Unable to decode owned ip_list", err.Error())
		return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
	}
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		obj, _ := types.ObjectValue(ipEntryObjectTypes().AttrTypes, map[string]attr.Value{"ip": types.StringValue(entry.IP)})
		values = append(values, obj)
	}
	list, _ := types.ListValue(ipEntryObjectTypes(), values)
	wrapper, _ := types.ObjectValue(ipListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	return wrapper
}

func statePathListWrapper(rawItems []json.RawMessage, owned bool, diagnostics *diag.Diagnostics) types.Object {
	if !owned {
		return types.ObjectNull(pathListWrapperObjectTypes().AttrTypes)
	}
	if rawItems == nil {
		return types.ObjectNull(pathListWrapperObjectTypes().AttrTypes)
	}
	entries, err := client.DecodeMlApiProtectionPathList(rawItems)
	if err != nil {
		diagnostics.AddError("Unable to decode owned path_list", err.Error())
		return types.ObjectNull(pathListWrapperObjectTypes().AttrTypes)
	}
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		obj, _ := types.ObjectValue(pathEntryObjectTypes().AttrTypes, map[string]attr.Value{
			"type":    types.StringValue(entry.Type),
			"pattern": types.StringValue(entry.Pattern),
		})
		values = append(values, obj)
	}
	list, _ := types.ListValue(pathEntryObjectTypes(), values)
	wrapper, _ := types.ObjectValue(pathListWrapperObjectTypes().AttrTypes, map[string]attr.Value{"item": list})
	return wrapper
}
