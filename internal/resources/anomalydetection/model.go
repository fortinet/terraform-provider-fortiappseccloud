package anomalydetection

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
	Status     types.Bool   `tfsdk:"status"`
	Action     types.String `tfsdk:"action"`
	IPListType types.String `tfsdk:"ip_list_type"`
	IPList     types.Object `tfsdk:"ip_list"`
}

// ipListWrapperModel models the ip_list ownership wrapper. Its item block is
// the ordered list of IP entries.
type ipListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

type ipEntryModel struct {
	IP types.String `tfsdk:"ip"`
}

var configsAttributeTypes = map[string]attr.Type{
	"status":       types.BoolType,
	"action":       types.StringType,
	"ip_list_type": types.StringType,
	"ip_list":      ipListWrapperObjectTypes(),
}

func ipListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: ipEntryObjectTypes()},
	}}
}

func ipEntryObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"ip": types.StringType,
	}}
}

// validateTemplateConfigs enforces the template/configs mutual exclusion:
// template=true forbids configs; template=false requires configs.
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

// validateRequiredConfigs enforces the required request fields from the
// AnomalyDetection API schema when the configs block is active. They are
// Terraform-optional at the schema layer so a template=true transition can
// omit the complete parent block without stale required-child diagnostics.
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
	case values.Action.IsNull():
		return fmt.Errorf("configs.action must be configured")
	case values.IPListType.IsNull():
		return fmt.Errorf("configs.ip_list_type must be configured")
	}
	return nil
}

// ownedIPList records whether the ip_list wrapper is present and the ordered
// entries Terraform owns. Set=false preserves the raw remote array opaquely;
// Set=true with empty Items sends []; Set=true with populated Items replaces.
type ownedIPList struct {
	Set   bool
	Items []client.AnomalyDetectionIPListEntry
}

// buildOwnedIPList produces the owned ip_list from the Terraform wrapper,
// regenerating one-based idx in Terraform order and enforcing the reviewed
// 30-item bound and required non-empty ip. Wire-only idx is never in state.
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
		// Wrapper omitted: preserve the remote array opaquely.
		return ownedIPList{Set: false}, diagnostics
	}
	if values.IPList.IsUnknown() {
		diagnostics.AddError("Unknown anomaly detection ip_list", "The ip_list ownership wrapper must be known during apply.")
		return ownedIPList{}, diagnostics
	}
	var wrapper ipListWrapperModel
	diagnostics.Append(values.IPList.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return ownedIPList{}, diagnostics
	}
	if wrapper.Item.IsUnknown() {
		diagnostics.AddError("Unknown anomaly detection ip_list", "The ip_list item blocks must be known during apply.")
		return ownedIPList{}, diagnostics
	}
	owned := ownedIPList{Set: true, Items: []client.AnomalyDetectionIPListEntry{}}
	if wrapper.Item.IsNull() {
		// Empty wrapper: send [].
		return owned, diagnostics
	}
	var entries []ipEntryModel
	diagnostics.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return ownedIPList{}, diagnostics
	}
	if len(entries) > client.AnomalyDetectionIPListMaxEntries {
		diagnostics.AddError("Invalid anomaly detection ip_list",
			fmt.Sprintf("ip_list may contain at most %d item blocks.", client.AnomalyDetectionIPListMaxEntries))
		return ownedIPList{}, diagnostics
	}
	items := make([]client.AnomalyDetectionIPListEntry, 0, len(entries))
	for index, entry := range entries {
		if entry.IP.IsNull() || entry.IP.IsUnknown() || entry.IP.ValueString() == "" {
			diagnostics.AddError("Invalid anomaly detection ip_list",
				fmt.Sprintf("ip_list item %d requires a non-empty ip.", index+1))
			return ownedIPList{}, diagnostics
		}
		items = append(items, client.AnomalyDetectionIPListEntry{IDX: index + 1, IP: entry.IP.ValueString()})
	}
	owned.Items = items
	return owned, diagnostics
}

// mergeAnomalyDetection overlays the Terraform-owned scalars and, when the
// ip_list wrapper is present, the ordered ip_list onto a fresh GET result,
// preserving unknown envelope/config fields. When the wrapper is omitted, the
// remote ip_list is preserved opaquely (not overwritten).
func mergeAnomalyDetection(ctx context.Context, document client.AnomalyDetectionDocument, template bool, configs types.Object) (client.WAFModuleResult, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	updated := document.Result.Clone()
	updated.Template = template
	if template {
		// Template inheritance: do not overlay owned configs.
		return updated, diagnostics
	}
	if configs.IsNull() || configs.IsUnknown() {
		diagnostics.AddError("Invalid anomaly detection configuration", "configs must be configured when template is false.")
		return updated, diagnostics
	}
	var values configsModel
	diagnostics.Append(configs.As(ctx, &values, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if values.Status.IsNull() || values.Status.IsUnknown() {
		diagnostics.AddError("Invalid anomaly detection configuration", "configs.status must be configured when template is false.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("status", values.Status.ValueBool()); err != nil {
		diagnostics.AddError("Unable to merge anomaly detection status", err.Error())
		return updated, diagnostics
	}
	if values.Action.IsNull() || values.Action.IsUnknown() {
		diagnostics.AddError("Invalid anomaly detection configuration", "configs.action must be configured when template is false.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("action", values.Action.ValueString()); err != nil {
		diagnostics.AddError("Unable to merge anomaly detection action", err.Error())
		return updated, diagnostics
	}
	if values.IPListType.IsNull() || values.IPListType.IsUnknown() {
		diagnostics.AddError("Invalid anomaly detection configuration", "configs.ip_list_type must be configured when template is false.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("ip_list_type", values.IPListType.ValueString()); err != nil {
		diagnostics.AddError("Unable to merge anomaly detection ip_list_type", err.Error())
		return updated, diagnostics
	}

	owned, ownedDiag := buildOwnedIPList(ctx, configs)
	diagnostics.Append(ownedDiag...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if owned.Set {
		if err := updated.SetConfig("ip_list", owned.Items); err != nil {
			diagnostics.AddError("Unable to merge anomaly detection ip_list", err.Error())
			return updated, diagnostics
		}
	}
	return updated, diagnostics
}

// ownershipSource tells stateModel whether Terraform owns the ip_list for this
// read, controlling whether the remote array is flattened or preserved opaquely.
type ownershipSource uint8

const (
	ownershipPriorState ownershipSource = iota
	ownershipImported
	ownershipConfigured
)

// stateModel reconstructs the Terraform model from a fresh GET. The ip_list
// wrapper is populated (strictly decoded) only when Terraform owns or imports
// it; when omitted (PriorState with a null prior wrapper), it stays null and
// the remote array is preserved opaquely. When template is true, configs is
// null (Terraform observes the inherited template config without owning it).
func stateModel(epID string, document client.AnomalyDetectionDocument, source ownershipSource, priorConfigs types.Object) (resourceModel, diag.Diagnostics) {
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
		"status":       types.BoolPointerValue(document.Config.Status),
		"action":       types.StringPointerValue(document.Config.Action),
		"ip_list_type": types.StringPointerValue(document.Config.IPListType),
		"ip_list":      stateIPListWrapper(document.Config.IPList, owned, &diagnostics),
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

func stateIPListWrapper(rawItems []json.RawMessage, owned bool, diagnostics *diag.Diagnostics) types.Object {
	if !owned {
		return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
	}
	entries, err := client.DecodeAnomalyDetectionIPList(rawItems)
	if err != nil {
		diagnostics.AddError("Unable to decode owned ip_list", err.Error())
		return types.ObjectNull(ipListWrapperObjectTypes().AttrTypes)
	}
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		object, objectDiag := types.ObjectValue(ipEntryObjectTypes().AttrTypes, map[string]attr.Value{
			"ip": types.StringValue(entry.IP),
		})
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
