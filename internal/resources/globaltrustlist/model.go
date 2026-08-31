package globaltrustlist

import (
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
)

type resourceModel struct {
	EPID    types.String `tfsdk:"ep_id"`
	Configs types.Object `tfsdk:"configs"`
}

type configsModel struct {
	Status    types.Bool   `tfsdk:"status"`
	TrustList types.Object `tfsdk:"trust_list"`
}

// trustListWrapperModel models the trust_list ownership wrapper. Its item block
// is the ordered list of trust-list entries.
type trustListWrapperModel struct {
	Item types.List `tfsdk:"item"`
}

type trustEntryModel struct {
	Name   types.String `tfsdk:"name"`
	Status types.Bool   `tfsdk:"status"`
	URL    types.String `tfsdk:"url"`
}

var configsAttributeTypes = map[string]attr.Type{
	"status":     types.BoolType,
	"trust_list": trustListWrapperObjectTypes(),
}

func trustListWrapperObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"item": types.ListType{ElemType: trustEntryObjectTypes()},
	}}
}

func trustEntryObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":   types.StringType,
		"status": types.BoolType,
		"url":    types.StringType,
	}}
}

// validateConfigs enforces the reviewed ownership rules. The global trust-list
// parameter envelope has configs but no template, so there is no template/configs
// mutual-exclusion here; configs is always required.
func validateConfigs(model resourceModel) error {
	if model.Configs.IsUnknown() {
		return nil
	}
	if model.Configs.IsNull() {
		return fmt.Errorf("configs must be configured")
	}
	return nil
}

// ownedTrustList records whether the trust_list wrapper is present and the
// ordered entries Terraform owns. Set=false means the wrapper is omitted and
// the remote array is preserved opaquely; Set=true with empty Items means send
// []; Set=true with populated Items means replace the array in Terraform order.
type ownedTrustList struct {
	Set   bool
	Items []client.GlobalTrustListEntry
}

// buildOwnedTrustList produces the owned trust_list from the Terraform wrapper,
// regenerating one-based idx in Terraform order and enforcing the reviewed
// 30-item and name(63)/url(255) bounds. Wire-only idx is never exposed in state.
func buildOwnedTrustList(ctx context.Context, configs types.Object) (ownedTrustList, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if configs.IsNull() || configs.IsUnknown() {
		return ownedTrustList{}, diagnostics
	}
	var values configsModel
	diagnostics.Append(configs.As(ctx, &values, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return ownedTrustList{}, diagnostics
	}
	if values.TrustList.IsNull() {
		// Wrapper omitted: preserve the remote array opaquely.
		return ownedTrustList{Set: false}, diagnostics
	}
	if values.TrustList.IsUnknown() {
		diagnostics.AddError("Unknown global trust list trust_list", "The trust_list ownership wrapper must be known during apply.")
		return ownedTrustList{}, diagnostics
	}
	var wrapper trustListWrapperModel
	diagnostics.Append(values.TrustList.As(ctx, &wrapper, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return ownedTrustList{}, diagnostics
	}
	if wrapper.Item.IsUnknown() {
		diagnostics.AddError("Unknown global trust list trust_list", "The trust_list item blocks must be known during apply.")
		return ownedTrustList{}, diagnostics
	}
	owned := ownedTrustList{Set: true, Items: []client.GlobalTrustListEntry{}}
	if wrapper.Item.IsNull() {
		// Empty wrapper: send [].
		return owned, diagnostics
	}
	var entries []trustEntryModel
	diagnostics.Append(wrapper.Item.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return ownedTrustList{}, diagnostics
	}
	if len(entries) > client.GlobalTrustListMaxEntries {
		diagnostics.AddError("Invalid global trust list trust_list",
			fmt.Sprintf("trust_list may contain at most %d item blocks.", client.GlobalTrustListMaxEntries))
		return ownedTrustList{}, diagnostics
	}
	items := make([]client.GlobalTrustListEntry, 0, len(entries))
	for index, entry := range entries {
		if entry.Name.IsNull() || entry.Name.IsUnknown() || entry.Name.ValueString() == "" {
			diagnostics.AddError("Invalid global trust list trust_list",
				fmt.Sprintf("trust_list item %d requires a non-empty name.", index+1))
			return ownedTrustList{}, diagnostics
		}
		name := entry.Name.ValueString()
		if utf8.RuneCountInString(name) > client.GlobalTrustListNameMaxLen {
			diagnostics.AddError("Invalid global trust list trust_list",
				fmt.Sprintf("trust_list item %d name length %d exceeds limit %d UTF-8 characters.", index+1, utf8.RuneCountInString(name), client.GlobalTrustListNameMaxLen))
			return ownedTrustList{}, diagnostics
		}
		item := client.GlobalTrustListEntry{IDX: index + 1, Name: name}
		if !entry.URL.IsNull() && !entry.URL.IsUnknown() {
			url := entry.URL.ValueString()
			if utf8.RuneCountInString(url) > client.GlobalTrustListURLMaxLen {
				diagnostics.AddError("Invalid global trust list trust_list",
					fmt.Sprintf("trust_list item %d url length %d exceeds limit %d UTF-8 characters.", index+1, utf8.RuneCountInString(url), client.GlobalTrustListURLMaxLen))
				return ownedTrustList{}, diagnostics
			}
			item.URL = &url
		}
		if !entry.Status.IsNull() && !entry.Status.IsUnknown() {
			status := entry.Status.ValueBool()
			item.Status = &status
		}
		items = append(items, item)
	}
	owned.Items = items
	return owned, diagnostics
}

// mergeGlobalTrustList overlays the Terraform-owned status and the trust_list
// (when the wrapper is present) onto a fresh GET result, preserving unknown
// envelope and config fields. When the trust_list wrapper is omitted, the remote
// trust_list is preserved opaquely (not overwritten).
func mergeGlobalTrustList(ctx context.Context, document client.GlobalTrustListDocument, configs types.Object) (client.GlobalTrustListResult, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	updated := document.Result.Clone()

	if configs.IsNull() || configs.IsUnknown() {
		diagnostics.AddError("Invalid global trust list configuration", "configs must be configured during apply.")
		return updated, diagnostics
	}
	var values configsModel
	diagnostics.Append(configs.As(ctx, &values, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if values.Status.IsNull() || values.Status.IsUnknown() {
		diagnostics.AddError("Invalid global trust list configuration", "configs.status must be configured during apply.")
		return updated, diagnostics
	}
	if err := updated.SetConfig("status", values.Status.ValueBool()); err != nil {
		diagnostics.AddError("Unable to merge global trust list status", err.Error())
		return updated, diagnostics
	}

	owned, ownedDiag := buildOwnedTrustList(ctx, configs)
	diagnostics.Append(ownedDiag...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	if owned.Set {
		if err := updated.SetConfig("trust_list", owned.Items); err != nil {
			diagnostics.AddError("Unable to merge global trust list entries", err.Error())
			return updated, diagnostics
		}
	}
	return updated, diagnostics
}

// ownershipSource tells stateModel whether Terraform owns the trust_list
// collection for this read, which controls whether the remote array is
// flattened into the wrapper or preserved opaquely (wrapper null).
type ownershipSource uint8

const (
	// ownershipPriorState preserves ownership recorded by a normal Read: the
	// wrapper is owned iff it was non-null in prior state. When not owned, the
	// remote array is preserved opaquely and the wrapper stays null.
	ownershipPriorState ownershipSource = iota
	// ownershipImported hydrates the wrapper from the remote array on the first
	// Read after import (strict decode, fail-closed).
	ownershipImported
	// ownershipConfigured owns the collection per the apply plan/config: the
	// wrapper is owned iff present in the plan.
	ownershipConfigured
)

// stateModel reconstructs the Terraform model from a fresh GET. The trust_list
// wrapper is populated (strictly decoded) only when Terraform owns or imports
// the collection; when the wrapper is omitted (PriorState with a null prior
// wrapper), the remote array is preserved opaquely and the wrapper stays null
// so a later plan does not import unowned data.
func stateModel(epID string, document client.GlobalTrustListDocument, source ownershipSource, priorConfigs types.Object) (resourceModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	model := resourceModel{
		EPID:    types.StringValue(epID),
		Configs: types.ObjectNull(configsAttributeTypes),
	}
	owned := trustListOwned(source, priorConfigs, &diagnostics)
	attributes := map[string]attr.Value{
		"status":     types.BoolPointerValue(document.Config.Status),
		"trust_list": stateTrustListWrapper(document.Config.TrustList, owned, &diagnostics),
	}
	configs, objectDiag := types.ObjectValue(configsAttributeTypes, attributes)
	diagnostics.Append(objectDiag...)
	model.Configs = configs
	return model, diagnostics
}

// trustListOwned reports whether Terraform owns the trust_list collection for
// this read. PriorState: owned iff the prior configs' trust_list wrapper was
// non-null. Imported: always owned. Configured: owned iff priorConfigs' wrapper
// was non-null (the plan mirrors config presence).
func trustListOwned(source ownershipSource, priorConfigs types.Object, diagnostics *diag.Diagnostics) bool {
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
	return !configs.TrustList.IsNull() && !configs.TrustList.IsUnknown()
}

// stateTrustListWrapper flattens the remote trust_list into the ownership
// wrapper when Terraform owns it. When not owned, the wrapper is null (omitted)
// so the remote array is preserved opaquely and a later plan does not import
// it. When owned, the raw remote items are strictly decoded (fail-closed unknown
// keys, idx validation, bounds, required name) and populated in idx order.
func stateTrustListWrapper(rawItems []json.RawMessage, owned bool, diagnostics *diag.Diagnostics) types.Object {
	if !owned {
		return types.ObjectNull(trustListWrapperObjectTypes().AttrTypes)
	}
	entries, err := client.DecodeGlobalTrustListEntries(rawItems)
	if err != nil {
		diagnostics.AddError("Unable to decode owned trust_list", err.Error())
		return types.ObjectNull(trustListWrapperObjectTypes().AttrTypes)
	}
	values := make([]attr.Value, 0, len(entries))
	for _, entry := range entries {
		attributes := map[string]attr.Value{
			"name":   types.StringValue(entry.Name),
			"status": types.BoolPointerValue(entry.Status),
			"url":    types.StringPointerValue(entry.URL),
		}
		object, objectDiag := types.ObjectValue(trustEntryObjectTypes().AttrTypes, attributes)
		diagnostics.Append(objectDiag...)
		values = append(values, object)
	}
	list, listDiag := types.ListValue(trustEntryObjectTypes(), values)
	diagnostics.Append(listDiag...)
	wrapper, wrapperDiag := types.ObjectValue(trustListWrapperObjectTypes().AttrTypes, map[string]attr.Value{
		"item": list,
	})
	diagnostics.Append(wrapperDiag...)
	return wrapper
}
