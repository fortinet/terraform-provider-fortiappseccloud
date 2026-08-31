package wafmodule

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
)

// OwnershipSource tells a codec which Terraform boundary controls flattening.
type OwnershipSource uint8

const (
	// OwnershipConfigured uses configuration presence after Create or Update.
	OwnershipConfigured OwnershipSource = iota
	// OwnershipPriorState preserves ownership recorded by a normal Read.
	OwnershipPriorState
	// OwnershipImported hydrates all supported fields on the first Read after import.
	OwnershipImported
)

// OwnershipContext carries raw Framework values to a generated codec without
// exposing its nested model to the shared runtime.
type OwnershipContext struct {
	Source OwnershipSource
	Config tfsdk.Config
	Plan   tfsdk.Plan
	State  tfsdk.State
}

// OwnershipConfigs reads only the common configs attribute from either an app
// module or a template module Terraform boundary. Reading by attribute path
// avoids coupling generated ownership logic to either top-level identity
// model.
func OwnershipConfigs(ctx context.Context, ownership OwnershipContext) (types.Object, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	configs := types.ObjectNull(nil)
	switch ownership.Source {
	case OwnershipConfigured:
		diagnostics.Append(ownership.Config.GetAttribute(ctx, path.Root("configs"), &configs)...)
	case OwnershipPriorState:
		diagnostics.Append(ownership.State.GetAttribute(ctx, path.Root("configs"), &configs)...)
	default:
		diagnostics.AddError("Invalid WAF module ownership", "The shared runtime supplied an unsupported ownership source.")
	}
	return configs, diagnostics
}

// ConfiguredString returns an overlay only when the practitioner configured
// the value. A resolved plan value is used for configured unknowns.
func ConfiguredString(config, plan types.String, name string) (client.Optional[string], diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if config.IsNull() {
		return client.Optional[string]{}, diagnostics
	}
	if config.IsUnknown() {
		if plan.IsNull() || plan.IsUnknown() {
			diagnostics.AddError("Unknown WAF module value", fmt.Sprintf("The configured value for %s is still unknown during apply.", name))
			return client.Optional[string]{}, diagnostics
		}
		return client.Optional[string]{Set: true, Value: plan.ValueString()}, diagnostics
	}
	return client.Optional[string]{Set: true, Value: config.ValueString()}, diagnostics
}

// ConfiguredBool returns an overlay only when the practitioner configured the
// value. Explicit false values remain distinguishable from omission.
func ConfiguredBool(config, plan types.Bool, name string) (client.Optional[bool], diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if config.IsNull() {
		return client.Optional[bool]{}, diagnostics
	}
	if config.IsUnknown() {
		if plan.IsNull() || plan.IsUnknown() {
			diagnostics.AddError("Unknown WAF module value", fmt.Sprintf("The configured value for %s is still unknown during apply.", name))
			return client.Optional[bool]{}, diagnostics
		}
		return client.Optional[bool]{Set: true, Value: plan.ValueBool()}, diagnostics
	}
	return client.Optional[bool]{Set: true, Value: config.ValueBool()}, diagnostics
}

// ConfiguredInt64 returns an overlay only when the practitioner configured the
// integer value. A resolved plan value is used for configured unknowns. Zero
// remains distinguishable from omission because the overlay is only Set when
// the configuration explicitly carried a value.
func ConfiguredInt64(config, plan types.Int64, name string) (client.Optional[int64], diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if config.IsNull() {
		return client.Optional[int64]{}, diagnostics
	}
	if config.IsUnknown() {
		if plan.IsNull() || plan.IsUnknown() {
			diagnostics.AddError("Unknown WAF module value", fmt.Sprintf("The configured value for %s is still unknown during apply.", name))
			return client.Optional[int64]{}, diagnostics
		}
		return client.Optional[int64]{Set: true, Value: plan.ValueInt64()}, diagnostics
	}
	return client.Optional[int64]{Set: true, Value: config.ValueInt64()}, diagnostics
}
