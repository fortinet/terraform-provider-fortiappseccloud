package globaltrustlist

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/locking"
)

func TestValidateConfigs(t *testing.T) {
	t.Parallel()

	configs := testConfigsObject(t, true, testOmittedTrustListWrapper())
	tests := map[string]struct {
		model   resourceModel
		wantErr bool
	}{
		"configs present": {
			model: resourceModel{EPID: types.StringValue("123"), Configs: configs},
		},
		"configs null": {
			model:   resourceModel{EPID: types.StringValue("123"), Configs: types.ObjectNull(configsAttributeTypes)},
			wantErr: true,
		},
		"configs unknown defers": {
			model: resourceModel{EPID: types.StringValue("123"), Configs: types.ObjectUnknown(configsAttributeTypes)},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := validateConfigs(test.model)
			if test.wantErr && err == nil {
				t.Fatalf("validateConfigs() expected an error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validateConfigs() error = %v", err)
			}
		})
	}
}

// TestValidateConfigAcceptsReviewedBounds is a valid control proving the
// resource's ValidateConfig hook accepts a fully-known config at the reviewed
// bounds (status plus a populated trust_list). The negative bound cases (31
// entries, over-length name/url) are exercised by the Terraform CLI lifecycle
// test, where the Framework schema-level validators (listvalidator.SizeAtMost,
// stringvalidator.UTF8LengthAtMost) run during the plan/validate engine pass
// rather than the direct resource.ValidateConfig hook.
func TestValidateConfigAcceptsReviewedBounds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	implementation := &globalTrustListResource{locks: locking.NewRegistry()}
	resourceSchema := testResourceSchema(t, ctx, implementation)

	entries := make([]trustEntryModel, 30)
	for i := range entries {
		entries[i] = trustEntry("entry", true, "/u")
	}
	list := testTrustListWrapper(t, entries...)
	model := resourceModel{
		EPID:    types.StringValue("123"),
		Configs: testConfigsObject(t, true, list),
	}
	resp := resource.ValidateConfigResponse{}
	implementation.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: testConfigFor(t, ctx, resourceSchema, &model)}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ValidateConfig(30 entries) diagnostics = %v", resp.Diagnostics)
	}
}
