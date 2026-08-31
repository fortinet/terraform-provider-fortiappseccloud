package wafmodule

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/contract"
	profile "terraform-provider-fortiappseccloud/internal/generator/profile/waf"
	"terraform-provider-fortiappseccloud/internal/locking"
)

// TestAccDescriptorDrivenDisable is intentionally a direct live lifecycle test
// of one selected generated or hand-written candidate. A production policy is
// promoted to disable only after this exact module/ep_id gate succeeds and the
// result is recorded as module-specific live provenance.
func TestAccDescriptorDrivenDisable(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactLiveGate(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactLiveGate(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_APP", "yes")
	epID := requireLiveEnvironment(t, "FORTIAPPSECCLOUD_TEST_EP_ID")
	module := requireLiveEnvironment(t, "FORTIAPPSECCLOUD_TEST_MODULE")
	skipUnlessExactLiveGate(t, "FORTIAPPSECCLOUD_ACC_MODULE_DISABLE_WRITE", "disable_v1:"+module+":"+epID)
	appName := requireLiveEnvironment(t, "FORTIAPPSECCLOUD_TEST_APP_NAME")
	api := liveWAFModuleClient(t)
	application, err := api.FindApplicationByEPID(context.Background(), epID)
	if err != nil {
		t.Fatalf("resolve authorized disposable application: %v", err)
	}
	if application.AppName != appName {
		t.Fatal("FORTIAPPSECCLOUD_TEST_APP_NAME does not match the authorized ep_id")
	}

	candidate, ok := reviewedDisableCandidates(t)[module]
	if !ok {
		t.Fatalf("%q is not a reviewed standalone configs.status disable candidate", module)
	}
	endpoint := candidate
	snapshot, err := api.GetWAFModule(context.Background(), endpoint, epID)
	if err != nil {
		t.Fatalf("snapshot %s: %v", module, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if restoreErr := api.PutWAFModule(ctx, endpoint, epID, snapshot.Result); restoreErr != nil {
			t.Errorf("restore %s: %v", module, restoreErr)
			return
		}
		restored, restoreErr := api.GetWAFModule(ctx, endpoint, epID)
		if restoreErr != nil {
			t.Errorf("verify %s restoration: %v", module, restoreErr)
			return
		}
		if !semanticEqual(snapshot.Result, restored.Result) {
			t.Errorf("%s restoration did not reproduce the complete saved envelope", module)
		}
	})

	enabled := snapshot.Result.Clone()
	enabled.Template = false
	if err := requireBooleanDisableField(snapshot.Result, "status"); err != nil {
		t.Fatalf("%s is not safely writable: %v", module, err)
	}
	if err := enabled.SetConfig("status", true); err != nil {
		t.Fatal(err)
	}
	if err := api.PutWAFModule(context.Background(), endpoint, epID, enabled); err != nil {
		t.Fatalf("prepare enabled %s configuration: %v", module, err)
	}
	current, err := api.GetWAFModule(context.Background(), endpoint, epID)
	if err != nil {
		t.Fatalf("verify enabled %s configuration: %v", module, err)
	}
	if current.Result.Template || !liveRawBool(current.Result.Configs["status"]) {
		t.Fatalf("enabled %s did not report template=false and configs.status=true", module)
	}
	if !semanticEqual(enabled, current.Result) {
		t.Fatalf("enabling %s changed fields outside template/configs.status", module)
	}

	codec := liveDisableCodec{}
	descriptor := Descriptor{
		TypeNameSuffix: "waf_acc_" + module + "_disable",
		Endpoint:       endpoint,
		Codec:          codec,
		Destroy: DestroyPolicy{
			Mode: DestroyDisable, Verified: true, Field: "status",
			Reason: "exact endpoint-specific acceptance lifecycle",
		},
	}
	implementation := NewResource(descriptor, locking.NewRegistry()).(*moduleResource)
	implementation.service = api
	configs, diagnostics := types.ObjectValue(map[string]attr.Type{"action": types.StringType, "status": types.BoolType}, map[string]attr.Value{"action": types.StringValue("alert"), "status": types.BoolValue(true)})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	state := tfsdk.State{Schema: codec.Schema(context.Background())}
	if diagnostics := state.Set(context.Background(), &baseModel{EPID: types.StringValue(epID), Template: types.BoolValue(false), Configs: configs}); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	expected := current.Result.Clone()
	expected.Template = false
	if err := expected.SetConfig("status", false); err != nil {
		t.Fatal(err)
	}
	response := resource.DeleteResponse{}
	implementation.Delete(context.Background(), resource.DeleteRequest{State: state}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("descriptor Delete() diagnostics = %v", response.Diagnostics)
	}
	disabled, err := api.GetWAFModule(context.Background(), endpoint, epID)
	if err != nil {
		t.Fatalf("read descriptor-disabled %s configuration: %v", module, err)
	}
	if !semanticEqual(expected, disabled.Result) {
		t.Fatalf("%s disable did not preserve the complete envelope except for template=false and configs.status=false", module)
	}
}

func TestDisableLiveCandidateInventory(t *testing.T) {
	t.Parallel()

	candidates := reviewedDisableCandidates(t)
	if len(candidates) != 29 {
		t.Fatalf("reviewed live disable candidates = %d, want 29", len(candidates))
	}
	for _, ineligible := range []string{"caching_compression", "global_trust_list_parameter", "routings"} {
		if _, ok := candidates[ineligible]; ok {
			t.Errorf("unsafe module %q appeared in the live disable candidates", ineligible)
		}
	}
}

func reviewedDisableCandidates(t *testing.T) map[string]client.WAFModuleEndpoint {
	t.Helper()
	overrides, err := profile.DecodeOverrides(profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("decode reviewed generated-module policy: %v", err)
	}
	candidates := make(map[string]client.WAFModuleEndpoint)
	for _, reviewed := range overrides.Resources {
		if reviewed.Destroy.Field != "status" {
			continue
		}
		module := strings.TrimPrefix(reviewed.GetPath, "/waf/apps/{ep_id}/")
		if module == reviewed.GetPath || module == "" || strings.Contains(module, "/") {
			t.Fatalf("invalid generated candidate path %q", reviewed.GetPath)
		}
		candidates[module] = client.WAFModuleEndpoint{
			Path:      reviewed.GetPath,
			Operation: reviewed.OperationName + " destroy verification",
		}
	}
	for _, reviewed := range contract.ReviewedCustomResourceContracts() {
		if reviewed.DestroyField != "status" {
			continue
		}
		if _, duplicate := candidates[reviewed.Module]; duplicate {
			t.Fatalf("duplicate disable candidate %q", reviewed.Module)
		}
		candidates[reviewed.Module] = client.WAFModuleEndpoint{
			Path:      reviewed.PublicPath,
			Operation: reviewed.Module + " destroy verification",
		}
	}
	return candidates
}

type liveDisableCodec struct{}

func (liveDisableCodec) Schema(context.Context) schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{Required: true}, "template": schema.BoolAttribute{Required: true},
		},
		Blocks: map[string]schema.Block{"configs": schema.SingleNestedBlock{Attributes: map[string]schema.Attribute{
			"action": schema.StringAttribute{Optional: true}, "status": schema.BoolAttribute{Optional: true},
		}}},
	}
}
func (liveDisableCodec) ValidateConfig(context.Context, tfsdk.Config) diag.Diagnostics { return nil }
func (liveDisableCodec) BuildPatch(context.Context, tfsdk.Config, tfsdk.Plan, tfsdk.State) (Patch, diag.Diagnostics) {
	return nil, nil
}
func (liveDisableCodec) ValidateResult(context.Context, client.WAFModuleResult, OwnershipContext) diag.Diagnostics {
	return nil
}
func (liveDisableCodec) Flatten(context.Context, string, client.WAFModuleResult, OwnershipContext) (any, diag.Diagnostics) {
	return nil, nil
}

func liveWAFModuleClient(t *testing.T) *client.Client {
	t.Helper()
	api, err := client.New(context.Background(), client.Config{
		BaseURL: os.Getenv("FORTIAPPSECCLOUD_HOSTNAME"), APIToken: os.Getenv("FORTIAPPSECCLOUD_API_TOKEN"),
		Username: os.Getenv("FORTIAPPSECCLOUD_USERNAME"), Password: os.Getenv("FORTIAPPSECCLOUD_PASSWORD"), Timeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("configure acceptance client: %v", err)
	}
	return api
}

func requireLiveEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s must be set for this acceptance test", name)
	}
	return value
}

func skipUnlessExactLiveGate(t *testing.T, name, expected string) {
	t.Helper()
	if os.Getenv(name) != expected {
		t.Skipf("%s does not authorize this exact target and write lifecycle", name)
	}
}

func semanticEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	var leftValue, rightValue any
	if json.Unmarshal(leftJSON, &leftValue) != nil || json.Unmarshal(rightJSON, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func liveRawBool(value json.RawMessage) bool {
	var result bool
	_ = json.Unmarshal(value, &result)
	return result
}
