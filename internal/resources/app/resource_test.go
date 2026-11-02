package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

func TestCreateUsesPublicPlacementAndBootstrapOrigin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	endpoint := testEndpoint()
	endpoint["cert_type"] = float64(1)
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", ExtraDomains: []string{"api.example.com"}, CNAME: "demo.edge.example", Platform: "AWS", PlatformRegion: "us-east-1", TemplateID: "template-1", TemplateName: "legacy-template"}, endpoint: endpoint}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	plan := testAppModel(t, ctx)
	plan.CertificateMode = types.StringValue("custom")
	request := resource.CreateRequest{Plan: appPlan(t, ctx, schema, &plan)}
	response := resource.CreateResponse{State: nullAppState(ctx, schema)}
	implementation.Create(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	if service.created.AppName != "demo" || service.created.CreationOrigin != client.ApplicationCreationOriginTerraform || service.created.ServerAddress != "192.0.2.10" || service.created.ServerType != "https" || service.created.Region != "us-east-1" || service.created.Platform != "AWS" || service.created.CertType == nil || *service.created.CertType != 1 {
		t.Fatalf("create request = %#v", service.created)
	}
	if got := service.calls; !reflect.DeepEqual(got, []string{"create", "find-id:100", "endpoint:100"}) {
		t.Fatalf("calls = %#v", got)
	}
	var state resourceModel
	if diagnostics := response.State.Get(ctx, &state); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if state.EPID.ValueString() != "100" || state.CNAMEs.IsNull() || state.InitialOrigin.IsNull() || state.CertificateMode.ValueString() != "custom" || state.AttachedTemplateID.ValueString() != "template-1" || state.AttachedTemplateName.ValueString() != "legacy-template" {
		t.Fatalf("state = %#v", state)
	}
	if !state.HTTP2Status.ValueBool() || state.IPv6Option.ValueBool() || state.CertChallengeMode.ValueString() != "dns" || state.BlockURL.ValueString() != "PredefinedMsg" {
		t.Fatalf("endpoint state fields = %#v", state)
	}
}

func TestCreateRunsOnlyPublicPrechecksWhenRequested(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", Platform: "AWS", PlatformRegion: "us-east-1"}, endpoint: testEndpoint(), dnsAddresses: []string{"192.0.2.10"}}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	plan := testAppModel(t, ctx)
	plan.Precheck = types.BoolValue(true)
	plan.CertificateMode = types.StringUnknown()
	plan.InitialOrigin, _ = types.ObjectValue(initialOriginTypes, map[string]attr.Value{"address": types.StringValue("origin.example.com"), "protocol": types.StringValue("https"), "port": types.Int64Value(443)})
	response := resource.CreateResponse{State: nullAppState(ctx, schema)}
	implementation.Create(ctx, resource.CreateRequest{Plan: appPlan(t, ctx, schema, &plan)}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	want := []string{"dns:origin.example.com", "connectivity:192.0.2.10", "create", "find-id:100", "endpoint:100"}
	if !reflect.DeepEqual(service.calls, want) {
		t.Fatalf("calls = %#v, want %#v", service.calls, want)
	}
	if service.created.CertType != nil {
		t.Fatalf("omitted certificate_mode sent cert_type = %d", *service.created.CertType)
	}
}

func TestCreateRetainsIdentityWhenEndpointSettingsFail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, stage := range []string{"read", "write"} {
		t.Run(stage, func(t *testing.T) {
			service := &fakeAppService{
				application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", Platform: "AWS", PlatformRegion: "us-east-1"},
				endpoint:    testEndpoint(),
			}
			if stage == "read" {
				service.getEndpointError = errors.New("endpoint unavailable")
			} else {
				service.putEndpointError = errors.New("endpoint settings rejected")
			}
			implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
			schema := currentSchema()
			plan := testAppModel(t, ctx)
			plan.HTTP2Status = types.BoolValue(true)
			response := resource.CreateResponse{State: nullAppState(ctx, schema)}
			implementation.Create(ctx, resource.CreateRequest{Plan: appPlan(t, ctx, schema, &plan)}, &response)
			if !response.Diagnostics.HasError() {
				t.Fatal("Create() did not report the endpoint failure")
			}
			if response.State.Raw.IsNull() {
				t.Fatal("Create() lost the identity of the application after endpoint failure")
			}
			var state resourceModel
			if diagnostics := response.State.Get(ctx, &state); diagnostics.HasError() {
				t.Fatal(diagnostics)
			}
			if state.EPID.ValueString() != "100" {
				t.Fatalf("created application ID = %q, want 100", state.EPID.ValueString())
			}
		})
	}
}

func TestInitialOriginChangeRequiresReplacement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := currentSchema()
	prior := testAppModel(t, ctx)
	plan := prior
	plan.InitialOrigin, _ = types.ObjectValue(initialOriginTypes, map[string]attr.Value{"address": types.StringValue("192.0.2.20"), "protocol": types.StringValue("https"), "port": types.Int64Value(443)})
	request := resource.ModifyPlanRequest{State: appState(t, ctx, schema, &prior), Plan: appPlan(t, ctx, schema, &plan)}
	response := resource.ModifyPlanResponse{Plan: request.Plan}
	(&appResource{}).ModifyPlan(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan() diagnostics = %v", response.Diagnostics)
	}
	if len(response.RequiresReplace) != 1 || response.RequiresReplace[0].String() != "initial_origin" {
		t.Fatalf("RequiresReplace = %#v", response.RequiresReplace)
	}
}

func TestInitialOriginAdoptionAfterImportDoesNotRequireReplacement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	resourceSchema := currentSchema()
	prior := testAppModel(t, ctx)
	prior.InitialOrigin = types.ObjectNull(initialOriginTypes)
	plan := testAppModel(t, ctx)
	request := resource.ModifyPlanRequest{State: appState(t, ctx, resourceSchema, &prior), Plan: appPlan(t, ctx, resourceSchema, &plan)}
	response := resource.ModifyPlanResponse{Plan: request.Plan}
	(&appResource{}).ModifyPlan(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("ModifyPlan() diagnostics = %v", response.Diagnostics)
	}
	if len(response.RequiresReplace) != 0 {
		t.Fatalf("RequiresReplace = %#v", response.RequiresReplace)
	}
}

func TestResolveImportedApplicationByEPIDOrLegacyName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("ep_id", func(t *testing.T) {
		service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo"}}
		implementation := &appResource{service: service}
		state := resourceModel{LegacyAppName: types.StringValue("100")}
		var diagnostics diag.Diagnostics
		application, ok := implementation.resolveStateApplication(ctx, state, &diagnostics)
		if !ok || diagnostics.HasError() || application.EPID != "100" {
			t.Fatalf("resolve = %#v, %t, diagnostics = %v", application, ok, diagnostics)
		}
		if want := []string{"find-id:100"}; !reflect.DeepEqual(service.calls, want) {
			t.Fatalf("calls = %#v, want %#v", service.calls, want)
		}
	})

	t.Run("legacy_name", func(t *testing.T) {
		service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo"}}
		implementation := &appResource{service: service}
		state := resourceModel{LegacyAppName: types.StringValue("demo")}
		var diagnostics diag.Diagnostics
		application, ok := implementation.resolveStateApplication(ctx, state, &diagnostics)
		if !ok || diagnostics.HasError() || application.EPID != "100" {
			t.Fatalf("resolve = %#v, %t, diagnostics = %v", application, ok, diagnostics)
		}
		if want := []string{"find-id:demo", "find-name:demo"}; !reflect.DeepEqual(service.calls, want) {
			t.Fatalf("calls = %#v, want %#v", service.calls, want)
		}
	})
}

func TestUpdateUsesNonOverlappingPublicEndpoints(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", CNAME: "demo.edge.example", Platform: "AWS", CDNStatus: 1, PlatformRegion: "CDN", BlockMode: 1}, endpoint: testEndpoint()}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	prior := testAppModel(t, ctx)
	prior.EPID = types.StringValue("100")
	plan := prior
	plan.CDN = types.BoolValue(true)
	plan.GlobalCDN = types.BoolValue(true)
	plan.Region = types.StringNull()
	plan.ExtraDomains, _ = types.ListValueFrom(ctx, types.StringType, []string{"new.example.com"})
	plan.BlockMode = types.BoolValue(true)
	plan.CertificateMode = types.StringValue("custom")
	plan.HTTP2Status = types.BoolValue(true)
	plan.IPv6Option = types.BoolValue(false)
	plan.CertChallengeMode = types.StringValue("dns")
	plan.BlockURL = types.StringValue("PredefinedMsg")
	plan.SslOptions = configuredSslOptions(t, ctx, "mozilla_old")
	request := resource.UpdateRequest{State: appState(t, ctx, schema, &prior), Plan: appPlan(t, ctx, schema, &plan)}
	response := resource.UpdateResponse{State: appState(t, ctx, schema, &prior)}
	implementation.Update(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	wantCalls := []string{"update-placement:100", "endpoint:100", "update-endpoint:100", "update-block:100", "find-id:100", "endpoint:100"}
	if !reflect.DeepEqual(service.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", service.calls, wantCalls)
	}
	if service.updatedEndpoint["custom_port"] != nil || service.updatedEndpoint["custom_http_port"] != int64(80) || service.updatedEndpoint["cert_type"] != 1 || service.updatedEndpoint["cert_auto_status"] != float64(7) || service.updatedEndpoint["cert_challenge_mode"] != 2 {
		t.Fatalf("endpoint request = %#v", service.updatedEndpoint)
	}
	if service.updatedEndpoint["http2_status"] != 1 || service.updatedEndpoint["ipv6_option"] != 0 || service.updatedEndpoint["block_url"] != "PredefinedMsg" || service.updatedEndpoint["preserve"] != true {
		t.Fatalf("endpoint request = %#v", service.updatedEndpoint)
	}
	sent := service.updatedEndpoint["ssl_options"].(map[string]any)
	if sent["encryption_level"] != "mozilla_old" || sent["hsts_max_age"] != int64(31536000) || sent["http_2_https"] != 1 {
		t.Fatalf("ssl_options request = %#v", sent)
	}
	if _, ok := sent["available_tls13_custom_cipher"]; ok {
		t.Fatalf("ssl_options request carries response-only fields: %#v", sent)
	}
	var state resourceModel
	if diagnostics := response.State.Get(ctx, &state); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !state.HTTP2Status.ValueBool() || state.IPv6Option.ValueBool() || state.CertChallengeMode.ValueString() != "dns" || state.BlockURL.ValueString() != "PredefinedMsg" {
		t.Fatalf("state = %#v", state)
	}
	if state.SslOptions.IsNull() {
		t.Fatal("state ssl_options is null after update")
	}
	var stateOptions sslOptionsModel
	if diagnostics := state.SslOptions.As(ctx, &stateOptions, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	// The plain mock stores the PUT document verbatim, so the refreshed block
	// carries the written level and members; the API recomputes tls_1_x from
	// the level, which is why those attributes are computed-only.
	if stateOptions.EncryptionLevel.ValueString() != "mozilla_old" || !stateOptions.HTTP2HTTPS.ValueBool() || stateOptions.HSTSMaxAge.ValueInt64() != 31536000 {
		t.Fatalf("state ssl_options = %#v", stateOptions)
	}
}

func TestUpdateEndpointFieldsNotPlannedPreserveRemoteValues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", Platform: "AWS", PlatformRegion: "us-east-1"}, endpoint: testEndpoint()}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	prior := testAppModel(t, ctx)
	prior.EPID = types.StringValue("100")
	prior.HTTP2Status = types.BoolValue(true)
	prior.IPv6Option = types.BoolValue(false)
	prior.CertChallengeMode = types.StringValue("dns")
	prior.BlockURL = types.StringValue("PredefinedMsg")
	plan := prior
	// The practitioner changed only extra_domains; the endpoint fields carry
	// no configuration of their own and must preserve the GET values.
	plan.HTTP2Status = types.BoolUnknown()
	plan.IPv6Option = types.BoolUnknown()
	plan.CertChallengeMode = types.StringUnknown()
	plan.BlockURL = types.StringUnknown()
	plan.ExtraDomains, _ = types.ListValueFrom(ctx, types.StringType, []string{"new.example.com"})
	request := resource.UpdateRequest{State: appState(t, ctx, schema, &prior), Plan: appPlan(t, ctx, schema, &plan)}
	response := resource.UpdateResponse{State: appState(t, ctx, schema, &prior)}
	implementation.Update(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	if service.updatedEndpoint["http2_status"] != float64(1) || service.updatedEndpoint["ipv6_option"] != float64(0) || service.updatedEndpoint["cert_challenge_mode"] != float64(2) || service.updatedEndpoint["block_url"] != "PredefinedMsg" {
		t.Fatalf("endpoint request = %#v", service.updatedEndpoint)
	}
}

func TestUpdateEndpointFieldsTriggerPutOnChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", Platform: "AWS", PlatformRegion: "us-east-1"}, endpoint: testEndpoint()}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	prior := testAppModel(t, ctx)
	prior.EPID = types.StringValue("100")
	// No other owned endpoint field changes; only http2_status flips.
	prior.HTTP2Status = types.BoolValue(true)
	prior.IPv6Option = types.BoolNull()
	prior.CertChallengeMode = types.StringNull()
	prior.BlockURL = types.StringNull()
	plan := prior
	plan.HTTP2Status = types.BoolValue(false)
	request := resource.UpdateRequest{State: appState(t, ctx, schema, &prior), Plan: appPlan(t, ctx, schema, &plan)}
	response := resource.UpdateResponse{State: appState(t, ctx, schema, &prior)}
	implementation.Update(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	for _, call := range service.calls {
		if call == "update-endpoint:100" {
			if service.updatedEndpoint["http2_status"] != 0 {
				t.Fatalf("endpoint request = %#v", service.updatedEndpoint)
			}
			return
		}
	}
	t.Fatalf("endpoint PUT was not triggered; calls = %#v", service.calls)
}

func TestUpdateBlockURLPreservesEmptyString(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", Platform: "AWS", PlatformRegion: "us-east-1"}, endpoint: testEndpoint()}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	prior := testAppModel(t, ctx)
	prior.EPID = types.StringValue("100")
	prior.BlockURL = types.StringValue("PredefinedMsg")
	plan := prior
	plan.BlockURL = types.StringValue("")
	response := resource.UpdateResponse{State: appState(t, ctx, schema, &prior)}
	implementation.Update(ctx, resource.UpdateRequest{State: appState(t, ctx, schema, &prior), Plan: appPlan(t, ctx, schema, &plan)}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	var state resourceModel
	if diagnostics := response.State.Get(ctx, &state); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !state.BlockURL.Equal(plan.BlockURL) {
		t.Fatalf("block_url = %s, want the configured empty string", state.BlockURL)
	}
}

func TestDeleteUsesStableEPIDAndWaitsForAbsence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo"}}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	model := testAppModel(t, ctx)
	model.EPID = types.StringValue("100")
	response := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: appState(t, ctx, currentSchema(), &model)}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", response.Diagnostics)
	}
	want := []string{"find-id:100", "delete:100", "find-id:100", "exists:100"}
	if !reflect.DeepEqual(service.calls, want) {
		t.Fatalf("calls = %#v, want %#v", service.calls, want)
	}
}

func TestUpgradeStateV0PreservesLegacyInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	oldSchema := legacySchemaV0()
	extra, _ := types.ListValueFrom(ctx, types.StringType, []string{"api.example.com"})
	services, _ := types.MapValueFrom(ctx, types.Int64Type, map[string]int64{"http": 80, "https": 443})
	type legacyModel struct {
		ID                  types.String `tfsdk:"id"`
		AppName             types.String `tfsdk:"app_name"`
		DomainName          types.String `tfsdk:"domain_name"`
		ExtraDomains        types.List   `tfsdk:"extra_domains"`
		AppService          types.Map    `tfsdk:"app_service"`
		OriginServerIP      types.String `tfsdk:"origin_server_ip"`
		OriginServerService types.String `tfsdk:"origin_server_service"`
		OriginServerPort    types.Int64  `tfsdk:"origin_server_port"`
		CDN                 types.Bool   `tfsdk:"cdn"`
		ContinentCDN        types.Bool   `tfsdk:"continent_cdn"`
		Continent           types.String `tfsdk:"continent"`
		Block               types.Bool   `tfsdk:"block"`
		Template            types.String `tfsdk:"template"`
		CNAME               types.String `tfsdk:"cname"`
		EPID                types.String `tfsdk:"ep_id"`
	}
	old := legacyModel{ID: types.StringValue("demo"), AppName: types.StringValue("demo"), DomainName: types.StringValue("demo.example.com"), ExtraDomains: extra, AppService: services, OriginServerIP: types.StringValue("192.0.2.10"), OriginServerService: types.StringValue("HTTPS"), OriginServerPort: types.Int64Value(443), CDN: types.BoolValue(false), ContinentCDN: types.BoolValue(false), Continent: types.StringNull(), Block: types.BoolValue(true), Template: types.StringValue("legacy-template"), CNAME: types.StringValue(`["a.edge.example","b.edge.example"]`), EPID: types.StringNull()}
	oldState := appState(t, ctx, oldSchema, &old)
	request := resource.UpgradeStateRequest{State: &oldState}
	response := resource.UpgradeStateResponse{State: tfsdk.State{Schema: currentSchema()}}
	upgradeStateV0(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("upgrade diagnostics = %v", response.Diagnostics)
	}
	var upgraded resourceModel
	if diagnostics := response.State.Get(ctx, &upgraded); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if upgraded.LegacyAppName.ValueString() != "demo" || upgraded.Platform.IsNull() == false || upgraded.BlockMode.ValueBool() != true || !upgraded.CertificateMode.IsNull() || upgraded.AttachedTemplateName.ValueString() != "legacy-template" || !upgraded.AttachedTemplateID.IsNull() {
		t.Fatalf("upgraded = %#v", upgraded)
	}
	var cnames []string
	if diagnostics := upgraded.CNAMEs.ElementsAs(ctx, &cnames, false); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !reflect.DeepEqual(cnames, []string{"a.edge.example", "b.edge.example"}) {
		t.Fatalf("cnames = %#v", cnames)
	}
}

func TestUpgradeStateV1LeavesCertificateModeForRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	current := testAppModel(t, ctx)
	current.EPID = types.StringValue("100")
	old := resourceModelV1{
		EPID: current.EPID, LegacyAppName: current.LegacyAppName, AppName: current.AppName, DomainName: current.DomainName,
		ExtraDomains: current.ExtraDomains, Services: current.Services, HTTPPort: current.HTTPPort, HTTPSPort: current.HTTPSPort,
		Platform: current.Platform, Region: current.Region, CDN: current.CDN, GlobalCDN: current.GlobalCDN, Continent: current.Continent,
		BlockMode: current.BlockMode, InitialOrigin: current.InitialOrigin, Precheck: current.Precheck,
		CNAMEs: current.CNAMEs, PlacementRegion: current.PlacementRegion,
		AttachedTemplateID: current.AttachedTemplateID, AttachedTemplateName: current.AttachedTemplateName,
	}
	oldState := appState(t, ctx, schemaV1(), &old)
	response := resource.UpgradeStateResponse{State: tfsdk.State{Schema: currentSchema()}}
	upgradeStateV1(ctx, resource.UpgradeStateRequest{State: &oldState}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("upgrade diagnostics = %v", response.Diagnostics)
	}
	var upgraded resourceModel
	if diagnostics := response.State.Get(ctx, &upgraded); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if upgraded.EPID.ValueString() != "100" || upgraded.AppName.ValueString() != "demo" || !upgraded.CertificateMode.IsNull() {
		t.Fatalf("upgraded = %#v", upgraded)
	}
}

func TestCertificateModeFromEndpoint(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		value   any
		present bool
		want    string
		wantErr bool
	}{
		{name: "automatic float", value: float64(0), present: true, want: "automatic"},
		{name: "custom integer", value: int(1), present: true, want: "custom"},
		{name: "custom json number", value: json.Number("1"), present: true, want: "custom"},
		{name: "missing", wantErr: true},
		{name: "unsupported", value: float64(2), present: true, wantErr: true},
		{name: "fraction", value: float64(0.5), present: true, wantErr: true},
		{name: "string", value: "0", present: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := map[string]any{}
			if test.present {
				document["cert_type"] = test.value
			}
			got, err := certificateModeFromEndpoint(document)
			if (err != nil) != test.wantErr {
				t.Fatalf("certificateModeFromEndpoint() error = %v, wantErr %t", err, test.wantErr)
			}
			if !test.wantErr && got.ValueString() != test.want {
				t.Fatalf("certificateModeFromEndpoint() = %q, want %q", got.ValueString(), test.want)
			}
		})
	}
}

func testAppModel(t *testing.T, ctx context.Context) resourceModel {
	t.Helper()
	extra, _ := types.ListValueFrom(ctx, types.StringType, []string{"api.example.com"})
	services, _ := types.SetValueFrom(ctx, types.StringType, []string{"http", "https"})
	origin, diagnostics := types.ObjectValue(initialOriginTypes, map[string]attr.Value{"address": types.StringValue("192.0.2.10"), "protocol": types.StringValue("https"), "port": types.Int64Value(443)})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return resourceModel{EPID: types.StringNull(), LegacyAppName: types.StringNull(), AppName: types.StringValue("demo"), DomainName: types.StringValue("demo.example.com"), ExtraDomains: extra, Services: services, HTTPPort: types.Int64Value(80), HTTPSPort: types.Int64Value(443), Platform: types.StringValue("AWS"), Region: types.StringValue("us-east-1"), CDN: types.BoolValue(false), GlobalCDN: types.BoolValue(false), Continent: types.StringNull(), BlockMode: types.BoolValue(false), CertificateMode: types.StringValue("automatic"), InitialOrigin: origin, Precheck: types.BoolValue(false), CNAMEs: types.ListNull(types.StringType), PlacementRegion: types.StringNull(), AttachedTemplateID: types.StringNull(), AttachedTemplateName: types.StringNull(), SslOptions: types.ObjectNull(sslOptionsTypes)}
}

func testEndpoint() map[string]any {
	return map[string]any{"extra_domains": []any{"api.example.com"}, "http_status": float64(1), "https_status": float64(1), "custom_port": map[string]any{"http": float64(80), "https": float64(443)}, "cert_type": float64(0), "cert_auto_status": float64(7), "cert_challenge_mode": float64(2), "http2_status": float64(1), "ipv6_option": float64(0), "block_url": "PredefinedMsg", "ssl_options": map[string]any{"encryption_level": "mozilla_intermediate", "tls_1_1": float64(0), "tls_1_2": float64(1), "tls_1_3": float64(1), "http_2_https": float64(0), "hsts_header": float64(0), "hsts_max_age": float64(15552000), "hsts_preload": float64(0), "hsts_sub_domains": float64(0), "internal_cookie_secure": float64(0), "internal_cookie_httponly": float64(0), "selected_ssl_custom_cipher": []any{"ECDHE-RSA-AES128-GCM-SHA256"}, "selected_ssl_custom_cipher_http2": []any{"ECDHE-RSA-AES256-GCM-SHA384"}, "selected_tls13_custom_cipher": []any{"TLS_AES_256_GCM_SHA384"}, "available_ssl_custom_cipher": []any{"ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES128-GCM-SHA256"}, "available_ssl_custom_cipher_http2": []any{"ECDHE-RSA-AES256-GCM-SHA384"}, "available_tls13_custom_cipher": []any{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}}, "preserve": true}
}

// configuredSslOptions builds a practitioner-configured ssl_options block.
// Only the explicitly configured members are set; the rest stay null to prove
// the merge-PUT carries the fresh GET values for unset members.
func configuredSslOptions(t *testing.T, ctx context.Context, level string) types.Object {
	t.Helper()
	object, diagnostics := types.ObjectValue(sslOptionsTypes, map[string]attr.Value{
		"encryption_level":                  types.StringValue(level),
		"tls_1_1":                           types.BoolNull(),
		"tls_1_2":                           types.BoolNull(),
		"tls_1_3":                           types.BoolNull(),
		"http_2_https":                      types.BoolValue(true),
		"hsts_header":                       types.BoolNull(),
		"hsts_max_age":                      types.Int64Value(31536000),
		"hsts_preload":                      types.BoolNull(),
		"hsts_sub_domains":                  types.BoolNull(),
		"internal_cookie_secure":            types.BoolNull(),
		"internal_cookie_httponly":          types.BoolNull(),
		"selected_ssl_custom_cipher":        types.ListNull(types.StringType),
		"selected_ssl_custom_cipher_http2":  types.ListNull(types.StringType),
		"selected_tls13_custom_cipher":      types.ListNull(types.StringType),
		"available_ssl_custom_cipher":       types.ListNull(types.StringType),
		"available_ssl_custom_cipher_http2": types.ListNull(types.StringType),
		"available_tls13_custom_cipher":     types.ListNull(types.StringType),
	})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return object
}

func TestValidateSslOptionsRequiresEncryptionLevelOnlyWhenConfigured(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, testCase := range []struct {
		name      string
		omitted   bool
		level     types.String
		wantError bool
	}{
		{name: "omitted block", omitted: true},
		{name: "configured level", level: types.StringValue("mozilla_intermediate")},
		{name: "unknown level", level: types.StringUnknown()},
		{name: "missing level", level: types.StringNull(), wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := testAppModel(t, ctx)
			if !testCase.omitted {
				attributes := configuredSslOptions(t, ctx, "mozilla_intermediate").Attributes()
				attributes["encryption_level"] = testCase.level
				attributes["hsts_header"] = types.BoolValue(true)
				var diagnostics diag.Diagnostics
				config.SslOptions, diagnostics = types.ObjectValue(sslOptionsTypes, attributes)
				if diagnostics.HasError() {
					t.Fatal(diagnostics)
				}
			}
			var diagnostics diag.Diagnostics
			validateSslOptionsConfig(ctx, config, &diagnostics)
			if diagnostics.HasError() != testCase.wantError {
				t.Fatalf("validation diagnostics = %v, want error %t", diagnostics, testCase.wantError)
			}
			if testCase.wantError && diagnostics[0].Summary() != "Missing SSL encryption level" {
				t.Fatalf("unexpected validation diagnostic: %v", diagnostics)
			}
		})
	}
}

func TestValidateSslOptionsRejectsHstsDependentsWithoutHeader(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	hstsDisabled, diagnostics := types.ObjectValue(sslOptionsTypes, map[string]attr.Value{
		"encryption_level":                  types.StringValue("mozilla_intermediate"),
		"tls_1_1":                           types.BoolNull(),
		"tls_1_2":                           types.BoolNull(),
		"tls_1_3":                           types.BoolNull(),
		"http_2_https":                      types.BoolNull(),
		"hsts_header":                       types.BoolValue(false),
		"hsts_max_age":                      types.Int64Value(31536000),
		"hsts_preload":                      types.BoolNull(),
		"hsts_sub_domains":                  types.BoolNull(),
		"internal_cookie_secure":            types.BoolNull(),
		"internal_cookie_httponly":          types.BoolNull(),
		"selected_ssl_custom_cipher":        types.ListNull(types.StringType),
		"selected_ssl_custom_cipher_http2":  types.ListNull(types.StringType),
		"selected_tls13_custom_cipher":      types.ListNull(types.StringType),
		"available_ssl_custom_cipher":       types.ListNull(types.StringType),
		"available_ssl_custom_cipher_http2": types.ListNull(types.StringType),
		"available_tls13_custom_cipher":     types.ListNull(types.StringType),
	})
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	config := testAppModel(t, ctx)
	config.SslOptions = hstsDisabled
	var validator diag.Diagnostics
	validateSslOptionsConfig(ctx, config, &validator)
	if !validator.HasError() {
		t.Fatal("hsts_max_age with hsts_header disabled was accepted")
	}
	if len(validator.Errors()) != 1 {
		t.Fatalf("diagnostics = %v", validator)
	}

	// The same block with hsts_header enabled is valid.
	hstsEnabledObject := map[string]attr.Value{}
	for key, value := range hstsDisabled.Attributes() {
		hstsEnabledObject[key] = value
	}
	hstsEnabledObject["hsts_header"] = types.BoolValue(true)
	hstsEnabled, diagnostics := types.ObjectValue(sslOptionsTypes, hstsEnabledObject)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	config.SslOptions = hstsEnabled
	var clean diag.Diagnostics
	validateSslOptionsConfig(ctx, config, &clean)
	if clean.HasError() {
		t.Fatalf("hsts_max_age with hsts_header enabled was rejected: %v", clean)
	}

	// A value supplied by another resource is not known during validation.
	// Defer the dependency check until that value is resolved.
	hstsEnabledObject["hsts_header"] = types.BoolUnknown()
	config.SslOptions, diagnostics = types.ObjectValue(sslOptionsTypes, hstsEnabledObject)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var deferred diag.Diagnostics
	validateSslOptionsConfig(ctx, config, &deferred)
	if deferred.HasError() {
		t.Fatalf("unknown hsts_header was rejected before it could resolve: %v", deferred)
	}
}

// TestUpdateSslOptionsCarriesRemoteCiphers proves computed-only cipher lists
// are carried from the fresh GET document into the PUT so an encryption-level
// update never overwrites the remote ciphers with the API default.
func TestUpdateSslOptionsCarriesRemoteCiphers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", Platform: "AWS", PlatformRegion: "us-east-1"}, endpoint: testEndpoint()}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	prior := testAppModel(t, ctx)
	prior.EPID = types.StringValue("100")
	plan := prior
	plan.SslOptions = configuredSslOptions(t, ctx, "mozilla_old")
	request := resource.UpdateRequest{State: appState(t, ctx, schema, &prior), Plan: appPlan(t, ctx, schema, &plan)}
	response := resource.UpdateResponse{State: appState(t, ctx, schema, &prior)}
	implementation.Update(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	sent := service.updatedEndpoint["ssl_options"].(map[string]any)
	if sent["selected_ssl_custom_cipher"] == nil || sent["selected_tls13_custom_cipher"] == nil {
		t.Fatalf("ssl_options request dropped remote cipher lists: %#v", sent)
	}
}

func TestUpdateSslOptionsNotPlannedPreservesRemoteDocument(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeAppService{application: client.Application{EPID: "100", AppName: "demo", DomainName: "demo.example.com", Platform: "AWS", PlatformRegion: "us-east-1"}, endpoint: testEndpoint()}
	implementation := &appResource{service: service, locks: locking.NewRegistry(), pollAttempts: 1}
	schema := currentSchema()
	prior := testAppModel(t, ctx)
	prior.EPID = types.StringValue("100")
	// The practitioner changed only extra_domains; ssl_options is not
	// configured and must stay absent from the request document replacement.
	plan := prior
	plan.SslOptions = types.ObjectNull(sslOptionsTypes)
	plan.ExtraDomains, _ = types.ListValueFrom(ctx, types.StringType, []string{"new.example.com"})
	request := resource.UpdateRequest{State: appState(t, ctx, schema, &prior), Plan: appPlan(t, ctx, schema, &plan)}
	response := resource.UpdateResponse{State: appState(t, ctx, schema, &prior)}
	implementation.Update(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Update() diagnostics = %v", response.Diagnostics)
	}
	sent, ok := service.updatedEndpoint["ssl_options"].(map[string]any)
	if !ok || sent["encryption_level"] != "mozilla_intermediate" || sent["hsts_max_age"] != float64(15552000) {
		t.Fatalf("ssl_options request = %#v", service.updatedEndpoint["ssl_options"])
	}
	if sent["available_ssl_custom_cipher"] == nil {
		t.Fatalf("ssl_options request dropped remote members: %#v", sent)
	}
	var state resourceModel
	if diagnostics := response.State.Get(ctx, &state); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !state.SslOptions.IsNull() {
		t.Fatal("omitted ssl_options block must remain null in state")
	}
}

func appState(t *testing.T, ctx context.Context, resourceSchema resourceschema.Schema, model any) tfsdk.State {
	t.Helper()
	state := tfsdk.State{Schema: resourceSchema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return state
}

func appPlan(t *testing.T, ctx context.Context, resourceSchema resourceschema.Schema, model any) tfsdk.Plan {
	t.Helper()
	plan := tfsdk.Plan{Schema: resourceSchema}
	if diagnostics := plan.Set(ctx, model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return plan
}
func nullAppState(ctx context.Context, resourceSchema resourceschema.Schema) tfsdk.State {
	return tfsdk.State{Schema: resourceSchema, Raw: tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil)}
}

type fakeAppService struct {
	calls            []string
	created          client.ApplicationCreateRequest
	application      client.Application
	endpoint         map[string]any
	updatedEndpoint  map[string]any
	getEndpointError error
	putEndpointError error
	dnsAddresses     []string
	deleted          bool
}

func (s *fakeAppService) CreateApplication(_ context.Context, request client.ApplicationCreateRequest) (client.ApplicationCreateResponse, error) {
	s.calls = append(s.calls, "create")
	s.created = request
	return client.ApplicationCreateResponse{EPID: "100", DomainInfo: []client.ApplicationDomainInfo{{DNS: "demo.edge.example"}}}, nil
}
func (s *fakeAppService) UpdateApplication(_ context.Context, id string, _ client.ApplicationUpdateRequest) error {
	s.calls = append(s.calls, "update-placement:"+id)
	return nil
}
func (s *fakeAppService) UpdateApplicationBlockMode(_ context.Context, id string, _ bool) error {
	s.calls = append(s.calls, "update-block:"+id)
	return nil
}
func (s *fakeAppService) GetApplicationEndpoint(_ context.Context, id string) (map[string]any, error) {
	s.calls = append(s.calls, "endpoint:"+id)
	if s.getEndpointError != nil {
		return nil, s.getEndpointError
	}
	result := map[string]any{}
	for key, value := range s.endpoint {
		result[key] = value
	}
	return result, nil
}
func (s *fakeAppService) PutApplicationEndpoint(_ context.Context, id string, document map[string]any) error {
	s.calls = append(s.calls, "update-endpoint:"+id)
	if s.putEndpointError != nil {
		return s.putEndpointError
	}
	s.updatedEndpoint = document
	s.endpoint = document
	return nil
}
func (s *fakeAppService) DeleteApplication(_ context.Context, id string) error {
	s.calls = append(s.calls, "delete:"+id)
	s.deleted = true
	return nil
}
func (s *fakeAppService) FindApplicationByName(_ context.Context, name string) (client.Application, error) {
	s.calls = append(s.calls, "find-name:"+name)
	return s.application, nil
}
func (s *fakeAppService) FindApplicationByEPID(_ context.Context, id string) (client.Application, error) {
	s.calls = append(s.calls, "find-id:"+id)
	if s.deleted || id != s.application.EPID {
		return client.Application{}, errors.New("not found")
	}
	return s.application, nil
}
func (s *fakeAppService) ApplicationExists(_ context.Context, id string) (bool, error) {
	s.calls = append(s.calls, "exists:"+id)
	return !s.deleted, nil
}
func (s *fakeAppService) DNSLookup(_ context.Context, domain string) ([]string, error) {
	s.calls = append(s.calls, "dns:"+domain)
	return s.dnsAddresses, nil
}
func (s *fakeAppService) TestBackendConnectivity(_ context.Context, request client.BackendConnectivityRequest) error {
	s.calls = append(s.calls, "connectivity:"+request.Address)
	return nil
}
