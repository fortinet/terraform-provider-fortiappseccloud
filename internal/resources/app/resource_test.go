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
	if service.updatedEndpoint["custom_port"] != nil || service.updatedEndpoint["custom_http_port"] != int64(80) || service.updatedEndpoint["cert_type"] != 1 || service.updatedEndpoint["cert_auto_status"] != float64(7) || service.updatedEndpoint["cert_challenge_mode"] != float64(2) {
		t.Fatalf("endpoint request = %#v", service.updatedEndpoint)
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
	return resourceModel{EPID: types.StringNull(), LegacyAppName: types.StringNull(), AppName: types.StringValue("demo"), DomainName: types.StringValue("demo.example.com"), ExtraDomains: extra, Services: services, HTTPPort: types.Int64Value(80), HTTPSPort: types.Int64Value(443), Platform: types.StringValue("AWS"), Region: types.StringValue("us-east-1"), CDN: types.BoolValue(false), GlobalCDN: types.BoolValue(false), Continent: types.StringNull(), BlockMode: types.BoolValue(false), CertificateMode: types.StringValue("automatic"), InitialOrigin: origin, Precheck: types.BoolValue(false), CNAMEs: types.ListNull(types.StringType), PlacementRegion: types.StringNull(), AttachedTemplateID: types.StringNull(), AttachedTemplateName: types.StringNull()}
}

func testEndpoint() map[string]any {
	return map[string]any{"extra_domains": []any{"api.example.com"}, "http_status": float64(1), "https_status": float64(1), "custom_port": map[string]any{"http": float64(80), "https": float64(443)}, "cert_type": float64(0), "cert_auto_status": float64(7), "cert_challenge_mode": float64(2), "preserve": true}
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
	calls           []string
	created         client.ApplicationCreateRequest
	application     client.Application
	endpoint        map[string]any
	updatedEndpoint map[string]any
	dnsAddresses    []string
	deleted         bool
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
	result := map[string]any{}
	for key, value := range s.endpoint {
		result[key] = value
	}
	return result, nil
}
func (s *fakeAppService) PutApplicationEndpoint(_ context.Context, id string, document map[string]any) error {
	s.calls = append(s.calls, "update-endpoint:"+id)
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
