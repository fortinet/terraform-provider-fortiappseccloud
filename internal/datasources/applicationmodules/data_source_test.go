package applicationmodules

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
)

type fakeApplicationModulesService struct {
	statuses client.ApplicationModuleStatuses
	err      error
	epID     string
}

func (s *fakeApplicationModulesService) GetApplicationModules(_ context.Context, epID string) (client.ApplicationModuleStatuses, error) {
	s.epID = epID
	return s.statuses, s.err
}

func TestApplicationModulesMetadataAndSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dataSource := NewDataSource()
	var metadata datasource.MetadataResponse
	dataSource.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &metadata)
	if metadata.TypeName != "fortiappseccloud_waf_modules" {
		t.Fatalf("type name = %q", metadata.TypeName)
	}

	var response datasource.SchemaResponse
	dataSource.Schema(ctx, datasource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics = %v", response.Diagnostics)
	}
	if len(response.Schema.Attributes) != 2 {
		t.Fatalf("attributes = %#v", response.Schema.Attributes)
	}
	epID, ok := response.Schema.Attributes["ep_id"].(datasourceschema.StringAttribute)
	if !ok || !epID.Required {
		t.Fatalf("ep_id schema = %#v", response.Schema.Attributes["ep_id"])
	}
	modules, ok := response.Schema.Attributes["modules"].(datasourceschema.ListAttribute)
	if !ok || !modules.Computed || !modules.ElementType.Equal(moduleStatusObjectType) {
		t.Fatalf("modules schema = %#v", response.Schema.Attributes["modules"])
	}
}

func TestApplicationModulesConfigure(t *testing.T) {
	t.Parallel()

	dataSource := &applicationModulesDataSource{}
	var response datasource.ConfigureResponse
	dataSource.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Configure accepted unexpected provider data")
	}

	apiClient := &client.Client{}
	response = datasource.ConfigureResponse{}
	dataSource.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: apiClient}, &response)
	if response.Diagnostics.HasError() || dataSource.service != apiClient {
		t.Fatalf("Configure diagnostics = %v, service = %#v", response.Diagnostics, dataSource.service)
	}
}

func TestApplicationModulesRead(t *testing.T) {
	t.Parallel()

	inherited := "disable"
	service := &fakeApplicationModulesService{
		statuses: client.ApplicationModuleStatuses{
			{ID: "advanced_bot_protection", Status: "enable", Inherited: &inherited},
			{ID: "url_access", Status: "disable"},
		},
	}
	dataSource := &applicationModulesDataSource{service: service}
	request, response := applicationModulesReadRequest(t, " app/id ")
	dataSource.Read(context.Background(), request, response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read diagnostics = %v", response.Diagnostics)
	}
	if service.epID != "app/id" {
		t.Fatalf("service ep_id = %q", service.epID)
	}

	var state dataSourceModel
	response.Diagnostics.Append(response.State.Get(context.Background(), &state)...)
	if response.Diagnostics.HasError() {
		t.Fatalf("State.Get diagnostics = %v", response.Diagnostics)
	}
	if state.EPID.ValueString() != "app/id" || state.Modules.IsNull() || state.Modules.IsUnknown() {
		t.Fatalf("state = %#v", state)
	}
	if len(state.Modules.Elements()) != 2 {
		t.Fatalf("modules = %#v", state.Modules)
	}
	first := state.Modules.Elements()[0].(types.Object).Attributes()
	if first["id"].(types.String).ValueString() != "advanced_bot_protection" ||
		first["status"].(types.String).ValueString() != "enable" ||
		first["inherited"].(types.String).ValueString() != "disable" {
		t.Fatalf("first module = %#v", first)
	}
	second := state.Modules.Elements()[1].(types.Object).Attributes()
	if !second["inherited"].(types.String).IsNull() {
		t.Fatalf("second inherited = %#v, want null", second["inherited"])
	}
}

func TestApplicationModulesReadAcceptsEmptyInventory(t *testing.T) {
	t.Parallel()

	dataSource := &applicationModulesDataSource{service: &fakeApplicationModulesService{
		statuses: client.ApplicationModuleStatuses{},
	}}
	request, response := applicationModulesReadRequest(t, "app")
	dataSource.Read(context.Background(), request, response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read diagnostics = %v", response.Diagnostics)
	}
	var state dataSourceModel
	if diagnostics := response.State.Get(context.Background(), &state); diagnostics.HasError() {
		t.Fatalf("State.Get diagnostics = %v", diagnostics)
	}
	if state.Modules.IsNull() || len(state.Modules.Elements()) != 0 {
		t.Fatalf("modules = %#v, want non-null empty list", state.Modules)
	}
}

func TestApplicationModulesReadErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		epID    string
		service applicationModulesService
	}{
		"provider not configured": {epID: "app"},
		"empty application ID":    {epID: "  ", service: &fakeApplicationModulesService{}},
		"client error": {
			epID:    "app",
			service: &fakeApplicationModulesService{err: errors.New("synthetic read error")},
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dataSource := &applicationModulesDataSource{service: test.service}
			request, response := applicationModulesReadRequest(t, test.epID)
			dataSource.Read(context.Background(), request, response)
			if !response.Diagnostics.HasError() {
				t.Fatalf("Read accepted %s", name)
			}
		})
	}
}

func TestApplicationModulesValidateConfig(t *testing.T) {
	t.Parallel()

	dataSource := &applicationModulesDataSource{}
	schema := applicationModulesSchema(t)
	for _, epID := range []string{"", " \t "} {
		config := applicationModulesConfig(t, schema, epID)
		var response datasource.ValidateConfigResponse
		dataSource.ValidateConfig(context.Background(), datasource.ValidateConfigRequest{Config: config}, &response)
		if !response.Diagnostics.HasError() {
			t.Fatalf("ValidateConfig accepted %q", epID)
		}
	}
}

func applicationModulesReadRequest(t *testing.T, epID string) (datasource.ReadRequest, *datasource.ReadResponse) {
	t.Helper()
	schema := applicationModulesSchema(t)
	config := applicationModulesConfig(t, schema, epID)
	return datasource.ReadRequest{Config: config}, &datasource.ReadResponse{
		State: tfsdk.State{Schema: schema},
	}
}

func applicationModulesSchema(t *testing.T) datasourceschema.Schema {
	t.Helper()
	var response datasource.SchemaResponse
	NewDataSource().Schema(context.Background(), datasource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics = %v", response.Diagnostics)
	}
	return response.Schema
}

func applicationModulesConfig(t *testing.T, schema datasourceschema.Schema, epID string) tfsdk.Config {
	t.Helper()
	state := tfsdk.State{Schema: schema}
	model := dataSourceModel{
		EPID:    types.StringValue(epID),
		Modules: types.ListNull(moduleStatusObjectType),
	}
	if diagnostics := state.Set(context.Background(), &model); diagnostics.HasError() {
		t.Fatalf("State.Set diagnostics = %v", diagnostics)
	}
	return tfsdk.Config{Schema: schema, Raw: state.Raw.Copy()}
}

func TestModuleStatusObjectTypeContract(t *testing.T) {
	t.Parallel()

	want := map[string]any{
		"id":        types.StringType,
		"status":    types.StringType,
		"inherited": types.StringType,
	}
	got := make(map[string]any, len(moduleStatusObjectType.AttrTypes))
	for name, attributeType := range moduleStatusObjectType.AttrTypes {
		got[name] = attributeType
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("module object attributes = %#v, want %#v", got, want)
	}
}
