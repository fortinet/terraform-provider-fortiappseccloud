package signatureexception

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
)

type fakeSignatureExceptionService struct {
	view        client.SignatureExceptionView
	err         error
	epID        string
	signatureID string
}

func (s *fakeSignatureExceptionService) GetSignatureException(_ context.Context, epID, signatureID string) (client.SignatureExceptionView, error) {
	s.epID = epID
	s.signatureID = signatureID
	return s.view, s.err
}

func TestSignatureExceptionMetadataAndSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dataSource := NewDataSource()
	var metadata datasource.MetadataResponse
	dataSource.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &metadata)
	if metadata.TypeName != "fortiappseccloud_waf_signature_exception" {
		t.Fatalf("type name = %q", metadata.TypeName)
	}
	schema := signatureExceptionSchema(t)
	if len(schema.Attributes) != 3 {
		t.Fatalf("attributes = %#v", schema.Attributes)
	}
	for _, name := range []string{"ep_id", "signature_id"} {
		attribute, ok := schema.Attributes[name].(datasourceschema.StringAttribute)
		if !ok || !attribute.Required {
			t.Fatalf("%s schema = %#v", name, schema.Attributes[name])
		}
	}
	template, ok := schema.Attributes["template_id"].(datasourceschema.StringAttribute)
	if !ok || !template.Computed {
		t.Fatalf("template_id schema = %#v", schema.Attributes["template_id"])
	}
}

func TestSignatureExceptionConfigure(t *testing.T) {
	t.Parallel()

	dataSource := &signatureExceptionDataSource{}
	var response datasource.ConfigureResponse
	dataSource.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: 1}, &response)
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

func TestSignatureExceptionRead(t *testing.T) {
	t.Parallel()

	templateID := "template-id"
	service := &fakeSignatureExceptionService{
		view: client.SignatureExceptionView{TemplateID: &templateID},
	}
	dataSource := &signatureExceptionDataSource{service: service}
	request, response := signatureExceptionReadRequest(t, " app/id ", " 030000001 ")
	dataSource.Read(context.Background(), request, response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read diagnostics = %v", response.Diagnostics)
	}
	if service.epID != "app/id" || service.signatureID != "030000001" {
		t.Fatalf("service identity = %q/%q", service.epID, service.signatureID)
	}
	var state dataSourceModel
	if diagnostics := response.State.Get(context.Background(), &state); diagnostics.HasError() {
		t.Fatalf("State.Get diagnostics = %v", diagnostics)
	}
	if state.EPID.ValueString() != "app/id" ||
		state.SignatureID.ValueString() != "030000001" ||
		state.TemplateID.ValueString() != "template-id" {
		t.Fatalf("state = %#v", state)
	}
}

func TestSignatureExceptionReadAllowsAbsentTemplate(t *testing.T) {
	t.Parallel()

	dataSource := &signatureExceptionDataSource{service: &fakeSignatureExceptionService{}}
	request, response := signatureExceptionReadRequest(t, "app", "030000001")
	dataSource.Read(context.Background(), request, response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Read diagnostics = %v", response.Diagnostics)
	}
	var state dataSourceModel
	if diagnostics := response.State.Get(context.Background(), &state); diagnostics.HasError() {
		t.Fatalf("State.Get diagnostics = %v", diagnostics)
	}
	if !state.TemplateID.IsNull() {
		t.Fatalf("template_id = %#v, want null", state.TemplateID)
	}
}

func TestSignatureExceptionReadErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		epID        string
		signatureID string
		service     signatureExceptionService
	}{
		"provider not configured": {epID: "app", signatureID: "030000001"},
		"empty application ID":    {epID: " ", signatureID: "030000001", service: &fakeSignatureExceptionService{}},
		"empty signature ID":      {epID: "app", signatureID: "\t", service: &fakeSignatureExceptionService{}},
		"client error": {
			epID:        "app",
			signatureID: "030000001",
			service:     &fakeSignatureExceptionService{err: errors.New("synthetic read error")},
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dataSource := &signatureExceptionDataSource{service: test.service}
			request, response := signatureExceptionReadRequest(t, test.epID, test.signatureID)
			dataSource.Read(context.Background(), request, response)
			if !response.Diagnostics.HasError() {
				t.Fatalf("Read accepted %s", name)
			}
		})
	}
}

func TestSignatureExceptionValidateConfig(t *testing.T) {
	t.Parallel()

	dataSource := &signatureExceptionDataSource{}
	schema := signatureExceptionSchema(t)
	for _, input := range []struct {
		epID        string
		signatureID string
	}{
		{epID: "", signatureID: "030000001"},
		{epID: "app", signatureID: " \t "},
	} {
		config := signatureExceptionConfig(t, schema, input.epID, input.signatureID)
		var response datasource.ValidateConfigResponse
		dataSource.ValidateConfig(context.Background(), datasource.ValidateConfigRequest{Config: config}, &response)
		if !response.Diagnostics.HasError() {
			t.Fatalf("ValidateConfig accepted %#v", input)
		}
	}
}

func signatureExceptionReadRequest(t *testing.T, epID, signatureID string) (datasource.ReadRequest, *datasource.ReadResponse) {
	t.Helper()
	schema := signatureExceptionSchema(t)
	config := signatureExceptionConfig(t, schema, epID, signatureID)
	return datasource.ReadRequest{Config: config}, &datasource.ReadResponse{
		State: tfsdk.State{Schema: schema},
	}
}

func signatureExceptionSchema(t *testing.T) datasourceschema.Schema {
	t.Helper()
	var response datasource.SchemaResponse
	NewDataSource().Schema(context.Background(), datasource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Schema diagnostics = %v", response.Diagnostics)
	}
	return response.Schema
}

func signatureExceptionConfig(t *testing.T, schema datasourceschema.Schema, epID, signatureID string) tfsdk.Config {
	t.Helper()
	state := tfsdk.State{Schema: schema}
	model := dataSourceModel{
		EPID:        types.StringValue(epID),
		SignatureID: types.StringValue(signatureID),
		TemplateID:  types.StringNull(),
	}
	if diagnostics := state.Set(context.Background(), &model); diagnostics.HasError() {
		t.Fatalf("State.Set diagnostics = %v", diagnostics)
	}
	return tfsdk.Config{Schema: schema, Raw: state.Raw.Copy()}
}
