package template

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

func TestTemplateCreateReadDeleteLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeTemplateService{}
	implementation := &templateResource{
		service:      service,
		locks:        locking.NewRegistry(),
		pollAttempts: 1,
	}
	resourceSchema := templateSchema(t, ctx, implementation)
	model := resourceModel{
		TemplateID: types.StringUnknown(),
		Name:       types.StringValue("terraform-template"),
		Predefined: types.BoolUnknown(),
		Features:   types.ListUnknown(types.StringType),
	}
	config := templateConfig(t, ctx, resourceSchema, &model)
	plan := templatePlan(t, ctx, resourceSchema, &model)
	create := resource.CreateResponse{State: templateNullState(ctx, resourceSchema)}
	implementation.Create(ctx, resource.CreateRequest{Config: config, Plan: plan}, &create)
	if create.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", create.Diagnostics)
	}
	if !reflect.DeepEqual(service.createRequests, []client.TemplateCreateRequest{{
		Name: "terraform-template", Endpoints: []string{},
	}}) {
		t.Fatalf("create requests = %#v", service.createRequests)
	}
	state := templateState(t, ctx, create.State)
	if state.TemplateID.ValueString() != "tpl_123456" || state.Name.ValueString() != "terraform-template" ||
		state.Predefined.ValueBool() || len(state.Features.Elements()) != 0 {
		t.Fatalf("created state = %#v", state)
	}

	service.current.Features = []string{"csrf_protection"}
	read := resource.ReadResponse{State: copyTemplateState(create.State)}
	implementation.Read(ctx, resource.ReadRequest{State: create.State}, &read)
	if read.Diagnostics.HasError() {
		t.Fatalf("Read() diagnostics = %v", read.Diagnostics)
	}
	state = templateState(t, ctx, read.State)
	if len(state.Features.Elements()) != 1 {
		t.Fatalf("features = %#v", state.Features)
	}

	deleteResponse := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: read.State}, &deleteResponse)
	if deleteResponse.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", deleteResponse.Diagnostics)
	}
	if !reflect.DeepEqual(service.deleteIDs, []string{"tpl_123456"}) {
		t.Fatalf("delete IDs = %#v", service.deleteIDs)
	}
}

func TestTemplateImportSetsOnlyStableID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	implementation := NewResource(nil).(*templateResource)
	resourceSchema := templateSchema(t, ctx, implementation)
	empty := templateStateFor(t, ctx, resourceSchema, &resourceModel{
		TemplateID: types.StringNull(),
		Name:       types.StringNull(),
		Predefined: types.BoolNull(),
		Features:   types.ListNull(types.StringType),
	})
	response := resource.ImportStateResponse{State: copyTemplateState(empty)}
	implementation.ImportState(ctx, resource.ImportStateRequest{ID: " tpl_123456 "}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("ImportState() diagnostics = %v", response.Diagnostics)
	}
	state := templateState(t, ctx, response.State)
	if state.TemplateID.ValueString() != "tpl_123456" || !state.Name.IsNull() ||
		!state.Predefined.IsNull() || !state.Features.IsNull() {
		t.Fatalf("imported state = %#v", state)
	}
}

func TestTemplateDeleteRejectsPredefinedTemplate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeTemplateService{}
	implementation := &templateResource{
		service:      service,
		locks:        locking.NewRegistry(),
		pollAttempts: 1,
	}
	resourceSchema := templateSchema(t, ctx, implementation)
	state := templateStateFor(t, ctx, resourceSchema, &resourceModel{
		TemplateID: types.StringValue("predefined-1"),
		Name:       types.StringValue("Default"),
		Predefined: types.BoolValue(true),
		Features:   types.ListValueMust(types.StringType, []attr.Value{}),
	})
	response := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: state}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("Delete() accepted a predefined template")
	}
	if len(service.deleteIDs) != 0 {
		t.Fatalf("DeleteTemplate() calls = %#v", service.deleteIDs)
	}
}

func TestTemplateDeleteAccepts403AfterInventoryConfirmsAbsence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	service := &fakeTemplateService{deletedStatus: http.StatusForbidden}
	service.current = client.Template{
		TemplateID: "tpl_123456",
		Name:       "terraform-template",
		Features:   []string{},
		Endpoints:  []client.TemplateEndpoint{},
	}
	implementation := &templateResource{
		service:      service,
		locks:        locking.NewRegistry(),
		pollAttempts: 1,
	}
	resourceSchema := templateSchema(t, ctx, implementation)
	state := templateStateFor(t, ctx, resourceSchema, &resourceModel{
		TemplateID: types.StringValue("tpl_123456"),
		Name:       types.StringValue("terraform-template"),
		Predefined: types.BoolValue(false),
		Features:   types.ListValueMust(types.StringType, []attr.Value{}),
	})
	response := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: state}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", response.Diagnostics)
	}
	if !reflect.DeepEqual(service.deleteIDs, []string{"tpl_123456"}) {
		t.Fatalf("delete IDs = %#v", service.deleteIDs)
	}
}

type fakeTemplateService struct {
	current        client.Template
	createRequests []client.TemplateCreateRequest
	deleteIDs      []string
	deleted        bool
	deletedStatus  int
}

func (s *fakeTemplateService) CreateTemplate(_ context.Context, request client.TemplateCreateRequest) (client.TemplateCreateResponse, error) {
	s.createRequests = append(s.createRequests, request)
	s.current = client.Template{
		TemplateID: "tpl_123456",
		Name:       request.Name,
		Predefined: false,
		Features:   []string{},
		Endpoints:  []client.TemplateEndpoint{},
	}
	return client.TemplateCreateResponse{Result: s.current, Detail: "Template created"}, nil
}

func (s *fakeTemplateService) GetTemplate(context.Context, string) (client.Template, error) {
	if s.deleted {
		status := s.deletedStatus
		if status == 0 {
			status = http.StatusNotFound
		}
		return client.Template{}, &client.APIError{Operation: "get template", StatusCode: status}
	}
	return s.current, nil
}

func (s *fakeTemplateService) TemplateExists(context.Context, string) (bool, error) {
	return !s.deleted, nil
}

func (s *fakeTemplateService) DeleteTemplate(_ context.Context, templateID string) error {
	s.deleteIDs = append(s.deleteIDs, templateID)
	s.deleted = true
	return nil
}

func templateSchema(t *testing.T, ctx context.Context, implementation resource.Resource) schema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	implementation.Schema(ctx, resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Schema() diagnostics = %v", response.Diagnostics)
	}
	return response.Schema
}

func templateStateFor(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.State {
	t.Helper()
	state := tfsdk.State{Schema: resourceSchema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatalf("State.Set() diagnostics = %v", diagnostics)
	}
	return state
}

func templateConfig(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Config {
	t.Helper()
	state := templateStateFor(t, ctx, resourceSchema, model)
	return tfsdk.Config{Schema: resourceSchema, Raw: state.Raw.Copy()}
}

func templatePlan(t *testing.T, ctx context.Context, resourceSchema schema.Schema, model any) tfsdk.Plan {
	t.Helper()
	state := templateStateFor(t, ctx, resourceSchema, model)
	return tfsdk.Plan{Schema: resourceSchema, Raw: state.Raw.Copy()}
}

func templateNullState(ctx context.Context, resourceSchema schema.Schema) tfsdk.State {
	return tfsdk.State{
		Schema: resourceSchema,
		Raw:    tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil),
	}
}

func copyTemplateState(state tfsdk.State) tfsdk.State {
	return tfsdk.State{Schema: state.Schema, Raw: state.Raw.Copy()}
}

func templateState(t *testing.T, ctx context.Context, state tfsdk.State) resourceModel {
	t.Helper()
	var model resourceModel
	if diagnostics := state.Get(ctx, &model); diagnostics.HasError() {
		t.Fatalf("State.Get() diagnostics = %v", diagnostics)
	}
	return model
}
