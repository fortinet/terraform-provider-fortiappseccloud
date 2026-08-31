package templateattachment

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

func TestMembershipUpdatesPreserveUnrelatedApplications(t *testing.T) {
	t.Parallel()
	service := &fakeTemplateService{template: client.Template{TemplateID: "template-1", Endpoints: []client.TemplateEndpoint{{EPID: "100"}, {EPID: "300"}}}}
	implementation := &attachmentResource{service: service, locks: locking.NewRegistry()}
	var diagnostics diag.Diagnostics
	if !implementation.ensureMembership(context.Background(), "200", "template-1", true, &diagnostics) || diagnostics.HasError() {
		t.Fatalf("attach diagnostics = %v", diagnostics)
	}
	if !reflect.DeepEqual(service.puts[0], []string{"100", "200", "300"}) {
		t.Fatalf("attach PUT = %#v", service.puts[0])
	}
	diagnostics = nil
	if !implementation.ensureMembership(context.Background(), "200", "template-1", false, &diagnostics) || diagnostics.HasError() {
		t.Fatalf("detach diagnostics = %v", diagnostics)
	}
	if !reflect.DeepEqual(service.puts[1], []string{"100", "300"}) {
		t.Fatalf("detach PUT = %#v", service.puts[1])
	}
}

func TestAttachmentLifecyclePreservesAndRemovesOnlyManagedMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := &fakeTemplateService{template: client.Template{TemplateID: "template-1", Endpoints: []client.TemplateEndpoint{{EPID: "100"}, {EPID: "300"}}}}
	implementation := &attachmentResource{service: service, locks: locking.NewRegistry()}
	var schemaResponse resource.SchemaResponse
	implementation.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	resourceSchema := schemaResponse.Schema
	plan := tfsdk.Plan{Schema: resourceSchema}
	model := resourceModel{EPID: types.StringValue("200"), TemplateID: types.StringValue("template-1")}
	if diagnostics := plan.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	createResponse := resource.CreateResponse{State: tfsdk.State{Schema: resourceSchema, Raw: tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil)}}
	implementation.Create(ctx, resource.CreateRequest{Plan: plan}, &createResponse)
	if createResponse.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", createResponse.Diagnostics)
	}
	if !reflect.DeepEqual(service.puts, [][]string{{"100", "200", "300"}}) {
		t.Fatalf("attach PUTs = %#v", service.puts)
	}
	deleteResponse := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: createResponse.State}, &deleteResponse)
	if deleteResponse.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", deleteResponse.Diagnostics)
	}
	if !reflect.DeepEqual(service.puts, [][]string{{"100", "200", "300"}, {"100", "300"}}) {
		t.Fatalf("detach PUTs = %#v", service.puts)
	}
}

type fakeTemplateService struct {
	template client.Template
	puts     [][]string
}

func (s *fakeTemplateService) GetTemplate(context.Context, string) (client.Template, error) {
	return s.template, nil
}
func (s *fakeTemplateService) PutTemplateEndpoints(_ context.Context, _ string, ids []string) error {
	s.puts = append(s.puts, append([]string(nil), ids...))
	s.template.Endpoints = make([]client.TemplateEndpoint, len(ids))
	for index, id := range ids {
		s.template.Endpoints[index].EPID = id
	}
	return nil
}
func (s *fakeTemplateService) FindApplicationByEPID(context.Context, string) (client.Application, error) {
	return client.Application{}, nil
}
