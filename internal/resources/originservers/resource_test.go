package originservers

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

func TestOriginCodecCanonicalizesIndicesAndPreservesReviewedFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	addressA, addressB := "192.0.2.10", "origin.example.com"
	typeIP, typeDomain, enabled := "ip", "domain", "enable"
	indexTwo, indexOne := int64(2), int64(1)
	certVerify, locked := true, true
	pools := []client.OriginServerPool{{
		Health: client.OriginServerHealth{Enabled: false}, LBAlgorithm: "round-robin", Name: "default_pool",
		Persistence: client.OriginServerPersistence{Type: "disable"}, ServerBalance: true,
		Servers: []client.OriginServer{
			{Address: &addressA, Type: &typeIP, Status: &enabled, Index: &indexTwo, CertificateVerify: &certVerify, Locked: &locked},
			{Address: &addressB, Type: &typeDomain, Status: &enabled, Index: &indexOne},
		},
	}}
	value, diagnostics := flattenPools(ctx, pools)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	expanded, diagnostics := expandPools(ctx, value)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if got := *expanded[0].Servers[0].Address; got != addressB {
		t.Fatalf("first address = %q", got)
	}
	if *expanded[0].Servers[0].Index != 1 || *expanded[0].Servers[1].Index != 2 {
		t.Fatalf("indices = %#v", expanded[0].Servers)
	}
	if expanded[0].Servers[1].CertificateVerify == nil || !*expanded[0].Servers[1].CertificateVerify {
		t.Fatalf("certificate_verify lost: %#v", expanded[0].Servers[1])
	}
	if expanded[0].Servers[1].Locked != nil {
		t.Fatalf("server-owned locked was sent: %#v", expanded[0].Servers[1])
	}
	if !reflect.DeepEqual(expanded[0].Persistence.Type, "disable") {
		t.Fatalf("pool = %#v", expanded[0])
	}
}

func TestOriginLifecycleUsesFreshGetPutGetAndForgetDestroy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	address, serverType, status := "192.0.2.10", "ip", "enable"
	pools := []client.OriginServerPool{{
		Health: client.OriginServerHealth{Enabled: false}, LBAlgorithm: "round-robin", Name: "default_pool",
		Persistence: client.OriginServerPersistence{Type: "disable"}, ServerBalance: true,
		Servers: []client.OriginServer{{Address: &address, Type: &serverType, Status: &status}},
	}}
	poolValue, diagnostics := flattenPools(ctx, pools)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	service := &fakeOriginService{pools: pools}
	implementation := &originServersResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := originTestSchema(t, ctx, implementation)
	plan := tfsdk.Plan{Schema: resourceSchema}
	model := resourceModel{EPID: types.StringValue("100"), ServerPools: poolValue}
	if diagnostics := plan.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	response := resource.CreateResponse{State: tfsdk.State{Schema: resourceSchema, Raw: tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil)}}
	implementation.Create(ctx, resource.CreateRequest{Plan: plan}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"get:100", "put:100", "get:100"}) {
		t.Fatalf("calls = %#v", service.calls)
	}
	deleteResponse := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: response.State}, &deleteResponse)
	if deleteResponse.Diagnostics.HasError() || len(deleteResponse.Diagnostics) != 1 {
		t.Fatalf("Delete() diagnostics = %v", deleteResponse.Diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"get:100", "put:100", "get:100", "get:100"}) {
		t.Fatalf("destroy calls = %#v", service.calls)
	}
}

func TestOriginCodecRequiresEncryptionLevelForSSL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model := serverModel{
		Address: types.StringValue("origin.example.com"), Type: types.StringValue("domain"), Status: types.StringValue("enable"),
		SSL: types.BoolValue(true), EncryptionLevel: types.StringNull(), ConnectionFilters: types.ListNull(types.ObjectType{AttrTypes: filterTypes}),
	}
	if _, diagnostics := expandServer(ctx, model, 0, 0); !diagnostics.HasError() {
		t.Fatal("expandServer() accepted ssl=true without encryption_level")
	}
	model.EncryptionLevel = types.StringValue("mozilla_intermediate")
	if _, diagnostics := expandServer(ctx, model, 0, 0); diagnostics.HasError() {
		t.Fatalf("expandServer() rejected explicit encryption_level: %v", diagnostics)
	}
}

func TestOriginSchemaDoesNotInventConditionalBackendDefaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	implementation := &originServersResource{locks: locking.NewRegistry()}
	resourceSchema := originTestSchema(t, ctx, implementation)
	pools := resourceSchema.Blocks["server_pools"].(resourceschema.ListNestedBlock)
	persistence := pools.NestedObject.Blocks["persistence"].(resourceschema.SingleNestedBlock)
	if timeout := persistence.Attributes["timeout"].(resourceschema.Int64Attribute); timeout.Default != nil {
		t.Fatal("persistence.timeout has an unconditional default")
	}
	servers := pools.NestedObject.Blocks["servers"].(resourceschema.ListNestedBlock)
	for _, name := range []string{"tls_1_0", "tls_1_1"} {
		if attribute := servers.NestedObject.Attributes[name].(resourceschema.BoolAttribute); attribute.Default != nil {
			t.Fatalf("%s has an unconditional default", name)
		}
	}
}

func originTestSchema(t *testing.T, ctx context.Context, implementation *originServersResource) resourceschema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	implementation.Schema(ctx, resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	return response.Schema
}

type fakeOriginService struct {
	calls []string
	pools []client.OriginServerPool
}

func (s *fakeOriginService) GetOriginServers(_ context.Context, epID string) (client.OriginServersDocument, error) {
	s.calls = append(s.calls, "get:"+epID)
	return client.OriginServersDocument{Result: client.OriginServersResult{ServerPools: s.pools}}, nil
}

func (s *fakeOriginService) PutOriginServers(_ context.Context, epID string, pools []client.OriginServerPool) error {
	s.calls = append(s.calls, "put:"+epID)
	s.pools = pools
	return nil
}

func (s *fakeOriginService) ApplicationExists(context.Context, string) (bool, error) {
	return true, nil
}
