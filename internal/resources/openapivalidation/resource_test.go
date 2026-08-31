package openapivalidation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

func TestUpgradeStateV0ResolvesIdentityAndHashesFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	filePath := filepath.Join(t.TempDir(), "schema.yaml")
	contents := []byte("openapi: 3.0.0\n")
	if err := os.WriteFile(filePath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	files, _ := types.ListValueFrom(ctx, types.StringType, []string{filePath})
	type legacyModel struct {
		ID              types.String `tfsdk:"id"`
		AppName         types.String `tfsdk:"app_name"`
		Action          types.String `tfsdk:"action"`
		Enable          types.Bool   `tfsdk:"enable"`
		ValidationFiles types.List   `tfsdk:"validation_files"`
	}
	old := legacyModel{ID: types.StringValue("demo"), AppName: types.StringValue("demo"), Action: types.StringValue("alert_deny"), Enable: types.BoolValue(true), ValidationFiles: files}
	oldState := openAPIState(t, ctx, legacySchemaV0(), &old)
	response := resource.UpgradeStateResponse{State: tfsdk.State{Schema: currentSchema()}}
	upgradeStateV0(ctx, resource.UpgradeStateRequest{State: &oldState}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("upgrade diagnostics = %v", response.Diagnostics)
	}
	var upgraded resourceModel
	if diagnostics := response.State.Get(ctx, &upgraded); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	var hashes []string
	if diagnostics := upgraded.ValidationFileHashes.ElementsAs(ctx, &hashes, false); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	want := sha256.Sum256(contents)
	if upgraded.LegacyAppName.ValueString() != "demo" || !reflect.DeepEqual(hashes, []string{hex.EncodeToString(want[:])}) {
		t.Fatalf("upgraded = %#v hashes=%#v", upgraded, hashes)
	}
}

func TestReadMakesRemoteValidationFileDriftActionable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	filePath := filepath.Join(t.TempDir(), "schema.yaml")
	if err := os.WriteFile(filePath, []byte("openapi: 3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, _ := types.ListValueFrom(ctx, types.StringType, []string{filePath})
	hashes, _ := types.ListValueFrom(ctx, types.StringType, []string{"prior-sha256"})
	prior := resourceModel{
		EPID: types.StringValue("100"), LegacyAppName: types.StringNull(), Action: types.StringValue("alert"), Enable: types.BoolValue(true),
		ValidationFiles: files, ValidationFileHashes: hashes,
		RemoteFiles: types.ListNull(types.ObjectType{AttrTypes: remoteFileTypes}),
	}
	state := openAPIState(t, ctx, currentSchema(), &prior)
	var diagnostics diag.Diagnostics
	(&openAPIResource{}).setState(ctx, prior, "100", client.OpenAPIValidationConfig{
		Action: "alert", Status: true, FileList: []client.OpenAPIValidationFile{{Index: 1, Name: "different.yaml"}},
	}, &state, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("setState() diagnostics = %v", diagnostics)
	}
	var updated resourceModel
	if stateDiagnostics := state.Get(ctx, &updated); stateDiagnostics.HasError() {
		t.Fatal(stateDiagnostics)
	}
	if !updated.ValidationFiles.IsNull() || !updated.ValidationFileHashes.IsNull() || updated.RemoteFiles.IsNull() {
		t.Fatalf("updated drift state = %#v", updated)
	}
}

func TestOpenAPIValidationLifecycleUploadsRefreshesAndDisables(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	filePath := filepath.Join(t.TempDir(), "schema.yaml")
	if err := os.WriteFile(filePath, []byte("openapi: 3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, _ := types.ListValueFrom(ctx, types.StringType, []string{filePath})
	service := &fakeOpenAPIService{}
	implementation := &openAPIResource{service: service, locks: locking.NewRegistry()}
	resourceSchema := currentSchema()
	plan := tfsdk.Plan{Schema: resourceSchema}
	model := resourceModel{
		EPID: types.StringValue("100"), LegacyAppName: types.StringNull(), Action: types.StringValue("alert"), Enable: types.BoolValue(true),
		ValidationFiles: files, ValidationFileHashes: types.ListNull(types.StringType), RemoteFiles: types.ListNull(types.ObjectType{AttrTypes: remoteFileTypes}),
	}
	if diagnostics := plan.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	response := resource.CreateResponse{State: tfsdk.State{Schema: resourceSchema, Raw: tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil)}}
	implementation.Create(ctx, resource.CreateRequest{Plan: plan}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"put:100", "get:100"}) || len(service.uploads) != 1 || service.uploads[0].Path != filePath {
		t.Fatalf("create calls/uploads = %#v %#v", service.calls, service.uploads)
	}
	deleteResponse := resource.DeleteResponse{}
	implementation.Delete(ctx, resource.DeleteRequest{State: response.State}, &deleteResponse)
	if deleteResponse.Diagnostics.HasError() {
		t.Fatalf("Delete() diagnostics = %v", deleteResponse.Diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"put:100", "get:100", "put:100", "get:100"}) || service.config.Status || len(service.config.FileList) != 0 {
		t.Fatalf("delete result = calls %#v config %#v", service.calls, service.config)
	}
}

func TestOpenAPIValidationWaitsForObservableConfiguration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	filePath := filepath.Join(t.TempDir(), "schema.yaml")
	if err := os.WriteFile(filePath, []byte("openapi: 3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, _ := types.ListValueFrom(ctx, types.StringType, []string{filePath})
	service := &fakeOpenAPIService{staleReads: 1, stale: client.OpenAPIValidationDocument{Result: client.OpenAPIValidationResult{
		Template: true, Configs: client.OpenAPIValidationConfig{Action: "alert_deny", Status: false},
	}}}
	implementation := &openAPIResource{service: service, locks: locking.NewRegistry(), pollAttempts: 2}
	resourceSchema := currentSchema()
	plan := tfsdk.Plan{Schema: resourceSchema}
	model := resourceModel{
		EPID: types.StringValue("100"), LegacyAppName: types.StringNull(), Action: types.StringValue("alert"), Enable: types.BoolValue(true),
		ValidationFiles: files, ValidationFileHashes: types.ListNull(types.StringType), RemoteFiles: types.ListNull(types.ObjectType{AttrTypes: remoteFileTypes}),
	}
	if diagnostics := plan.Set(ctx, &model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	response := resource.CreateResponse{State: tfsdk.State{Schema: resourceSchema, Raw: tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil)}}
	implementation.Create(ctx, resource.CreateRequest{Plan: plan}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Create() diagnostics = %v", response.Diagnostics)
	}
	if !reflect.DeepEqual(service.calls, []string{"put:100", "get:100", "get:100"}) {
		t.Fatalf("calls = %#v", service.calls)
	}
}

func openAPIState(t *testing.T, ctx context.Context, resourceSchema resourceschema.Schema, model any) tfsdk.State {
	t.Helper()
	state := tfsdk.State{Schema: resourceSchema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return state
}

type fakeOpenAPIService struct {
	calls      []string
	config     client.OpenAPIValidationConfig
	uploads    []client.OpenAPIUpload
	staleReads int
	stale      client.OpenAPIValidationDocument
}

func (s *fakeOpenAPIService) GetOpenAPIValidation(_ context.Context, epID string) (client.OpenAPIValidationDocument, error) {
	s.calls = append(s.calls, "get:"+epID)
	if s.staleReads > 0 {
		s.staleReads--
		return s.stale, nil
	}
	return client.OpenAPIValidationDocument{Result: client.OpenAPIValidationResult{Configs: s.config}}, nil
}

func (s *fakeOpenAPIService) PutOpenAPIValidation(_ context.Context, epID string, config client.OpenAPIValidationConfig, uploads []client.OpenAPIUpload) error {
	s.calls = append(s.calls, "put:"+epID)
	s.config = config
	s.uploads = append([]client.OpenAPIUpload(nil), uploads...)
	if len(uploads) > 0 {
		s.config.FileList = make([]client.OpenAPIValidationFile, len(uploads))
		for index, upload := range uploads {
			s.config.FileList[index] = client.OpenAPIValidationFile{Name: filepath.Base(upload.Path), Index: int64(index + 1)}
		}
	}
	sort.SliceStable(s.config.FileList, func(i, j int) bool { return s.config.FileList[i].Index < s.config.FileList[j].Index })
	return nil
}

func (s *fakeOpenAPIService) FindApplicationByName(context.Context, string) (client.Application, error) {
	return client.Application{EPID: "100"}, nil
}
func (s *fakeOpenAPIService) FindApplicationByEPID(context.Context, string) (client.Application, error) {
	return client.Application{EPID: "100"}, nil
}
func (s *fakeOpenAPIService) ApplicationExists(context.Context, string) (bool, error) {
	return true, nil
}
