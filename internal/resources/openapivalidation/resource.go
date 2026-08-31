package openapivalidation

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                   = (*openAPIResource)(nil)
	_ resource.ResourceWithConfigure      = (*openAPIResource)(nil)
	_ resource.ResourceWithImportState    = (*openAPIResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*openAPIResource)(nil)
	_ resource.ResourceWithUpgradeState   = (*openAPIResource)(nil)
	_ resource.ResourceWithValidateConfig = (*openAPIResource)(nil)
)

type openAPIService interface {
	GetOpenAPIValidation(context.Context, string) (client.OpenAPIValidationDocument, error)
	PutOpenAPIValidation(context.Context, string, client.OpenAPIValidationConfig, []client.OpenAPIUpload) error
	FindApplicationByName(context.Context, string) (client.Application, error)
	FindApplicationByEPID(context.Context, string) (client.Application, error)
	ApplicationExists(context.Context, string) (bool, error)
}

type openAPIResource struct {
	service      openAPIService
	locks        *locking.Registry
	pollAttempts int
	pollDelay    time.Duration
}

const (
	defaultOpenAPIPollAttempts = 30
	defaultOpenAPIPollDelay    = 2 * time.Second
)

type resourceModel struct {
	EPID                 types.String `tfsdk:"ep_id"`
	LegacyAppName        types.String `tfsdk:"legacy_app_name"`
	Action               types.String `tfsdk:"action"`
	Enable               types.Bool   `tfsdk:"enable"`
	ValidationFiles      types.List   `tfsdk:"validation_files"`
	ValidationFileHashes types.List   `tfsdk:"validation_file_hashes"`
	RemoteFiles          types.List   `tfsdk:"remote_files"`
}

type remoteFileModel struct {
	Description types.String `tfsdk:"description"`
	MD5         types.String `tfsdk:"md5"`
	Name        types.String `tfsdk:"name"`
	Title       types.String `tfsdk:"title"`
	URL         types.String `tfsdk:"url"`
}

var remoteFileTypes = map[string]attr.Type{
	"description": types.StringType, "md5": types.StringType, "name": types.StringType, "title": types.StringType, "url": types.StringType,
}

// NewResource creates the Framework replacement under the existing public name.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &openAPIResource{locks: locks, pollAttempts: defaultOpenAPIPollAttempts, pollDelay: defaultOpenAPIPollDelay}
}

func (r *openAPIResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_openapi_validation"
}

func (r *openAPIResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = currentSchema()
}

func currentSchema() schema.Schema {
	return schema.Schema{Version: 1, MarkdownDescription: "Manages OpenAPI validation using file paths. File contents are uploaded but never stored in Terraform state.", Attributes: map[string]schema.Attribute{
		"ep_id":                  schema.StringAttribute{Optional: true, Computed: true, MarkdownDescription: "Stable application endpoint ID and import identity."},
		"legacy_app_name":        schema.StringAttribute{Computed: true, MarkdownDescription: "Migration-only application name used to resolve legacy SDKv2 identity."},
		"action":                 schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("alert", "alert_deny", "deny_no_log")}},
		"enable":                 schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		"validation_files":       schema.ListAttribute{Optional: true, ElementType: types.StringType, Validators: []validator.List{listvalidator.SizeAtMost(10)}},
		"validation_file_hashes": schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "SHA-256 hashes of validation_files in matching order."},
		"remote_files":           schema.ListAttribute{Computed: true, ElementType: types.ObjectType{AttrTypes: remoteFileTypes}},
	}}
}

func legacySchemaV0() schema.Schema {
	return schema.Schema{Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true}, "app_name": schema.StringAttribute{Optional: true},
		"action": schema.StringAttribute{Optional: true}, "enable": schema.BoolAttribute{Optional: true},
		"validation_files": schema.ListAttribute{Optional: true, ElementType: types.StringType},
	}}
}

func (r *openAPIResource) UpgradeState(context.Context) map[int64]resource.StateUpgrader {
	prior := legacySchemaV0()
	return map[int64]resource.StateUpgrader{0: {PriorSchema: &prior, StateUpgrader: upgradeStateV0}}
}

func upgradeStateV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	type legacyModel struct {
		ID              types.String `tfsdk:"id"`
		AppName         types.String `tfsdk:"app_name"`
		Action          types.String `tfsdk:"action"`
		Enable          types.Bool   `tfsdk:"enable"`
		ValidationFiles types.List   `tfsdk:"validation_files"`
	}
	var old legacyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := old.ID
	if name.IsNull() || name.IsUnknown() || strings.TrimSpace(name.ValueString()) == "" {
		name = old.AppName
	}
	hashes := types.ListNull(types.StringType)
	if paths, diagnostics := pathsFromList(ctx, old.ValidationFiles); !diagnostics.HasError() {
		if values, err := hashFiles(paths); err == nil {
			hashes, diagnostics = types.ListValueFrom(ctx, types.StringType, values)
			resp.Diagnostics.Append(diagnostics...)
		} else {
			resp.Diagnostics.AddWarning("Validation file hashes deferred", fmt.Sprintf("Legacy state was upgraded, but configured validation files could not be hashed yet: %v", err))
		}
	}
	upgraded := resourceModel{EPID: types.StringNull(), LegacyAppName: name, Action: old.Action, Enable: old.Enable, ValidationFiles: old.ValidationFiles, ValidationFileHashes: hashes, RemoteFiles: types.ListNull(types.ObjectType{AttrTypes: remoteFileTypes})}
	resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
}

func (r *openAPIResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	apiClient, ok := req.ProviderData.(*client.Client)
	if !ok || apiClient == nil {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T.", req.ProviderData))
		return
	}
	r.service = apiClient
}

func (r *openAPIResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.EPID.IsNull() && config.LegacyAppName.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Missing application ID", "ep_id is required for new OpenAPI validation resources. legacy_app_name is used only during state migration.")
	}
}

func (r *openAPIResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	resp.Plan = req.Plan
	if req.Plan.Raw.IsNull() {
		return
	}
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.ValidationFiles.IsUnknown() {
		return
	}
	paths, diagnostics := pathsFromList(ctx, config.ValidationFiles)
	resp.Diagnostics.Append(diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}
	hashes, err := hashFiles(paths)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("validation_files"), "Unable to read validation file", err.Error())
		return
	}
	value, valueDiags := types.ListValueFrom(ctx, types.StringType, hashes)
	resp.Diagnostics.Append(valueDiags...)
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("validation_file_hashes"), value)...)
}

func (r *openAPIResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *openAPIResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID, ok := r.resolveEPID(ctx, state, &resp.Diagnostics)
	if !ok {
		if !resp.Diagnostics.HasError() {
			resp.State.RemoveResource(ctx)
		}
		return
	}
	document, err := r.service.GetOpenAPIValidation(ctx, epID)
	if err != nil {
		if r.parentAbsent(ctx, epID, err, &resp.Diagnostics) {
			resp.State.RemoveResource(ctx)
			return
		}
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("Unable to read OpenAPI validation", err.Error())
		}
		return
	}
	r.setState(ctx, state, epID, document.Result.Configs, &resp.State, &resp.Diagnostics)
}

func (r *openAPIResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *openAPIResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID, ok := r.resolveEPID(ctx, state, &resp.Diagnostics)
	if !ok {
		return
	}
	unlock := r.locks.Lock("waf-openapi-validation:" + epID)
	defer unlock()
	config := client.OpenAPIValidationConfig{Action: "alert", Status: false, FileList: []client.OpenAPIValidationFile{}}
	if err := r.service.PutOpenAPIValidation(ctx, epID, config, nil); err != nil {
		if r.parentAbsent(ctx, epID, err, &resp.Diagnostics) {
			return
		}
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("Unable to disable OpenAPI validation", err.Error())
		}
		return
	}
	verified, err := r.waitForConfiguration(ctx, epID, config, nil)
	if err != nil {
		resp.Diagnostics.AddError("Unable to verify OpenAPI validation disable", err.Error())
		return
	}
	if verified.Result.Template || verified.Result.Configs.Status || len(verified.Result.Configs.FileList) != 0 {
		resp.Diagnostics.AddError("OpenAPI validation disable was not applied", "The API did not report status=false and an empty file list after destroy.")
	}
}

func (r *openAPIResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *openAPIResource) apply(ctx context.Context, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	epID, ok := r.resolveEPID(ctx, plan, diagnostics)
	if !ok {
		return
	}
	paths, pathDiags := pathsFromList(ctx, plan.ValidationFiles)
	diagnostics.Append(pathDiags...)
	if diagnostics.HasError() {
		return
	}
	files := make([]client.OpenAPIValidationFile, 0, len(paths))
	uploads := make([]client.OpenAPIUpload, 0, len(paths))
	for index, filePath := range paths {
		files = append(files, client.OpenAPIValidationFile{Name: filepath.Base(filePath), Index: int64(index + 1)})
		uploads = append(uploads, client.OpenAPIUpload{FieldName: "file_" + strconv.Itoa(index+1), Path: filePath})
	}
	config := client.OpenAPIValidationConfig{Action: plan.Action.ValueString(), Status: plan.Enable.ValueBool(), FileList: files}
	unlock := r.locks.Lock("waf-openapi-validation:" + epID)
	defer unlock()
	if err := r.service.PutOpenAPIValidation(ctx, epID, config, uploads); err != nil {
		if r.parentAbsent(ctx, epID, err, diagnostics) {
			diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
			return
		}
		if !diagnostics.HasError() {
			diagnostics.AddError("Unable to update OpenAPI validation", err.Error())
		}
		return
	}
	normalized, err := r.waitForConfiguration(ctx, epID, config, paths)
	if err != nil {
		diagnostics.AddError("Unable to refresh OpenAPI validation", err.Error())
		return
	}
	r.setState(ctx, plan, epID, normalized.Result.Configs, state, diagnostics)
}

func (r *openAPIResource) waitForConfiguration(ctx context.Context, epID string, expected client.OpenAPIValidationConfig, paths []string) (client.OpenAPIValidationDocument, error) {
	attempts := r.pollAttempts
	if attempts < 1 {
		attempts = 1
	}
	delay := r.pollDelay
	var last client.OpenAPIValidationDocument
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		document, err := r.service.GetOpenAPIValidation(ctx, epID)
		if err == nil {
			last = document
			lastErr = nil
			if openAPIConfigurationMatches(document, expected, paths) {
				return document, nil
			}
		} else {
			lastErr = err
		}
		if attempt+1 == attempts {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return client.OpenAPIValidationDocument{}, ctx.Err()
		case <-timer.C:
		}
	}
	if lastErr != nil {
		return client.OpenAPIValidationDocument{}, lastErr
	}
	return last, fmt.Errorf("OpenAPI validation update did not become observable before the polling limit")
}

func openAPIConfigurationMatches(document client.OpenAPIValidationDocument, expected client.OpenAPIValidationConfig, paths []string) bool {
	config := document.Result.Configs
	return !document.Result.Template && config.Action == expected.Action && config.Status == expected.Status && validationFilesMatchRemote(paths, config.FileList)
}

func (r *openAPIResource) setState(ctx context.Context, prior resourceModel, epID string, config client.OpenAPIValidationConfig, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	remote := append([]client.OpenAPIValidationFile(nil), config.FileList...)
	sort.SliceStable(remote, func(i, j int) bool { return remote[i].Index < remote[j].Index })
	models := make([]remoteFileModel, 0, len(remote))
	for _, file := range remote {
		models = append(models, remoteFileModel{Description: types.StringValue(file.Description), MD5: types.StringValue(file.MD5), Name: types.StringValue(file.Name), Title: types.StringValue(file.Title), URL: types.StringValue(file.URL)})
	}
	remoteValue, remoteDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: remoteFileTypes}, models)
	diagnostics.Append(remoteDiags...)
	updated := prior
	updated.EPID = types.StringValue(epID)
	updated.LegacyAppName = types.StringNull()
	updated.Action = types.StringValue(config.Action)
	updated.Enable = types.BoolValue(config.Status)
	updated.RemoteFiles = remoteValue
	if paths, pathDiags := pathsFromList(ctx, prior.ValidationFiles); !pathDiags.HasError() && len(paths) > 0 && !validationFilesMatchRemote(paths, remote) {
		// Keep remote metadata for diagnosis, but clear the configured-file state so
		// Terraform plans a restoring upload from the still-present configuration.
		updated.ValidationFiles = types.ListNull(types.StringType)
		updated.ValidationFileHashes = types.ListNull(types.StringType)
	}
	diagnostics.Append(state.Set(ctx, &updated)...)
}

func validationFilesMatchRemote(paths []string, remote []client.OpenAPIValidationFile) bool {
	if len(paths) != len(remote) {
		return false
	}
	for index, filePath := range paths {
		if filepath.Base(filePath) != remote[index].Name {
			return false
		}
		remoteMD5 := strings.ToLower(strings.TrimSpace(remote[index].MD5))
		if remoteMD5 == "" {
			continue
		}
		contents, err := os.ReadFile(filePath)
		if err != nil {
			return false
		}
		sum := md5.Sum(contents) //nolint:gosec // Compatibility digest returned by the remote API; SHA-256 remains in Terraform state.
		if hex.EncodeToString(sum[:]) != remoteMD5 {
			return false
		}
	}
	return true
}

func (r *openAPIResource) resolveEPID(ctx context.Context, state resourceModel, diagnostics *diag.Diagnostics) (string, bool) {
	if !state.EPID.IsNull() && !state.EPID.IsUnknown() && strings.TrimSpace(state.EPID.ValueString()) != "" {
		return strings.TrimSpace(state.EPID.ValueString()), true
	}
	name := strings.TrimSpace(state.LegacyAppName.ValueString())
	if name == "" {
		diagnostics.AddError("Unable to migrate OpenAPI validation identity", "Legacy state did not contain an app_name. Import the resource using ep_id.")
		return "", false
	}
	if application, err := r.service.FindApplicationByEPID(ctx, name); err == nil {
		return application.EPID, true
	}
	application, err := r.service.FindApplicationByName(ctx, name)
	if err != nil {
		diagnostics.AddError("Unable to migrate OpenAPI validation identity", fmt.Sprintf("Could not resolve legacy application %q to an ep_id: %v. Import using ep_id as the recovery path.", name, err))
		return "", false
	}
	return application.EPID, true
}

func (r *openAPIResource) parentAbsent(ctx context.Context, epID string, operationErr error, diagnostics *diag.Diagnostics) bool {
	if !client.IsStatus(operationErr, http.StatusBadRequest, http.StatusNotFound) {
		return false
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		diagnostics.AddError("Unable to verify parent application", err.Error())
		return false
	}
	return !exists
}

func (r *openAPIResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service == nil {
		diagnostics.AddError("OpenAPI validation client is not configured", "Configure the provider before managing OpenAPI validation.")
		return false
	}
	return true
}

func pathsFromList(ctx context.Context, value types.List) ([]string, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if value.IsNull() {
		return []string{}, diagnostics
	}
	if value.IsUnknown() {
		diagnostics.AddError("Unknown validation files", "validation_files must be known during apply.")
		return nil, diagnostics
	}
	var paths []string
	diagnostics.Append(value.ElementsAs(ctx, &paths, false)...)
	for index, filePath := range paths {
		if strings.TrimSpace(filePath) == "" {
			diagnostics.AddError("Invalid validation file path", fmt.Sprintf("validation_files[%d] must not be empty.", index))
		}
	}
	return paths, diagnostics
}

func hashFiles(paths []string) ([]string, error) {
	hashes := make([]string, 0, len(paths))
	for _, filePath := range paths {
		contents, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", filePath, err)
		}
		sum := sha256.Sum256(contents)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	return hashes, nil
}
