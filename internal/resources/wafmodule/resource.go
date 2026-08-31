package wafmodule

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

const maxConflictAttempts = 3

var (
	_ resource.Resource                   = (*moduleResource)(nil)
	_ resource.ResourceWithConfigure      = (*moduleResource)(nil)
	_ resource.ResourceWithImportState    = (*moduleResource)(nil)
	_ resource.ResourceWithValidateConfig = (*moduleResource)(nil)
)

type moduleService interface {
	GetWAFModule(context.Context, client.WAFModuleEndpoint, string) (client.WAFModuleDocument, error)
	PutWAFModule(context.Context, client.WAFModuleEndpoint, string, client.WAFModuleResult) error
	ApplicationExists(context.Context, string) (bool, error)
}

// DisableRequest records the exact, individually live-verified app-module
// disable operation. Current may be supplied when the caller has already
// completed the required fresh GET.
type DisableRequest struct {
	ModuleName      string
	EPID            string
	Field           string
	Verified        bool
	Current         *client.WAFModuleDocument
	NormalizeForPut func(client.WAFModuleResult) (client.WAFModuleResult, error)
}

// DisableAccess adapts either a generated or hand-written app-module client to
// the shared GET -> full-response-preserving PUT -> verification GET lifecycle.
type DisableAccess struct {
	Get               func(context.Context) (client.WAFModuleDocument, error)
	Put               func(context.Context, client.WAFModuleResult) error
	ApplicationExists func(context.Context) (bool, error)
}

// TemplateDisableRequest records one reviewed template-module disable
// operation. Current may be supplied when the caller has already completed
// the required fresh GET while holding the template lock.
type TemplateDisableRequest struct {
	ModuleName      string
	TemplateID      string
	Field           string
	CoupledFields   []string
	Verified        bool
	Current         *client.WAFTemplateModuleDocument
	NormalizeForPut func(client.WAFModuleResult) (client.WAFModuleResult, error)
}

// TemplateDisableAccess adapts a template-module client to the shared
// GET -> full-response-preserving PUT -> verification GET lifecycle.
type TemplateDisableAccess struct {
	Get            func(context.Context) (client.WAFTemplateModuleDocument, error)
	Put            func(context.Context, client.WAFModuleResult) error
	TemplateExists func(context.Context) (bool, error)
}

type disableResultRequest struct {
	moduleName      string
	resourceID      string
	identityName    string
	field           string
	coupledFields   []string
	verified        bool
	current         *client.WAFModuleResult
	normalizeForPut func(client.WAFModuleResult) (client.WAFModuleResult, error)
}

type disableResultAccess struct {
	get          func(context.Context) (client.WAFModuleResult, error)
	put          func(context.Context, client.WAFModuleResult) error
	parentAbsent func(context.Context, error) (bool, error)
}

type moduleResource struct {
	descriptor    Descriptor
	descriptorErr error
	service       moduleService
	locks         *locking.Registry
}

type baseModel struct {
	EPID     types.String `tfsdk:"ep_id"`
	Template types.Bool   `tfsdk:"template"`
	Configs  types.Object `tfsdk:"configs"`
}

// NewResource creates a descriptor-driven app-scoped WAF module resource.
func NewResource(descriptor Descriptor, locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &moduleResource{
		descriptor:    descriptor,
		descriptorErr: descriptor.Validate(),
		locks:         locks,
	}
}

func (r *moduleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.descriptor.TypeNameSuffix
}

func (r *moduleResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	if err := r.staticError(); err != nil {
		resp.Diagnostics.AddError("Invalid WAF module descriptor", err.Error())
		return
	}
	resp.Schema = r.descriptor.Codec.Schema(ctx)
}

func (r *moduleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *moduleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if err := r.staticError(); err != nil {
		resp.Diagnostics.AddError("Invalid WAF module descriptor", err.Error())
		return
	}
	var config baseModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid "+r.moduleName()+" application ID", "ep_id must not be empty or whitespace for "+r.moduleName()+".")
	}
	if err := validateTemplateConfigs(config); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("configs"), "Invalid "+r.moduleName()+" configuration", err.Error())
	}
	resp.Diagnostics.Append(r.descriptor.Codec.ValidateConfig(ctx, req.Config)...)
}

func (r *moduleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	currentState := nullState(ctx, r.descriptor.Codec.Schema(ctx))
	r.apply(ctx, req.Config, req.Plan, currentState, &resp.State, &resp.Diagnostics)
}

func (r *moduleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state baseModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID, ok := r.knownEPID(state.EPID, &resp.Diagnostics, "read")
	if !ok {
		return
	}

	unlock := r.locks.Lock(r.resourceKey(epID))
	defer unlock()

	document, err := r.service.GetWAFModule(ctx, r.descriptor.Endpoint, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to read "+r.moduleName(), checkErr.Error())
			return
		}
		if absent {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read "+r.moduleName(), err.Error())
		return
	}

	ownership := OwnershipContext{Source: OwnershipPriorState, State: req.State}
	if state.Template.IsNull() || state.Template.IsUnknown() {
		ownership.Source = OwnershipImported
	}
	r.setState(ctx, epID, document.Result, ownership, &resp.State, &resp.Diagnostics)
}

func (r *moduleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	r.apply(ctx, req.Config, req.Plan, req.State, &resp.State, &resp.Diagnostics)
}

func (r *moduleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state baseModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID, ok := r.knownEPID(state.EPID, &resp.Diagnostics, "destroy")
	if !ok {
		return
	}

	unlock := r.locks.Lock(r.resourceKey(epID))
	defer unlock()

	current, err := r.service.GetWAFModule(ctx, r.descriptor.Endpoint, epID)
	if err != nil {
		absent, checkErr := r.parentAbsent(ctx, epID, err)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to forget "+r.moduleName(), checkErr.Error())
			return
		}
		if absent {
			return
		}
		resp.Diagnostics.AddError("Unable to forget "+r.moduleName(), err.Error())
		return
	}

	switch r.descriptor.Destroy.Mode {
	case DestroyForget:
		resp.Diagnostics.AddWarning(
			"Remote "+r.moduleName()+" configuration remains",
			"Terraform removed this resource from state without changing the remote "+r.moduleName()+" configuration. "+strings.TrimSpace(r.descriptor.Destroy.Reason)+".",
		)
	case DestroyDisable:
		r.disableOnDestroy(ctx, epID, current, &resp.Diagnostics)
	default:
		resp.Diagnostics.AddError("Unable to destroy "+r.moduleName(), fmt.Sprintf("Unsupported destroy policy %q.", r.descriptor.Destroy.Mode))
	}
}

func (r *moduleResource) disableOnDestroy(ctx context.Context, epID string, current client.WAFModuleDocument, diagnostics *diag.Diagnostics) {
	DisableOnDestroy(ctx, DisableRequest{
		ModuleName: r.moduleName(),
		EPID:       epID,
		Field:      r.descriptor.Destroy.Field,
		Verified:   r.descriptor.Destroy.Verified,
		Current:    &current,
	}, DisableAccess{
		Get: func(ctx context.Context) (client.WAFModuleDocument, error) {
			return r.service.GetWAFModule(ctx, r.descriptor.Endpoint, epID)
		},
		Put: func(ctx context.Context, result client.WAFModuleResult) error {
			return r.service.PutWAFModule(ctx, r.descriptor.Endpoint, epID, result)
		},
		ApplicationExists: func(ctx context.Context) (bool, error) {
			return r.service.ApplicationExists(ctx, epID)
		},
	}, diagnostics)
}

// DisableOnDestroy executes the reviewed app-module disable sequence. Callers
// must hold the application/module lock for the whole sequence.
func DisableOnDestroy(ctx context.Context, request DisableRequest, access DisableAccess, diagnostics *diag.Diagnostics) {
	if access.Get == nil || access.Put == nil || access.ApplicationExists == nil {
		moduleName := strings.TrimSpace(request.ModuleName)
		if moduleName == "" {
			moduleName = "app module"
		}
		diagnostics.AddError("Unable to disable "+moduleName, "The module disable client is incomplete.")
		return
	}
	var current *client.WAFModuleResult
	if request.Current != nil {
		result := request.Current.Result
		current = &result
	}
	disableResultOnDestroy(ctx, disableResultRequest{
		moduleName:      request.ModuleName,
		resourceID:      request.EPID,
		identityName:    "application ep_id",
		field:           request.Field,
		verified:        request.Verified,
		current:         current,
		normalizeForPut: request.NormalizeForPut,
	}, disableResultAccess{
		get: func(ctx context.Context) (client.WAFModuleResult, error) {
			document, err := access.Get(ctx)
			return document.Result, err
		},
		put: access.Put,
		parentAbsent: func(ctx context.Context, moduleErr error) (bool, error) {
			return disableParentAbsent(ctx, access, moduleErr)
		},
	}, diagnostics)
}

// DisableTemplateOnDestroy executes the reviewed template-module disable
// sequence: fresh GET, complete response preservation, the reviewed boolean
// disable fields set false, PUT, and a complete normalized verification GET.
// Callers must hold the template lock for the whole sequence.
func DisableTemplateOnDestroy(ctx context.Context, request TemplateDisableRequest, access TemplateDisableAccess, diagnostics *diag.Diagnostics) {
	if access.Get == nil || access.Put == nil || access.TemplateExists == nil {
		moduleName := strings.TrimSpace(request.ModuleName)
		if moduleName == "" {
			moduleName = "template module"
		}
		diagnostics.AddError("Unable to disable "+moduleName, "The module disable client is incomplete.")
		return
	}
	var current *client.WAFModuleResult
	if request.Current != nil {
		result := request.Current.Result
		current = &result
	}
	disableResultOnDestroy(ctx, disableResultRequest{
		moduleName:      request.ModuleName,
		resourceID:      request.TemplateID,
		identityName:    "template_id",
		field:           request.Field,
		coupledFields:   append([]string(nil), request.CoupledFields...),
		verified:        request.Verified,
		current:         current,
		normalizeForPut: request.NormalizeForPut,
	}, disableResultAccess{
		get: func(ctx context.Context) (client.WAFModuleResult, error) {
			document, err := access.Get(ctx)
			return document.Result, err
		},
		put: access.Put,
		parentAbsent: func(ctx context.Context, moduleErr error) (bool, error) {
			return disableTemplateParentAbsent(ctx, access, moduleErr)
		},
	}, diagnostics)
}

func disableResultOnDestroy(ctx context.Context, request disableResultRequest, access disableResultAccess, diagnostics *diag.Diagnostics) {
	moduleName := strings.TrimSpace(request.moduleName)
	if moduleName == "" {
		moduleName = "WAF module"
	}
	if !request.verified {
		diagnostics.AddError("Unable to disable "+moduleName, "The module destroy policy has not been verified.")
		return
	}
	field := strings.TrimSpace(request.field)
	if field != "status" {
		diagnostics.AddError("Unable to disable "+moduleName, fmt.Sprintf("The reviewed disable field must be configs.status, got configs.%s.", field))
		return
	}
	if err := validateRuntimeCoupledDisableFields(request.coupledFields); err != nil {
		diagnostics.AddError("Unable to disable "+moduleName, err.Error())
		return
	}
	disableFields := append([]string{field}, request.coupledFields...)
	if strings.TrimSpace(request.resourceID) == "" {
		diagnostics.AddError("Unable to disable "+moduleName, "The "+request.identityName+" must be known and non-empty during destroy.")
		return
	}
	if access.get == nil || access.put == nil || access.parentAbsent == nil {
		diagnostics.AddError("Unable to disable "+moduleName, "The module disable client is incomplete.")
		return
	}

	var current client.WAFModuleResult
	if request.current != nil {
		current = *request.current
	} else {
		var err error
		current, err = access.get(ctx)
		if err != nil {
			absent, checkErr := access.parentAbsent(ctx, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read "+moduleName+" before destroy", checkErr.Error())
				return
			}
			if absent {
				return
			}
			diagnostics.AddError("Unable to read "+moduleName+" before destroy", err.Error())
			return
		}
	}

	for attempt := 1; attempt <= maxConflictAttempts; attempt++ {
		for _, disableField := range disableFields {
			if _, err := booleanConfigPath(current, disableField); err != nil {
				diagnostics.AddError("Unable to prepare "+moduleName+" disable request", err.Error())
				return
			}
		}
		updated := current.Clone()
		updated.Template = false
		for _, disableField := range disableFields {
			if err := setBooleanConfigPath(&updated, disableField, false); err != nil {
				diagnostics.AddError("Unable to prepare "+moduleName+" disable request", err.Error())
				return
			}
		}
		if request.normalizeForPut != nil {
			var err error
			updated, err = request.normalizeForPut(updated)
			if err != nil {
				diagnostics.AddError("Unable to prepare "+moduleName+" disable request", err.Error())
				return
			}
		}
		for _, disableField := range disableFields {
			enabled, err := booleanConfigPath(updated, disableField)
			if err != nil {
				diagnostics.AddError("Unable to prepare "+moduleName+" disable request", err.Error())
				return
			}
			if enabled {
				diagnostics.AddError("Unable to prepare "+moduleName+" disable request", "The PUT normalizer changed configs."+disableField+" back to true.")
				return
			}
		}
		if err := access.put(ctx, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < maxConflictAttempts {
				refreshed, refreshErr := access.get(ctx)
				if refreshErr != nil {
					diagnostics.AddError("Unable to refresh "+moduleName+" after destroy conflict", refreshErr.Error())
					return
				}
				current = refreshed
				continue
			}
			absent, checkErr := access.parentAbsent(ctx, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to disable "+moduleName, checkErr.Error())
				return
			}
			if absent {
				return
			}
			diagnostics.AddError("Unable to disable "+moduleName, err.Error())
			return
		}
		verified, err := access.get(ctx)
		if err != nil {
			absent, checkErr := access.parentAbsent(ctx, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to verify "+moduleName+" disable", checkErr.Error())
				return
			}
			if absent {
				return
			}
			diagnostics.AddError("Unable to verify "+moduleName+" disable", err.Error())
			return
		}
		if verified.Template {
			diagnostics.AddError(moduleName+" disable was not applied", "The API did not report template=false after destroy.")
			return
		}
		for _, disableField := range disableFields {
			enabled, err := booleanConfigPath(verified, disableField)
			if err != nil {
				diagnostics.AddError(moduleName+" disable was not verifiable", err.Error()+" after destroy.")
				return
			}
			if enabled {
				diagnostics.AddError(moduleName+" disable was not applied", "The API did not report configs."+disableField+"=false after destroy.")
				return
			}
		}
		verifiedResult := verified
		if request.normalizeForPut != nil {
			verifiedResult, err = request.normalizeForPut(verifiedResult)
			if err != nil {
				diagnostics.AddError("Unable to verify "+moduleName+" disable", err.Error())
				return
			}
		}
		if !semanticWAFModuleResultEqual(updated, verifiedResult) {
			expectedChanges := make([]string, 0, len(disableFields)+1)
			expectedChanges = append(expectedChanges, "template=false")
			for _, disableField := range disableFields {
				expectedChanges = append(expectedChanges, "configs."+disableField+"=false")
			}
			diagnostics.AddError(
				moduleName+" disable changed unowned configuration",
				"The API response after destroy did not preserve the complete module envelope except for "+strings.Join(expectedChanges, ", ")+".",
			)
		}
		return
	}
}

func disableTemplateParentAbsent(ctx context.Context, access TemplateDisableAccess, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound) {
		return false, nil
	}
	if access.TemplateExists == nil {
		return false, fmt.Errorf("template module request failed and template existence check is unavailable: %w", moduleErr)
	}
	exists, err := access.TemplateExists(ctx)
	if err != nil {
		return false, fmt.Errorf("template module request failed and template existence check failed: %w", err)
	}
	return !exists, nil
}

func disableParentAbsent(ctx context.Context, access DisableAccess, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusNotFound) {
		return false, nil
	}
	exists, err := access.ApplicationExists(ctx)
	if err != nil {
		return false, fmt.Errorf("module request returned 404 and application existence check failed: %w", err)
	}
	return !exists, nil
}

func requireBooleanDisableField(result client.WAFModuleResult, field string) error {
	_, err := booleanConfigPath(result, field)
	return err
}

func validateRuntimeCoupledDisableFields(fields []string) error {
	if len(fields) == 0 {
		return nil
	}
	if len(fields) != 2 || fields[0] != "cache.status" || fields[1] != "compress.status" {
		return fmt.Errorf("the reviewed coupled disable fields must be configs.cache.status and configs.compress.status")
	}
	return nil
}

func booleanConfigPath(result client.WAFModuleResult, field string) (bool, error) {
	parts := strings.Split(field, ".")
	switch len(parts) {
	case 1:
		value, ok := result.Configs[parts[0]]
		if !ok {
			return false, fmt.Errorf("the API response omitted configs.%s", field)
		}
		boolean, ok := decodeBoolean(value)
		if !ok {
			return false, fmt.Errorf("the API response returned non-boolean configs.%s", field)
		}
		return boolean, nil
	case 2:
		value, ok := result.Configs[parts[0]]
		if !ok {
			return false, fmt.Errorf("the API response omitted configs.%s", parts[0])
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(value, &nested); err != nil || nested == nil {
			return false, fmt.Errorf("the API response returned non-object configs.%s", parts[0])
		}
		value, ok = nested[parts[1]]
		if !ok {
			return false, fmt.Errorf("the API response omitted configs.%s", field)
		}
		boolean, ok := decodeBoolean(value)
		if !ok {
			return false, fmt.Errorf("the API response returned non-boolean configs.%s", field)
		}
		return boolean, nil
	default:
		return false, fmt.Errorf("unsupported disable field path configs.%s", field)
	}
}

func setBooleanConfigPath(result *client.WAFModuleResult, field string, value bool) error {
	parts := strings.Split(field, ".")
	switch len(parts) {
	case 1:
		return result.SetConfig(parts[0], value)
	case 2:
		raw, ok := result.Configs[parts[0]]
		if !ok {
			return fmt.Errorf("the API response omitted configs.%s", parts[0])
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err != nil || nested == nil {
			return fmt.Errorf("the API response returned non-object configs.%s", parts[0])
		}
		if _, err := booleanConfigPath(*result, field); err != nil {
			return err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("encode configs.%s: %w", field, err)
		}
		nested[parts[1]] = encoded
		encodedNested, err := json.Marshal(nested)
		if err != nil {
			return fmt.Errorf("encode configs.%s: %w", parts[0], err)
		}
		result.Configs[parts[0]] = encodedNested
		return nil
	default:
		return fmt.Errorf("unsupported disable field path configs.%s", field)
	}
}

func decodeBoolean(value json.RawMessage) (bool, bool) {
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return false, false
	}
	boolean, ok := decoded.(bool)
	return boolean, ok
}

func semanticWAFModuleResultEqual(left, right client.WAFModuleResult) bool {
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

func (r *moduleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid "+r.moduleName()+" import ID", "Importing "+r.moduleName()+" requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *moduleResource) apply(
	ctx context.Context,
	config tfsdk.Config,
	plan tfsdk.Plan,
	currentState tfsdk.State,
	state *tfsdk.State,
	diagnostics *diag.Diagnostics,
) {
	var configBase, planBase baseModel
	diagnostics.Append(config.Get(ctx, &configBase)...)
	diagnostics.Append(plan.Get(ctx, &planBase)...)
	if diagnostics.HasError() {
		return
	}
	if err := validateTemplateConfigs(configBase); err != nil {
		diagnostics.AddError("Invalid "+r.moduleName()+" configuration", err.Error())
		return
	}
	if err := validateTemplateConfigs(planBase); err != nil {
		diagnostics.AddError("Invalid "+r.moduleName()+" configuration", err.Error())
		return
	}
	epID, ok := r.knownEPID(planBase.EPID, diagnostics, "apply")
	if !ok {
		return
	}
	if planBase.Template.IsNull() || planBase.Template.IsUnknown() {
		diagnostics.AddError("Unknown "+r.moduleName()+" template setting", "template must be known during apply.")
		return
	}

	diagnostics.Append(r.descriptor.Codec.ValidateConfig(ctx, config)...)
	if diagnostics.HasError() {
		return
	}
	patch, patchDiagnostics := r.descriptor.Codec.BuildPatch(ctx, config, plan, currentState)
	diagnostics.Append(patchDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	if !planBase.Template.ValueBool() && patch == nil {
		diagnostics.AddError("Unable to prepare "+r.moduleName()+" configuration", "The module codec returned no patch for locally managed configuration.")
		return
	}

	ownership := OwnershipContext{
		Source: OwnershipConfigured,
		Config: config,
		Plan:   plan,
		State:  currentState,
	}
	unlock := r.locks.Lock(r.resourceKey(epID))
	defer unlock()

	for attempt := 1; attempt <= maxConflictAttempts; attempt++ {
		current, err := r.service.GetWAFModule(ctx, r.descriptor.Endpoint, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read "+r.moduleName()+" before update", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist for %s.", epID, r.moduleName()))
				return
			}
			diagnostics.AddError("Unable to read "+r.moduleName()+" before update", err.Error())
			return
		}

		diagnostics.Append(r.descriptor.Codec.ValidateResult(ctx, current.Result, ownership)...)
		if diagnostics.HasError() {
			return
		}
		updated := current.Result.Clone()
		updated.Template = planBase.Template.ValueBool()
		if !updated.Template {
			diagnostics.Append(patch.Apply(ctx, &updated)...)
			if diagnostics.HasError() {
				return
			}
			updated.Template = false
		}

		if err := r.service.PutWAFModule(ctx, r.descriptor.Endpoint, epID, updated); err != nil {
			if client.IsStatus(err, http.StatusConflict) && attempt < maxConflictAttempts {
				continue
			}
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to update "+r.moduleName(), checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed while updating %s.", epID, r.moduleName()))
				return
			}
			diagnostics.AddError("Unable to update "+r.moduleName(), err.Error())
			return
		}

		normalized, err := r.service.GetWAFModule(ctx, r.descriptor.Endpoint, epID)
		if err != nil {
			absent, checkErr := r.parentAbsent(ctx, epID, err)
			if checkErr != nil {
				diagnostics.AddError("Unable to read normalized "+r.moduleName()+" configuration", checkErr.Error())
				return
			}
			if absent {
				diagnostics.AddError("Application not found", fmt.Sprintf("Application %q was removed after updating %s.", epID, r.moduleName()))
				return
			}
			diagnostics.AddError("Unable to read normalized "+r.moduleName()+" configuration", err.Error())
			return
		}
		r.setState(ctx, epID, normalized.Result, ownership, state, diagnostics)
		return
	}
}

func (r *moduleResource) setState(
	ctx context.Context,
	epID string,
	result client.WAFModuleResult,
	ownership OwnershipContext,
	state *tfsdk.State,
	diagnostics *diag.Diagnostics,
) {
	diagnostics.Append(r.descriptor.Codec.ValidateResult(ctx, result, ownership)...)
	if diagnostics.HasError() {
		return
	}
	model, modelDiagnostics := r.descriptor.Codec.Flatten(ctx, epID, result, ownership)
	diagnostics.Append(modelDiagnostics...)
	if diagnostics.HasError() {
		return
	}
	if model == nil {
		diagnostics.AddError("Unable to flatten "+r.moduleName()+" configuration", "The module codec returned no Terraform state model.")
		return
	}
	diagnostics.Append(state.Set(ctx, model)...)
}

func (r *moduleResource) parentAbsent(ctx context.Context, epID string, moduleErr error) (bool, error) {
	if !client.IsStatus(moduleErr, http.StatusBadRequest, http.StatusNotFound) {
		return false, nil
	}
	exists, err := r.service.ApplicationExists(ctx, epID)
	if err != nil {
		return false, fmt.Errorf("%s request failed: %v; parent application check failed: %w", r.moduleName(), moduleErr, err)
	}
	return !exists, nil
}

func (r *moduleResource) ready(diagnostics *diag.Diagnostics) bool {
	if err := r.staticError(); err != nil {
		diagnostics.AddError("Invalid WAF module descriptor", err.Error())
		return false
	}
	if r.service != nil {
		return true
	}
	diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud API client was not configured before the "+r.moduleName()+" resource operation.")
	return false
}

func (r *moduleResource) staticError() error {
	if r.descriptorErr != nil {
		return r.descriptorErr
	}
	return r.descriptor.Validate()
}

func (r *moduleResource) moduleName() string {
	name := strings.TrimSpace(r.descriptor.Endpoint.Operation)
	if name == "" {
		name = r.descriptor.TypeNameSuffix
	}
	return strings.ReplaceAll(name, "_", " ")
}

func (r *moduleResource) resourceKey(epID string) string {
	return r.descriptor.Endpoint.Path + "\x00" + epID
}

func validateTemplateConfigs(model baseModel) error {
	if model.Template.IsUnknown() || model.Configs.IsUnknown() {
		return nil
	}
	if model.Template.IsNull() {
		return fmt.Errorf("template must be configured")
	}
	if model.Template.ValueBool() && !model.Configs.IsNull() {
		return fmt.Errorf("configs must be omitted when template is true")
	}
	if !model.Template.ValueBool() && model.Configs.IsNull() {
		return fmt.Errorf("configs must be configured when template is false")
	}
	return nil
}

func (r *moduleResource) knownEPID(value types.String, diagnostics *diag.Diagnostics, operation string) (string, bool) {
	if value.IsNull() || value.IsUnknown() || strings.TrimSpace(value.ValueString()) == "" {
		diagnostics.AddError("Invalid "+r.moduleName()+" application ID", "ep_id must be known and non-empty during "+r.moduleName()+" "+operation+".")
		return "", false
	}
	return strings.TrimSpace(value.ValueString()), true
}

func nullState(ctx context.Context, resourceSchema schema.Schema) tfsdk.State {
	return tfsdk.State{
		Schema: resourceSchema,
		Raw:    tftypes.NewValue(resourceSchema.Type().TerraformType(ctx), nil),
	}
}
