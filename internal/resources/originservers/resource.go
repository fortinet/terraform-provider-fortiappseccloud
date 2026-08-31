package originservers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                   = (*originServersResource)(nil)
	_ resource.ResourceWithConfigure      = (*originServersResource)(nil)
	_ resource.ResourceWithImportState    = (*originServersResource)(nil)
	_ resource.ResourceWithValidateConfig = (*originServersResource)(nil)
)

type originService interface {
	GetOriginServers(context.Context, string) (client.OriginServersDocument, error)
	PutOriginServers(context.Context, string, []client.OriginServerPool) error
	ApplicationExists(context.Context, string) (bool, error)
}

type originServersResource struct {
	service originService
	locks   *locking.Registry
}

type resourceModel struct {
	EPID        types.String `tfsdk:"ep_id"`
	ServerPools types.List   `tfsdk:"server_pools"`
}

type poolModel struct {
	Health        types.Object `tfsdk:"health"`
	LBAlgorithm   types.String `tfsdk:"lb_algorithm"`
	Name          types.String `tfsdk:"name"`
	Persistence   types.Object `tfsdk:"persistence"`
	ServerBalance types.Bool   `tfsdk:"server_balance"`
	Servers       types.List   `tfsdk:"servers"`
}

type healthModel struct {
	Enabled  types.Bool   `tfsdk:"enabled"`
	Code     types.Int64  `tfsdk:"code"`
	Interval types.Int64  `tfsdk:"interval"`
	Matched  types.String `tfsdk:"matched"`
	Method   types.String `tfsdk:"method"`
	Retry    types.Int64  `tfsdk:"retry"`
	Timeout  types.Int64  `tfsdk:"timeout"`
	URL      types.String `tfsdk:"url"`
}

type persistenceModel struct {
	Type    types.String `tfsdk:"type"`
	Timeout types.Int64  `tfsdk:"timeout"`
	Domain  types.String `tfsdk:"domain"`
	Name    types.String `tfsdk:"name"`
	Path    types.String `tfsdk:"path"`
}

type serverModel struct {
	Address           types.String `tfsdk:"address"`
	Backup            types.Bool   `tfsdk:"backup"`
	CertificateVerify types.Bool   `tfsdk:"certificate_verify"`
	ConnectionFilters types.List   `tfsdk:"connection_filters"`
	ConnectionName    types.String `tfsdk:"connection_name"`
	EncryptionLevel   types.String `tfsdk:"encryption_level"`
	HTTP2             types.Bool   `tfsdk:"http2"`
	HTTPPort          types.Int64  `tfsdk:"http_port"`
	HTTPSPort         types.Int64  `tfsdk:"https_port"`
	Port              types.Int64  `tfsdk:"port"`
	SSL               types.Bool   `tfsdk:"ssl"`
	Status            types.String `tfsdk:"status"`
	TLS10             types.Bool   `tfsdk:"tls_1_0"`
	TLS11             types.Bool   `tfsdk:"tls_1_1"`
	TLS12             types.Bool   `tfsdk:"tls_1_2"`
	TLS13             types.Bool   `tfsdk:"tls_1_3"`
	Type              types.String `tfsdk:"type"`
	Weight            types.Int64  `tfsdk:"weight"`
	HealthCheckStatus types.String `tfsdk:"health_check_status"`
	Locked            types.Bool   `tfsdk:"locked"`
}

type filterModel struct {
	Name   types.String `tfsdk:"name"`
	Values types.List   `tfsdk:"values"`
}

var (
	healthTypes = map[string]attr.Type{
		"enabled": types.BoolType, "code": types.Int64Type, "interval": types.Int64Type, "matched": types.StringType,
		"method": types.StringType, "retry": types.Int64Type, "timeout": types.Int64Type, "url": types.StringType,
	}
	persistenceTypes = map[string]attr.Type{
		"type": types.StringType, "timeout": types.Int64Type, "domain": types.StringType, "name": types.StringType, "path": types.StringType,
	}
	filterTypes = map[string]attr.Type{"name": types.StringType, "values": types.ListType{ElemType: types.StringType}}
	serverTypes = map[string]attr.Type{
		"address": types.StringType, "backup": types.BoolType, "certificate_verify": types.BoolType,
		"connection_filters": types.ListType{ElemType: types.ObjectType{AttrTypes: filterTypes}}, "connection_name": types.StringType,
		"encryption_level": types.StringType, "http2": types.BoolType, "http_port": types.Int64Type, "https_port": types.Int64Type,
		"port": types.Int64Type, "ssl": types.BoolType, "status": types.StringType, "tls_1_0": types.BoolType, "tls_1_1": types.BoolType,
		"tls_1_2": types.BoolType, "tls_1_3": types.BoolType, "type": types.StringType, "weight": types.Int64Type,
		"health_check_status": types.StringType, "locked": types.BoolType,
	}
	poolTypes = map[string]attr.Type{
		"health": types.ObjectType{AttrTypes: healthTypes}, "lb_algorithm": types.StringType, "name": types.StringType,
		"persistence": types.ObjectType{AttrTypes: persistenceTypes}, "server_balance": types.BoolType,
		"servers": types.ListType{ElemType: types.ObjectType{AttrTypes: serverTypes}},
	}
)

// NewResource creates the complete origin server-pool owner.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &originServersResource{locks: locks}
}

func (r *originServersResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_origin_servers"
}

func (r *originServersResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Owns the complete public origin server-pool configuration for one application. Destroy forgets state because no safe minimal remote pool has been live verified.",
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
		Blocks: map[string]schema.Block{
			"server_pools": schema.ListNestedBlock{
				Validators: []validator.List{listvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"lb_algorithm":   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("round-robin"), Validators: []validator.String{stringvalidator.OneOf("round-robin", "weighted-round-robin", "least-connections", "src-ip-hash")}},
						"name":           schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.UTF8LengthBetween(1, 40)}},
						"server_balance": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
					},
					Blocks: map[string]schema.Block{
						"health":      schema.SingleNestedBlock{Attributes: healthSchema()},
						"persistence": schema.SingleNestedBlock{Attributes: persistenceSchema()},
						"servers": schema.ListNestedBlock{
							Validators: []validator.List{listvalidator.SizeAtLeast(1)},
							NestedObject: schema.NestedBlockObject{Attributes: serverSchema(), Blocks: map[string]schema.Block{
								"connection_filters": schema.ListNestedBlock{NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{Required: true}, "values": schema.ListAttribute{Required: true, ElementType: types.StringType},
								}}},
							}},
						},
					},
				},
			},
		},
	}
}

func healthSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"enabled":  schema.BoolAttribute{Required: true},
		"code":     schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(302), Validators: []validator.Int64{int64validator.Between(200, 599)}},
		"interval": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(10), Validators: []validator.Int64{int64validator.Between(1, 300)}},
		"matched":  schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.UTF8LengthAtMost(1024)}},
		"method":   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("head"), Validators: []validator.String{stringvalidator.OneOf("head", "get", "post")}},
		"retry":    schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(3), Validators: []validator.Int64{int64validator.Between(1, 10)}},
		"timeout":  schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(3), Validators: []validator.Int64{int64validator.Between(1, 30)}},
		"url":      schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.UTF8LengthAtMost(255)}},
	}
}

func persistenceSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"type":    schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("disable", "source-ip", "insert-cookie")}},
		"timeout": schema.Int64Attribute{Optional: true, Computed: true, Validators: []validator.Int64{int64validator.Between(10, 86400)}},
		"domain":  schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.UTF8LengthAtMost(255)}},
		"name":    schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.UTF8LengthAtMost(127)}},
		"path":    schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.UTF8LengthAtMost(255)}},
	}
}

func serverSchema() map[string]schema.Attribute {
	portValidators := []validator.Int64{int64validator.Between(1, 65535)}
	return map[string]schema.Attribute{
		"address":             schema.StringAttribute{Optional: true, Computed: true},
		"backup":              schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
		"certificate_verify":  schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), MarkdownDescription: "Reviewed production field omitted by OpenAPI 26.3.a."},
		"connection_name":     schema.StringAttribute{Optional: true, Computed: true},
		"encryption_level":    schema.StringAttribute{Optional: true, Computed: true, Validators: []validator.String{stringvalidator.OneOf("mozilla_modern", "mozilla_intermediate", "mozilla_old", "customized", "high", "medium")}},
		"http2":               schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
		"http_port":           schema.Int64Attribute{Optional: true, Computed: true, Validators: portValidators},
		"https_port":          schema.Int64Attribute{Optional: true, Computed: true, Validators: portValidators},
		"port":                schema.Int64Attribute{Optional: true, Computed: true, Validators: portValidators},
		"ssl":                 schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		"status":              schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("disable", "enable", "maintain")}},
		"tls_1_0":             schema.BoolAttribute{Optional: true, Computed: true},
		"tls_1_1":             schema.BoolAttribute{Optional: true, Computed: true},
		"tls_1_2":             schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		"tls_1_3":             schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		"type":                schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("ip", "domain", "dynamic")}},
		"weight":              schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(1), Validators: []validator.Int64{int64validator.Between(1, 9999)}},
		"health_check_status": schema.StringAttribute{Computed: true, MarkdownDescription: "Server-owned production field omitted by OpenAPI 26.3.a."},
		"locked":              schema.BoolAttribute{Computed: true, MarkdownDescription: "Server-owned production field omitted by OpenAPI 26.3.a."},
	}
}

func (r *originServersResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *originServersResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.ServerPools.IsNull() || config.ServerPools.IsUnknown() {
		return
	}
	_, conversionDiags := expandPools(ctx, config.ServerPools)
	resp.Diagnostics.Append(conversionDiags...)
}

func (r *originServersResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *originServersResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID, ok := knownEPID(state.EPID, &resp.Diagnostics)
	if !ok {
		return
	}
	unlock := r.locks.Lock("waf-origin-servers:" + epID)
	defer unlock()
	document, err := r.service.GetOriginServers(ctx, epID)
	if err != nil {
		if r.parentAbsent(ctx, epID, err, &resp.Diagnostics) {
			resp.State.RemoveResource(ctx)
			return
		}
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("Unable to read origin servers", err.Error())
		}
		return
	}
	r.setState(ctx, epID, document.Result.ServerPools, &resp.State, &resp.Diagnostics)
}

func (r *originServersResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *originServersResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID, ok := knownEPID(state.EPID, &resp.Diagnostics)
	if !ok {
		return
	}
	_, err := r.service.GetOriginServers(ctx, epID)
	if err != nil {
		if r.parentAbsent(ctx, epID, err, &resp.Diagnostics) {
			return
		}
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("Unable to inspect origin servers before destroy", err.Error())
		}
		return
	}
	resp.Diagnostics.AddWarning("Remote origin server configuration remains", "Terraform removed this resource from state without changing origin servers because no safe minimal/default pool has been live verified.")
}

func (r *originServersResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires a non-empty application ep_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ep_id"), id)...)
}

func (r *originServersResource) apply(ctx context.Context, plan resourceModel, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	if !r.ready(diagnostics) {
		return
	}
	epID, ok := knownEPID(plan.EPID, diagnostics)
	if !ok {
		return
	}
	pools, conversionDiags := expandPools(ctx, plan.ServerPools)
	diagnostics.Append(conversionDiags...)
	if diagnostics.HasError() {
		return
	}
	unlock := r.locks.Lock("waf-origin-servers:" + epID)
	defer unlock()
	current, err := r.service.GetOriginServers(ctx, epID)
	if err != nil {
		if r.parentAbsent(ctx, epID, err, diagnostics) {
			diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
			return
		}
		if !diagnostics.HasError() {
			diagnostics.AddError("Unable to read origin servers before update", err.Error())
		}
		return
	}
	client.MergeOriginServerOmittedFields(pools, current.Result.ServerPools)
	if err := r.service.PutOriginServers(ctx, epID, pools); err != nil {
		if r.parentAbsent(ctx, epID, err, diagnostics) {
			diagnostics.AddError("Application not found", fmt.Sprintf("Application %q does not exist.", epID))
			return
		}
		if !diagnostics.HasError() {
			diagnostics.AddError("Unable to update origin servers", err.Error())
		}
		return
	}
	normalized, err := r.service.GetOriginServers(ctx, epID)
	if err != nil {
		diagnostics.AddError("Unable to refresh origin servers", err.Error())
		return
	}
	r.setState(ctx, epID, normalized.Result.ServerPools, state, diagnostics)
}

func (r *originServersResource) setState(ctx context.Context, epID string, pools []client.OriginServerPool, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	value, flattenDiags := flattenPools(ctx, pools)
	diagnostics.Append(flattenDiags...)
	if diagnostics.HasError() {
		return
	}
	diagnostics.Append(state.Set(ctx, &resourceModel{EPID: types.StringValue(epID), ServerPools: value})...)
}

func expandPools(ctx context.Context, value types.List) ([]client.OriginServerPool, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if value.IsNull() || value.IsUnknown() {
		diagnostics.AddError("Missing origin server pools", "server_pools must be known and contain at least one pool.")
		return nil, diagnostics
	}
	var models []poolModel
	diagnostics.Append(value.ElementsAs(ctx, &models, false)...)
	pools := make([]client.OriginServerPool, 0, len(models))
	for poolIndex, model := range models {
		var health healthModel
		var persistence persistenceModel
		diagnostics.Append(model.Health.As(ctx, &health, basetypes.ObjectAsOptions{})...)
		diagnostics.Append(model.Persistence.As(ctx, &persistence, basetypes.ObjectAsOptions{})...)
		var serverModels []serverModel
		diagnostics.Append(model.Servers.ElementsAs(ctx, &serverModels, false)...)
		servers := make([]client.OriginServer, 0, len(serverModels))
		for serverIndex, server := range serverModels {
			wire, serverDiags := expandServer(ctx, server, poolIndex, serverIndex)
			diagnostics.Append(serverDiags...)
			wire.Index = int64Pointer(int64(serverIndex + 1))
			servers = append(servers, wire)
		}
		pools = append(pools, client.OriginServerPool{
			Health:      client.OriginServerHealth{Enabled: health.Enabled.ValueBool(), Code: optionalInt64(health.Code), Interval: optionalInt64(health.Interval), Matched: optionalString(health.Matched), Method: optionalString(health.Method), Retry: optionalInt64(health.Retry), Timeout: optionalInt64(health.Timeout), URL: optionalString(health.URL)},
			LBAlgorithm: model.LBAlgorithm.ValueString(), Name: model.Name.ValueString(), ServerBalance: model.ServerBalance.ValueBool(), Servers: servers,
			Persistence: client.OriginServerPersistence{Type: persistence.Type.ValueString(), Timeout: optionalInt64(persistence.Timeout), Domain: optionalString(persistence.Domain), Name: optionalString(persistence.Name), Path: optionalString(persistence.Path)},
		})
	}
	return pools, diagnostics
}

func expandServer(ctx context.Context, model serverModel, poolIndex, serverIndex int) (client.OriginServer, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var filterModels []filterModel
	if !model.ConnectionFilters.IsNull() && !model.ConnectionFilters.IsUnknown() {
		diagnostics.Append(model.ConnectionFilters.ElementsAs(ctx, &filterModels, false)...)
	}
	filters := make([]client.OriginServerFilter, 0, len(filterModels))
	for _, filter := range filterModels {
		var values []string
		diagnostics.Append(filter.Values.ElementsAs(ctx, &values, false)...)
		filters = append(filters, client.OriginServerFilter{Name: filter.Name.ValueString(), Values: values})
	}
	typeName := model.Type.ValueString()
	if (typeName == "ip" || typeName == "domain") && strings.TrimSpace(model.Address.ValueString()) == "" {
		diagnostics.AddError("Missing origin server address", fmt.Sprintf("server_pools[%d].servers[%d].address is required for type %q.", poolIndex, serverIndex, typeName))
	}
	if typeName == "dynamic" && strings.TrimSpace(model.ConnectionName.ValueString()) == "" {
		diagnostics.AddError("Missing connector name", fmt.Sprintf("server_pools[%d].servers[%d].connection_name is required for type dynamic.", poolIndex, serverIndex))
	}
	if !model.SSL.IsNull() && !model.SSL.IsUnknown() && model.SSL.ValueBool() &&
		(model.EncryptionLevel.IsNull() || model.EncryptionLevel.IsUnknown() || strings.TrimSpace(model.EncryptionLevel.ValueString()) == "") {
		diagnostics.AddError("Missing origin encryption level", fmt.Sprintf("server_pools[%d].servers[%d].encryption_level must be configured when ssl=true because the API requires an explicit cipher policy on write.", poolIndex, serverIndex))
	}
	return client.OriginServer{
		Address: optionalString(model.Address), Backup: optionalBool(model.Backup), CertificateVerify: optionalBool(model.CertificateVerify), ConnectionFilters: filters,
		ConnectionName: optionalString(model.ConnectionName), EncryptionLevel: optionalString(model.EncryptionLevel), HTTP2: optionalBool(model.HTTP2),
		HTTPPort: optionalInt64(model.HTTPPort), HTTPSPort: optionalInt64(model.HTTPSPort), Port: optionalInt64(model.Port), SSL: optionalBool(model.SSL),
		Status: optionalString(model.Status), TLS10: optionalBool(model.TLS10), TLS11: optionalBool(model.TLS11), TLS12: optionalBool(model.TLS12), TLS13: optionalBool(model.TLS13),
		Type: optionalString(model.Type), Weight: optionalInt64(model.Weight),
	}, diagnostics
}

func flattenPools(ctx context.Context, pools []client.OriginServerPool) (types.List, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	models := make([]poolModel, 0, len(pools))
	for _, pool := range pools {
		health, healthDiags := types.ObjectValueFrom(ctx, healthTypes, healthModel{
			Enabled: types.BoolValue(pool.Health.Enabled), Code: int64Value(pool.Health.Code), Interval: int64Value(pool.Health.Interval), Matched: stringValue(pool.Health.Matched),
			Method: stringValue(pool.Health.Method), Retry: int64Value(pool.Health.Retry), Timeout: int64Value(pool.Health.Timeout), URL: stringValue(pool.Health.URL),
		})
		diagnostics.Append(healthDiags...)
		persistence, persistenceDiags := types.ObjectValueFrom(ctx, persistenceTypes, persistenceModel{
			Type: types.StringValue(pool.Persistence.Type), Timeout: int64Value(pool.Persistence.Timeout), Domain: stringValue(pool.Persistence.Domain), Name: stringValue(pool.Persistence.Name), Path: stringValue(pool.Persistence.Path),
		})
		diagnostics.Append(persistenceDiags...)
		sort.SliceStable(pool.Servers, func(i, j int) bool { return pointerInt64(pool.Servers[i].Index) < pointerInt64(pool.Servers[j].Index) })
		serverModels := make([]serverModel, 0, len(pool.Servers))
		for _, server := range pool.Servers {
			filters := make([]filterModel, 0, len(server.ConnectionFilters))
			for _, filter := range server.ConnectionFilters {
				values, valueDiags := types.ListValueFrom(ctx, types.StringType, filter.Values)
				diagnostics.Append(valueDiags...)
				filters = append(filters, filterModel{Name: types.StringValue(filter.Name), Values: values})
			}
			filterValue, filterDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: filterTypes}, filters)
			diagnostics.Append(filterDiags...)
			serverModels = append(serverModels, serverModel{
				Address: stringValue(server.Address), Backup: boolValue(server.Backup), CertificateVerify: boolValue(server.CertificateVerify), ConnectionFilters: filterValue,
				ConnectionName: stringValue(server.ConnectionName), EncryptionLevel: stringValue(server.EncryptionLevel), HTTP2: boolValue(server.HTTP2),
				HTTPPort: int64Value(server.HTTPPort), HTTPSPort: int64Value(server.HTTPSPort), Port: int64Value(server.Port), SSL: boolValue(server.SSL), Status: stringValue(server.Status),
				TLS10: boolValue(server.TLS10), TLS11: boolValue(server.TLS11), TLS12: boolValue(server.TLS12), TLS13: boolValue(server.TLS13), Type: stringValue(server.Type), Weight: int64Value(server.Weight),
				HealthCheckStatus: stringValue(server.HealthCheckStatus), Locked: boolValue(server.Locked),
			})
		}
		servers, serverDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: serverTypes}, serverModels)
		diagnostics.Append(serverDiags...)
		models = append(models, poolModel{Health: health, LBAlgorithm: types.StringValue(pool.LBAlgorithm), Name: types.StringValue(pool.Name), Persistence: persistence, ServerBalance: types.BoolValue(pool.ServerBalance), Servers: servers})
	}
	value, valueDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: poolTypes}, models)
	diagnostics.Append(valueDiags...)
	return value, diagnostics
}

func (r *originServersResource) parentAbsent(ctx context.Context, epID string, operationErr error, diagnostics *diag.Diagnostics) bool {
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

func (r *originServersResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service == nil {
		diagnostics.AddError("Origin server client is not configured", "Configure the provider before managing origin servers.")
		return false
	}
	return true
}

func knownEPID(value types.String, diagnostics *diag.Diagnostics) (string, bool) {
	if value.IsNull() || value.IsUnknown() || strings.TrimSpace(value.ValueString()) == "" {
		diagnostics.AddError("Invalid application ID", "ep_id must be known and non-empty.")
		return "", false
	}
	return strings.TrimSpace(value.ValueString()), true
}

func optionalString(value types.String) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueString()
	return &result
}
func optionalInt64(value types.Int64) *int64 {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueInt64()
	return &result
}
func optionalBool(value types.Bool) *bool {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueBool()
	return &result
}
func stringValue(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}
	return types.StringValue(*value)
}
func int64Value(value *int64) types.Int64 {
	if value == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*value)
}
func boolValue(value *bool) types.Bool {
	if value == nil {
		return types.BoolNull()
	}
	return types.BoolValue(*value)
}
func int64Pointer(value int64) *int64 { return &value }
func pointerInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
