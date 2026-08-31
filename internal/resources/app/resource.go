package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
)

var (
	_ resource.Resource                   = (*appResource)(nil)
	_ resource.ResourceWithConfigure      = (*appResource)(nil)
	_ resource.ResourceWithImportState    = (*appResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*appResource)(nil)
	_ resource.ResourceWithUpgradeState   = (*appResource)(nil)
	_ resource.ResourceWithValidateConfig = (*appResource)(nil)
)

const (
	currentSchemaVersion     = 2
	defaultPollAttempts      = 30
	certificateModeAutomatic = "automatic"
	certificateModeCustom    = "custom"
	certificateTypeAutomatic = 0
	certificateTypeCustom    = 1
)

type appService interface {
	CreateApplication(context.Context, client.ApplicationCreateRequest) (client.ApplicationCreateResponse, error)
	UpdateApplication(context.Context, string, client.ApplicationUpdateRequest) error
	UpdateApplicationBlockMode(context.Context, string, bool) error
	GetApplicationEndpoint(context.Context, string) (map[string]any, error)
	PutApplicationEndpoint(context.Context, string, map[string]any) error
	DeleteApplication(context.Context, string) error
	FindApplicationByName(context.Context, string) (client.Application, error)
	FindApplicationByEPID(context.Context, string) (client.Application, error)
	ApplicationExists(context.Context, string) (bool, error)
	DNSLookup(context.Context, string) ([]string, error)
	TestBackendConnectivity(context.Context, client.BackendConnectivityRequest) error
}

type appResource struct {
	service      appService
	locks        *locking.Registry
	pollAttempts int
	pollDelay    time.Duration
}

type resourceModel struct {
	EPID                 types.String `tfsdk:"ep_id"`
	LegacyAppName        types.String `tfsdk:"legacy_app_name"`
	AppName              types.String `tfsdk:"app_name"`
	DomainName           types.String `tfsdk:"domain_name"`
	ExtraDomains         types.List   `tfsdk:"extra_domains"`
	Services             types.Set    `tfsdk:"services"`
	HTTPPort             types.Int64  `tfsdk:"http_port"`
	HTTPSPort            types.Int64  `tfsdk:"https_port"`
	Platform             types.String `tfsdk:"platform"`
	Region               types.String `tfsdk:"region"`
	CDN                  types.Bool   `tfsdk:"cdn"`
	GlobalCDN            types.Bool   `tfsdk:"global_cdn"`
	Continent            types.String `tfsdk:"continent"`
	BlockMode            types.Bool   `tfsdk:"block_mode"`
	CertificateMode      types.String `tfsdk:"certificate_mode"`
	InitialOrigin        types.Object `tfsdk:"initial_origin"`
	Precheck             types.Bool   `tfsdk:"precheck"`
	CNAMEs               types.List   `tfsdk:"cnames"`
	PlacementRegion      types.String `tfsdk:"placement_region"`
	AttachedTemplateID   types.String `tfsdk:"attached_template_id"`
	AttachedTemplateName types.String `tfsdk:"attached_template_name"`
}

type initialOriginModel struct {
	Address  types.String `tfsdk:"address"`
	Protocol types.String `tfsdk:"protocol"`
	Port     types.Int64  `tfsdk:"port"`
}

var initialOriginTypes = map[string]attr.Type{
	"address":  types.StringType,
	"protocol": types.StringType,
	"port":     types.Int64Type,
}

// NewResource creates the Framework application resource under the legacy public name.
func NewResource(locks *locking.Registry) resource.Resource {
	if locks == nil {
		locks = locking.NewRegistry()
	}
	return &appResource{locks: locks, pollAttempts: defaultPollAttempts, pollDelay: 2 * time.Second}
}

func (r *appResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_app"
}

func (r *appResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = currentSchema()
}

func currentSchema() schema.Schema {
	return schema.Schema{
		Version:             currentSchemaVersion,
		MarkdownDescription: "Manages application identity, placement, public listener settings, automatic/custom certificate mode, and the bootstrap-only initial origin. Ongoing origin pools and template membership are owned by separate resources.",
		Attributes: map[string]schema.Attribute{
			"ep_id":           schema.StringAttribute{Computed: true, MarkdownDescription: "Stable application endpoint ID and import identity."},
			"legacy_app_name": schema.StringAttribute{Computed: true, MarkdownDescription: "Migration-only application name used to resolve legacy SDKv2 identity."},
			"app_name": schema.StringAttribute{
				Required: true, Validators: []validator.String{stringvalidator.UTF8LengthBetween(1, 64)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"domain_name": schema.StringAttribute{
				Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"extra_domains": schema.ListAttribute{
				Optional: true, Computed: true, ElementType: types.StringType,
				Validators: []validator.List{listvalidator.SizeAtMost(9)},
			},
			"services": schema.SetAttribute{
				Required: true, ElementType: types.StringType,
				Validators: []validator.Set{setvalidator.SizeBetween(1, 2), setvalidator.ValueStringsAre(stringvalidator.OneOf("http", "https"))},
			},
			"http_port":  schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(80), Validators: []validator.Int64{int64validator.Between(1, 65535)}},
			"https_port": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(443), Validators: []validator.Int64{int64validator.Between(1, 65535)}},
			"platform": schema.StringAttribute{
				Required: true, Validators: []validator.String{stringvalidator.OneOf("AWS", "Azure", "GCP", "OCI", "C8T")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"region":     schema.StringAttribute{Optional: true},
			"cdn":        schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"global_cdn": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"continent":  schema.StringAttribute{Optional: true},
			"block_mode": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"certificate_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(certificateModeAutomatic, certificateModeCustom),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "Certificate-management mode. `automatic` maps to API `cert_type=0`; `custom` maps to `cert_type=1`. This field does not upload or attach certificate, private-key, CA, or CRL content.",
			},
			"precheck":         schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"cnames":           schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"placement_region": schema.StringAttribute{Computed: true},
			"attached_template_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Observed remote template membership. Configuration ownership belongs to waf_template_attachment.",
			},
			"attached_template_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Observed remote template name. Configuration ownership belongs to waf_template_attachment.",
			},
		},
		Blocks: map[string]schema.Block{
			"initial_origin": schema.SingleNestedBlock{Attributes: map[string]schema.Attribute{
				"address":  schema.StringAttribute{Required: true},
				"protocol": schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("http", "https")}},
				"port":     schema.Int64Attribute{Required: true, Validators: []validator.Int64{int64validator.Between(1, 65535)}},
			}},
		},
	}
}

func schemaV1() schema.Schema {
	previous := currentSchema()
	previous.Version = 1
	delete(previous.Attributes, "certificate_mode")
	return previous
}

func legacySchemaV0() schema.Schema {
	return schema.Schema{Attributes: map[string]schema.Attribute{
		"id":                    schema.StringAttribute{Computed: true},
		"app_name":              schema.StringAttribute{Optional: true},
		"domain_name":           schema.StringAttribute{Optional: true},
		"extra_domains":         schema.ListAttribute{Optional: true, ElementType: types.StringType},
		"app_service":           schema.MapAttribute{Optional: true, ElementType: types.Int64Type},
		"origin_server_ip":      schema.StringAttribute{Optional: true},
		"origin_server_service": schema.StringAttribute{Optional: true},
		"origin_server_port":    schema.Int64Attribute{Optional: true},
		"cdn":                   schema.BoolAttribute{Optional: true},
		"continent_cdn":         schema.BoolAttribute{Optional: true},
		"continent":             schema.StringAttribute{Optional: true, Computed: true},
		"block":                 schema.BoolAttribute{Optional: true},
		"template":              schema.StringAttribute{Optional: true},
		"cname":                 schema.StringAttribute{Optional: true, Computed: true},
		"ep_id":                 schema.StringAttribute{Optional: true, Computed: true},
	}}
}

func (r *appResource) UpgradeState(context.Context) map[int64]resource.StateUpgrader {
	legacy := legacySchemaV0()
	previous := schemaV1()
	return map[int64]resource.StateUpgrader{
		0: {PriorSchema: &legacy, StateUpgrader: upgradeStateV0},
		1: {PriorSchema: &previous, StateUpgrader: upgradeStateV1},
	}
}

func upgradeStateV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
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
	var old legacyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
	if resp.Diagnostics.HasError() {
		return
	}

	legacyName := old.ID
	if legacyName.IsNull() || legacyName.IsUnknown() || strings.TrimSpace(legacyName.ValueString()) == "" {
		legacyName = old.AppName
	}
	services := make([]string, 0, 2)
	if !old.AppService.IsNull() && !old.AppService.IsUnknown() {
		values := map[string]types.Int64{}
		resp.Diagnostics.Append(old.AppService.ElementsAs(ctx, &values, false)...)
		for _, name := range []string{"http", "https"} {
			if value, ok := values[name]; ok && !value.IsNull() && !value.IsUnknown() {
				services = append(services, name)
			}
		}
	}
	serviceValue, serviceDiags := types.SetValueFrom(ctx, types.StringType, services)
	resp.Diagnostics.Append(serviceDiags...)

	protocol := strings.ToLower(strings.TrimSpace(old.OriginServerService.ValueString()))
	if protocol == "" {
		protocol = "https"
	}
	origin, originDiags := types.ObjectValue(initialOriginTypes, map[string]attr.Value{
		"address": old.OriginServerIP, "protocol": types.StringValue(protocol), "port": old.OriginServerPort,
	})
	resp.Diagnostics.Append(originDiags...)

	cnames := []string{}
	if !old.CNAME.IsNull() && !old.CNAME.IsUnknown() && strings.TrimSpace(old.CNAME.ValueString()) != "" {
		if err := json.Unmarshal([]byte(old.CNAME.ValueString()), &cnames); err != nil {
			cnames = []string{old.CNAME.ValueString()}
		}
	}
	cnameValue, cnameDiags := types.ListValueFrom(ctx, types.StringType, cnames)
	resp.Diagnostics.Append(cnameDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	globalCDN := types.BoolValue(false)
	if old.CDN.ValueBool() && !old.ContinentCDN.ValueBool() {
		globalCDN = types.BoolValue(true)
	}
	upgraded := resourceModel{
		EPID: old.EPID, LegacyAppName: legacyName, AppName: old.AppName, DomainName: old.DomainName,
		ExtraDomains: old.ExtraDomains, Services: serviceValue, HTTPPort: types.Int64Value(80), HTTPSPort: types.Int64Value(443),
		Platform: types.StringNull(), Region: types.StringNull(), CDN: old.CDN, GlobalCDN: globalCDN, Continent: old.Continent,
		BlockMode: old.Block, CertificateMode: types.StringNull(), InitialOrigin: origin, Precheck: types.BoolValue(false), CNAMEs: cnameValue, PlacementRegion: types.StringNull(),
		AttachedTemplateID: types.StringNull(), AttachedTemplateName: old.Template,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
}

type resourceModelV1 struct {
	EPID                 types.String `tfsdk:"ep_id"`
	LegacyAppName        types.String `tfsdk:"legacy_app_name"`
	AppName              types.String `tfsdk:"app_name"`
	DomainName           types.String `tfsdk:"domain_name"`
	ExtraDomains         types.List   `tfsdk:"extra_domains"`
	Services             types.Set    `tfsdk:"services"`
	HTTPPort             types.Int64  `tfsdk:"http_port"`
	HTTPSPort            types.Int64  `tfsdk:"https_port"`
	Platform             types.String `tfsdk:"platform"`
	Region               types.String `tfsdk:"region"`
	CDN                  types.Bool   `tfsdk:"cdn"`
	GlobalCDN            types.Bool   `tfsdk:"global_cdn"`
	Continent            types.String `tfsdk:"continent"`
	BlockMode            types.Bool   `tfsdk:"block_mode"`
	InitialOrigin        types.Object `tfsdk:"initial_origin"`
	Precheck             types.Bool   `tfsdk:"precheck"`
	CNAMEs               types.List   `tfsdk:"cnames"`
	PlacementRegion      types.String `tfsdk:"placement_region"`
	AttachedTemplateID   types.String `tfsdk:"attached_template_id"`
	AttachedTemplateName types.String `tfsdk:"attached_template_name"`
}

func upgradeStateV1(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	var old resourceModelV1
	resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
	if resp.Diagnostics.HasError() {
		return
	}
	upgraded := resourceModel{
		EPID: old.EPID, LegacyAppName: old.LegacyAppName, AppName: old.AppName, DomainName: old.DomainName,
		ExtraDomains: old.ExtraDomains, Services: old.Services, HTTPPort: old.HTTPPort, HTTPSPort: old.HTTPSPort,
		Platform: old.Platform, Region: old.Region, CDN: old.CDN, GlobalCDN: old.GlobalCDN, Continent: old.Continent,
		BlockMode: old.BlockMode, CertificateMode: types.StringNull(), InitialOrigin: old.InitialOrigin, Precheck: old.Precheck,
		CNAMEs: old.CNAMEs, PlacementRegion: old.PlacementRegion,
		AttachedTemplateID: old.AttachedTemplateID, AttachedTemplateName: old.AttachedTemplateName,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &upgraded)...)
}

func (r *appResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *appResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config resourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.HTTPPort.IsUnknown() && !config.HTTPSPort.IsUnknown() && !config.HTTPPort.IsNull() && !config.HTTPSPort.IsNull() && config.HTTPPort.ValueInt64() == config.HTTPSPort.ValueInt64() {
		resp.Diagnostics.AddAttributeError(path.Root("https_port"), "Invalid listener ports", "http_port and https_port must differ.")
	}
	validatePlacement(config, &resp.Diagnostics)
}

func (r *appResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	resp.Plan = req.Plan
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}
	var prior, plan resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || prior.InitialOrigin.IsUnknown() || plan.InitialOrigin.IsUnknown() {
		return
	}
	// Import cannot reconstruct a bootstrap-only origin safely. Allow the
	// first configured value to be adopted into state without replacing the
	// existing application; subsequent known changes still require replacement.
	if prior.InitialOrigin.IsNull() {
		return
	}
	if !prior.InitialOrigin.Equal(plan.InitialOrigin) {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("initial_origin"))
	}
}

func validatePlacement(model resourceModel, diagnostics *diag.Diagnostics) {
	if model.CDN.IsNull() || model.CDN.IsUnknown() || model.GlobalCDN.IsUnknown() || model.Region.IsUnknown() || model.Continent.IsUnknown() {
		return
	}
	region := strings.TrimSpace(model.Region.ValueString())
	continent := strings.TrimSpace(model.Continent.ValueString())
	if !model.CDN.ValueBool() {
		if region == "" {
			diagnostics.AddAttributeError(path.Root("region"), "Missing application region", "region is required when cdn is false.")
		}
		if model.GlobalCDN.ValueBool() || continent != "" {
			diagnostics.AddAttributeError(path.Root("cdn"), "Conflicting placement settings", "global_cdn and continent must be unset when cdn is false.")
		}
		return
	}
	if region != "" {
		diagnostics.AddAttributeError(path.Root("region"), "Conflicting placement settings", "region must be unset when cdn is true.")
	}
	if model.GlobalCDN.ValueBool() == (continent != "") {
		diagnostics.AddAttributeError(path.Root("global_cdn"), "Invalid CDN placement", "Exactly one of global_cdn=true or continent must be configured when cdn is true.")
	}
}

func (r *appResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validatePlacement(plan, &resp.Diagnostics)
	origin, ok := decodeInitialOrigin(ctx, plan.InitialOrigin, &resp.Diagnostics)
	if !ok {
		return
	}
	if plan.Precheck.ValueBool() {
		if err := r.precheckOrigin(ctx, plan.DomainName.ValueString(), origin); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("precheck"), "Application origin precheck failed", err.Error())
			return
		}
	}
	services := stringSet(ctx, plan.Services, &resp.Diagnostics)
	extraDomains := stringList(ctx, plan.ExtraDomains, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	request := client.ApplicationCreateRequest{
		AppName: plan.AppName.ValueString(), CreationOrigin: client.ApplicationCreationOriginTerraform,
		DomainName: plan.DomainName.ValueString(), ExtraDomains: extraDomains,
		BlockMode: boolInt(plan.BlockMode.ValueBool()), CertType: certificateTypePointer(plan.CertificateMode), Service: services, ServerAddress: origin.Address.ValueString(),
		ServerType: origin.Protocol.ValueString(), ServerPort: origin.Port.ValueInt64(), CDNStatus: boolInt(plan.CDN.ValueBool()),
		IsGlobalCDN: boolInt(plan.GlobalCDN.ValueBool()), Continent: plan.Continent.ValueString(), Region: plan.Region.ValueString(),
		Platform: plan.Platform.ValueString(), CustomPort: client.ApplicationCustomPort{HTTP: plan.HTTPPort.ValueInt64(), HTTPS: plan.HTTPSPort.ValueInt64()},
	}
	unlock := r.locks.Lock("waf-app:" + request.AppName)
	defer unlock()
	created, err := r.service.CreateApplication(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create application", err.Error())
		return
	}
	epID := strings.TrimSpace(created.EPID)
	if epID == "" {
		resolved, resolveErr := r.service.FindApplicationByName(ctx, request.AppName)
		if resolveErr != nil {
			resp.Diagnostics.AddError("Unable to resolve created application", resolveErr.Error())
			return
		}
		epID = resolved.EPID
	}
	application, err := r.waitForApplication(ctx, epID, true)
	if err != nil {
		resp.Diagnostics.AddError("Application did not become readable", err.Error())
		return
	}
	r.setState(ctx, plan, application, created.DomainInfo, &resp.State, &resp.Diagnostics)
}

func (r *appResource) precheckOrigin(ctx context.Context, domainName string, origin initialOriginModel) error {
	address := strings.TrimSpace(origin.Address.ValueString())
	addresses := []string{address}
	if net.ParseIP(address) == nil {
		resolved, err := r.service.DNSLookup(ctx, address)
		if err != nil {
			return fmt.Errorf("resolve origin hostname: %w", err)
		}
		addresses = resolved
	}
	var failures int
	for _, resolvedAddress := range addresses {
		err := r.service.TestBackendConnectivity(ctx, client.BackendConnectivityRequest{
			DomainName: domainName,
			Address:    resolvedAddress,
			Protocol:   origin.Protocol.ValueString(),
			Port:       origin.Port.ValueInt64(),
		})
		if err == nil {
			return nil
		}
		failures++
	}
	return fmt.Errorf("none of %d resolved origin address(es) passed the public connectivity check", failures)
}

func (r *appResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	application, ok := r.resolveStateApplication(ctx, state, &resp.Diagnostics)
	if !ok {
		if !resp.Diagnostics.HasError() {
			resp.State.RemoveResource(ctx)
		}
		return
	}
	r.setState(ctx, state, application, nil, &resp.State, &resp.Diagnostics)
}

func (r *appResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var prior, plan resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	epID := prior.EPID.ValueString()
	if strings.TrimSpace(epID) == "" {
		resp.Diagnostics.AddError("Missing application ID", "The application must be refreshed to resolve its stable ep_id before update.")
		return
	}
	unlock := r.locks.Lock("waf-app:" + epID)
	defer unlock()

	if placementChanged(prior, plan) {
		err := r.service.UpdateApplication(ctx, epID, client.ApplicationUpdateRequest{
			AppName: plan.AppName.ValueString(), CDNStatus: boolInt(plan.CDN.ValueBool()), IsGlobalCDN: boolInt(plan.GlobalCDN.ValueBool()),
			Continent: plan.Continent.ValueString(), Region: plan.Region.ValueString(),
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update application placement", err.Error())
			return
		}
	}
	if endpointChanged(prior, plan) {
		document, err := r.service.GetApplicationEndpoint(ctx, epID)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read application endpoint before update", err.Error())
			return
		}
		prepareEndpointUpdate(document, plan, ctx, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if err := r.service.PutApplicationEndpoint(ctx, epID, document); err != nil {
			resp.Diagnostics.AddError("Unable to update application endpoint", err.Error())
			return
		}
	}
	if prior.BlockMode.ValueBool() != plan.BlockMode.ValueBool() {
		if err := r.service.UpdateApplicationBlockMode(ctx, epID, plan.BlockMode.ValueBool()); err != nil {
			resp.Diagnostics.AddError("Unable to update application block mode", err.Error())
			return
		}
	}
	application, err := r.service.FindApplicationByEPID(ctx, epID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to refresh updated application", err.Error())
		return
	}
	r.setState(ctx, plan, application, nil, &resp.State, &resp.Diagnostics)
}

func (r *appResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !r.ready(&resp.Diagnostics) {
		return
	}
	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	application, ok := r.resolveStateApplication(ctx, state, &resp.Diagnostics)
	if !ok {
		return
	}
	unlock := r.locks.Lock("waf-app:" + application.EPID)
	defer unlock()
	if err := r.service.DeleteApplication(ctx, application.EPID); err != nil {
		if !client.IsStatus(err, http.StatusBadRequest, http.StatusNotFound) {
			resp.Diagnostics.AddError("Unable to delete application", err.Error())
			return
		}
		exists, checkErr := r.service.ApplicationExists(ctx, application.EPID)
		if checkErr != nil {
			resp.Diagnostics.AddError("Unable to verify application deletion", checkErr.Error())
			return
		}
		if exists {
			resp.Diagnostics.AddError("Unable to delete application", err.Error())
			return
		}
		return
	}
	if _, err := r.waitForApplication(ctx, application.EPID, false); err != nil {
		resp.Diagnostics.AddError("Application deletion was not observable", err.Error())
	}
}

func (r *appResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Import requires an application ep_id or an unambiguous legacy app_name.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("legacy_app_name"), id)...)
}

func (r *appResource) resolveStateApplication(ctx context.Context, state resourceModel, diagnostics *diag.Diagnostics) (client.Application, bool) {
	if !state.EPID.IsNull() && !state.EPID.IsUnknown() && strings.TrimSpace(state.EPID.ValueString()) != "" {
		application, err := r.service.FindApplicationByEPID(ctx, state.EPID.ValueString())
		if err == nil {
			return application, true
		}
		exists, checkErr := r.service.ApplicationExists(ctx, state.EPID.ValueString())
		if checkErr != nil {
			diagnostics.AddError("Unable to resolve application", checkErr.Error())
			return client.Application{}, false
		}
		if !exists {
			return client.Application{}, false
		}
		diagnostics.AddError("Unable to resolve application", err.Error())
		return client.Application{}, false
	}
	name := strings.TrimSpace(state.LegacyAppName.ValueString())
	if name == "" {
		name = strings.TrimSpace(state.AppName.ValueString())
	}
	if name == "" {
		diagnostics.AddError("Unable to migrate application identity", "Legacy state did not contain an app_name. Import the resource using ep_id.")
		return client.Application{}, false
	}
	if application, err := r.service.FindApplicationByEPID(ctx, name); err == nil {
		return application, true
	}
	application, err := r.service.FindApplicationByName(ctx, name)
	if err != nil {
		diagnostics.AddError("Unable to migrate application identity", fmt.Sprintf("Could not resolve legacy application %q to an ep_id: %v. Import using ep_id as the recovery path.", name, err))
		return client.Application{}, false
	}
	return application, true
}

func (r *appResource) setState(ctx context.Context, prior resourceModel, application client.Application, createdDomains []client.ApplicationDomainInfo, state *tfsdk.State, diagnostics *diag.Diagnostics) {
	endpoint, err := r.service.GetApplicationEndpoint(ctx, application.EPID)
	if err != nil {
		diagnostics.AddError("Unable to refresh application endpoint", err.Error())
		return
	}
	certificateMode, err := certificateModeFromEndpoint(endpoint)
	if err != nil {
		diagnostics.AddAttributeError(path.Root("certificate_mode"), "Unable to read certificate mode", err.Error())
		return
	}
	extraDomains := application.ExtraDomains
	if value, ok := endpoint["extra_domains"].([]any); ok {
		extraDomains = anyStringSlice(value)
	}
	extraValue, extraDiags := types.ListValueFrom(ctx, types.StringType, extraDomains)
	diagnostics.Append(extraDiags...)

	services := []string{}
	if jsonBool(endpoint["http_status"]) {
		services = append(services, "http")
	}
	if jsonBool(endpoint["https_status"]) {
		services = append(services, "https")
	}
	if len(services) == 0 {
		services = stringSet(ctx, prior.Services, diagnostics)
	}
	serviceValue, serviceDiags := types.SetValueFrom(ctx, types.StringType, services)
	diagnostics.Append(serviceDiags...)

	httpPort := jsonInt64(endpoint["custom_http_port"], 0)
	httpsPort := jsonInt64(endpoint["custom_https_port"], 0)
	if ports, ok := endpoint["custom_port"].(map[string]any); ok {
		httpPort = jsonInt64(ports["http"], httpPort)
		httpsPort = jsonInt64(ports["https"], httpsPort)
	}
	if httpPort == 0 {
		httpPort = prior.HTTPPort.ValueInt64()
	}
	if httpsPort == 0 {
		httpsPort = prior.HTTPSPort.ValueInt64()
	}

	cnames := []string{}
	if application.CNAME != "" {
		cnames = append(cnames, application.CNAME)
	}
	for _, info := range createdDomains {
		if info.DNS != "" && !contains(cnames, info.DNS) {
			cnames = append(cnames, info.DNS)
		}
	}
	cnameValue, cnameDiags := types.ListValueFrom(ctx, types.StringType, cnames)
	diagnostics.Append(cnameDiags...)
	if diagnostics.HasError() {
		return
	}

	updated := prior
	updated.EPID = types.StringValue(application.EPID)
	updated.LegacyAppName = types.StringNull()
	updated.AppName = types.StringValue(application.AppName)
	updated.DomainName = types.StringValue(application.DomainName)
	updated.ExtraDomains = extraValue
	updated.Services = serviceValue
	updated.HTTPPort = types.Int64Value(httpPort)
	updated.HTTPSPort = types.Int64Value(httpsPort)
	updated.CertificateMode = certificateMode
	updated.Platform = types.StringValue(application.Platform)
	updated.CDN = types.BoolValue(application.CDNStatus == 1)
	updated.BlockMode = types.BoolValue(application.BlockMode == 1)
	updated.CNAMEs = cnameValue
	updated.PlacementRegion = types.StringValue(application.PlatformRegion)
	updated.AttachedTemplateID = nullableStringValue(application.TemplateID)
	updated.AttachedTemplateName = nullableStringValue(application.TemplateName)
	if application.CDNStatus == 0 {
		updated.Region = types.StringValue(application.PlatformRegion)
		updated.GlobalCDN = types.BoolValue(false)
		updated.Continent = types.StringNull()
	}
	diagnostics.Append(state.Set(ctx, &updated)...)
}

func (r *appResource) waitForApplication(ctx context.Context, epID string, present bool) (client.Application, error) {
	var lastErr error
	for attempt := 0; attempt < r.pollAttempts; attempt++ {
		application, err := r.service.FindApplicationByEPID(ctx, epID)
		if present && err == nil {
			return application, nil
		}
		if !present {
			exists, checkErr := r.service.ApplicationExists(ctx, epID)
			if checkErr == nil && !exists {
				return client.Application{}, nil
			}
			lastErr = checkErr
		} else {
			lastErr = err
		}
		if attempt+1 < r.pollAttempts && r.pollDelay > 0 {
			timer := time.NewTimer(r.pollDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return client.Application{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timed out waiting for application %q", epID)
	}
	return client.Application{}, lastErr
}

func (r *appResource) ready(diagnostics *diag.Diagnostics) bool {
	if r.service == nil {
		diagnostics.AddError("Application client is not configured", "Configure the provider before managing an application.")
		return false
	}
	return true
}

func decodeInitialOrigin(ctx context.Context, value types.Object, diagnostics *diag.Diagnostics) (initialOriginModel, bool) {
	if value.IsNull() || value.IsUnknown() {
		diagnostics.AddAttributeError(path.Root("initial_origin"), "Missing initial origin", "initial_origin must be known during application creation.")
		return initialOriginModel{}, false
	}
	var model initialOriginModel
	diagnostics.Append(value.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	return model, !diagnostics.HasError()
}

func stringList(ctx context.Context, value types.List, diagnostics *diag.Diagnostics) []string {
	if value.IsNull() || value.IsUnknown() {
		return []string{}
	}
	var result []string
	diagnostics.Append(value.ElementsAs(ctx, &result, false)...)
	return result
}

func stringSet(ctx context.Context, value types.Set, diagnostics *diag.Diagnostics) []string {
	if value.IsNull() || value.IsUnknown() {
		return []string{}
	}
	var result []string
	diagnostics.Append(value.ElementsAs(ctx, &result, false)...)
	sort.Strings(result)
	return result
}

func prepareEndpointUpdate(document map[string]any, plan resourceModel, ctx context.Context, diagnostics *diag.Diagnostics) {
	document["extra_domains"] = stringList(ctx, plan.ExtraDomains, diagnostics)
	services := stringSet(ctx, plan.Services, diagnostics)
	document["http_status"] = boolInt(contains(services, "http"))
	document["https_status"] = boolInt(contains(services, "https"))
	document["custom_http_port"] = plan.HTTPPort.ValueInt64()
	document["custom_https_port"] = plan.HTTPSPort.ValueInt64()
	delete(document, "custom_port")
	if certType := certificateTypePointer(plan.CertificateMode); certType != nil {
		document["cert_type"] = *certType
	}
}

func placementChanged(a, b resourceModel) bool {
	return a.CDN.ValueBool() != b.CDN.ValueBool() || a.GlobalCDN.ValueBool() != b.GlobalCDN.ValueBool() || a.Region.ValueString() != b.Region.ValueString() || a.Continent.ValueString() != b.Continent.ValueString()
}

func endpointChanged(a, b resourceModel) bool {
	return !a.ExtraDomains.Equal(b.ExtraDomains) || !a.Services.Equal(b.Services) || a.HTTPPort.ValueInt64() != b.HTTPPort.ValueInt64() || a.HTTPSPort.ValueInt64() != b.HTTPSPort.ValueInt64() || certificateModeChanged(a.CertificateMode, b.CertificateMode)
}

func certificateModeChanged(prior, plan types.String) bool {
	if plan.IsNull() || plan.IsUnknown() {
		return false
	}
	return prior.IsNull() || prior.IsUnknown() || !prior.Equal(plan)
}

func certificateTypePointer(mode types.String) *int {
	if mode.IsNull() || mode.IsUnknown() {
		return nil
	}
	value := certificateTypeAutomatic
	if mode.ValueString() == certificateModeCustom {
		value = certificateTypeCustom
	}
	return &value
}

func certificateModeFromEndpoint(document map[string]any) (types.String, error) {
	value, exists := document["cert_type"]
	if !exists || value == nil {
		return types.StringNull(), fmt.Errorf("application endpoint response omitted required cert_type")
	}
	var certType int64
	switch value := value.(type) {
	case float64:
		if value != certificateTypeAutomatic && value != certificateTypeCustom {
			return types.StringNull(), fmt.Errorf("application endpoint returned unsupported cert_type %v", value)
		}
		certType = int64(value)
	case int:
		certType = int64(value)
	case int64:
		certType = value
	case json.Number:
		parsed, err := value.Int64()
		if err != nil {
			return types.StringNull(), fmt.Errorf("application endpoint returned invalid cert_type %q", value)
		}
		certType = parsed
	default:
		return types.StringNull(), fmt.Errorf("application endpoint returned non-numeric cert_type %T", value)
	}
	switch certType {
	case certificateTypeAutomatic:
		return types.StringValue(certificateModeAutomatic), nil
	case certificateTypeCustom:
		return types.StringValue(certificateModeCustom), nil
	default:
		return types.StringNull(), fmt.Errorf("application endpoint returned unsupported cert_type %d", certType)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func anyStringSlice(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func jsonBool(value any) bool {
	switch value := value.(type) {
	case bool:
		return value
	case float64:
		return value != 0
	case int:
		return value != 0
	}
	return false
}

func jsonInt64(value any, fallback int64) int64 {
	switch value := value.(type) {
	case float64:
		return int64(value)
	case int:
		return int64(value)
	case int64:
		return value
	}
	return fallback
}

func nullableStringValue(value string) types.String {
	if strings.TrimSpace(value) == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}
