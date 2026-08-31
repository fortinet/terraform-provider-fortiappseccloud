package applicationmodules

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
)

var (
	_ datasource.DataSource                   = (*applicationModulesDataSource)(nil)
	_ datasource.DataSourceWithConfigure      = (*applicationModulesDataSource)(nil)
	_ datasource.DataSourceWithValidateConfig = (*applicationModulesDataSource)(nil)
)

var moduleStatusObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"id":        types.StringType,
	"status":    types.StringType,
	"inherited": types.StringType,
}}

type applicationModulesService interface {
	GetApplicationModules(context.Context, string) (client.ApplicationModuleStatuses, error)
}

type applicationModulesDataSource struct {
	service applicationModulesService
}

type dataSourceModel struct {
	EPID    types.String `tfsdk:"ep_id"`
	Modules types.List   `tfsdk:"modules"`
}

// NewDataSource creates the app-scoped bulk module-status data source.
func NewDataSource() datasource.DataSource {
	return &applicationModulesDataSource{}
}

func (d *applicationModulesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_modules"
}

func (d *applicationModulesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the complete app-level FortiAppSec Cloud WAF module status inventory. This data source never changes module configuration.",
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Application endpoint ID whose module statuses are read.",
			},
			"modules": schema.ListAttribute{
				Computed:            true,
				ElementType:         moduleStatusObjectType,
				MarkdownDescription: "Module statuses, sorted by module ID. Each object contains `id`, `status`, and nullable `inherited` string fields. Status values are `enable` or `disable`.",
			},
		},
	}
}

func (d *applicationModulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	apiClient, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T.", req.ProviderData))
		return
	}
	d.service = apiClient
}

func (d *applicationModulesDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config dataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.EPID.IsNull() || config.EPID.IsUnknown() {
		return
	}
	if strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty or whitespace.")
	}
}

func (d *applicationModulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config dataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.service == nil {
		resp.Diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud client is unavailable. Configure the provider before reading WAF modules.")
		return
	}
	if config.EPID.IsNull() || config.EPID.IsUnknown() || strings.TrimSpace(config.EPID.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must be known and non-empty while reading WAF modules.")
		return
	}

	epID := strings.TrimSpace(config.EPID.ValueString())
	statuses, err := d.service.GetApplicationModules(ctx, epID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read WAF modules", err.Error())
		return
	}

	elements := make([]attr.Value, 0, len(statuses))
	for _, status := range statuses {
		inherited := types.StringNull()
		if status.Inherited != nil {
			inherited = types.StringValue(*status.Inherited)
		}
		value, diagnostics := types.ObjectValue(moduleStatusObjectType.AttrTypes, map[string]attr.Value{
			"id":        types.StringValue(status.ID),
			"status":    types.StringValue(status.Status),
			"inherited": inherited,
		})
		resp.Diagnostics.Append(diagnostics...)
		if resp.Diagnostics.HasError() {
			return
		}
		elements = append(elements, value)
	}
	modules, diagnostics := types.ListValue(moduleStatusObjectType, elements)
	resp.Diagnostics.Append(diagnostics...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := dataSourceModel{
		EPID:    types.StringValue(epID),
		Modules: modules,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
