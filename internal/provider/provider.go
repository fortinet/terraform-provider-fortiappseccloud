package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/datasources/applicationmodules"
	"terraform-provider-fortiappseccloud/internal/datasources/signatureexception"
	"terraform-provider-fortiappseccloud/internal/locking"
	"terraform-provider-fortiappseccloud/internal/providerconfig"
	"terraform-provider-fortiappseccloud/internal/resources/accounttakeover"
	"terraform-provider-fortiappseccloud/internal/resources/anomalydetection"
	"terraform-provider-fortiappseccloud/internal/resources/app"
	"terraform-provider-fortiappseccloud/internal/resources/contentsrouting"
	"terraform-provider-fortiappseccloud/internal/resources/corsprotection"
	"terraform-provider-fortiappseccloud/internal/resources/customrule"
	generatedwaf "terraform-provider-fortiappseccloud/internal/resources/generated/waf"
	"terraform-provider-fortiappseccloud/internal/resources/globaltrustlist"
	"terraform-provider-fortiappseccloud/internal/resources/ipprotection"
	"terraform-provider-fortiappseccloud/internal/resources/mlapiprotection"
	"terraform-provider-fortiappseccloud/internal/resources/openapivalidation"
	"terraform-provider-fortiappseccloud/internal/resources/originservers"
	"terraform-provider-fortiappseccloud/internal/resources/template"
	"terraform-provider-fortiappseccloud/internal/resources/templateattachment"
)

var _ frameworkprovider.Provider = (*fortiAppSecCloudProvider)(nil)

type clientFactory func(context.Context, client.Config) (*client.Client, error)

type fortiAppSecCloudProvider struct {
	version   string
	commit    string
	locks     *locking.Registry
	newClient clientFactory
}

type providerModel struct {
	Hostname       types.String `tfsdk:"hostname"`
	APIToken       types.String `tfsdk:"api_token"`
	Username       types.String `tfsdk:"username"`
	Password       types.String `tfsdk:"password"`
	Insecure       types.Bool   `tfsdk:"insecure"`
	CACertFile     types.String `tfsdk:"cacert_file"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}

// New returns a Framework provider factory suitable for protocol-5 serving.
func New(version, commit string) func() frameworkprovider.Provider {
	return func() frameworkprovider.Provider {
		return &fortiAppSecCloudProvider{
			version:   version,
			commit:    commit,
			locks:     locking.NewRegistry(),
			newClient: client.New,
		}
	}
}

func (p *fortiAppSecCloudProvider) Metadata(_ context.Context, _ frameworkprovider.MetadataRequest, resp *frameworkprovider.MetadataResponse) {
	resp.TypeName = "fortiappseccloud"
	resp.Version = p.version
}

func (p *fortiAppSecCloudProvider) Schema(_ context.Context, _ frameworkprovider.SchemaRequest, resp *frameworkprovider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"hostname": schema.StringAttribute{
				Optional:    true,
				Description: providerconfig.HostnameDescription,
			},
			"username": schema.StringAttribute{
				Optional:    true,
				Description: providerconfig.UsernameDescription,
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: providerconfig.PasswordDescription,
			},
			"api_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: providerconfig.APITokenDescription,
			},
			"insecure":        schema.BoolAttribute{Optional: true, Description: providerconfig.InsecureDescription},
			"cacert_file":     schema.StringAttribute{Optional: true, Description: providerconfig.CACertFileDescription},
			"timeout_seconds": schema.Int64Attribute{Optional: true, Description: providerconfig.TimeoutSecondsDescription, Validators: []validator.Int64{int64validator.Between(1, 3600)}},
		},
	}
}

func (p *fortiAppSecCloudProvider) Configure(ctx context.Context, req frameworkprovider.ConfigureRequest, resp *frameworkprovider.ConfigureResponse) {
	var data providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input, ok := frameworkProviderInput(data, resp)
	if !ok {
		return
	}
	resolved, err := providerconfig.ResolveOS(input)
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}

	timeoutSeconds := int64(60)
	if !data.TimeoutSeconds.IsNull() {
		timeoutSeconds = data.TimeoutSeconds.ValueInt64()
	}
	apiClient, err := p.newClient(ctx, client.Config{
		BaseURL:    resolved.Hostname,
		APIToken:   resolved.APIToken,
		Username:   resolved.Username,
		Password:   resolved.Password,
		Insecure:   data.Insecure.ValueBool(),
		CACertFile: data.CACertFile.ValueString(),
		Timeout:    time.Duration(timeoutSeconds) * time.Second,
		UserAgent:  fmt.Sprintf("terraform-provider-fortiappseccloud/%s (%s)", p.version, p.commit),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure FortiAppSec Cloud client", err.Error())
		return
	}
	resp.ResourceData = apiClient
	resp.DataSourceData = apiClient
}

func (p *fortiAppSecCloudProvider) Resources(_ context.Context) []func() resource.Resource {
	resources := []func() resource.Resource{
		func() resource.Resource { return accounttakeover.NewResource(p.locks) },
		func() resource.Resource { return accounttakeover.NewTemplateResource(p.locks) },
		func() resource.Resource { return anomalydetection.NewResource(p.locks) },
		func() resource.Resource { return anomalydetection.NewTemplateResource(p.locks) },
		func() resource.Resource { return app.NewResource(p.locks) },
		func() resource.Resource { return customrule.NewResource(p.locks) },
		func() resource.Resource { return customrule.NewTemplateResource(p.locks) },
		func() resource.Resource { return contentsrouting.NewResource(p.locks) },
		func() resource.Resource { return corsprotection.NewResource(p.locks) },
		func() resource.Resource { return corsprotection.NewTemplateResource(p.locks) },
		func() resource.Resource { return globaltrustlist.NewResource(p.locks) },
		func() resource.Resource { return ipprotection.NewResource(p.locks) },
		func() resource.Resource { return ipprotection.NewTemplateResource(p.locks) },
		func() resource.Resource { return mlapiprotection.NewResource(p.locks) },
		func() resource.Resource { return mlapiprotection.NewTemplateResource(p.locks) },
		func() resource.Resource { return openapivalidation.NewResource(p.locks) },
		func() resource.Resource { return originservers.NewResource(p.locks) },
		func() resource.Resource { return template.NewResource(p.locks) },
		func() resource.Resource { return templateattachment.NewResource(p.locks) },
	}
	return append(resources, generatedwaf.Resources(p.locks)...)
}

func (p *fortiAppSecCloudProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		applicationmodules.NewDataSource,
		signatureexception.NewDataSource,
	}
}

func frameworkProviderInput(data providerModel, resp *frameworkprovider.ConfigureResponse) (providerconfig.Input, bool) {
	if data.Insecure.IsUnknown() || data.CACertFile.IsUnknown() || data.TimeoutSeconds.IsUnknown() {
		resp.Diagnostics.AddError("Unknown provider configuration", "insecure, cacert_file, and timeout_seconds must be known while configuring the provider.")
	}
	if !data.Insecure.IsNull() && data.Insecure.ValueBool() && !data.CACertFile.IsNull() && data.CACertFile.ValueString() != "" {
		resp.Diagnostics.AddError("Invalid provider configuration", "insecure and cacert_file cannot be configured together.")
	}
	values := []struct {
		name  string
		value types.String
		set   func(providerconfig.Value)
	}{
		{name: "hostname", value: data.Hostname},
		{name: "api_token", value: data.APIToken},
		{name: "username", value: data.Username},
		{name: "password", value: data.Password},
	}

	input := providerconfig.Input{}
	values[0].set = func(value providerconfig.Value) { input.Hostname = value }
	values[1].set = func(value providerconfig.Value) { input.APIToken = value }
	values[2].set = func(value providerconfig.Value) { input.Username = value }
	values[3].set = func(value providerconfig.Value) { input.Password = value }

	for _, item := range values {
		if item.value.IsUnknown() {
			resp.Diagnostics.AddError("Unknown provider configuration", fmt.Sprintf("%s must be known while configuring the provider.", item.name))
			continue
		}
		if item.value.IsNull() {
			item.set(providerconfig.Value{})
			continue
		}
		item.set(providerconfig.Value{Set: true, Value: item.value.ValueString()})
	}
	return input, !resp.Diagnostics.HasError()
}
