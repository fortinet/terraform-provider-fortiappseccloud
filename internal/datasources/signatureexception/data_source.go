package signatureexception

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
)

var (
	_ datasource.DataSource                   = (*signatureExceptionDataSource)(nil)
	_ datasource.DataSourceWithConfigure      = (*signatureExceptionDataSource)(nil)
	_ datasource.DataSourceWithValidateConfig = (*signatureExceptionDataSource)(nil)
)

type signatureExceptionService interface {
	GetSignatureException(context.Context, string, string) (client.SignatureExceptionView, error)
}

type signatureExceptionDataSource struct {
	service signatureExceptionService
}

type dataSourceModel struct {
	EPID        types.String `tfsdk:"ep_id"`
	SignatureID types.String `tfsdk:"signature_id"`
	TemplateID  types.String `tfsdk:"template_id"`
}

// NewDataSource creates the read-only signature-exception template view.
func NewDataSource() datasource.DataSource {
	return &signatureExceptionDataSource{}
}

func (d *signatureExceptionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_signature_exception"
}

func (d *signatureExceptionDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the limited public signature-exception view for one signature. The API returns only an optional template ID; this data source does not expose or manage exception rules.",
		Attributes: map[string]schema.Attribute{
			"ep_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Application endpoint ID.",
			},
			"signature_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Signature ID to query. The public GET requires this query value but does not declare a length or format constraint.",
			},
			"template_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Template identifier returned for the signature, or null when the optional public response field is absent.",
			},
		},
	}
}

func (d *signatureExceptionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *signatureExceptionDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config dataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validateIdentity(config, func(attribute path.Path, summary, detail string) {
		resp.Diagnostics.AddAttributeError(attribute, summary, detail)
	})
}

func (d *signatureExceptionDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config dataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.service == nil {
		resp.Diagnostics.AddError("Provider not configured", "The FortiAppSec Cloud client is unavailable. Configure the provider before reading a signature exception.")
		return
	}
	if config.EPID.IsNull() || config.EPID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("ep_id"), "Invalid application ID", "ep_id must be known while reading a signature exception.")
	}
	if config.SignatureID.IsNull() || config.SignatureID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("signature_id"), "Invalid signature ID", "signature_id must be known while reading a signature exception.")
	}
	validateIdentity(config, func(attribute path.Path, summary, detail string) {
		resp.Diagnostics.AddAttributeError(attribute, summary, detail)
	})
	if resp.Diagnostics.HasError() {
		return
	}

	epID := strings.TrimSpace(config.EPID.ValueString())
	signatureID := strings.TrimSpace(config.SignatureID.ValueString())
	view, err := d.service.GetSignatureException(ctx, epID, signatureID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read signature exception", err.Error())
		return
	}
	templateID := types.StringNull()
	if view.TemplateID != nil {
		templateID = types.StringValue(*view.TemplateID)
	}
	state := dataSourceModel{
		EPID:        types.StringValue(epID),
		SignatureID: types.StringValue(signatureID),
		TemplateID:  templateID,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func validateIdentity(config dataSourceModel, addError func(path.Path, string, string)) {
	if !config.EPID.IsNull() && !config.EPID.IsUnknown() && strings.TrimSpace(config.EPID.ValueString()) == "" {
		addError(path.Root("ep_id"), "Invalid application ID", "ep_id must not be empty or whitespace.")
	}
	if !config.SignatureID.IsNull() && !config.SignatureID.IsUnknown() && strings.TrimSpace(config.SignatureID.ValueString()) == "" {
		addError(path.Root("signature_id"), "Invalid signature ID", "signature_id must not be empty or whitespace.")
	}
}
