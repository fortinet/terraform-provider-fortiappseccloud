package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	legacyprovider "terraform-provider-fortiappseccloud/fortiappseccloud"
	"terraform-provider-fortiappseccloud/internal/client"
	"terraform-provider-fortiappseccloud/internal/locking"
	"terraform-provider-fortiappseccloud/internal/providerconfig"
)

func TestProviderMetadataSchemaAndResources(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	configured := New("1.2.3", "abc123")()

	var metadataResponse frameworkprovider.MetadataResponse
	configured.Metadata(ctx, frameworkprovider.MetadataRequest{}, &metadataResponse)
	if metadataResponse.TypeName != "fortiappseccloud" || metadataResponse.Version != "1.2.3" {
		t.Fatalf("metadata = %#v", metadataResponse)
	}

	var schemaResponse frameworkprovider.SchemaResponse
	configured.Schema(ctx, frameworkprovider.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema() diagnostics = %v", schemaResponse.Diagnostics)
	}
	legacy := legacyprovider.Provider()
	if len(schemaResponse.Schema.Attributes) != 7 {
		t.Fatalf("Framework attributes = %d, want 7", len(schemaResponse.Schema.Attributes))
	}
	for _, name := range []string{"hostname", "api_token", "username", "password"} {
		frameworkAttribute, ok := schemaResponse.Schema.Attributes[name].(providerschema.StringAttribute)
		if !ok {
			t.Fatalf("Framework attribute %q has type %T", name, schemaResponse.Schema.Attributes[name])
		}
		legacyAttribute := legacy.Schema[name]
		if frameworkAttribute.Optional != legacyAttribute.Optional {
			t.Errorf("%s optional mismatch: Framework %t, legacy %t", name, frameworkAttribute.Optional, legacyAttribute.Optional)
		}
		if frameworkAttribute.Sensitive != legacyAttribute.Sensitive {
			t.Errorf("%s sensitive mismatch: Framework %t, legacy %t", name, frameworkAttribute.Sensitive, legacyAttribute.Sensitive)
		}
		if frameworkAttribute.Description != legacyAttribute.Description {
			t.Errorf("%s description mismatch: Framework %q, legacy %q", name, frameworkAttribute.Description, legacyAttribute.Description)
		}
	}

	resources := configured.Resources(ctx)
	if len(resources) != 69 {
		t.Fatalf("Resources() returned %d resources, want 69", len(resources))
	}
	resourceNames := make(map[string]struct{}, len(resources))
	for _, constructor := range resources {
		var resourceMetadata resource.MetadataResponse
		constructor().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &resourceMetadata)
		if _, duplicate := resourceNames[resourceMetadata.TypeName]; duplicate {
			t.Fatalf("duplicate resource type name %q", resourceMetadata.TypeName)
		}
		resourceNames[resourceMetadata.TypeName] = struct{}{}
	}
	for _, name := range []string{
		"fortiappseccloud_waf_account_takeover",
		"fortiappseccloud_waf_anomaly_detection",
		"fortiappseccloud_waf_app",
		"fortiappseccloud_waf_content_routing",
		"fortiappseccloud_waf_custom_rule",
		"fortiappseccloud_waf_cors_protection",
		"fortiappseccloud_waf_csrf_protection",
		"fortiappseccloud_waf_global_trust_list_parameter",
		"fortiappseccloud_waf_ml_api_protection",
		"fortiappseccloud_waf_ip_protection",
		"fortiappseccloud_waf_openapi_validation",
		"fortiappseccloud_waf_origin_servers",
		"fortiappseccloud_waf_template_attachment",
		"fortiappseccloud_waf_template",
		"fortiappseccloud_waf_template_account_takeover",
		"fortiappseccloud_waf_template_anomaly_detection",
		"fortiappseccloud_waf_template_cors_protection",
		"fortiappseccloud_waf_template_csrf_protection",
		"fortiappseccloud_waf_template_custom_rule",
		"fortiappseccloud_waf_template_ip_protection",
		"fortiappseccloud_waf_template_ml_api_protection",
		"fortiappseccloud_waf_url_access",
	} {
		if _, ok := resourceNames[name]; !ok {
			t.Fatalf("Resources() did not register %q: %#v", name, resourceNames)
		}
	}
	dataSources := configured.DataSources(ctx)
	if len(dataSources) != 2 {
		t.Fatalf("DataSources() returned %d data sources, want 2", len(dataSources))
	}
	dataSourceNames := make(map[string]struct{}, len(dataSources))
	for _, constructor := range dataSources {
		var dataSourceMetadata datasource.MetadataResponse
		constructor().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "fortiappseccloud"}, &dataSourceMetadata)
		if _, duplicate := dataSourceNames[dataSourceMetadata.TypeName]; duplicate {
			t.Fatalf("duplicate data source type name %q", dataSourceMetadata.TypeName)
		}
		dataSourceNames[dataSourceMetadata.TypeName] = struct{}{}
	}
	for _, name := range []string{
		"fortiappseccloud_waf_modules",
		"fortiappseccloud_waf_signature_exception",
	} {
		if _, ok := dataSourceNames[name]; !ok {
			t.Errorf("DataSources() did not register %q: %#v", name, dataSourceNames)
		}
	}
}

func TestProviderConfigureCreatesFrameworkClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var captured client.Config
	apiClient := &client.Client{}
	configured := &fortiAppSecCloudProvider{
		version: "1.2.3",
		commit:  "abc123",
		locks:   locking.NewRegistry(),
		newClient: func(_ context.Context, config client.Config) (*client.Client, error) {
			captured = config
			return apiClient, nil
		},
	}
	var schemaResponse frameworkprovider.SchemaResponse
	configured.Schema(ctx, frameworkprovider.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema() diagnostics = %v", schemaResponse.Diagnostics)
	}
	model := providerModel{
		Hostname:       types.StringValue("https://api.example.test"),
		APIToken:       types.StringValue("test-token"),
		Username:       types.StringNull(),
		Password:       types.StringNull(),
		Insecure:       types.BoolValue(false),
		CACertFile:     types.StringNull(),
		TimeoutSeconds: types.Int64Value(90),
	}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	if diagnostics := state.Set(ctx, &model); diagnostics.HasError() {
		t.Fatalf("State.Set() diagnostics = %v", diagnostics)
	}
	request := frameworkprovider.ConfigureRequest{
		Config: tfsdk.Config{Schema: schemaResponse.Schema, Raw: state.Raw.Copy()},
	}
	var response frameworkprovider.ConfigureResponse
	configured.Configure(ctx, request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("Configure() diagnostics = %v", response.Diagnostics)
	}
	if captured.BaseURL != "https://api.example.test" || captured.APIToken != "test-token" {
		t.Fatalf("client config = %#v", captured)
	}
	if captured.Insecure || captured.CACertFile != "" || captured.Timeout != 90*time.Second {
		t.Fatalf("transport client config = %#v", captured)
	}
	if captured.UserAgent != "terraform-provider-fortiappseccloud/1.2.3 (abc123)" {
		t.Fatalf("UserAgent = %q", captured.UserAgent)
	}
	if response.ResourceData != apiClient || response.DataSourceData != apiClient {
		t.Fatalf("provider data = %#v, %#v", response.ResourceData, response.DataSourceData)
	}
}

func TestFrameworkProviderInput(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		model   providerModel
		want    providerconfig.Input
		wantErr bool
	}{
		"known values": {
			model: providerModel{
				Hostname: types.StringValue("api.example.test"),
				APIToken: types.StringValue("token"),
				Username: types.StringNull(),
				Password: types.StringNull(),
			},
			want: providerconfig.Input{
				Hostname: providerconfig.Value{Set: true, Value: "api.example.test"},
				APIToken: providerconfig.Value{Set: true, Value: "token"},
			},
		},
		"unknown value": {
			model: providerModel{
				Hostname: types.StringNull(),
				APIToken: types.StringUnknown(),
				Username: types.StringNull(),
				Password: types.StringNull(),
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var response frameworkprovider.ConfigureResponse
			input, ok := frameworkProviderInput(test.model, &response)
			if test.wantErr {
				if ok || !response.Diagnostics.HasError() {
					t.Fatalf("frameworkProviderInput() = %#v, %t, diagnostics = %v", input, ok, response.Diagnostics)
				}
				return
			}
			if !ok || response.Diagnostics.HasError() {
				t.Fatalf("frameworkProviderInput() diagnostics = %v", response.Diagnostics)
			}
			if input != test.want {
				t.Fatalf("frameworkProviderInput() = %#v, want %#v", input, test.want)
			}
		})
	}
}
