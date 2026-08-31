package fortiappseccloud

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fortiappseccloud/fortiappseccloud/waf"
	"terraform-provider-fortiappseccloud/internal/providerconfig"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: providerconfig.HostnameDescription,
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: providerconfig.UsernameDescription,
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: providerconfig.PasswordDescription,
			},
			"api_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: providerconfig.APITokenDescription,
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"fortiappseccloud_waf_app":                waf.ResourceApp(),
			"fortiappseccloud_waf_openapi_validation": waf.ResourceOpenApiValidation(),
		},

		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(_ context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	resolved, err := providerconfig.ResolveOS(providerconfig.Input{
		Hostname: sdkValue(d, "hostname"),
		APIToken: sdkValue(d, "api_token"),
		Username: sdkValue(d, "username"),
		Password: sdkValue(d, "password"),
	})
	if err != nil {
		return nil, diag.FromErr(err)
	}

	config := waf.Config{
		HostName: resolved.Hostname,
		UserName: resolved.Username,
		PassWord: resolved.Password,
		Token:    resolved.APIToken,
	}
	configured, err := config.CreateClient()
	if err != nil {
		return nil, diag.FromErr(fmt.Errorf("configure legacy FortiAppSec Cloud client: %w", err))
	}
	return configured, nil
}

func sdkValue(d *schema.ResourceData, name string) providerconfig.Value {
	value, ok := d.GetOk(name)
	if !ok {
		return providerconfig.Value{}
	}
	return providerconfig.Value{Set: true, Value: value.(string)}
}
