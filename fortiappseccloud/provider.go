package fortiappseccloud

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-fortiappseccloud/fortiappseccloud/waf"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"hostname": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The cloud-waf api domain",
			},
			"username": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
				Default:     "",
			},
			"password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
				Default:     "",
			},
			"api_token": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "You must specify api_token field or username and password fields",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"fortiappseccloud_waf_app":                waf.ResourceApp(),
			"fortiappseccloud_waf_openapi_validation": waf.ResourceOpenApiValidation(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {

	// Init client config with the values from TF files
	config := waf.Config{}
	if host, ok := d.GetOk("hostname"); ok {
		config.HostName = host.(string)
	} else {
		log.Printf("[ERROR] hostname must be specified ")
		return nil, fmt.Errorf("hostname is not configed")
	}
	token, ok := d.GetOk("api_token")
	if ok && token.(string) == "" || !ok {
		username, _ := d.GetOk("username")
		pass, _ := d.GetOk("password")
		if username.(string) == "" || pass.(string) == "" {
			return nil, fmt.Errorf("username or password is not configed")
		}
		config.UserName = username.(string)
		config.PassWord = pass.(string)

	} else {
		config.Token = token.(string)
	}

	return config.CreateClient()
}
