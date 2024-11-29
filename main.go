package main

import (
	"terraform-provider-fortiappseccloud/fortiappseccloud"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: fortiappseccloud.Provider})
}
