package contract

// URLAccessScope classifies the app- and template-level URL access resources.
var URLAccessScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/url_access",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_url_access",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/url_access",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_url_access",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/url_access",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_url_access",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/url_access",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_url_access",
		ClientMethod: "PutWAFTemplateModule",
	},
}
