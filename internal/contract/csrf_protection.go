package contract

// CSRFProtectionScope classifies the app- and template-level CSRF protection
// resources.
var CSRFProtectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/csrf_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_csrf_protection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/csrf_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_csrf_protection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/csrf_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_csrf_protection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/csrf_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_csrf_protection",
		ClientMethod: "PutWAFTemplateModule",
	},
}
