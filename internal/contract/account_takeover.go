package contract

// AccountTakeoverScope classifies the first managed Framework WAF module.
var AccountTakeoverScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/account_takeover",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_account_takeover",
		ClientMethod: "GetAccountTakeover",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/account_takeover",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_account_takeover",
		ClientMethod: "PutAccountTakeover",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/account_takeover",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_account_takeover",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/account_takeover",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_account_takeover",
		ClientMethod: "PutWAFTemplateModule",
	},
}
