package contract

// Disposition records how a public API operation participates in Terraform.
type Disposition string

const (
	DispositionDataSource        Disposition = "data_source"
	DispositionResourceRead      Disposition = "resource_read"
	DispositionResourceWrite     Disposition = "resource_write"
	DispositionSharedReference   Disposition = "shared_resource_and_reference_read"
	DispositionDeferred          Disposition = "deferred_pending_probe"
	DispositionAction            Disposition = "action"
	DispositionReadOnly          Disposition = "read_only"
	DispositionExplicitExclusion Disposition = "explicit_exclusion"
)

// Classification is the compact compatibility record used by focused scopes.
// OperationClassification carries the complete public inventory metadata.
type Classification struct {
	Method       string
	Path         string
	Disposition  Disposition
	Owner        string
	ClientMethod string
}

// InitialScope covers the read APIs implemented by internal/client in the first slice.
var InitialScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps",
		Disposition:  DispositionDataSource,
		Owner:        "fortiappseccloud_waf_apps",
		ClientMethod: "ListApplications/ListAllApplications/ListApplicationSummaries",
	},
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_app",
		ClientMethod: "GetApplication/FindApplicationByEPID",
	},
	{
		Method:       "GET",
		Path:         "/waf/template",
		Disposition:  DispositionDataSource,
		Owner:        "fortiappseccloud_waf_templates",
		ClientMethod: "ListTemplates",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template, fortiappseccloud_waf_template_attachment",
		ClientMethod: "GetTemplate",
	},
	{
		Method:       "GET",
		Path:         "/waf/settings",
		Disposition:  DispositionSharedReference,
		Owner:        "fortiappseccloud_waf_settings, fortiappseccloud_waf_regions",
		ClientMethod: "GetWAFSettings",
	},
}
