package contract

import "net/http"

// CustomDestroyPolicy records the reviewed Terraform destroy behavior for a
// hand-written custom app-module resource.
type CustomDestroyPolicy string

const (
	CustomDestroyForget  CustomDestroyPolicy = "forget_with_warning"
	CustomDestroyDisable CustomDestroyPolicy = "disable"
)

const (
	customDestroyCandidateReason = "The API has no DELETE operation. configs.status is a structural disable candidate, but this module remains forget-only until its own live GET-PUT-GET lifecycle is verified."
	customDestroyVerifiedReason  = "The API has no DELETE operation. The exact module-specific dev1 GET-preserve-PUT-GET lifecycle verified template=false plus configs.status=false, complete response preservation, and exact restoration in the accepted 2026-07-31 matrix."
	customDestroyNoStatusReason  = "The API has no DELETE operation and this resource does not expose the standard template plus configs.status envelope required by the reviewed disable lifecycle."
)

// CustomResourceContract is the reviewed ownership/lifecycle contract for one
// served hand-written custom app-module resource. Field-level wire facts remain
// in the pinned OpenAPI schemas and focused client/resource tests;
// this record pins the resource boundary connecting those facts to Terraform.
type CustomResourceContract struct {
	Module             string
	TerraformName      string
	PublicPath         string
	GetMethod          string
	PutMethod          string
	GetResponseSchema  string
	PutRequestSchema   string
	Ownership          string
	Identity           string
	ImportFormat       string
	DestroyPolicy      CustomDestroyPolicy
	DestroyField       string
	DestroyVerified    bool
	DestroyReason      string
	LocalLifecycleTest string
	DocumentationFile  string
	ExampleFile        string
}

var reviewedCustomResourceContracts = []CustomResourceContract{
	{
		Module: "global_trust_list_parameter", TerraformName: "fortiappseccloud_waf_global_trust_list_parameter",
		PublicPath: "/waf/apps/{ep_id}/global_trust_list_parameter", GetMethod: http.MethodGet, PutMethod: http.MethodPut,
		GetResponseSchema: "GetGlobalTrust", PutRequestSchema: "PutGlobalTrust",
		Ownership: "status and complete ordered trust_list when its ownership wrapper is present; no template field",
		Identity:  "ep_id", ImportFormat: "ep_id", DestroyPolicy: CustomDestroyForget,
		DestroyReason:      customDestroyNoStatusReason,
		LocalLifecycleTest: "TestTerraformCLIGlobalTrustListLifecycle",
		DocumentationFile:  "website/docs/r/waf_global_trust_list_parameter.html.markdown",
		ExampleFile:        "examples/waf/global_trust_list_parameter.tf",
	},
	{
		Module: "anomaly_detection", TerraformName: "fortiappseccloud_waf_anomaly_detection",
		PublicPath: "/waf/apps/{ep_id}/anomaly_detection", GetMethod: http.MethodGet, PutMethod: http.MethodPut,
		GetResponseSchema: "GetAnomalyDetection", PutRequestSchema: "PutAnomalyDetection",
		Ownership: "template plus status, action, ip_list_type, and complete ordered ip_list when its ownership wrapper is present",
		Identity:  "ep_id", ImportFormat: "ep_id", DestroyPolicy: CustomDestroyDisable,
		DestroyField: "status", DestroyVerified: true, DestroyReason: customDestroyVerifiedReason,
		LocalLifecycleTest: "TestTerraformCLIAnomalyDetectionLifecycle",
		DocumentationFile:  "website/docs/r/waf_anomaly_detection.html.markdown",
		ExampleFile:        "examples/waf/anomaly_detection.tf",
	},
	{
		Module: "cors_protection", TerraformName: "fortiappseccloud_waf_cors_protection",
		PublicPath: "/waf/apps/{ep_id}/cors_protection", GetMethod: http.MethodGet, PutMethod: http.MethodPut,
		GetResponseSchema: "GetCorsProtection", PutRequestSchema: "PutCorsProtection",
		Ownership: "template and the complete reviewed CORS configs object including its four required nested policy objects",
		Identity:  "ep_id", ImportFormat: "ep_id", DestroyPolicy: CustomDestroyDisable,
		DestroyField: "status", DestroyVerified: true, DestroyReason: customDestroyVerifiedReason,
		LocalLifecycleTest: "TestTerraformCLICorsProtectionLifecycle",
		DocumentationFile:  "website/docs/r/waf_cors_protection.html.markdown",
		ExampleFile:        "examples/waf/cors_protection.tf",
	},
	{
		Module: "ip_protection", TerraformName: "fortiappseccloud_waf_ip_protection",
		PublicPath: "/waf/apps/{ep_id}/ip_protection", GetMethod: http.MethodGet, PutMethod: http.MethodPut,
		GetResponseSchema: "GetIPProtection", PutRequestSchema: "PutIPProtection",
		Ownership: "template, status, ip_reputation, optional geo/country fields, and complete ordered ip_list when its ownership wrapper is present",
		Identity:  "ep_id", ImportFormat: "ep_id", DestroyPolicy: CustomDestroyDisable,
		DestroyField: "status", DestroyVerified: true, DestroyReason: customDestroyVerifiedReason,
		LocalLifecycleTest: "TestTerraformCLIIPProtectionLifecycle",
		DocumentationFile:  "website/docs/r/waf_ip_protection.html.markdown",
		ExampleFile:        "examples/waf/ip_protection.tf",
	},
	{
		Module: "routings", TerraformName: "fortiappseccloud_waf_content_routing",
		PublicPath: "/waf/apps/{ep_id}/routings", GetMethod: http.MethodGet, PutMethod: http.MethodPut,
		GetResponseSchema: "GetContentRouting", PutRequestSchema: "PutContentRoutingRequest",
		Ownership: "root status and complete ordered policy_list/rule_list when their ownership wrappers are present; origin pools are references only",
		Identity:  "ep_id", ImportFormat: "ep_id", DestroyPolicy: CustomDestroyForget,
		DestroyReason:      customDestroyNoStatusReason,
		LocalLifecycleTest: "TestTerraformCLIContentRoutingLifecycle",
		DocumentationFile:  "website/docs/r/waf_content_routing.html.markdown",
		ExampleFile:        "examples/waf/content_routing.tf",
	},
	{
		Module: "custom_rule", TerraformName: "fortiappseccloud_waf_custom_rule",
		PublicPath: "/waf/apps/{ep_id}/custom_rule", GetMethod: http.MethodGet, PutMethod: http.MethodPut,
		GetResponseSchema: "GetCustomRule", PutRequestSchema: "PutCustomRule",
		Ownership: "template, status, and complete ordered rule_list/filter_list when their ownership wrappers are present",
		Identity:  "ep_id", ImportFormat: "ep_id", DestroyPolicy: CustomDestroyDisable,
		DestroyField: "status", DestroyVerified: true, DestroyReason: customDestroyVerifiedReason,
		LocalLifecycleTest: "TestTerraformCLICustomRuleLifecycle",
		DocumentationFile:  "website/docs/r/waf_custom_rule.html.markdown",
		ExampleFile:        "examples/waf/custom_rule.tf",
	},
	{
		Module: "ml_api_protection", TerraformName: "fortiappseccloud_waf_ml_api_protection",
		PublicPath: "/waf/apps/{ep_id}/ml_api_protection", GetMethod: http.MethodGet, PutMethod: http.MethodPut,
		GetResponseSchema: "GetMlApiProtection", PutRequestSchema: "PutMlApiProtection",
		Ownership: "template plus main status/threat/IP/path configuration only; refresh, model, report, schema, and download endpoints are excluded",
		Identity:  "ep_id", ImportFormat: "ep_id", DestroyPolicy: CustomDestroyDisable,
		DestroyField: "status", DestroyVerified: true, DestroyReason: customDestroyVerifiedReason,
		LocalLifecycleTest: "TestTerraformCLIMlApiProtectionLifecycle",
		DocumentationFile:  "website/docs/r/waf_ml_api_protection.html.markdown",
		ExampleFile:        "examples/waf/ml_api_protection.tf",
	},
}

// ReviewedCustomResourceContracts returns a copy of the reviewed contracts so
// callers cannot mutate the package-level evidence.
func ReviewedCustomResourceContracts() []CustomResourceContract {
	result := make([]CustomResourceContract, len(reviewedCustomResourceContracts))
	copy(result, reviewedCustomResourceContracts)
	return result
}

// ReviewedCustomResourceContract returns the immutable reviewed lifecycle
// contract for one custom module.
func ReviewedCustomResourceContract(module string) (CustomResourceContract, bool) {
	for _, contract := range reviewedCustomResourceContracts {
		if contract.Module == module {
			return contract, true
		}
	}
	return CustomResourceContract{}, false
}
