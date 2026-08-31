package contract

// DataSourceContract is the reviewed public read boundary for one served
// Framework data source.
type DataSourceContract struct {
	TerraformName      string
	PublicPath         string
	ClientMethod       string
	ResponseSchema     string
	Identity           string
	StateProjection    string
	LocalLifecycleTest string
	DocumentationFile  string
	ExampleFile        string
}

var reviewedDataSourceContracts = []DataSourceContract{
	{
		TerraformName:      "fortiappseccloud_waf_modules",
		PublicPath:         "/waf/apps/{ep_id}/modules",
		ClientMethod:       "GetApplicationModules",
		ResponseSchema:     "array[ApplicationModuleStatus]",
		Identity:           "ep_id",
		StateProjection:    "ID-sorted list of exact id/status/optional-inherited objects; strict enum, duplicate, type, null, and unknown-field rejection",
		LocalLifecycleTest: "TestTerraformCLIApplicationModulesDataSource",
		DocumentationFile:  "website/docs/d/waf_modules.html.markdown",
		ExampleFile:        "examples/waf/modules.tf",
	},
	{
		TerraformName:      "fortiappseccloud_waf_signature_exception",
		PublicPath:         "/waf/apps/{ep_id}/signature_exception",
		ClientMethod:       "GetSignatureException",
		ResponseSchema:     "GetSignatureException",
		Identity:           "ep_id:signature_id",
		StateProjection:    "optional template ID only; the public GET does not return or reconstruct the exception rules accepted by PUT",
		LocalLifecycleTest: "TestTerraformCLISignatureExceptionDataSource",
		DocumentationFile:  "website/docs/d/waf_signature_exception.html.markdown",
		ExampleFile:        "examples/waf/signature_exception.tf",
	},
}

// ReviewedDataSourceContracts returns a copy of the reviewed contracts.
func ReviewedDataSourceContracts() []DataSourceContract {
	result := make([]DataSourceContract, len(reviewedDataSourceContracts))
	copy(result, reviewedDataSourceContracts)
	return result
}
