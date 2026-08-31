package contract

// XMLProtectionPolicyScope classifies the app-level XML protection policy
// resource and manages the corresponding template operations.
var XMLProtectionPolicyScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/xml_protection_policy",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_xml_protection_policy",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/xml_protection_policy",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_xml_protection_policy",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/xml_protection_policy",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_xml_protection_policy",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/xml_protection_policy",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_xml_protection_policy",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// XMLProtectionPolicyResource records the implemented twenty-second generated
// resource. It reuses the JSON-protection shape: a required status boolean
// (default false), a required action string enum (default alert_deny), two
// optional bucket and prefix strings, and one ordered object-item array
// (file_list, max 10) whose items reference XMLFile. XMLFile pins the
// wire-only positional idx (default 1), required name string (max 32),
// required url string, required limit_check/entity_check/schema_valid booleans
// (all default false), required filename string (max 58), and optional md5
// string. XMLFile differs from JsonFile only in the additional required
// entity_check boolean and the pinned filename 58-character maximum.
var XMLProtectionPolicyResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_xml_protection_policy",
	GoName:              "XMLProtectionPolicy",
	TypeNameSuffix:      "waf_xml_protection_policy",
	OperationName:       "XML protection policy",
	Path:                "/waf/apps/{ep_id}/xml_protection_policy",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetXMLProtection",
		PutRequest:     "#/components/schemas/PutXMLProtection",
		Configs:        "#/components/schemas/XMLProtection",
		CollectionItem: "#/components/schemas/XMLFile",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "bucket", Kind: "string", Required: false, HasDefault: false},
			{Name: "prefix", Kind: "string", Required: false, HasDefault: false},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "file_list", MaxItems: 10},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "entity_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "filename", Kind: "string", Required: true, HasDefault: false, MaxLength: 58},
			{Name: "limit_check", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "md5", Kind: "string", Required: false, HasDefault: false},
			{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 32},
			{Name: "schema_valid", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "url", Kind: "string", Required: true, HasDefault: false},
		},
	},
	Provenance: "Implemented as the twenty-second reviewed generated app-module resource and the XML-protection shape, reusing the JSON-protection structure: " +
		"a required status boolean (default false), a required action string enum (default alert_deny), two optional bucket and prefix strings, " +
		"and one ordered object-item collection (file_list, max 10) whose XMLFile item pins the wire-only positional idx (default 1), " +
		"required name string (max 32), required url string, required limit_check/entity_check/schema_valid booleans (all default false), " +
		"required filename string (max 58), and optional md5 string. " +
		"XMLFile differs from JsonFile only in the additional required entity_check boolean and the pinned filename 58-character maximum. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action enum, every config default, the entity_check/limit_check/schema_valid defaults, the file_list 10-item bound, the name 32-character and filename 58-character maximums, and the idx default are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}
