package contract

// ImplementationState records where a reviewed resource sits in generation.
type ImplementationState string

const (
	ImplementationStateSelectedNotGenerated ImplementationState = "selected_not_generated"
	ImplementationStateImplemented          ImplementationState = "implemented"
)

// ReviewedCandidate records one reviewed generated-resource contract.
type ReviewedCandidate struct {
	TerraformName       string                  `json:"terraform_name"`
	GoName              string                  `json:"go_name"`
	TypeNameSuffix      string                  `json:"type_name_suffix"`
	OperationName       string                  `json:"operation_name"`
	Path                string                  `json:"path"`
	ExpectedMethods     []string                `json:"expected_methods"`
	ImplementationState ImplementationState     `json:"implementation_state"`
	Refs                CandidateSchemaRefs     `json:"schema_refs"`
	Schema              CandidateSchemaContract `json:"schema"`
	Provenance          string                  `json:"provenance"`
}

// CandidateSchemaRefs pins one generated resource's OpenAPI schema graph.
type CandidateSchemaRefs struct {
	GetResponse    string `json:"get_response"`
	PutRequest     string `json:"put_request"`
	Configs        string `json:"configs"`
	CollectionItem string `json:"collection_item"`
}

// CandidateSchemaContract pins exact source constraints that affect the
// generated Terraform schema and request validation.
//
// ItemFields pins only the pure OpenAPI item fields. BackendEnrichedItemFields
// separately pins reviewed backend-enriched item fields that are absent from
// the pinned OpenAPI document but injected by the generator under a reviewed
// provenance. Keeping the two sets separate preserves the pure OpenAPI
// contract: the pinned source schema is never mutated, while the generated
// Terraform schema may carry reviewed backend additions.
type CandidateSchemaContract struct {
	ConfigFields []CandidateFieldConstraint      `json:"config_fields"`
	Collections  []CandidateCollectionConstraint `json:"collections"`
	ItemFields   []CandidateFieldConstraint      `json:"item_fields"`
	// CollectionItemFields pins per-collection item fields keyed by collection
	// name. It is used when a resource has multiple collections with different
	// item schemas. When empty, ItemFields is the shared item schema for every
	// collection. When non-empty, every collection must have an entry and
	// ItemFields is ignored.
	CollectionItemFields      map[string][]CandidateFieldConstraint  `json:"collection_item_fields,omitempty"`
	ScalarStringArrays        []CandidateScalarStringArrayConstraint `json:"scalar_string_arrays,omitempty"`
	BackendEnrichedItemFields []CandidateFieldConstraint             `json:"backend_enriched_item_fields,omitempty"`
	// ComputedOnlyItemFields pins reviewed backend-managed item fields that are
	// decoded from GET into Terraform state (Computed: true) and carried in the
	// PUT WireItem from the fresh GET (PreserveFromGet), but are NEVER read from
	// config/plan/state. They are distinct from BackendEnrichedItemFields
	// (which add writable fields absent from the pinned OpenAPI): computed-only
	// fields ARE in the pinned OpenAPI as optional readOnly strings. The generator
	// rejects computed-only config scalars, nested-object fields, arrays,
	// booleans, and integers until separately reviewed — only optional item
	// string fields are supported today.
	ComputedOnlyItemFields []CandidateComputedOnlyItemFieldConstraint `json:"computed_only_item_fields,omitempty"`
	// BackendEnrichedConfigScalarConstraints pins which integer config-scalar
	// Minimum/Maximum facets are reviewed backend enrichments absent from the
	// pinned OpenAPI but present in a separately reviewed external contract.
	// It is keyed by config-scalar field name. A pinned facet marker authorizes
	// the generator to apply a reviewed profile bound that the pinned OpenAPI
	// omits; the contract still pins the effective value so the reviewed
	// overlay cannot silently change. Mirrors BackendEnrichedItemFields but is
	// scoped to integer config-scalar numeric facets, not item fields.
	BackendEnrichedConfigScalarConstraints map[string]BackendEnrichedNumericFacets `json:"backend_enriched_config_scalar_constraints,omitempty"`
}

// CandidateComputedOnlyItemFieldConstraint pins one reviewed backend-managed
// (computed-only) item field. Path is the full dotted leaf path
// (e.g. "configs.user_list.item.uuid"). ReadOnly records that the backend owns
// the field (it is never practitioner-writable). PreserveFromGet records that
// the fresh GET value must be carried into the replacement PUT (omission could
// clear the backend value). Sensitive records that the value is redacted in
// plan/output (e.g. api_key) — sensitive values are still stored in Terraform
// state. Provenance records why the field is backend-managed.
type CandidateComputedOnlyItemFieldConstraint struct {
	Path            string `json:"path"`
	ReadOnly        bool   `json:"read_only"`
	PreserveFromGet bool   `json:"preserve_from_get"`
	Sensitive       bool   `json:"sensitive"`
	Provenance      string `json:"provenance"`
}

// BackendEnrichedNumericFacets pins which numeric facets of one integer
// config-scalar field are reviewed backend enrichments. Each facet is
// independent: a field may enrich only its maximum, only its minimum, or both.
// A facet marked true authorizes the generator to accept a reviewed profile
// bound that the pinned OpenAPI omits for that facet; the contract's
// CandidateFieldConstraint Minimum/Maximum still pins the effective value.
type BackendEnrichedNumericFacets struct {
	Minimum bool `json:"minimum"`
	Maximum bool `json:"maximum"`
}

// CandidateFieldConstraint records one exact reviewed source field.
type CandidateFieldConstraint struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Required   bool     `json:"required"`
	HasDefault bool     `json:"has_default"`
	Default    any      `json:"default,omitempty"`
	Enum       []string `json:"enum,omitempty"`
	// IntEnum pins a reviewed integer enum (e.g. sensitivity_level 1|2|3|4).
	// It is non-empty only when Kind == "integer" and the source enum is
	// numeric. Rendered as int64validator.OneOf.
	IntEnum   []int64 `json:"int_enum,omitempty"`
	MaxLength int     `json:"max_length,omitempty"`
	// MinLength pins a reviewed minimum string length. OpenAPI 26.3.a pins no
	// minLength on any reviewed field today, so this stays zero; the contract
	// and generator carry the capability so a future minLength is reviewed
	// rather than silently dropped.
	MinLength int      `json:"min_length,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	Minimum   *float64 `json:"minimum,omitempty"`
	Maximum   *float64 `json:"maximum,omitempty"`
	// AllowNull pins that a scalar wire field is explicitly nullable in the
	// pinned OpenAPI (nullable: true). It is non-empty only for Kind == "string"
	// or "boolean". The generated read/decode path treats a null remote value
	// as a stable null in Terraform state instead of a malformed-result error.
	AllowNull bool `json:"allow_null,omitempty"`
	// ReadOnly pins a source-managed field that is returned by GET but is not
	// writable through the module PUT contract.
	ReadOnly bool `json:"read_only,omitempty"`
	// ObjectFields pins the scalar fields of a nested-object item field (one
	// level deep). It is non-empty only when Kind == "object". The nested
	// object is rendered as a SingleNestedBlock inside the item block.
	ObjectFields []CandidateFieldConstraint `json:"object_fields,omitempty"`
	// SubItemArray pins a nested array-of-objects item field (one level deep).
	// It is non-empty only when Kind == "array". The nested array renders as a
	// SingleNestedBlock ownership wrapper containing an `item` ListNestedBlock
	// inside the parent item block, reusing the ownership omission/empty/
	// populated semantics. MaxItems pins the reviewed bound (0 = unbounded).
	SubItemArray *CandidateSubItemArrayConstraint `json:"sub_item_array,omitempty"`
	// StringArray pins an item-level scalar-string-array field (one level deep),
	// e.g. known_bots bad_bots_list.item.allow_list. It is non-empty only when
	// Kind == "string_array". The field renders as a SingleNestedBlock ownership
	// wrapper containing an `item` ListNestedBlock carrying a single synthetic
	// string attribute named by ItemAttribute, reusing the scalar-string-array
	// omission/empty/populated semantics inside the parent item. MaxItems pins
	// the reviewed bound (0 = unbounded). A free-form array has no Enum.
	StringArray *CandidateItemStringArrayConstraint `json:"string_array,omitempty"`
}

// CandidateItemStringArrayConstraint pins an item-level scalar-string-array
// field (one level deep), e.g. known_bots bad_bots_list.item.allow_list. It
// reuses the scalar-string-array ownership semantics inside a collection item.
type CandidateItemStringArrayConstraint struct {
	Name          string   `json:"name"`
	ItemAttribute string   `json:"item_attribute"`
	Enum          []string `json:"enum"`
	MaxItems      int      `json:"max_items"` // 0 = unbounded
	Required      bool     `json:"required"`
	// ItemMaxLength pins the reviewed per-item string UTF-8 maximum length,
	// e.g. rewriting_requests remove_header items (maxLength 63). Zero means
	// the reviewed item string carries no maximum (free-form, e.g. known_bots
	// allow_list/deny_list). Enforced in schema, build/encode, and decode.
	ItemMaxLength int `json:"item_max_length,omitempty"`
}

// CandidateSubItemArrayConstraint pins a nested array-of-objects inside a
// collection item (one level deep), e.g. parameter_validation rule_list.item
// .sub_rule_list or web_socket_security rule_list.item.origin_list.
type CandidateSubItemArrayConstraint struct {
	Name       string                     `json:"name"`
	MaxItems   int                        `json:"max_items"`
	ItemName   string                     `json:"item_name"` // wire item schema name, for provenance only
	ItemFields []CandidateFieldConstraint `json:"item_fields"`
}

// CandidateCollectionConstraint records one exact reviewed collection bound.
type CandidateCollectionConstraint struct {
	Name string `json:"name"`
	// MaxItems pins the reviewed item bound. A zero MaxItems means the reviewed
	// collection is unbounded by the source schema (no maxItems/Length(max=) in
	// the pinned OpenAPI), e.g. known_bots bad_bots_list/
	// good_bots_list. Bounded collections pin the reviewed positive bound.
	MaxItems int `json:"max_items"`
	// Unindexed pins that the collection's item schema has no positional idx
	// field. An unindexed collection sends items in Terraform order with no idx,
	// decodes the remote array in order without idx validation/sort, and treats
	// item identity as the whole object. Indexed collections (the default) carry
	// a wire-only idx with default 1.
	Unindexed bool `json:"unindexed,omitempty"`
}

// CandidateScalarStringArrayConstraint records one exact reviewed configs
// field that is an array of bare enum strings (no object item schema, no
// positional idx). It is encoded as an ownership wrapper of item blocks
// carrying a single synthetic string attribute named by ItemAttribute. A
// zero MaxItems means the reviewed array is unbounded by the source schema.
type CandidateScalarStringArrayConstraint struct {
	Name          string   `json:"name"`
	ItemAttribute string   `json:"item_attribute"`
	Enum          []string `json:"enum"`
	MaxItems      int      `json:"max_items"`
	// Required pins whether the pinned OpenAPI marks the array required. A
	// required array that Terraform owns must fail closed when the remote key
	// is absent instead of being silently coerced to an empty array.
	Required bool `json:"required"`
}

// CSRFProtectionResource records the first implemented generated resource.
var CSRFProtectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_csrf_protection",
	GoName:              "CSRFProtection",
	TypeNameSuffix:      "waf_csrf_protection",
	OperationName:       "CSRF protection",
	Path:                "/waf/apps/{ep_id}/csrf_protection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetCSRFProtection",
		PutRequest:     "#/components/schemas/PutCSRFProtection",
		Configs:        "#/components/schemas/CSRFProtection",
		CollectionItem: "#/components/schemas/CSRFParameter",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "page_list", MaxItems: 256},
			{Name: "url_list", MaxItems: 256},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "filter", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "name", Kind: "string", MaxLength: 63},
			{Name: "url", Kind: "string", Required: true, MaxLength: 255, Pattern: `^/.*$`},
			{Name: "value", Kind: "string", MaxLength: 255},
		},
	},
	Provenance: "Implemented as the first reviewed generated app-module resource. The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime.",
}

// URLAccessCandidate records the implemented second generated resource. The
// name is retained because the record also preserves the reviewed selection.
var URLAccessCandidate = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_url_access",
	GoName:              "URLAccess",
	TypeNameSuffix:      "waf_url_access",
	OperationName:       "URL access",
	Path:                "/waf/apps/{ep_id}/url_access",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse:    "#/components/schemas/GetUrlAccess",
		PutRequest:     "#/components/schemas/PutUrlAccess",
		Configs:        "#/components/schemas/UrlAccess",
		CollectionItem: "#/components/schemas/UrlAccessRule",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "rule_list", MaxItems: 12},
		},
		ItemFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "pass", Enum: []string{"alert_deny", "continue", "deny_no_log", "pass"}},
			{Name: "name", Kind: "string", Required: true, MaxLength: 39},
			{Name: "url", Kind: "string", Required: true, MaxLength: 255},
			{Name: "url_type", Kind: "string", Required: true, HasDefault: true, Default: "string", Enum: []string{"regex", "string"}},
		},
	},
	Provenance: "Selected as the closest structural neighbor of the first CSRF vertical slice and implemented as the second generated resource: " +
		"the pinned public app GET/PUT operations share the required configs/template envelope, " +
		"the ordered rule_list uses positional idx values, no POST or DELETE exists, and " +
		"the descriptor requires no shared runtime change. Runtime behavior remains locally tested rather than live-verified.",
}

// ImplementedGeneratedResources returns the deterministic reviewed resource set.
func ImplementedGeneratedResources() []ReviewedCandidate {
	resources := []ReviewedCandidate{CSRFProtectionResource, URLAccessCandidate, RequestLimitsResource, KnownAttacksResource, HttpHeaderSecurityResource, GraphQLProtectionResource, JsonProtectionResource, ParameterValidationResource, WebSocketSecurityResource, InformationLeakageResource, DDoSPreventionResource, CookieSecurityResource, KnownBotsResource, BotDeceptionResource, BiometricsBasedDetectionResource, WaitingRoomResource, MITBProtectionResource, ThresholdDetectionResource, MLBotDetectionResource, FileProtectionResource, MobileAPIProtectionResource, XMLProtectionPolicyResource, RewritingRequestsResource, APIGatewayResource, CachingCompressionResource}
	for index := range resources {
		resources[index].ExpectedMethods = append([]string(nil), resources[index].ExpectedMethods...)
		resources[index].Schema.ConfigFields = cloneCandidateFieldConstraints(resources[index].Schema.ConfigFields)
		resources[index].Schema.Collections = append([]CandidateCollectionConstraint(nil), resources[index].Schema.Collections...)
		resources[index].Schema.ItemFields = cloneCandidateFieldConstraints(resources[index].Schema.ItemFields)
		resources[index].Schema.CollectionItemFields = cloneCollectionItemFields(resources[index].Schema.CollectionItemFields)
		resources[index].Schema.ScalarStringArrays = cloneCandidateScalarStringArrays(resources[index].Schema.ScalarStringArrays)
		resources[index].Schema.BackendEnrichedItemFields = cloneCandidateFieldConstraints(resources[index].Schema.BackendEnrichedItemFields)
		resources[index].Schema.ComputedOnlyItemFields = append([]CandidateComputedOnlyItemFieldConstraint(nil), resources[index].Schema.ComputedOnlyItemFields...)
		resources[index].Schema.BackendEnrichedConfigScalarConstraints = cloneBackendEnrichedConfigScalarConstraints(resources[index].Schema.BackendEnrichedConfigScalarConstraints)
	}
	return resources
}

func cloneBackendEnrichedConfigScalarConstraints(constraints map[string]BackendEnrichedNumericFacets) map[string]BackendEnrichedNumericFacets {
	if constraints == nil {
		return nil
	}
	cloned := make(map[string]BackendEnrichedNumericFacets, len(constraints))
	for name, facets := range constraints {
		cloned[name] = facets
	}
	return cloned
}

func cloneCandidateScalarStringArrays(arrays []CandidateScalarStringArrayConstraint) []CandidateScalarStringArrayConstraint {
	cloned := append([]CandidateScalarStringArrayConstraint(nil), arrays...)
	for index := range cloned {
		cloned[index].Enum = append([]string(nil), cloned[index].Enum...)
	}
	return cloned
}

func cloneCollectionItemFields(fields map[string][]CandidateFieldConstraint) map[string][]CandidateFieldConstraint {
	if fields == nil {
		return nil
	}
	cloned := make(map[string][]CandidateFieldConstraint, len(fields))
	for name, itemFields := range fields {
		cloned[name] = cloneCandidateFieldConstraints(itemFields)
	}
	return cloned
}

func cloneCandidateFieldConstraints(fields []CandidateFieldConstraint) []CandidateFieldConstraint {
	cloned := append([]CandidateFieldConstraint(nil), fields...)
	for index := range cloned {
		cloned[index].Enum = append([]string(nil), cloned[index].Enum...)
		cloned[index].IntEnum = append([]int64(nil), cloned[index].IntEnum...)
		cloned[index].ObjectFields = cloneCandidateFieldConstraints(cloned[index].ObjectFields)
		if cloned[index].SubItemArray != nil {
			subArray := *cloned[index].SubItemArray
			subArray.ItemFields = cloneCandidateFieldConstraints(subArray.ItemFields)
			cloned[index].SubItemArray = &subArray
		}
		if cloned[index].StringArray != nil {
			strArray := *cloned[index].StringArray
			strArray.Enum = append([]string(nil), strArray.Enum...)
			cloned[index].StringArray = &strArray
		}
	}
	return cloned
}

// FindImplementedGeneratedResource returns one reviewed generated resource.
func FindImplementedGeneratedResource(terraformName string) (ReviewedCandidate, bool) {
	for _, resource := range ImplementedGeneratedResources() {
		if resource.TerraformName == terraformName {
			return resource, true
		}
	}
	return ReviewedCandidate{}, false
}
