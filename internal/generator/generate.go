package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"terraform-provider-fortiappseccloud/internal/contract"
	profile "terraform-provider-fortiappseccloud/internal/generator/profile/waf"
)

const (
	manifestOutputPath = "internal/generator/manifest/waf_modules.generated.json"
	registerOutputPath = "internal/resources/generated/waf/register.go"
)

// resourceOutputPath returns the per-resource generated Go path.
// module strips the leading "waf_" from TypeNameSuffix (waf_csrf_protection ->
// csrf_protection), so the path becomes internal/resources/generated/waf/resource_<module>.go.
func resourceOutputPath(typeNameSuffix string) string {
	module := strings.TrimPrefix(typeNameSuffix, "waf_")
	return "internal/resources/generated/waf/resource_" + module + ".go"
}

// docsOutputPath returns the per-resource docs markdown path.
func docsOutputPath(typeNameSuffix string) string {
	return "website/docs/r/" + typeNameSuffix + ".html.markdown"
}

func templateDocsOutputPath(typeNameSuffix string) string {
	return "website/docs/r/waf_template_" + strings.TrimPrefix(typeNameSuffix, "waf_") + ".html.markdown"
}

// Generate renders the complete selected generator output set in memory. It
// never writes files or accesses the network.
func Generate(openAPIJSON, overridesJSON []byte) (map[string][]byte, error) {
	manifest, err := BuildManifest(openAPIJSON, overridesJSON)
	if err != nil {
		return nil, err
	}
	return renderOutputs(manifest)
}

// BuildManifest validates the pinned source and reviewed policy and constructs
// a deterministic normalized representation.
func BuildManifest(openAPIJSON, overridesJSON []byte) (Manifest, error) {
	overrides, err := profile.DecodeOverrides(overridesJSON)
	if err != nil {
		return Manifest{}, err
	}
	normalizeOverrides(&overrides)
	parsed, err := parsePinnedOpenAPI(openAPIJSON)
	if err != nil {
		return Manifest{}, err
	}
	classifications, err := contract.ClassifyPublicWAF(parsed.inventory)
	if err != nil {
		return Manifest{}, fmt.Errorf("classify public WAF operations: %w", err)
	}
	publicCount, nonPublicCount := operationVisibilityCounts(parsed.inventory)
	if len(classifications) != publicCount {
		return Manifest{}, fmt.Errorf("classified %d public WAF operations, want %d", len(classifications), publicCount)
	}

	resources := make([]ResourceIR, 0, len(overrides.Resources))
	contracts := make([]contract.ReviewedCandidate, 0, len(overrides.Resources))
	for _, reviewed := range overrides.Resources {
		resourceContract, ok := contract.FindImplementedGeneratedResource(reviewed.TerraformName)
		if !ok {
			return Manifest{}, fmt.Errorf("reviewed resource %q has no implemented generated-resource contract", reviewed.TerraformName)
		}
		if reviewed.GoName != resourceContract.GoName || reviewed.TypeNameSuffix != resourceContract.TypeNameSuffix ||
			reviewed.OperationName != resourceContract.OperationName || reviewed.GetPath != resourceContract.Path ||
			reviewed.PutPath != resourceContract.Path {
			return Manifest{}, fmt.Errorf("reviewed resource %q metadata does not match its generated-resource contract", reviewed.TerraformName)
		}
		source, wireSchema, err := parsed.resourceSource(resourceContract)
		if err != nil {
			return Manifest{}, err
		}
		wireSchema.Required = true
		if err := injectBackendAdditions(&wireSchema, reviewed, resourceContract); err != nil {
			return Manifest{}, fmt.Errorf("resource %q: %w", reviewed.TerraformName, err)
		}
		if err := injectBackendConfigScalarConstraints(&wireSchema, reviewed, resourceContract); err != nil {
			return Manifest{}, fmt.Errorf("resource %q: %w", reviewed.TerraformName, err)
		}
		if err := validatePolicyCoverage(wireSchema, reviewed); err != nil {
			return Manifest{}, fmt.Errorf("resource %q: %w", reviewed.TerraformName, err)
		}
		if err := validateDestroyPolicySchema(wireSchema, reviewed.Destroy); err != nil {
			return Manifest{}, fmt.Errorf("resource %q: %w", reviewed.TerraformName, err)
		}
		if err := validateDestroyPolicySchema(wireSchema, reviewed.TemplateDestroy); err != nil {
			return Manifest{}, fmt.Errorf("template resource for %q: %w", reviewed.TerraformName, err)
		}
		resources = append(resources, ResourceIR{
			TerraformName: reviewed.TerraformName,
			GoName:        reviewed.GoName,
			Disposition:   reviewed.Mode,
			Source:        source,
			WireSchema:    wireSchema,
			Reviewed:      reviewed,
		})
		contracts = append(contracts, resourceContract)
	}
	if err := validateGeneratedResources(classifications, contracts); err != nil {
		return Manifest{}, err
	}

	return Manifest{
		Generated: generatedMarker,
		OpenAPI: OpenAPISource{
			Path:    "openapi_spec/openapi.json",
			Version: contract.BaselineVersion,
			SHA256:  contract.BaselineSHA256,
		},
		Scope: Scope{
			Classification:          "complete_public_waf_operation_matrix",
			FullWAFClassification:   true,
			PublicOperationCount:    publicCount,
			NonPublicOperationCount: nonPublicCount,
			SelectedResourceCount:   len(resources),
			Operations:              classifications,
		},
		Resources: resources,
	}, nil
}

func validateDestroyPolicySchema(root SchemaIR, policy profile.DestroyPolicy) error {
	if policy.Mode != "disable" && len(policy.CoupledFields) != 0 {
		return fmt.Errorf("only disable destroy policies may declare coupled fields")
	}
	if policy.Field == "" {
		if policy.Mode == "disable" {
			return fmt.Errorf("disable destroy policy must declare a field")
		}
		return nil
	}
	if policy.Field != "status" {
		return fmt.Errorf("destroy field must be configs.status")
	}
	var configs *SchemaIR
	for index := range root.Fields {
		if root.Fields[index].Name == "configs" {
			configs = &root.Fields[index]
			break
		}
	}
	if configs == nil || configs.Kind != "object" {
		return fmt.Errorf("destroy candidate requires a configs object")
	}
	if err := validateDestroyBooleanPath(*configs, policy.Field); err != nil {
		return err
	}
	seen := map[string]struct{}{policy.Field: {}}
	for _, field := range policy.CoupledFields {
		if _, duplicate := seen[field]; duplicate {
			return fmt.Errorf("destroy policy repeats configs.%s", field)
		}
		seen[field] = struct{}{}
		if err := validateDestroyBooleanPath(*configs, field); err != nil {
			return err
		}
	}
	return nil
}

func validateDestroyBooleanPath(configs SchemaIR, path string) error {
	parts := strings.Split(path, ".")
	current := configs
	for index, part := range parts {
		if part == "" {
			return fmt.Errorf("destroy field path configs.%s is invalid", path)
		}
		var found *SchemaIR
		for fieldIndex := range current.Fields {
			if current.Fields[fieldIndex].Name == part {
				found = &current.Fields[fieldIndex]
				break
			}
		}
		if found == nil {
			return fmt.Errorf("destroy candidate configs.%s is absent from the PUT schema", path)
		}
		if index < len(parts)-1 {
			if found.Kind != "object" {
				return fmt.Errorf("destroy candidate configs.%s traverses a non-object field", strings.Join(parts[:index+1], "."))
			}
			current = *found
			continue
		}
		if found.Kind != "boolean" {
			return fmt.Errorf("destroy candidate configs.%s must be boolean", path)
		}
		if found.ReadOnly != nil && *found.ReadOnly {
			return fmt.Errorf("destroy candidate configs.%s must be writable", path)
		}
	}
	return nil
}

func operationVisibilityCounts(document contract.Document) (int, int) {
	publicCount := 0
	for _, operation := range document.Operations {
		if operation.Public {
			publicCount++
		}
	}
	return publicCount, len(document.Operations) - publicCount
}

func validateGeneratedResources(
	classifications []contract.OperationClassification,
	resources []contract.ReviewedCandidate,
) error {
	if len(resources) == 0 {
		return fmt.Errorf("no implemented generated resources were selected")
	}
	type expectedOperation struct {
		resource     contract.ReviewedCandidate
		owner        string
		clientMethod string
	}
	expected := make(map[string]expectedOperation)
	for _, resource := range resources {
		if resource.ImplementationState != contract.ImplementationStateImplemented {
			return fmt.Errorf("generated resource %q is not implemented", resource.TerraformName)
		}
		if len(resource.ExpectedMethods) == 0 {
			return fmt.Errorf("generated resource %q has no expected methods", resource.TerraformName)
		}
		for _, method := range resource.ExpectedMethods {
			key := method + "\x00" + resource.Path
			if _, duplicate := expected[key]; duplicate {
				return fmt.Errorf("generated resource %q repeats expected method %s", resource.TerraformName, method)
			}
			clientMethod := "PutWAFModule"
			if method == "GET" {
				clientMethod = "GetWAFModule"
			}
			expected[key] = expectedOperation{resource: resource, owner: resource.TerraformName, clientMethod: clientMethod}

			const appPrefix = "/waf/apps/{ep_id}/"
			if !strings.HasPrefix(resource.Path, appPrefix) {
				return fmt.Errorf("generated resource %q path is not app-scoped", resource.TerraformName)
			}
			templatePath := "/waf/template/{template_id}/" + strings.TrimPrefix(resource.Path, appPrefix)
			templateKey := method + "\x00" + templatePath
			if _, duplicate := expected[templateKey]; duplicate {
				return fmt.Errorf("generated resource %q repeats expected template method %s", resource.TerraformName, method)
			}
			templateClientMethod := "PutWAFTemplateModule"
			if method == "GET" {
				templateClientMethod = "GetWAFTemplateModule"
			}
			expected[templateKey] = expectedOperation{
				resource:     resource,
				owner:        "fortiappseccloud_waf_template_" + strings.TrimPrefix(resource.TypeNameSuffix, "waf_"),
				clientMethod: templateClientMethod,
			}
		}
	}

	seen := make(map[string]struct{}, len(expected))
	for _, classification := range classifications {
		if classification.Coverage == contract.CoverageSelectedNext {
			return fmt.Errorf("public WAF matrix still contains selected-next operation %s %s", classification.Method, classification.Path)
		}
		key := classification.Method + "\x00" + classification.Path
		expectedOperation, ok := expected[key]
		if !ok {
			continue
		}
		if classification.Mode != contract.ModeGenerated || !contract.IsImplementedCoverage(classification.Coverage) ||
			classification.Owner != expectedOperation.owner {
			return fmt.Errorf("implemented generated-resource classification mismatch for %s %s", classification.Method, classification.Path)
		}
		if classification.ClientMethod != expectedOperation.clientMethod {
			return fmt.Errorf("implemented generated-resource client method for %s %s = %q, want %q", classification.Method, classification.Path, classification.ClientMethod, expectedOperation.clientMethod)
		}
		seen[key] = struct{}{}
	}
	if len(seen) != len(expected) {
		missing := make([]string, 0)
		for key := range expected {
			if _, ok := seen[key]; !ok {
				missing = append(missing, key)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("implemented generated-resource classifications are missing %v", missing)
	}
	return nil
}

func normalizeOverrides(overrides *profile.Overrides) {
	sort.Slice(overrides.Resources, func(i, j int) bool {
		return overrides.Resources[i].TerraformName < overrides.Resources[j].TerraformName
	})
	for index := range overrides.Resources {
		resource := &overrides.Resources[index]
		sort.Slice(resource.Fields, func(i, j int) bool {
			return resource.Fields[i].Path < resource.Fields[j].Path
		})
		sort.Slice(resource.Collections, func(i, j int) bool {
			return resource.Collections[i].Path < resource.Collections[j].Path
		})
		sort.Slice(resource.BackendFieldAdditions, func(i, j int) bool {
			return resource.BackendFieldAdditions[i].Path < resource.BackendFieldAdditions[j].Path
		})
		for additionIndex := range resource.BackendFieldAdditions {
			sort.Strings(resource.BackendFieldAdditions[additionIndex].Enum)
		}
		// Sort the reviewed backend config-scalar constraint enrichments by
		// path so semantically identical policy lists in any order produce
		// byte-identical generated output (the slice is serialized into the
		// manifest), matching the path-keyed determinism of the other slices.
		sort.Slice(resource.BackendConfigScalarConstraints, func(i, j int) bool {
			return resource.BackendConfigScalarConstraints[i].Path < resource.BackendConfigScalarConstraints[j].Path
		})
	}
}

func validatePolicyCoverage(root SchemaIR, reviewed profile.ResourceOverride) error {
	sourceLeaves := make(map[string]struct{})
	for _, field := range root.Fields {
		collectSchemaLeaves(field, "", sourceLeaves)
	}
	// A nested array-of-objects item field (e.g. rule_list.item.sub_rule_list)
	// is an item FIELD with its own FieldPolicy (ownership), so its path is a
	// policy leaf even though collectSchemaLeaves only emits its sub-item
	// scalar leaves. Add the array path for every object-item array nested
	// inside an item (parent path contains ".item"). Walk the top-level fields
	// (configs/template) so the leaf paths start at "configs", not the PUT
	// schema name.
	for _, field := range root.Fields {
		collectNestedSubItemArrayLeaves(field, "", sourceLeaves)
	}

	// Scalar-string-array collections (e.g. allow_methods) produce a single
	// string-item leaf "configs.<array>.item" that is reviewed by the
	// ScalarStringArrays policy rather than a per-leaf field policy. Remove
	// those leaves so coverage accounting only expects field policies for the
	// remaining scalar and object-item leaves.
	for _, array := range reviewed.ScalarStringArrays {
		delete(sourceLeaves, array.Path+".item")
	}
	// Item-level scalar-string-array fields (e.g. known_bots
	// bad_bots_list.item.allow_list) produce a single string-item leaf
	// "configs.<collection>.item.<array>.item" that is reviewed by the
	// ItemStringArrays policy rather than a per-leaf field policy. Remove those
	// leaves for the same reason.
	for _, array := range reviewed.ItemStringArrays {
		delete(sourceLeaves, array.Path+".item")
	}

	policyLeaves := make(map[string]struct{})
	// Build a set of collection and scalar-string-array paths so Fields that
	// are actually collection/scalar-string-array ownership wrappers are not
	// double-counted as policy leaves (they're reviewed by their own policies).
	collectionPaths := make(map[string]struct{})
	for _, coll := range reviewed.Collections {
		collectionPaths[coll.Path] = struct{}{}
	}
	scalarStringArrayPaths := make(map[string]struct{})
	for _, array := range reviewed.ScalarStringArrays {
		scalarStringArrayPaths[array.Path] = struct{}{}
	}
	for _, field := range reviewed.Fields {
		if field.Path == "ep_id" {
			continue
		}
		if field.WireOnly {
			delete(sourceLeaves, field.Path)
			continue
		}
		// Skip Fields that are collection or scalar-string-array ownership
		// wrappers — they're reviewed by their own policies, not per-leaf.
		if _, isColl := collectionPaths[field.Path]; isColl {
			delete(sourceLeaves, field.Path)
			delete(sourceLeaves, field.Path+".item")
			continue
		}
		if _, isSSA := scalarStringArrayPaths[field.Path]; isSSA {
			delete(sourceLeaves, field.Path+".item")
			continue
		}
		policyLeaves[field.Path] = struct{}{}
	}
	// Item-level scalar-string-array fields are item fields with their own
	// ItemStringArrays policy (ownership), so their paths are policy leaves.
	for _, array := range reviewed.ItemStringArrays {
		policyLeaves[array.Path] = struct{}{}
	}
	// Collections (configs-level and nested-object) are reviewed by their own
	// CollectionPolicy, not a per-leaf FieldPolicy. Remove their source leaves
	// (which are item-level field leaves under the collection path).
	for _, coll := range reviewed.Collections {
		delete(sourceLeaves, coll.Path)
		delete(sourceLeaves, coll.Path+".item")
	}
	// Configs-level scalar-string-arrays (including those nested inside
	// config objects like cache.allow_file_type) are reviewed by their own
	// ScalarStringArrays policy, not by Fields. Their source leaves are
	// already removed above. Do NOT add them to policyLeaves.
	missing := difference(sourceLeaves, policyLeaves)
	extra := difference(policyLeaves, sourceLeaves)
	if len(missing) != 0 || len(extra) != 0 {
		return fmt.Errorf("reviewed field policy does not cover the selected schema graph (missing=%v extra=%v)", missing, extra)
	}
	return nil
}

// collectNestedSubItemArrayLeaves adds a leaf for every object-item array that
// is nested inside a collection item (parent path contains ".item"). Such a
// nested array is an item field with its own FieldPolicy (ownership), distinct
// from a top-level configs collection (which is reviewed by a CollectionPolicy
// and must not produce a field-policy leaf).
func collectNestedSubItemArrayLeaves(schema SchemaIR, prefix string, leaves map[string]struct{}) {
	path := schema.Name
	if prefix != "" && path != "" {
		path = prefix + "." + path
	} else if prefix != "" {
		path = prefix
	}
	switch schema.Kind {
	case "object":
		for _, field := range schema.Fields {
			collectNestedSubItemArrayLeaves(field, path, leaves)
		}
	case "array":
		// A nested array-of-objects inside a collection item is an item field
		// with its own FieldPolicy (ownership); add it as a policy leaf. A
		// nested array-of-strings inside a collection item is an item-level
		// scalar-string-array field with its own ItemStringArrays policy; add
		// it as a policy leaf too.
		if schema.Items != nil && (schema.Items.Kind == "object" || schema.Items.Kind == "string") && strings.Contains(path, ".item") {
			if path != "" {
				leaves[path] = struct{}{}
			}
		}
		if schema.Items != nil {
			item := *schema.Items
			item.Name = "item"
			collectNestedSubItemArrayLeaves(item, path, leaves)
		}
	}
}

func collectSchemaLeaves(schema SchemaIR, prefix string, leaves map[string]struct{}) {
	path := schema.Name
	if prefix != "" && path != "" {
		path = prefix + "." + path
	} else if prefix != "" {
		path = prefix
	}
	switch schema.Kind {
	case "object":
		for _, field := range schema.Fields {
			if field.Name == "idx" {
				continue // wire-only, never a Terraform field
			}
			collectSchemaLeaves(field, path, leaves)
		}
	case "array":
		if schema.Items != nil {
			item := *schema.Items
			item.Name = "item"
			collectSchemaLeaves(item, path, leaves)
		}
	default:
		if path != "" {
			leaves[path] = struct{}{}
		}
	}
}

func difference(left, right map[string]struct{}) []string {
	result := make([]string, 0)
	for key := range left {
		if _, ok := right[key]; !ok {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

// injectBackendAdditions injects reviewed backend field additions into the
// pure OpenAPI wire schema. The pure OpenAPI schema is never mutated on disk
// (the pinned bytes/checksum stay unchanged); only the in-memory SchemaIR
// used for manifest rendering and code generation is enriched.
//
// The injection is generic and path-driven. Each addition path must resolve to
// a collection item scalar field of the form "configs.<collection>.item.<field>".
// It rejects unsupported path shapes, collisions with existing pure OpenAPI
// fields, duplicates, unsupported kinds, missing provenance, and any mismatch
// with the reviewed backend-enriched item field contract pinned in the
// resource contract. Injection runs strictly after the pure OpenAPI resource
// schema validation and before policy coverage, so the pure OpenAPI contract
// stays unchanged while the reviewed policy must cover every injected leaf.
func injectBackendAdditions(root *SchemaIR, reviewed profile.ResourceOverride, resourceContract contract.ReviewedCandidate) error {
	if len(reviewed.BackendFieldAdditions) == 0 {
		if len(resourceContract.Schema.BackendEnrichedItemFields) != 0 {
			return fmt.Errorf("resource contract pins %d backend-enriched item fields but the reviewed policy has none", len(resourceContract.Schema.BackendEnrichedItemFields))
		}
		return nil
	}
	if len(resourceContract.Schema.BackendEnrichedItemFields) != len(reviewed.BackendFieldAdditions) {
		return fmt.Errorf("reviewed backend additions count = %d, contract count = %d", len(reviewed.BackendFieldAdditions), len(resourceContract.Schema.BackendEnrichedItemFields))
	}
	contractByPath := make(map[string]contract.CandidateFieldConstraint, len(resourceContract.Schema.BackendEnrichedItemFields))
	for _, expected := range resourceContract.Schema.BackendEnrichedItemFields {
		contractByPath[expected.Name] = expected
	}
	seenPaths := make(map[string]struct{}, len(reviewed.BackendFieldAdditions))
	for _, addition := range reviewed.BackendFieldAdditions {
		if strings.TrimSpace(addition.Path) == "" {
			return fmt.Errorf("backend field addition has an empty path")
		}
		if strings.TrimSpace(addition.Provenance) == "" {
			return fmt.Errorf("backend field addition %q is missing provenance", addition.Path)
		}
		if _, duplicate := seenPaths[addition.Path]; duplicate {
			return fmt.Errorf("duplicate backend field addition %q", addition.Path)
		}
		seenPaths[addition.Path] = struct{}{}
		collection, itemField, ok := splitCollectionItemPath(addition.Path)
		if !ok {
			return fmt.Errorf("backend field addition %q is not a configs.<collection>.item.<field> path", addition.Path)
		}
		if addition.Kind != "string" && addition.Kind != "boolean" {
			return fmt.Errorf("backend field addition %q kind %q is unsupported (only string/boolean scalar item fields)", addition.Path, addition.Kind)
		}
		configs, err := findConfigsSchemaPtr(root)
		if err != nil {
			return fmt.Errorf("backend field addition %q: %w", addition.Path, err)
		}
		collectionField, err := findConfigsCollectionPtr(configs, collection)
		if err != nil {
			return fmt.Errorf("backend field addition %q: %w", addition.Path, err)
		}
		if collectionField.Items == nil || collectionField.Items.Kind != "object" {
			return fmt.Errorf("backend field addition %q targets a non-object collection item", addition.Path)
		}
		if existingField, exists := findItemFieldByName(collectionField.Items.Fields, itemField); exists {
			return fmt.Errorf("backend field addition %q collides with existing pure OpenAPI item field %q", addition.Path, existingField.Name)
		}
		expected, ok := contractByPath[itemField]
		if !ok {
			return fmt.Errorf("backend field addition %q field %q is not part of the reviewed backend-enriched item field contract", addition.Path, itemField)
		}
		if err := validateBackendAdditionContract(addition, expected); err != nil {
			return fmt.Errorf("backend field addition %q: %w", addition.Path, err)
		}
		injected := SchemaIR{
			Name:              itemField,
			Kind:              addition.Kind,
			Required:          addition.Required,
			BackendEnriched:   true,
			BackendProvenance: addition.Provenance,
		}
		switch addition.Kind {
		case "string":
			if addition.MaxLength > 0 {
				maxLength := addition.MaxLength
				injected.MaxLength = &maxLength
			}
			if addition.Pattern != "" {
				injected.Pattern = addition.Pattern
			}
			if len(addition.Enum) > 0 {
				injected.Enum = stringEnumAnyValues(addition.Enum)
			}
		}
		collectionField.Items.Fields = append(collectionField.Items.Fields, injected)
		sort.SliceStable(collectionField.Items.Fields, func(i, j int) bool {
			return collectionField.Items.Fields[i].Name < collectionField.Items.Fields[j].Name
		})
	}
	return nil
}

// splitCollectionItemPath parses a "configs.<collection>.item.<field>" path
// and returns the collection name and item field name. It rejects path shapes
// that are not reviewed collection item scalar leaves.
func splitCollectionItemPath(path string) (collection, itemField string, ok bool) {
	parts := strings.Split(path, ".")
	if len(parts) != 4 || parts[0] != "configs" || parts[2] != "item" {
		return "", "", false
	}
	collection = parts[1]
	itemField = parts[3]
	if collection == "" || itemField == "" {
		return "", "", false
	}
	return collection, itemField, true
}

// findConfigsSchemaPtr returns a pointer to the configs object field within
// root so callers can mutate it in place.
func findConfigsSchemaPtr(root *SchemaIR) (*SchemaIR, error) {
	for index := range root.Fields {
		if root.Fields[index].Name == "configs" && root.Fields[index].Kind == "object" {
			return &root.Fields[index], nil
		}
	}
	return nil, fmt.Errorf("PUT schema is missing the configs object")
}

// injectBackendConfigScalarConstraints applies reviewed integer config-scalar
// numeric bounds (minimum/maximum) that the pinned OpenAPI omits but the
// a separately reviewed external contract enforces. The pinned OpenAPI bytes and
// checksum stay unchanged; only the in-memory SchemaIR used for code
// generation and manifest rendering is enriched.
//
// The injection is path-driven and provenance-backed, mirroring
// injectBackendAdditions but scoped to integer config-scalar numeric facets.
// Each profile entry path must resolve to a configs integer scalar field of
// the form "configs.<field>". It rejects unsupported path shapes, fields that
// are not integer config scalars, collisions with a pure OpenAPI bound (the
// facet is already present), duplicates, missing provenance, profile entries
// without a matching contract marker, contract markers without a matching
// profile entry (exact ledger/marker match), and any mismatch between the
// profile bound and the contract's pinned effective value. Injection runs
// strictly after the pure OpenAPI resource schema validation (which already
// authorized the contract bound vs OpenAPI absence via the marker) and before
// policy coverage, so the pure OpenAPI contract stays unchanged while the
// reviewed policy must cover the enriched field and the generated schema
// emits the reviewed range validator.
func injectBackendConfigScalarConstraints(root *SchemaIR, reviewed profile.ResourceOverride, resourceContract contract.ReviewedCandidate) error {
	contractMarkers := resourceContract.Schema.BackendEnrichedConfigScalarConstraints
	if len(reviewed.BackendConfigScalarConstraints) == 0 && len(contractMarkers) == 0 {
		return nil
	}
	if len(reviewed.BackendConfigScalarConstraints) != len(contractMarkers) {
		return fmt.Errorf("reviewed backend config scalar constraints count = %d, contract marker count = %d", len(reviewed.BackendConfigScalarConstraints), len(contractMarkers))
	}
	configs, err := findConfigsSchemaPtr(root)
	if err != nil {
		return fmt.Errorf("backend config scalar constraints: %w", err)
	}
	// Index the contract config fields by name so the pinned effective bound
	// can be cross-checked against the profile-applied value.
	contractFields := make(map[string]contract.CandidateFieldConstraint, len(resourceContract.Schema.ConfigFields))
	for _, f := range resourceContract.Schema.ConfigFields {
		contractFields[f.Name] = f
	}
	consumedMarkers := make(map[string]struct{}, len(contractMarkers))
	seenPaths := make(map[string]struct{}, len(reviewed.BackendConfigScalarConstraints))
	for _, constraint := range reviewed.BackendConfigScalarConstraints {
		if strings.TrimSpace(constraint.Path) == "" {
			return fmt.Errorf("backend config scalar constraint has an empty path")
		}
		if strings.TrimSpace(constraint.Provenance) == "" {
			return fmt.Errorf("backend config scalar constraint %q is missing provenance", constraint.Path)
		}
		if _, duplicate := seenPaths[constraint.Path]; duplicate {
			return fmt.Errorf("duplicate backend config scalar constraint %q", constraint.Path)
		}
		seenPaths[constraint.Path] = struct{}{}
		fieldName, ok := splitConfigsScalarPath(constraint.Path)
		if !ok {
			return fmt.Errorf("backend config scalar constraint %q is not a configs.<field> path", constraint.Path)
		}
		marker, markerOK := contractMarkers[fieldName]
		if !markerOK {
			return fmt.Errorf("backend config scalar constraint %q has no matching reviewed contract marker", constraint.Path)
		}
		consumedMarkers[fieldName] = struct{}{}
		contractField, contractFieldOK := contractFields[fieldName]
		if !contractFieldOK {
			return fmt.Errorf("backend config scalar constraint %q targets a field not in the reviewed config scalar contract", constraint.Path)
		}
		if contractField.Kind != "integer" {
			return fmt.Errorf("backend config scalar constraint %q targets a non-integer config scalar (kind %q)", constraint.Path, contractField.Kind)
		}
		field, ok := findConfigsScalarPtr(configs, fieldName)
		if !ok {
			return fmt.Errorf("backend config scalar constraint %q targets a missing configs scalar field", constraint.Path)
		}
		if field.Kind != "integer" {
			return fmt.Errorf("backend config scalar constraint %q targets configs.%s kind %q, want integer", constraint.Path, fieldName, field.Kind)
		}
		// Apply each facet independently. A profile facet must match the
		// contract marker and the contract's pinned effective value, and must
		// not collide with a pure OpenAPI bound.
		if constraint.Minimum != nil {
			if !marker.Minimum {
				return fmt.Errorf("backend config scalar constraint %q pins a minimum the contract does not mark enriched", constraint.Path)
			}
			if field.Minimum != nil {
				return fmt.Errorf("backend config scalar constraint %q minimum collides with a pinned OpenAPI minimum", constraint.Path)
			}
			if contractField.Minimum == nil || *contractField.Minimum != float64(*constraint.Minimum) {
				return fmt.Errorf("backend config scalar constraint %q minimum does not match the reviewed contract value", constraint.Path)
			}
			minimum := float64(*constraint.Minimum)
			field.Minimum = &minimum
		} else if marker.Minimum {
			return fmt.Errorf("backend config scalar constraint %q contract marks minimum enriched but the profile pins none", constraint.Path)
		}
		if constraint.Maximum != nil {
			if !marker.Maximum {
				return fmt.Errorf("backend config scalar constraint %q pins a maximum the contract does not mark enriched", constraint.Path)
			}
			if field.Maximum != nil {
				return fmt.Errorf("backend config scalar constraint %q maximum collides with a pinned OpenAPI maximum", constraint.Path)
			}
			if contractField.Maximum == nil || *contractField.Maximum != float64(*constraint.Maximum) {
				return fmt.Errorf("backend config scalar constraint %q maximum does not match the reviewed contract value", constraint.Path)
			}
			maximum := float64(*constraint.Maximum)
			field.Maximum = &maximum
		} else if marker.Maximum {
			return fmt.Errorf("backend config scalar constraint %q contract marks maximum enriched but the profile pins none", constraint.Path)
		}
		if constraint.Minimum == nil && constraint.Maximum == nil {
			return fmt.Errorf("backend config scalar constraint %q pins neither minimum nor maximum", constraint.Path)
		}
		// Mark the field backend-enriched so the manifest records the
		// enrichment provenance. The bound values are already applied above.
		field.BackendEnriched = true
		field.BackendProvenance = constraint.Provenance
	}
	if len(consumedMarkers) != len(contractMarkers) {
		return fmt.Errorf("reviewed backend config scalar constraints did not consume every contract marker: consumed %d of %d", len(consumedMarkers), len(contractMarkers))
	}
	return nil
}

// splitConfigsScalarPath parses a "configs.<field>" path and returns the
// config-scalar field name. It rejects path shapes that are not reviewed
// config-scalar leaves.
func splitConfigsScalarPath(path string) (field string, ok bool) {
	parts := strings.Split(path, ".")
	if len(parts) != 2 || parts[0] != "configs" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// findConfigsScalarPtr returns a pointer to the named scalar field within the
// configs object so callers can mutate it in place.
func findConfigsScalarPtr(configs *SchemaIR, name string) (*SchemaIR, bool) {
	for index := range configs.Fields {
		if configs.Fields[index].Name == name {
			return &configs.Fields[index], true
		}
	}
	return nil, false
}

// findConfigsCollectionPtr returns a pointer to the named array collection
// within configs so callers can mutate it in place.
func findConfigsCollectionPtr(configs *SchemaIR, name string) (*SchemaIR, error) {
	for index := range configs.Fields {
		if configs.Fields[index].Name == name && configs.Fields[index].Kind == "array" {
			return &configs.Fields[index], nil
		}
	}
	return nil, fmt.Errorf("configs collection %q is missing", name)
}

func findItemFieldByName(fields []SchemaIR, name string) (SchemaIR, bool) {
	for _, field := range fields {
		if field.Name == name {
			return field, true
		}
	}
	return SchemaIR{}, false
}

// validateBackendAdditionContract enforces that a reviewed backend addition
// matches the reviewed backend-enriched item field contract pinned in the
// resource contract. The contract is the source of truth for kind/required/
// enum/max-length/pattern; the reviewed policy must agree exactly.
func validateBackendAdditionContract(addition profile.BackendFieldAddition, expected contract.CandidateFieldConstraint) error {
	if addition.Kind != expected.Kind {
		return fmt.Errorf("kind = %q, want %q", addition.Kind, expected.Kind)
	}
	if addition.Required != expected.Required {
		return fmt.Errorf("required = %v, want %v", addition.Required, expected.Required)
	}
	if expected.HasDefault {
		return fmt.Errorf("backend-enriched field defaults are unsupported")
	}
	if !sortedStringsEqual(addition.Enum, expected.Enum) {
		return fmt.Errorf("enum = %v, want %v", addition.Enum, expected.Enum)
	}
	if addition.MaxLength != expected.MaxLength {
		return fmt.Errorf("max_length = %d, want %d", addition.MaxLength, expected.MaxLength)
	}
	if addition.Pattern != expected.Pattern {
		return fmt.Errorf("pattern = %q, want %q", addition.Pattern, expected.Pattern)
	}
	return nil
}

func sortedStringsEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gotCopy := append([]string(nil), got...)
	wantCopy := append([]string(nil), want...)
	sort.Strings(gotCopy)
	sort.Strings(wantCopy)
	for i := range gotCopy {
		if gotCopy[i] != wantCopy[i] {
			return false
		}
	}
	return true
}

// stringEnumAnyValues converts a string slice to a sorted, duplicate-free
// []any enum value list matching the normalized SchemaIR.Enum shape produced
// by the OpenAPI resolver (see normalizeEnumValues). Reviewed backend-enriched
// enums carry no duplicates today, but deduping keeps the invariant uniform
// across source and enriched enums.
func stringEnumAnyValues(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, _ := json.Marshal(out[i])
		right, _ := json.Marshal(out[j])
		return bytes.Compare(left, right) < 0
	})
	result := make([]any, 0, len(out))
	var last []byte
	for _, value := range out {
		canonical, _ := json.Marshal(value)
		if last != nil && bytes.Equal(last, canonical) {
			continue
		}
		result = append(result, value)
		last = canonical
	}
	return result
}
