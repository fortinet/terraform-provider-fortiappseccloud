package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"terraform-provider-fortiappseccloud/internal/contract"
)

type rawOpenAPI struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

type parsedOpenAPI struct {
	inventory contract.Document
	raw       rawOpenAPI
	resolver  *schemaResolver
}

type schemaResolver struct {
	schemas map[string]json.RawMessage
	memo    map[string]SchemaIR
	active  map[string]bool
}

const crossFieldExtensionV1 = "x-fortinet-cross-field-v1"

type rawCrossFieldRuleV1 struct {
	Kind     string                    `json:"kind"`
	Field    string                    `json:"field"`
	Minimum  *int64                    `json:"minimum"`
	Maximum  *int64                    `json:"maximum"`
	Left     string                    `json:"left"`
	Operator string                    `json:"operator"`
	Right    string                    `json:"right"`
	When     *rawCrossFieldConditionV1 `json:"when"`
}

type rawCrossFieldConditionV1 struct {
	Field  string                     `json:"field"`
	Equals *bool                      `json:"equals"`
	AllOf  []rawCrossFieldConditionV1 `json:"all_of"`
}

func parsePinnedOpenAPI(data []byte) (*parsedOpenAPI, error) {
	inventory, err := contract.ParseOpenAPI(data)
	if err != nil {
		return nil, err
	}
	if inventory.Version != contract.BaselineVersion {
		return nil, fmt.Errorf("OpenAPI version mismatch: got %q, want %q", inventory.Version, contract.BaselineVersion)
	}
	if inventory.SHA256 != contract.BaselineSHA256 {
		return nil, fmt.Errorf("OpenAPI checksum mismatch: got %q, want %q", inventory.SHA256, contract.BaselineSHA256)
	}
	var raw rawOpenAPI
	if err := decodeSingleJSON(data, &raw); err != nil {
		return nil, fmt.Errorf("decode pinned OpenAPI generator input: %w", err)
	}
	if raw.Paths == nil || raw.Components.Schemas == nil {
		return nil, fmt.Errorf("pinned OpenAPI generator input is missing paths or components.schemas")
	}
	return &parsedOpenAPI{
		inventory: inventory,
		raw:       raw,
		resolver:  newSchemaResolver(raw.Components.Schemas),
	}, nil
}

func newSchemaResolver(schemas map[string]json.RawMessage) *schemaResolver {
	return &schemaResolver{
		schemas: schemas,
		memo:    make(map[string]SchemaIR),
		active:  make(map[string]bool),
	}
}

func (r *schemaResolver) Resolve(ref string) (SchemaIR, error) {
	name, err := localSchemaName(ref)
	if err != nil {
		return SchemaIR{}, err
	}
	if schema, ok := r.memo[name]; ok {
		return schema, nil
	}
	if r.active[name] {
		return SchemaIR{}, fmt.Errorf("cyclic schema reference %q", ref)
	}
	raw, ok := r.schemas[name]
	if !ok {
		return SchemaIR{}, fmt.Errorf("schema reference %q does not exist", ref)
	}
	r.active[name] = true
	defer delete(r.active, name)

	schema, err := r.resolveRaw(raw, ref)
	if err != nil {
		return SchemaIR{}, fmt.Errorf("resolve schema %q: %w", name, err)
	}
	schema.Name = name
	schema.SourceRef = ref
	r.memo[name] = schema
	return schema, nil
}

func (r *schemaResolver) resolveRaw(data json.RawMessage, location string) (SchemaIR, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return SchemaIR{}, fmt.Errorf("schema at %s must be an object: %w", location, err)
	}
	if refRaw, ok := object["$ref"]; ok {
		if len(object) != 1 {
			return SchemaIR{}, fmt.Errorf("$ref at %s has unsupported sibling keywords", location)
		}
		var ref string
		if err := json.Unmarshal(refRaw, &ref); err != nil || strings.TrimSpace(ref) == "" {
			return SchemaIR{}, fmt.Errorf("$ref at %s must be a non-empty string", location)
		}
		return r.Resolve(ref)
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf", "not"} {
		if _, ok := object[keyword]; ok {
			return SchemaIR{}, fmt.Errorf("unsupported %s at %s", keyword, location)
		}
	}
	nullable := false
	if nullableRaw, ok := object["nullable"]; ok {
		if err := json.Unmarshal(nullableRaw, &nullable); err != nil {
			return SchemaIR{}, fmt.Errorf("nullable at %s must be boolean", location)
		}
	}

	var kind string
	typeRaw, ok := object["type"]
	if !ok || json.Unmarshal(typeRaw, &kind) != nil || kind == "" {
		return SchemaIR{}, fmt.Errorf("schema at %s must have one supported string type", location)
	}
	schema := SchemaIR{Kind: kind, Nullable: nullable}
	if err := decodeOptional(object, "readOnly", &schema.ReadOnly); err != nil {
		return SchemaIR{}, fmt.Errorf("readOnly at %s: %w", location, err)
	}
	if raw, ok := object["default"]; ok {
		if err := decodeAny(raw, &schema.Default); err != nil {
			return SchemaIR{}, fmt.Errorf("default at %s: %w", location, err)
		}
	}
	if raw, ok := object["enum"]; ok {
		if err := decodeSingleJSON(raw, &schema.Enum); err != nil {
			return SchemaIR{}, fmt.Errorf("enum at %s: %w", location, err)
		}
		normalized, err := normalizeEnumValues(schema.Enum)
		if err != nil {
			return SchemaIR{}, fmt.Errorf("enum at %s: %w", location, err)
		}
		schema.Enum = normalized
	}
	if err := decodeOptional(object, "pattern", &schema.Pattern); err != nil {
		return SchemaIR{}, fmt.Errorf("pattern at %s: %w", location, err)
	}
	for keyword, target := range map[string]any{
		"minLength": &schema.MinLength,
		"maxLength": &schema.MaxLength,
		"minimum":   &schema.Minimum,
		"maximum":   &schema.Maximum,
		"minItems":  &schema.MinItems,
		"maxItems":  &schema.MaxItems,
	} {
		if err := decodeOptional(object, keyword, target); err != nil {
			return SchemaIR{}, fmt.Errorf("%s at %s: %w", keyword, location, err)
		}
	}

	switch kind {
	case "object":
		var properties map[string]json.RawMessage
		if raw, ok := object["properties"]; ok {
			if err := decodeSingleJSON(raw, &properties); err != nil {
				return SchemaIR{}, fmt.Errorf("properties at %s: %w", location, err)
			}
		}
		var required []string
		if raw, ok := object["required"]; ok {
			if err := decodeSingleJSON(raw, &required); err != nil {
				return SchemaIR{}, fmt.Errorf("required at %s: %w", location, err)
			}
		}
		requiredSet := make(map[string]struct{}, len(required))
		for _, name := range required {
			if _, duplicate := requiredSet[name]; duplicate {
				return SchemaIR{}, fmt.Errorf("duplicate required property %q at %s", name, location)
			}
			if _, exists := properties[name]; !exists {
				return SchemaIR{}, fmt.Errorf("required property %q at %s is not declared", name, location)
			}
			requiredSet[name] = struct{}{}
		}
		names := make([]string, 0, len(properties))
		for name := range properties {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			field, err := r.resolveRaw(properties[name], location+"/properties/"+escapeJSONPointer(name))
			if err != nil {
				return SchemaIR{}, err
			}
			field.Name = name
			_, field.Required = requiredSet[name]
			schema.Fields = append(schema.Fields, field)
		}
	case "array":
		rawItems, ok := object["items"]
		if !ok {
			return SchemaIR{}, fmt.Errorf("array at %s is missing items", location)
		}
		items, err := r.resolveRaw(rawItems, location+"/items")
		if err != nil {
			return SchemaIR{}, err
		}
		schema.Items = &items
	case "string", "boolean", "integer", "number":
	default:
		return SchemaIR{}, fmt.Errorf("unknown schema type %q at %s", kind, location)
	}
	for key := range object {
		if strings.HasPrefix(key, "x-fortinet-cross-field-") && key != crossFieldExtensionV1 {
			return SchemaIR{}, fmt.Errorf("unsupported cross-field extension %q at %s", key, location)
		}
	}
	if raw, ok := object[crossFieldExtensionV1]; ok {
		if schema.Kind != "object" {
			return SchemaIR{}, fmt.Errorf("%s at %s is supported only on object schemas", crossFieldExtensionV1, location)
		}
		rules, err := decodeCrossFieldRulesV1(raw, schema, location)
		if err != nil {
			return SchemaIR{}, err
		}
		schema.CrossFieldRules = rules
	}
	return schema, nil
}

func decodeCrossFieldRulesV1(raw json.RawMessage, schema SchemaIR, location string) ([]CrossFieldRuleIR, error) {
	var source []rawCrossFieldRuleV1
	if err := decodeStrictJSON(raw, &source); err != nil {
		return nil, fmt.Errorf("decode %s at %s: %w", crossFieldExtensionV1, location, err)
	}
	if len(source) == 0 {
		return nil, fmt.Errorf("%s at %s must be a non-empty array", crossFieldExtensionV1, location)
	}
	fields := make(map[string]SchemaIR, len(schema.Fields))
	for _, field := range schema.Fields {
		fields[field.Name] = field
	}
	rules := make([]CrossFieldRuleIR, 0, len(source))
	seen := make(map[string]struct{}, len(source))
	for index, rule := range source {
		ruleLocation := fmt.Sprintf("%s/%d", location+"/"+crossFieldExtensionV1, index)
		resolved := CrossFieldRuleIR{
			Kind: rule.Kind, Field: rule.Field, Minimum: rule.Minimum, Maximum: rule.Maximum,
			Left: rule.Left, Operator: rule.Operator, Right: rule.Right,
		}
		switch rule.Kind {
		case "conditional_range":
			if rule.Field == "" || rule.Minimum == nil || rule.Maximum == nil || rule.When == nil {
				return nil, fmt.Errorf("conditional_range at %s requires field, minimum, maximum, and when", ruleLocation)
			}
			if rule.Left != "" || rule.Operator != "" || rule.Right != "" {
				return nil, fmt.Errorf("conditional_range at %s contains compare-only fields", ruleLocation)
			}
			field, ok := fields[rule.Field]
			if !ok {
				return nil, fmt.Errorf("conditional_range at %s references unknown field %q", ruleLocation, rule.Field)
			}
			if field.Kind != "integer" {
				return nil, fmt.Errorf("conditional_range field %q at %s must be an integer", rule.Field, ruleLocation)
			}
			if field.Minimum != nil || field.Maximum != nil {
				return nil, fmt.Errorf("conditional_range field %q at %s must not also declare unconditional minimum/maximum", rule.Field, ruleLocation)
			}
			if *rule.Minimum > *rule.Maximum {
				return nil, fmt.Errorf("conditional_range at %s has minimum greater than maximum", ruleLocation)
			}
		case "compare":
			if rule.Left == "" || rule.Operator == "" || rule.Right == "" {
				return nil, fmt.Errorf("compare at %s requires left, operator, and right", ruleLocation)
			}
			if rule.Field != "" || rule.Minimum != nil || rule.Maximum != nil {
				return nil, fmt.Errorf("compare at %s contains conditional_range-only fields", ruleLocation)
			}
			for _, operand := range []struct{ side, name string }{{"left", rule.Left}, {"right", rule.Right}} {
				field, ok := fields[operand.name]
				if !ok {
					return nil, fmt.Errorf("compare at %s references unknown %s field %q", ruleLocation, operand.side, operand.name)
				}
				if field.Kind != "integer" {
					return nil, fmt.Errorf("compare %s field %q at %s must be an integer", operand.side, operand.name, ruleLocation)
				}
			}
			if !slices.Contains([]string{"less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal"}, rule.Operator) {
				return nil, fmt.Errorf("compare at %s has unsupported operator %q", ruleLocation, rule.Operator)
			}
		default:
			return nil, fmt.Errorf("%s at %s has unsupported kind %q", crossFieldExtensionV1, ruleLocation, rule.Kind)
		}
		if rule.When != nil {
			condition, err := validateCrossFieldConditionV1(*rule.When, fields, ruleLocation+"/when")
			if err != nil {
				return nil, err
			}
			resolved.When = &condition
		}
		keyBytes, _ := json.Marshal(resolved)
		key := string(keyBytes)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate %s rule at %s", crossFieldExtensionV1, ruleLocation)
		}
		seen[key] = struct{}{}
		rules = append(rules, resolved)
	}
	return rules, nil
}

func validateCrossFieldConditionV1(source rawCrossFieldConditionV1, fields map[string]SchemaIR, location string) (CrossFieldConditionIR, error) {
	hasLeaf := source.Field != "" || source.Equals != nil
	hasAll := len(source.AllOf) != 0
	if hasLeaf == hasAll {
		return CrossFieldConditionIR{}, fmt.Errorf("condition at %s must contain exactly one boolean equality or one non-empty all_of", location)
	}
	if hasLeaf {
		if source.Field == "" || source.Equals == nil {
			return CrossFieldConditionIR{}, fmt.Errorf("condition at %s requires both field and equals", location)
		}
		field, ok := fields[source.Field]
		if !ok {
			return CrossFieldConditionIR{}, fmt.Errorf("condition at %s references unknown field %q", location, source.Field)
		}
		if field.Kind != "boolean" {
			return CrossFieldConditionIR{}, fmt.Errorf("condition field %q at %s must be boolean", source.Field, location)
		}
		equals := *source.Equals
		return CrossFieldConditionIR{Field: source.Field, Equals: &equals}, nil
	}
	condition := CrossFieldConditionIR{AllOf: make([]CrossFieldConditionIR, 0, len(source.AllOf))}
	for index, child := range source.AllOf {
		resolved, err := validateCrossFieldConditionV1(child, fields, fmt.Sprintf("%s/all_of/%d", location, index))
		if err != nil {
			return CrossFieldConditionIR{}, err
		}
		condition.AllOf = append(condition.AllOf, resolved)
	}
	return condition, nil
}

func (p *parsedOpenAPI) resourceSource(resource contract.ReviewedCandidate) (OperationSource, SchemaIR, error) {
	path := resource.Path
	getInventory, ok := p.inventory.Find("GET", path)
	if !ok || !getInventory.Public {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("public GET %s is missing", path)
	}
	putInventory, ok := p.inventory.Find("PUT", path)
	if !ok || !putInventory.Public {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("public PUT %s is missing", path)
	}
	pathItem, ok := p.raw.Paths[path]
	if !ok {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("OpenAPI path %s is missing", path)
	}
	getRaw, ok := pathItem["get"]
	if !ok {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("GET %s is missing", path)
	}
	putRaw, ok := pathItem["put"]
	if !ok {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("PUT %s is missing", path)
	}
	getRef, err := responseSchemaRef(getRaw, "200")
	if err != nil {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("GET %s: %w", path, err)
	}
	putRef, err := requestSchemaRef(putRaw)
	if err != nil {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("PUT %s: %w", path, err)
	}
	if getRef != resource.Refs.GetResponse || putRef != resource.Refs.PutRequest {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("%s operation refs changed: GET=%q PUT=%q", resource.OperationName, getRef, putRef)
	}
	resultRef, err := p.componentPropertyRef(getRef, "result")
	if err != nil {
		return OperationSource{}, SchemaIR{}, err
	}
	if resultRef != resource.Refs.PutRequest {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("GET result ref = %q, want %q", resultRef, resource.Refs.PutRequest)
	}
	getResult, err := p.resolver.Resolve(resultRef)
	if err != nil {
		return OperationSource{}, SchemaIR{}, err
	}
	putRequest, err := p.resolver.Resolve(putRef)
	if err != nil {
		return OperationSource{}, SchemaIR{}, err
	}
	if !reflect.DeepEqual(getResult, putRequest) {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("GET result and PUT request schemas are not structurally compatible")
	}
	if err := validateGeneratedResourceSchema(putRequest, resource); err != nil {
		return OperationSource{}, SchemaIR{}, fmt.Errorf("%s schema: %w", resource.OperationName, err)
	}
	source := OperationSource{
		GetMethod:      "GET",
		GetPath:        path,
		GetResponseRef: getRef,
		GetResultRef:   resultRef,
		PutMethod:      "PUT",
		PutPath:        path,
		PutRequestRef:  putRef,
	}
	templateSource, err := p.templateResourceSource(resource, source)
	if err != nil {
		return OperationSource{}, SchemaIR{}, err
	}
	return templateSource, putRequest, nil
}

func (p *parsedOpenAPI) templateResourceSource(resource contract.ReviewedCandidate, source OperationSource) (OperationSource, error) {
	const appPrefix = "/waf/apps/{ep_id}/"
	if !strings.HasPrefix(resource.Path, appPrefix) {
		return OperationSource{}, fmt.Errorf("%s app module path does not start with %s", resource.OperationName, appPrefix)
	}
	path := "/waf/template/{template_id}/" + strings.TrimPrefix(resource.Path, appPrefix)
	getInventory, ok := p.inventory.Find("GET", path)
	if !ok || !getInventory.Public {
		return OperationSource{}, fmt.Errorf("public GET %s is missing", path)
	}
	putInventory, ok := p.inventory.Find("PUT", path)
	if !ok || !putInventory.Public {
		return OperationSource{}, fmt.Errorf("public PUT %s is missing", path)
	}
	pathItem, ok := p.raw.Paths[path]
	if !ok {
		return OperationSource{}, fmt.Errorf("OpenAPI path %s is missing", path)
	}
	getRaw, getOK := pathItem["get"]
	putRaw, putOK := pathItem["put"]
	if !getOK || !putOK {
		return OperationSource{}, fmt.Errorf("template module path %s must expose GET and PUT", path)
	}
	getRef, err := responseSchemaRef(getRaw, "200")
	if err != nil {
		return OperationSource{}, fmt.Errorf("GET %s: %w", path, err)
	}
	putRef, err := requestSchemaRef(putRaw)
	if err != nil {
		return OperationSource{}, fmt.Errorf("PUT %s: %w", path, err)
	}
	resultRef, err := p.componentPropertyRef(getRef, "result")
	if err != nil {
		return OperationSource{}, fmt.Errorf("GET %s: %w", path, err)
	}
	if getRef != source.GetResponseRef || resultRef != source.GetResultRef || putRef != source.PutRequestRef {
		return OperationSource{}, fmt.Errorf(
			"%s template module schemas differ from app module schemas: GET=%q result=%q PUT=%q, want GET=%q result=%q PUT=%q",
			resource.OperationName,
			getRef,
			resultRef,
			putRef,
			source.GetResponseRef,
			source.GetResultRef,
			source.PutRequestRef,
		)
	}
	source.TemplateGetMethod = "GET"
	source.TemplateGetPath = path
	source.TemplateGetResponseRef = getRef
	source.TemplateGetResultRef = resultRef
	source.TemplatePutMethod = "PUT"
	source.TemplatePutPath = path
	source.TemplatePutRequestRef = putRef
	return source, nil
}

func (p *parsedOpenAPI) componentPropertyRef(componentRef, property string) (string, error) {
	name, err := localSchemaName(componentRef)
	if err != nil {
		return "", err
	}
	raw, ok := p.raw.Components.Schemas[name]
	if !ok {
		return "", fmt.Errorf("schema %q is missing", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", fmt.Errorf("decode schema %q: %w", name, err)
	}
	var properties map[string]json.RawMessage
	if err := json.Unmarshal(object["properties"], &properties); err != nil {
		return "", fmt.Errorf("schema %q properties: %w", name, err)
	}
	propertyRaw, ok := properties[property]
	if !ok {
		return "", fmt.Errorf("schema %q is missing property %q", name, property)
	}
	return exactRef(propertyRaw, fmt.Sprintf("schema %s property %s", name, property))
}

func responseSchemaRef(operationRaw json.RawMessage, status string) (string, error) {
	var operation struct {
		Responses map[string]struct {
			Content map[string]struct {
				Schema json.RawMessage `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(operationRaw, &operation); err != nil {
		return "", fmt.Errorf("decode operation: %w", err)
	}
	response, ok := operation.Responses[status]
	if !ok {
		return "", fmt.Errorf("response %s is missing", status)
	}
	media, ok := response.Content["application/json"]
	if !ok {
		return "", fmt.Errorf("response %s application/json schema is missing", status)
	}
	return exactRef(media.Schema, "response schema")
}

func requestSchemaRef(operationRaw json.RawMessage) (string, error) {
	var operation struct {
		RequestBody struct {
			Content map[string]struct {
				Schema json.RawMessage `json:"schema"`
			} `json:"content"`
		} `json:"requestBody"`
	}
	if err := json.Unmarshal(operationRaw, &operation); err != nil {
		return "", fmt.Errorf("decode operation: %w", err)
	}
	media, ok := operation.RequestBody.Content["application/json"]
	if !ok {
		return "", fmt.Errorf("request application/json schema is missing")
	}
	return exactRef(media.Schema, "request schema")
}

func exactRef(raw json.RawMessage, location string) (string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", fmt.Errorf("%s must be an object: %w", location, err)
	}
	if len(object) != 1 {
		return "", fmt.Errorf("%s must contain only $ref", location)
	}
	var ref string
	if err := json.Unmarshal(object["$ref"], &ref); err != nil || ref == "" {
		return "", fmt.Errorf("%s has an invalid $ref", location)
	}
	if _, err := localSchemaName(ref); err != nil {
		return "", err
	}
	return ref, nil
}

func localSchemaName(ref string) (string, error) {
	const prefix = "#/components/schemas/"
	if !strings.HasPrefix(ref, "#") {
		return "", fmt.Errorf("external schema reference %q is not allowed", ref)
	}
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Errorf("schema reference %q must be under #/components/schemas", ref)
	}
	encoded := strings.TrimPrefix(ref, prefix)
	if encoded == "" || strings.Contains(encoded, "/") {
		return "", fmt.Errorf("schema reference %q must identify exactly one component schema", ref)
	}
	name, err := unescapeJSONPointer(encoded)
	if err != nil {
		return "", fmt.Errorf("schema reference %q: %w", ref, err)
	}
	return name, nil
}

func unescapeJSONPointer(segment string) (string, error) {
	var builder strings.Builder
	for index := 0; index < len(segment); index++ {
		if segment[index] != '~' {
			builder.WriteByte(segment[index])
			continue
		}
		if index+1 >= len(segment) {
			return "", fmt.Errorf("invalid JSON Pointer escape")
		}
		index++
		switch segment[index] {
		case '0':
			builder.WriteByte('~')
		case '1':
			builder.WriteByte('/')
		default:
			return "", fmt.Errorf("invalid JSON Pointer escape ~%c", segment[index])
		}
	}
	return builder.String(), nil
}

func escapeJSONPointer(segment string) string {
	return strings.ReplaceAll(strings.ReplaceAll(segment, "~", "~0"), "/", "~1")
}

func decodeSingleJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func decodeAny(raw json.RawMessage, target *any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}

func decodeOptional(object map[string]json.RawMessage, name string, target any) error {
	raw, ok := object[name]
	if !ok {
		return nil
	}
	value := reflect.ValueOf(target)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return fmt.Errorf("internal target for %s is not a pointer", name)
	}
	if value.Elem().Kind() == reflect.Pointer {
		element := reflect.New(value.Elem().Type().Elem())
		if err := json.Unmarshal(raw, element.Interface()); err != nil {
			return err
		}
		value.Elem().Set(element)
		return nil
	}
	return json.Unmarshal(raw, target)
}

func validateGeneratedResourceSchema(root SchemaIR, resource contract.ReviewedCandidate) error {
	if root.Kind != "object" {
		return fmt.Errorf("PUT schema kind = %q, want object", root.Kind)
	}
	if root.SourceRef != resource.Refs.PutRequest {
		return fmt.Errorf("PUT schema source ref = %q, want %q", root.SourceRef, resource.Refs.PutRequest)
	}
	configs, err := requiredField(root, "configs", "object")
	if err != nil {
		return err
	}
	if configs.SourceRef != resource.Refs.Configs {
		return fmt.Errorf("configs source ref = %q, want %q", configs.SourceRef, resource.Refs.Configs)
	}
	if _, err := requiredField(root, "template", "boolean"); err != nil {
		return err
	}
	if len(root.Fields) != 2 {
		return fmt.Errorf("PUT envelope contains %d fields, want configs and template", len(root.Fields))
	}

	collectionCount := 0
	scalarStringArrayCount := 0
	for _, field := range configs.Fields {
		switch field.Kind {
		case "string", "boolean", "integer", "object":
			// Config scalars may be required or optional on the wire. The
			// reviewed Terraform policy (optional_computed) preserves the
			// current GET value when omitted regardless of wire requiredness.
			// Kind "object" is a nested composite config object (e.g.
			// caching_compression cache/compress) rendered as a
			// SingleNestedBlock with its own scalar sub-fields. Sub-collections
			// and sub-scalar-string-arrays inside the nested object are
			// validated separately via their own reviewed contract entries.
		case "array":
			if field.Items == nil {
				return fmt.Errorf("configs.%s array is missing items", field.Name)
			}
			item := *field.Items
			if item.Kind == "string" {
				// Scalar-string-array collection (e.g. allow_methods): a
				// required array of bare enum strings with no object item
				// schema and no positional idx. It is reviewed separately
				// against the ScalarStringArrays contract.
				scalarStringArrayCount++
				continue
			}
			collectionCount++
			// Look up the reviewed collection contract by name to drive the
			// bounded/unbounded and indexed/unindexed validations from the
			// pinned contract rather than guessing from the source schema.
			reviewedCollection, ok := reviewedCollectionByName(resource, field.Name)
			if !ok {
				return fmt.Errorf("configs.%s is not in the reviewed collection set", field.Name)
			}
			if field.Required {
				return fmt.Errorf("configs.%s must remain an optional item array", field.Name)
			}
			// MaxItems == 0 in the reviewed contract means the collection is
			// unbounded (no maxItems in the pinned OpenAPI); a nil
			// source MaxItems is then accepted. A positive reviewed bound still
			// requires a matching source maxItems.
			if reviewedCollection.MaxItems == 0 {
				if field.MaxItems != nil {
					return fmt.Errorf("configs.%s maxItems changed (expected unbounded)", field.Name)
				}
			} else {
				if field.MaxItems == nil || *field.MaxItems != reviewedCollection.MaxItems {
					return fmt.Errorf("configs.%s maxItems changed", field.Name)
				}
			}
			if item.Kind != "object" {
				return fmt.Errorf("configs.%s item kind %q is unsupported", field.Name, item.Kind)
			}
			// When the contract pins a single shared CollectionItem ref, every
			// object-item collection must reference it. When the contract uses
			// per-collection item schemas (Refs.CollectionItem empty), the ref
			// is not enforced here; deep validation runs in
			// validateCandidateSchemaContract.
			if resource.Refs.CollectionItem != "" && item.SourceRef != resource.Refs.CollectionItem {
				return fmt.Errorf("configs.%s item ref = %q, want %q", field.Name, item.SourceRef, resource.Refs.CollectionItem)
			}
			if !reviewedCollection.Unindexed {
				idx, err := optionalIdxField(item, "idx")
				if err != nil {
					return err
				}
				// The reviewed contract pins the idx wire kind ("integer" or
				// "string"). Only rewriting_requests reviewed a string idx; every
				// other resource's idx is integer (the default when the contract
				// omits idx from ItemFields/CollectionItemFields). A pinned
				// OpenAPI change that flips the kind must be detected as drift,
				// not silently accepted (the generator emits different wire JSON
				// for string idx). Reject a mismatch against the reviewed kind.
				if idx.Kind != reviewedIdxKind(resource, field.Name) {
					return fmt.Errorf("configs.%s.item.idx kind = %q, want %q", field.Name, idx.Kind, reviewedIdxKind(resource, field.Name))
				}
				// idx is optional. Every reviewed item schema pins default 1
				// except GraphQLProtectionRule, whose pinned idx carries no
				// default, and file_protection custom_file_types, whose pinned
				// idx carries default 0. Accept the no-default shape only for
				// GraphQL and the zero-default shape only for file_protection
				// custom_file_types; for every other resource require the
				// reviewed default 1 so a schema change that drops the default
				// is detected as drift. idx carries no bounds and is not
				// readOnly for any reviewed resource. The generated runtime
				// always writes one-based indices and rejects non-positive idx
				// on read, so the pinned source default does not affect wire
				// behavior; it is a source-schema fact only.
				//
				// The reviewed idx wire kind is integer for every resource
				// except rewriting_requests, whose RewritingRule.idx is a
				// string on the wire (default "1"). Both kinds pin the same
				// string-rendered default "1" (fmt.Sprint of integer 1 or
				// string "1" both yield "1"), so the default check is shared.
				defaultStr := fmt.Sprint(idx.Default)
				allowNoDefault := resource.TerraformName == contract.GraphQLProtectionResource.TerraformName
				allowZeroDefault := resource.TerraformName == contract.FileProtectionResource.TerraformName && field.Name == "custom_file_types"
				if defaultStr != "1" && !(allowNoDefault && defaultStr == "<nil>") && !(allowZeroDefault && defaultStr == "0") {
					return fmt.Errorf("configs.%s.item.idx default changed", field.Name)
				}
				if idx.Minimum != nil || idx.Maximum != nil || idx.ReadOnly != nil {
					return fmt.Errorf("configs.%s.item.idx constraints changed", field.Name)
				}
			}
			for _, itemField := range item.Fields {
				if itemField.Name == "idx" {
					if reviewedCollection.Unindexed {
						return fmt.Errorf("configs.%s.item unexpectedly carries an idx field but the reviewed contract pins Unindexed", field.Name)
					}
					continue
				}
				switch itemField.Kind {
				case "string", "boolean", "integer", "object":
				case "array":
					// An item field that is an array is either a nested
					// array-of-objects (Items.Kind == "object", the existing
					// SubItemArray shape) or an item-level scalar-string-array
					// (Items.Kind == "string", the new shape). Both are routed
					// and validated against the reviewed contract at render and
					// in validateCollectionItemFields.
					if itemField.Items == nil {
						return fmt.Errorf("configs.%s.item.%s array is missing items", field.Name, itemField.Name)
					}
					if itemField.Items.Kind != "object" && itemField.Items.Kind != "string" {
						return fmt.Errorf("configs.%s.item.%s item kind %q is unsupported", field.Name, itemField.Name, itemField.Items.Kind)
					}
				default:
					return fmt.Errorf("configs.%s.item.%s kind %q is unsupported", field.Name, itemField.Name, itemField.Kind)
				}
			}
		default:
			return fmt.Errorf("configs.%s kind %q is unsupported", field.Name, field.Kind)
		}
	}
	if collectionCount == 0 && scalarStringArrayCount == 0 && len(configs.Fields) == 0 {
		return fmt.Errorf("configs contains no reviewed fields, ordered collection, or scalar string array")
	}
	return validateCandidateSchemaContract(configs, resource.Schema, resource.TerraformName)
}

func validateCandidateSchemaContract(configs SchemaIR, reviewed contract.CandidateSchemaContract, resourceName string) error {
	configFields := make(map[string]SchemaIR)
	collections := make(map[string]SchemaIR)
	scalarStringArrays := make(map[string]SchemaIR)
	for _, field := range configs.Fields {
		if field.Kind == "array" {
			if field.Items != nil && field.Items.Kind == "string" {
				scalarStringArrays[field.Name] = field
				continue
			}
			collections[field.Name] = field
			continue
		}
		configFields[field.Name] = field
	}
	// For nested-object config fields (e.g. caching_compression cache/compress),
	// look inside the object for nested collections and scalar-string-arrays.
	// These are registered with dotted paths like "cache.cookie_list".
	for _, field := range configs.Fields {
		if field.Kind != "object" {
			continue
		}
		for _, sub := range field.Fields {
			if sub.Kind == "array" && sub.Items != nil {
				if sub.Items.Kind == "string" {
					scalarStringArrays[field.Name+"."+sub.Name] = sub
				} else if sub.Items.Kind == "object" {
					collections[field.Name+"."+sub.Name] = sub
				}
			}
		}
	}
	if len(configFields) != len(reviewed.ConfigFields) {
		return fmt.Errorf("configs scalar field count = %d, want %d", len(configFields), len(reviewed.ConfigFields))
	}
	for _, expected := range reviewed.ConfigFields {
		field, ok := configFields[expected.Name]
		if !ok {
			return fmt.Errorf("configs.%s is missing from the reviewed source schema", expected.Name)
		}
		var enriched *contract.BackendEnrichedNumericFacets
		if reviewed.BackendEnrichedConfigScalarConstraints != nil {
			if facets, ok := reviewed.BackendEnrichedConfigScalarConstraints[expected.Name]; ok {
				enriched = &facets
			}
		}
		if err := validateCandidateFieldConstraint("configs."+expected.Name, field, expected, enriched, resourceName); err != nil {
			return err
		}
		delete(configFields, expected.Name)
	}
	if len(configFields) != 0 {
		return fmt.Errorf("configs contains unreviewed scalar fields %v", sortedSchemaKeys(configFields))
	}

	if len(collections) != len(reviewed.Collections) {
		return fmt.Errorf("configs collection count = %d, want %d", len(collections), len(reviewed.Collections))
	}
	collectionItems := make(map[string]SchemaIR, len(collections))
	for _, expected := range reviewed.Collections {
		collection, ok := collections[expected.Name]
		if !ok {
			return fmt.Errorf("configs.%s is missing from the reviewed source schema", expected.Name)
		}
		if expected.MaxItems == 0 {
			if collection.MaxItems != nil {
				return fmt.Errorf("configs.%s maxItems changed (expected unbounded)", expected.Name)
			}
		} else {
			if collection.MaxItems == nil || *collection.MaxItems != expected.MaxItems {
				return fmt.Errorf("configs.%s maxItems changed", expected.Name)
			}
		}
		if collection.Items == nil || collection.Items.Kind != "object" {
			return fmt.Errorf("configs.%s has no object item schema", expected.Name)
		}
		collectionItems[expected.Name] = *collection.Items
		delete(collections, expected.Name)
	}
	if len(collections) != 0 {
		return fmt.Errorf("configs contains unreviewed collections %v", sortedSchemaKeys(collections))
	}

	if len(scalarStringArrays) != len(reviewed.ScalarStringArrays) {
		return fmt.Errorf("configs scalar string array count = %d, want %d", len(scalarStringArrays), len(reviewed.ScalarStringArrays))
	}
	for _, expected := range reviewed.ScalarStringArrays {
		array, ok := scalarStringArrays[expected.Name]
		if !ok {
			return fmt.Errorf("configs.%s is missing from the reviewed source schema", expected.Name)
		}
		if array.Items == nil || array.Items.Kind != "string" {
			return fmt.Errorf("configs.%s is not a string-item array", expected.Name)
		}
		if array.Required != expected.Required {
			return fmt.Errorf("configs.%s required changed", expected.Name)
		}
		wantEnum := append([]string(nil), expected.Enum...)
		sort.Strings(wantEnum)
		if !slices.Equal(stringEnumValues(array.Items.Enum), wantEnum) {
			return fmt.Errorf("configs.%s item enum changed", expected.Name)
		}
		if expected.MaxItems == 0 {
			if array.MaxItems != nil {
				return fmt.Errorf("configs.%s maxItems changed (expected unbounded)", expected.Name)
			}
		} else {
			if array.MaxItems == nil || *array.MaxItems != expected.MaxItems {
				return fmt.Errorf("configs.%s maxItems changed", expected.Name)
			}
		}
		delete(scalarStringArrays, expected.Name)
	}
	if len(scalarStringArrays) != 0 {
		return fmt.Errorf("configs contains unreviewed scalar string arrays %v", sortedSchemaKeys(scalarStringArrays))
	}

	if len(collectionItems) == 0 {
		if len(reviewed.ItemFields) != 0 || len(reviewed.CollectionItemFields) != 0 {
			return fmt.Errorf("reviewed item fields exist but configs contains no reviewed collection item schema")
		}
		return nil
	}

	// When CollectionItemFields is pinned, every collection has its own item
	// contract. Otherwise ItemFields is the shared item contract for every
	// collection (the original single-item-schema shape).
	if len(reviewed.CollectionItemFields) != 0 {
		if len(reviewed.CollectionItemFields) != len(collectionItems) {
			return fmt.Errorf("collection item field sets = %d, want %d", len(reviewed.CollectionItemFields), len(collectionItems))
		}
		for name, itemSchema := range collectionItems {
			expected, ok := reviewed.CollectionItemFields[name]
			if !ok {
				return fmt.Errorf("collection %q has no reviewed item field contract", name)
			}
			if err := validateCollectionItemFields(name, itemSchema, expected, resourceName, computedOnlyForCollection(reviewed, name)); err != nil {
				return err
			}
		}
		return nil
	}

	if len(collectionItems) > 1 {
		// The shared ItemFields contract is only valid when every collection
		// shares one item schema. Reject drift if they differ.
		var first *SchemaIR
		for _, item := range collectionItems {
			if first == nil {
				anchor := item
				first = &anchor
				continue
			}
			if !reflect.DeepEqual(*first, item) {
				return fmt.Errorf("configs collections share no single item schema; pin CollectionItemFields instead")
			}
		}
	}
	var sharedItem SchemaIR
	for _, item := range collectionItems {
		sharedItem = item
		break
	}
	return validateCollectionItemFields("(shared)", sharedItem, reviewed.ItemFields, resourceName, computedOnlyForCollection(reviewed, "(shared)"))
}

// computedOnlyForCollection returns the reviewed computed-only item fields
// whose path targets the named collection (e.g. "configs.user_list.item.uuid"
// belongs to collection "user_list"). The shared single-item-schema shape
// passes "(shared)" and matches no per-collection computed-only field, so a
// computed-only field on a shared-schema resource is rejected elsewhere as an
// unsupported combination.
func computedOnlyForCollection(reviewed contract.CandidateSchemaContract, collection string) []contract.CandidateComputedOnlyItemFieldConstraint {
	prefix := "configs." + collection + ".item."
	var out []contract.CandidateComputedOnlyItemFieldConstraint
	for _, c := range reviewed.ComputedOnlyItemFields {
		if strings.HasPrefix(c.Path, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// validateCollectionItemFields validates one collection's item schema against
// its reviewed field contract, recursing one level into nested-object fields.
// The wire-only idx field is validated separately (optional integer, default 1)
// and excluded from the reviewed field-count comparison. file_protection
// custom_file_types is the one reviewed collection whose pinned idx carries
// default 0; the runtime writes one-based indices and rejects non-positive idx
// on read, so the zero default is a source-schema fact only.
//
// computedOnly lists the reviewed backend-managed (computed-only) item fields
// for this collection. OpenAPI 26.3.a marks them readOnly and they are NOT in
// the reviewed writable ItemFields. The validator
// reconciles them into the expected field count and validates each against its
// OpenAPI counterpart (string, non-nullable, no default/bounds), so a schema
// change to a computed-only field is detected as drift.
func validateCollectionItemFields(collection string, itemSchema SchemaIR, reviewed []contract.CandidateFieldConstraint, resourceName string, computedOnly []contract.CandidateComputedOnlyItemFieldConstraint) error {
	itemFields := make(map[string]SchemaIR)
	for _, field := range itemSchema.Fields {
		if field.Name != "idx" {
			itemFields[field.Name] = field
		}
	}
	reviewedNonIdx := make([]contract.CandidateFieldConstraint, 0, len(reviewed))
	for _, expected := range reviewed {
		if expected.Name == "idx" {
			idx, err := optionalIdxField(itemSchema, "idx")
			if err != nil {
				return fmt.Errorf("collection %s item idx: %w", collection, err)
			}
			// The reviewed contract pins the idx wire kind ("integer" or
			// "string"); a pinned OpenAPI change that flips the kind must be
			// detected as drift, not silently accepted (the generator emits
			// different wire JSON for string idx). Reject a mismatch.
			if idx.Kind != expected.Kind {
				return fmt.Errorf("collection %s item idx kind = %q, want %q", collection, idx.Kind, expected.Kind)
			}
			defaultStr := fmt.Sprint(idx.Default)
			allowZeroDefault := resourceName == contract.FileProtectionResource.TerraformName && collection == "custom_file_types"
			if (defaultStr != "1" && !(allowZeroDefault && defaultStr == "0")) || idx.Minimum != nil || idx.Maximum != nil || idx.ReadOnly != nil {
				return fmt.Errorf("collection %s item idx constraints changed", collection)
			}
			continue
		}
		reviewedNonIdx = append(reviewedNonIdx, expected)
	}
	// Validate the reviewed computed-only (backend-managed) item fields.
	// Reconcile them
	// into the expected field set and validate each against its OpenAPI
	// counterpart: a non-nullable string with no default, bounds, enum, or
	// pattern (a backend-managed credential/timestamp is opaque to the
	// practitioner). A schema change to a computed-only field is drift.
	for _, computed := range computedOnly {
		field, ok := itemFields[computed.Path]
		if !ok {
			// The OpenAPI item may use the leaf name; computed.Path is the full
			// dotted path, so fall back to the last segment.
			leaf := computed.Path
			if idx := strings.LastIndex(leaf, "."); idx >= 0 {
				leaf = leaf[idx+1:]
			}
			field, ok = itemFields[leaf]
			if !ok {
				return fmt.Errorf("collection %s computed-only item field %s is missing from the reviewed source schema", collection, computed.Path)
			}
		}
		if field.Kind != "string" {
			return fmt.Errorf("collection %s computed-only item field %s kind = %q, want string", collection, computed.Path, field.Kind)
		}
		if field.Required {
			return fmt.Errorf("collection %s computed-only item field %s is required, but backend-managed fields must be optional", collection, computed.Path)
		}
		readOnly := field.ReadOnly != nil && *field.ReadOnly
		if readOnly != computed.ReadOnly {
			return fmt.Errorf("collection %s computed-only item field %s readOnly changed", collection, computed.Path)
		}
		if field.Default != nil || field.Minimum != nil || field.Maximum != nil || field.MaxLength != nil || field.MinLength != nil || field.Pattern != "" || len(field.Enum) != 0 {
			return fmt.Errorf("collection %s computed-only item field %s carries a constraint, but backend-managed fields are opaque", collection, computed.Path)
		}
		// computed-only fields are not nullable (an explicit null is rejected on
		// decode); the pinned OpenAPI must not mark them nullable.
		if field.Nullable {
			return fmt.Errorf("collection %s computed-only item field %s is nullable, but backend-managed fields must reject an explicit null", collection, computed.Path)
		}
		delete(itemFields, field.Name)
	}
	if len(itemFields) != len(reviewedNonIdx) {
		return fmt.Errorf("collection %s item field count = %d, want %d", collection, len(itemFields), len(reviewedNonIdx))
	}
	for _, expected := range reviewedNonIdx {
		field, ok := itemFields[expected.Name]
		if !ok {
			return fmt.Errorf("collection %s item field %s is missing from the reviewed source schema", collection, expected.Name)
		}
		if err := validateCandidateFieldConstraint("collection "+collection+" item."+expected.Name, field, expected, nil, resourceName); err != nil {
			return err
		}
		delete(itemFields, expected.Name)
	}
	if len(itemFields) != 0 {
		return fmt.Errorf("collection %s item contains unreviewed fields %v", collection, sortedSchemaKeys(itemFields))
	}
	return nil
}

func validateCandidateFieldConstraint(path string, field SchemaIR, expected contract.CandidateFieldConstraint, enriched *contract.BackendEnrichedNumericFacets, resourceName string) error {
	// An item-level scalar-string-array is pinned in the contract as Kind
	// "string_array" but resolves from the pinned OpenAPI as Kind "array" with
	// string items. Accept that mapping here; the deep validation below checks
	// the string items and the reviewed bound.
	if expected.Kind == "string_array" {
		if field.Kind != "array" || field.Required != expected.Required {
			return fmt.Errorf("%s kind/required changed", path)
		}
		if expected.StringArray == nil {
			return fmt.Errorf("%s is a string_array item field but the contract pins no string array", path)
		}
		if field.Items == nil || field.Items.Kind != "string" {
			return fmt.Errorf("%s is not a string-item array", path)
		}
		want := expected.StringArray
		if want.MaxItems == 0 {
			if field.MaxItems != nil {
				return fmt.Errorf("%s maxItems changed (expected unbounded)", path)
			}
		} else if field.MaxItems == nil || *field.MaxItems != want.MaxItems {
			return fmt.Errorf("%s maxItems changed", path)
		}
		if !slices.Equal(stringEnumValues(field.Items.Enum), want.Enum) {
			return fmt.Errorf("%s item enum changed", path)
		}
		return nil
	}
	if field.Kind != expected.Kind || field.Required != expected.Required {
		return fmt.Errorf("%s kind/required changed", path)
	}
	readOnly := field.ReadOnly != nil && *field.ReadOnly
	if readOnly != expected.ReadOnly {
		return fmt.Errorf("%s readOnly changed", path)
	}
	if (field.Default != nil) != expected.HasDefault || expected.HasDefault && !defaultValueEqual(field.Default, expected.Default) {
		return fmt.Errorf("%s default changed", path)
	}
	if !slices.Equal(stringEnumValues(field.Enum), expected.Enum) {
		return fmt.Errorf("%s enum changed", path)
	}
	if expected.MaxLength == 0 {
		if field.MaxLength != nil {
			return fmt.Errorf("%s maxLength changed", path)
		}
	} else if field.MaxLength == nil || *field.MaxLength != expected.MaxLength {
		return fmt.Errorf("%s maxLength changed", path)
	}
	if expected.MinLength == 0 {
		if field.MinLength != nil {
			return fmt.Errorf("%s minLength changed", path)
		}
	} else if field.MinLength == nil || *field.MinLength != expected.MinLength {
		return fmt.Errorf("%s minLength changed", path)
	}
	if field.Nullable != expected.AllowNull {
		return fmt.Errorf("%s nullable changed", path)
	}
	if field.Pattern != expected.Pattern {
		return fmt.Errorf("%s pattern changed", path)
	}
	// Minimum/Maximum use per-facet source selection. A facet marked as a
	// reviewed backend config-scalar constraint enrichment (absent from the
	// pinned OpenAPI but present in a separately reviewed external contract) authorizes the contract to pin a
	// bound the pure OpenAPI omits: the OpenAPI facet must be absent and the
	// contract facet must be present. Otherwise the contract facet must equal
	// the pure OpenAPI facet exactly (the existing drift check). This is the
	// source-selection rule: an explicitly marked individual facet, absent
	// from the pinned OpenAPI, is replaced by an equality check against the
	// reviewed contract value applied by the generator.
	if err := validateNumericFacet(path, "minimum", field.Minimum, expected.Minimum, enriched != nil && enriched.Minimum); err != nil {
		return err
	}
	if err := validateNumericFacet(path, "maximum", field.Maximum, expected.Maximum, enriched != nil && enriched.Maximum); err != nil {
		return err
	}
	if !intEnumEqual(field.Enum, expected.IntEnum) {
		return fmt.Errorf("%s int_enum changed", path)
	}
	if expected.Kind == "object" {
		// For nested config objects (e.g. caching_compression cache/compress),
		// the contract's ObjectFields pins only the scalar sub-fields. Array
		// sub-fields (sub-collections and sub-scalar-string-arrays) are validated
		// separately via the Collections and ScalarStringArrays contract entries.
		// Exclude array fields from the count.
		nonArrayFields := 0
		for _, sub := range field.Fields {
			if sub.Kind != "array" {
				nonArrayFields++
			}
		}
		if nonArrayFields != len(expected.ObjectFields) {
			return fmt.Errorf("%s object field count = %d, want %d", path, nonArrayFields, len(expected.ObjectFields))
		}
		objectFields := make(map[string]SchemaIR, len(field.Fields))
		for _, sub := range field.Fields {
			objectFields[sub.Name] = sub
		}
		for _, expectedSub := range expected.ObjectFields {
			sub, ok := objectFields[expectedSub.Name]
			if !ok {
				return fmt.Errorf("%s object field %s is missing from the reviewed source schema", path, expectedSub.Name)
			}
			if err := validateCandidateFieldConstraint(path+"."+expectedSub.Name, sub, expectedSub, nil, resourceName); err != nil {
				return err
			}
		}
	}
	if expected.Kind == "array" {
		if expected.SubItemArray == nil {
			return fmt.Errorf("%s is an array item field but the contract pins no sub-item array", path)
		}
		if field.Items == nil || field.Items.Kind != "object" {
			return fmt.Errorf("%s is not an object-item array", path)
		}
		want := expected.SubItemArray
		if want.MaxItems == 0 {
			if field.MaxItems != nil {
				return fmt.Errorf("%s maxItems changed (expected unbounded)", path)
			}
		} else if field.MaxItems == nil || *field.MaxItems != want.MaxItems {
			return fmt.Errorf("%s maxItems changed", path)
		}
		itemFields := make(map[string]SchemaIR, len(field.Items.Fields))
		for _, sub := range field.Items.Fields {
			if sub.Name != "idx" {
				itemFields[sub.Name] = sub
			}
		}
		// Validate the nested wire-only idx: must exist, be an optional integer
		// with default 1 and no bounds, so generated decoding can rely on it.
		// file_protection custom_file_types.item.file_content_match_rule is the
		// one reviewed sub-item whose pinned idx carries default 0; the runtime
		// still writes one-based indices and rejects non-positive idx on read,
		// so the zero default is a source-schema fact only.
		idx, err := optionalField(*field.Items, "idx", "integer")
		if err != nil {
			return fmt.Errorf("%s item idx: %w", path, err)
		}
		allowZeroDefault := resourceName == contract.FileProtectionResource.TerraformName &&
			path == "collection custom_file_types item.match_rules"
		if (fmt.Sprint(idx.Default) != "1" && !(allowZeroDefault && fmt.Sprint(idx.Default) == "0")) || idx.Minimum != nil || idx.Maximum != nil || idx.ReadOnly != nil {
			return fmt.Errorf("%s item idx constraints changed", path)
		}
		if len(itemFields) != len(want.ItemFields) {
			return fmt.Errorf("%s item field count = %d, want %d", path, len(itemFields), len(want.ItemFields))
		}
		for _, expectedSub := range want.ItemFields {
			sub, ok := itemFields[expectedSub.Name]
			if !ok {
				return fmt.Errorf("%s item field %s is missing from the reviewed source schema", path, expectedSub.Name)
			}
			if err := validateCandidateFieldConstraint(path+".item."+expectedSub.Name, sub, expectedSub, nil, resourceName); err != nil {
				return err
			}
		}
	}
	return nil
}

// intEnumEqual compares an OpenAPI-decoded integer enum (json.Number values in
// SchemaIR.Enum) against the reviewed pinned []int64. Non-integer enums return
// true only when both sides are empty (string enums are validated separately).
func intEnumEqual(got []any, want []int64) bool {
	if len(want) == 0 {
		// No reviewed integer enum: the OpenAPI enum, if any, must be a string
		// enum (validated by stringEnumValues) or absent. An integer enum in
		// the source with no reviewed IntEnum is rejected.
		for _, value := range got {
			if _, ok := value.(json.Number); ok {
				return false
			}
		}
		return true
	}
	gotInts := make([]int64, 0, len(got))
	for _, value := range got {
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		parsed, err := number.Int64()
		if err != nil {
			return false
		}
		gotInts = append(gotInts, parsed)
	}
	slices.Sort(gotInts)
	wantCopy := append([]int64(nil), want...)
	slices.Sort(wantCopy)
	return slices.Equal(gotInts, wantCopy)
}

// floatConstraintEqual compares an optional OpenAPI numeric bound against the
// reviewed pinned pointer. A nil pointer means the bound is absent. JSON
// numbers decode into SchemaIR as *float64 and the contract pins *float64, so
// both sides compare the same concrete type.
func floatConstraintEqual(got *float64, want *float64) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return *got == *want
}

// validateNumericFacet applies the per-facet source-selection rule for one
// integer config-scalar minimum/maximum bound. When enriched is true the
// facet is a reviewed backend config-scalar constraint enrichment absent
// from the pinned OpenAPI: the pure OpenAPI facet must be absent and the
// contract facet must be present (the generator injects the reviewed bound).
// Otherwise the contract facet must equal the pure OpenAPI facet exactly,
// preserving drift detection. The rule is applied independently per facet so
// a field may enrich only its maximum, only its minimum, or both.
func validateNumericFacet(path, label string, openAPI, contractBound *float64, enriched bool) error {
	if enriched {
		if openAPI != nil {
			return fmt.Errorf("%s %s changed: reviewed backend enrichment collides with a pinned OpenAPI %s", path, label, label)
		}
		if contractBound == nil {
			return fmt.Errorf("%s %s changed: reviewed backend enrichment marker present but the contract pins no %s", path, label, label)
		}
		return nil
	}
	if !floatConstraintEqual(openAPI, contractBound) {
		return fmt.Errorf("%s %s changed", path, label)
	}
	return nil
}

// defaultValueEqual compares a reviewed default against the OpenAPI-decoded
// default. The resolver uses encoding/json with UseNumber, so JSON numbers
// arrive as json.Number while the reviewed contract pins integers as Go int
// (and floats as Go float64). Strings and booleans round-trip as their native
// Go types and compare directly. Numeric values compare by their parsed
// float64 value so json.Number("8192") equals int(8192).
func defaultValueEqual(got any, want any) bool {
	if reflect.DeepEqual(got, want) {
		return true
	}
	gotNumber, gotOK := numericValue(got)
	wantNumber, wantOK := numericValue(want)
	return gotOK && wantOK && gotNumber == wantNumber
}

// numericValue returns the float64 value of a JSON number, Go integer, or Go
// float, and whether the value is numeric. Non-numeric values return false.
func numericValue(value any) (float64, bool) {
	switch v := value.(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// normalizeEnumValues sorts decoded OpenAPI enum values by their canonical
// JSON bytes and removes byte-identical duplicates. The pinned OpenAPI
// occasionally carries duplicate enum values (e.g. FileType.type); the
// generated map literals, validators, docs, and manifest cannot represent
// duplicates, so the in-memory SchemaIR.Enum is normalized to a sorted,
// duplicate-free set. The pinned OpenAPI bytes and checksum are unchanged.
//
// Validation compares this normalized source set against the reviewed contract
// slice with slices.Equal, so a duplicate that appears only in the contract
// (longer slice) still fails validation. Only byte-identical values collapse;
// similar-but-distinct values are preserved. A canonicalization failure returns
// an error so the resolver fails closed rather than guessing.
func normalizeEnumValues(values []any) ([]any, error) {
	if len(values) == 0 {
		return nil, nil
	}
	type enumEntry struct {
		value any
		bytes []byte
	}
	entries := make([]enumEntry, 0, len(values))
	for _, value := range values {
		canonical, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("canonicalize enum value: %w", err)
		}
		entries = append(entries, enumEntry{value: value, bytes: canonical})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].bytes, entries[j].bytes) < 0
	})
	result := make([]any, 0, len(entries))
	var last []byte
	for _, entry := range entries {
		if last != nil && bytes.Equal(last, entry.bytes) {
			continue
		}
		result = append(result, entry.value)
		last = entry.bytes
	}
	return result, nil
}

func sortedSchemaKeys(values map[string]SchemaIR) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func requiredField(parent SchemaIR, name, kind string) (SchemaIR, error) {
	field, err := findField(parent, name, kind)
	if err != nil {
		return SchemaIR{}, err
	}
	if !field.Required {
		return SchemaIR{}, fmt.Errorf("field %s.%s is no longer required", parent.Name, name)
	}
	return field, nil
}

// reviewedCollectionByName returns the reviewed collection contract for the
// named configs collection, driving bounded/unbounded and indexed/unindexed
// validation from the pinned contract.
func reviewedCollectionByName(resource contract.ReviewedCandidate, name string) (contract.CandidateCollectionConstraint, bool) {
	for _, collection := range resource.Schema.Collections {
		if collection.Name == name {
			return collection, true
		}
	}
	return contract.CandidateCollectionConstraint{}, false
}

func optionalField(parent SchemaIR, name, kind string) (SchemaIR, error) {
	field, err := findField(parent, name, kind)
	if err != nil {
		return SchemaIR{}, err
	}
	if field.Required {
		return SchemaIR{}, fmt.Errorf("field %s.%s unexpectedly became required", parent.Name, name)
	}
	return field, nil
}

// reviewedIdxKind returns the reviewed idx wire kind ("integer" or "string")
// for one collection's item schema. It looks up the pinned idx field in the
// per-collection item fields, then the shared item fields, defaulting to
// "integer" (the reviewed kind for every resource except rewriting_requests,
// whose RewritingRule.idx is a string). This lets the OpenAPI validator reject
// an integer<->string idx kind drift against the reviewed contract.
func reviewedIdxKind(resource contract.ReviewedCandidate, collectionName string) string {
	if perCollection, ok := resource.Schema.CollectionItemFields[collectionName]; ok {
		for _, f := range perCollection {
			if f.Name == "idx" {
				return f.Kind
			}
		}
	}
	for _, f := range resource.Schema.ItemFields {
		if f.Name == "idx" {
			return f.Kind
		}
	}
	return "integer"
}

// optionalIdxField validates the wire-only positional idx field. The reviewed
// idx wire kind is integer for every resource except rewriting_requests, whose
// RewritingRule.idx is a string on the wire (default "1"). Both kinds are
// accepted here; the kind is checked against the reviewed contract by the
// caller, and the default and bounds checks are applied by the caller.
func optionalIdxField(parent SchemaIR, name string) (SchemaIR, error) {
	for _, field := range parent.Fields {
		if field.Name == name {
			if field.Kind != "integer" && field.Kind != "string" {
				return SchemaIR{}, fmt.Errorf("field %s.%s type = %q, want %q or %q", parent.Name, name, field.Kind, "integer", "string")
			}
			if field.Required {
				return SchemaIR{}, fmt.Errorf("field %s.%s unexpectedly became required", parent.Name, name)
			}
			return field, nil
		}
	}
	return SchemaIR{}, fmt.Errorf("field %s.%s is missing", parent.Name, name)
}

func findField(parent SchemaIR, name, kind string) (SchemaIR, error) {
	for _, field := range parent.Fields {
		if field.Name == name {
			if field.Kind != kind {
				return SchemaIR{}, fmt.Errorf("field %s.%s type = %q, want %q", parent.Name, name, field.Kind, kind)
			}
			return field, nil
		}
	}
	return SchemaIR{}, fmt.Errorf("field %s.%s is missing", parent.Name, name)
}

func jsonNumberInt(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(number.String())
	return parsed, err == nil
}
