package generator

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	waf "terraform-provider-fortiappseccloud/internal/generator/profile/waf"
)

// RenderModel is the deterministic render-only view derived from a Manifest.
// It is never serialized into the manifest; templates consume it directly so
// the resource codec, register, and docs templates stay schema/policy-driven
// without per-resource if/else branches.
type RenderModel struct {
	Marker    string
	Manifest  Manifest
	Resources []ResourceRender
}

// ResourceRender is one resource's complete render view. All Go code
// fragments are precomputed so templates stay declarative and deterministic.
type ResourceRender struct {
	// Identity.
	TerraformName   string
	GoName          string
	LowerCamel      string // initialism-aware: CSRFProtection -> csrfProtection
	TypeNameSuffix  string
	OperationName   string
	GetPath         string
	TemplateGetPath string

	// Destroy.
	DestroyModeGo                string
	DestroyField                 string
	DestroyReason                string
	DestroyVerified              bool
	DestroyDisables              bool
	DestroyCandidate             bool
	TemplateDestroyModeGo        string
	TemplateDestroyField         string
	TemplateDestroyReason        string
	TemplateDestroyVerified      bool
	TemplateDestroyDisables      bool
	TemplateDestroyCoupledFields []string

	// Configs scalar attributes (sorted by Terraform name).
	Scalars []ScalarRender

	// Ownership collections (sorted by Terraform block name).
	Collections []CollectionRender

	// ScalarStringArrays are configs arrays of bare enum strings encoded as
	// ownership wrappers of item blocks (e.g. allow_methods).
	ScalarStringArrays []ScalarStringArrayRender

	// CrossFieldRules are the machine-readable object-level constraints from
	// x-fortinet-cross-field-v1. They are enforced for app and template
	// configuration, apply-time planned values, and successful API responses.
	CrossFieldRules []CrossFieldRuleRender

	// SharedItemFields are the item fields shared by all collections. All
	// collections of one resource share the same item schema, so the typed
	// model and attribute-type maps are emitted once.
	SharedItemFields []ItemFieldRender
	// SharedKnownKeys are the known wire keys (including idx) shared by all
	// collections, used by the result decoder's fail-closed key check.
	SharedKnownKeys []string
	// UsesSharedItemSchema is true when every collection shares one item
	// schema, so the shared item model/wire/attribute-types are emitted and
	// used. Per-collection item schemas (e.g. known_attacks, known_bots) emit
	// per-collection codecs instead and do not use the shared types.
	UsesSharedItemSchema bool

	// Imports lists the Go imports the codec requires, sorted stdlib-first.
	Imports []string
	// ImportBlock is the full rendered import block (with stdlib/third-party/
	// local grouping) for the codec file.
	ImportBlock string

	// Modifier flags drive conditional codec helpers.
	HasFilter                bool // emits DefaultFalseModifier (item bool default false)
	HasDefaultTrue           bool // emits DefaultTrueModifier (item bool default true)
	HasClearStrings          bool // emits ClearStringModifier
	NeedsRegexp              bool // imports regexp and emits URL pattern vars
	NeedsStringStateModifier bool // declares stringStateModifier in Schema
	NeedsBoolStateModifier   bool // declares boolStateModifier in Schema
	NeedsInt64StateModifier  bool // declares int64StateModifier in Schema
	HasInt64Scalars          bool // emits the ConfiguredInt64 build helper when any config scalar is an integer
	HasStringScalars         bool // emits the ConfiguredString helper once
	HasBoolScalars           bool // emits the ConfiguredBool helper once
	HasCollections           bool // emits the object-item collection helpers and codec arms
	HasNestedCollections     bool // true when a flat Terraform ownership wrapper maps into a nested wire object
	HasOwnership             bool // true when there are collections or scalar-string-arrays that use the owned set
	// HasStringIdx is true when any collection's wire-only positional idx is
	// a JSON string (e.g. rewriting_requests RewritingRule.idx). It emits the
	// named Idx type with string-quoted marshaling and the ParseIdx helper.
	HasStringIdx bool

	// Docs is the resource docs page view.
	Docs DocsRender

	// Precomputed codec fragments that depend on the variable-length scalar
	// and collection sets. Keeping these here lets the template stay linear.
	DecodeScalarsSig        string // full signature, e.g. "(scalarsStruct, diag.Diagnostics)"
	DecodeScalarsReturn     string // return operands, e.g. "scalarsResult, diagnostics"
	OwnershipStruct         string // ownership result struct type name
	OwnershipStructZero     string // zero-value struct literal
	OwnershipStructImported string // imported struct literal (all true)
	OwnershipStructValues   string // struct literal from configs model
	ScalarsStruct           string // scalars result struct type name
	ScalarsStructZero       string // zero-value struct literal
}

// CrossFieldRuleRender contains prevalidated Go expressions for one v1 rule.
// Expressions are built only from reviewed schema field identifiers and the
// closed operator grammar, keeping the resource template data-driven.
type CrossFieldRuleRender struct {
	ConfiguredCondition   string
	ConfiguredKnown       string
	ConfiguredViolation   string
	ConfiguredGuard       string
	ConfiguredGuardPrefix string
	DecodedCondition      string
	DecodedKnown          string
	DecodedViolation      string
	DecodedGuard          string
	DecodedGuardPrefix    string
	Message               string
	Docs                  string
}

// ScalarRender is one configs-level scalar attribute.
type ScalarRender struct {
	Name     string // Terraform attribute name, e.g. "action" or "status"
	GoName   string // exported Go struct field name, e.g. "Action"
	Kind     string // "string", "boolean", or "integer"
	GoType   string // "types.String", "types.Bool", or "types.Int64"
	AttrType string // "types.StringType", "types.BoolType", or "types.Int64Type"
	// Required mirrors the pinned OpenAPI required flag. A required scalar must
	// be present and non-null on every successful GET; an optional scalar decodes
	// a missing or null remote value to stable null state instead of erroring.
	Required bool // true when the pinned OpenAPI marks the scalar required
	// ComputedOnly marks an OpenAPI readOnly config scalar. It is decoded into
	// state but never accepted from configuration or included in a PUT patch.
	ComputedOnly bool
	UseState     bool // use_state_for_unknown plan modifier
	// WireType is the scalars decode struct field type. An optional scalar uses
	// a pointer type so a missing/null remote value decodes to nil; a required
	// scalar uses the non-pointer type.
	WireType string // "string", "bool", "int64", or "*string"/"*bool"/"*int64" when optional
	// PatchType is the client.Optional[T] type used by the PUT patch struct.
	// It is always the non-pointer Go wire type so ConfiguredString/Bool/Int64
	// and set() keep working regardless of optional read semantics.
	PatchType string   // "string", "bool", or "int64"
	Enum      []string // sorted enum values when Kind == "string"; empty otherwise
	IsIntEnum bool     // true when Kind == "integer" and a reviewed integer enum exists
	EnumMap   string   // name of the enum valid map variable, "" if none
	EnumValid string   // name of the enum validation function, "" if none
	Min       int64    // inclusive minimum when Kind == "integer" and bounded; 0 if unset
	Max       int64    // inclusive maximum when Kind == "integer" and bounded; 0 if unset
	HasRange  bool     // true when Kind == "integer" and both min and max bounds exist (two-sided)
	HasMin    bool     // true when Kind == "integer" and a reviewed minimum exists (one- or two-sided)
	HasMax    bool     // true when Kind == "integer" and a reviewed maximum exists (one- or two-sided)
	// BoundMessage is the human-facing bound description for a malformed/
	// invalid diagnostic, e.g. "between 1 and 100", "at least 1", "at most 100".
	// Empty when no integer bound is present. The template builds the Go check
	// expression from HasMin/HasMax/Min/Max so the missing endpoint of a
	// one-sided bound is never treated as zero.
	BoundMessage string
	// Decode* bounds default to the pinned configurable bounds. A narrowly
	// reviewed RemoteMaximum may widen only successful-response decoding while
	// schema/build validation continues to use Min/Max above.
	DecodeMin          int64
	DecodeMax          int64
	DecodeHasMin       bool
	DecodeHasMax       bool
	DecodeBoundMessage string
	MaxLength          int  // UTF-8 max length when Kind == "string" and >0; else 0
	MinLength          int  // UTF-8 min length when Kind == "string" and >0; else 0
	AllowNull          bool // true when the pinned OpenAPI marks the scalar nullable
	AllowWireNull      bool // true when reviewed production responses may return null
	WireAliases        []WireAliasRender
	// Pattern is the reviewed regex pattern when Kind == "string" and set; else "".
	// Enforced in schema (RegexMatches), build/encode, response decode, and docs,
	// mirroring MaxLength. PatternVar is the regexp var name; "" if none.
	// PatternMessage is the user-facing validation message for PatternVar.
	Pattern        string
	PatternVar     string
	PatternMessage string
	// Sensitive is true when the reviewed Terraform policy marks this scalar
	// sensitive (e.g. a token secret). The generated schema attribute emits
	// Sensitive: true so Terraform redacts the value in plan output and state
	// diffs, and the docs argument text notes the field is sensitive. The value
	// is never printed in generated examples or diagnostics.
	Sensitive bool // true when the reviewed policy marks the scalar sensitive
	// HasDefault records that this optional config scalar has a reviewed OpenAPI
	// default. DefaultLiteral is the Go literal for that default (e.g.
	// `"X-Forwarded-For"`, `true`, `60`). When the successful GET omits an
	// optional scalar with a reviewed default, the decode substitutes the
	// default (not nil) so a configured-default value does not produce a
	// perpetual diff when the backend omits default-valued keys. Scalars
	// without a reviewed default keep the established stable-nil decode.
	HasDefault     bool
	DefaultLiteral string
	// ObjectFields holds the scalar sub-fields when Kind == "object" (nested
	// composite config object, one level deep). The nested object renders as a
	// SingleNestedBlock inside the configs block. Used by caching_compression
	// cache/compress nested config fields.
	ObjectFields []ItemFieldRender
	// ObjectAttrTypes is the attr.Type map name for the nested config object.
	ObjectAttrTypes string
	SchemaExpr      string // full schema.XxxAttribute{...} Go expression
}

// WireAliasRender is one deterministic bidirectional wire/Terraform string
// mapping used by response normalization and configured PUT encoding.
type WireAliasRender struct {
	WireLiteral      string
	TerraformLiteral string
}

// CollectionRender is one configs-level ownership collection.
type CollectionRender struct {
	WireName    string // wire/JSON key, e.g. "page_list" or "rule_list"
	WireParent  string // containing wire object for a flattened nested collection, e.g. "cache"; empty for top-level
	GoName      string // exported Go struct field name, e.g. "PageList"
	LocalName   string // lower-camel local identifier, e.g. "pageList" or "urlList"
	MaxItems    int    // reviewed max items bound, e.g. 256 or 12; 0 means unbounded
	MaxItemsVar string // name of the max-items const, e.g. "csrfProtectionPageListMaxItems"; "" when unbounded
	Item        ItemRender
	// Unindexed is true when the reviewed collection's item schema has no
	// positional idx. An unindexed collection sends items in Terraform order
	// with no idx, decodes the remote array in order without idx validation or
	// sort, and treats item identity as the whole object. Fail-closed unknown
	// keys still apply per item.
	Unindexed bool
	// CodecPrefix names per-collection item helpers, e.g. "csrfProtectionPageList".
	CodecPrefix           string
	ItemAttributeTypes    string
	WrapperAttributeTypes string
	HasNestedObjects      bool
	HasItemStringArrays   bool // true when any item field is an item-level scalar-string-array
	// IdxKind is "int" (default) when the collection's wire-only positional idx
	// is a JSON number, or "string" when it is a JSON string (e.g.
	// rewriting_requests RewritingRule.idx, default "1"). A string idx is
	// treated as a string-encoded positive integer: the internal sort/key type
	// stays int (parsed from the string), so sort, match, and duplicate
	// detection remain numeric. Only the wire JSON type differs.
	IdxKind string
}

// ItemScalarStringArrayRender is one item-level scalar-string-array field (one
// level deep), e.g. known_bots bad_bots_list.item.allow_list. It reuses the
// scalar-string-array ownership semantics inside a collection item: an omitted
// wrapper preserves the raw remote array and keeps state null; a present empty
// wrapper sends []; a present populated wrapper replaces the complete ordered
// array. There is no positional idx and no max-items bound when MaxItems is zero.
type ItemScalarStringArrayRender struct {
	WireName      string   // wire/JSON key, e.g. "allow_list"
	GoName        string   // exported Go struct field name, e.g. "AllowList"
	LocalName     string   // lower-camel local identifier, e.g. "allowList"
	ItemAttribute string   // synthetic item block attribute name, e.g. "value"
	ItemGoName    string   // exported Go name of the item attribute, e.g. "Value"
	Enum          []string // sorted enum values
	EnumMap       string   // name of the enum valid map variable, "" if none
	EnumValid     string   // name of the enum validation function, "" if none
	MaxItems      int      // reviewed max items bound; 0 means unbounded
	MaxItemsVar   string   // name of the max-items const, "" when unbounded
	Required      bool     // true when the pinned OpenAPI marks the array required
	// ItemMaxLength pins the reviewed per-item string UTF-8 maximum length
	// (0 = no maximum). Enforced in schema, build/encode, and decode.
	ItemMaxLength         int
	CodecPrefix           string // per-item-string-array helper prefix
	ItemAttributeTypes    string // attr.Type map name for the item-string-array item object
	WrapperAttributeTypes string // attr.Type map name for the ownership wrapper
}

// ScalarStringArrayRender is one configs-level scalar-string-array ownership
// collection. Each item block carries a single synthetic enum string attribute
// (ItemAttribute). There is no positional idx and no max-items bound when
// MaxItems is zero.
type ScalarStringArrayRender struct {
	WireName      string   // wire/JSON key, e.g. "allow_methods"
	GoName        string   // exported Go struct field name, e.g. "AllowMethods"
	LocalName     string   // lower-camel local identifier, e.g. "allowMethods"
	ItemAttribute string   // synthetic item block attribute name, e.g. "method"
	ItemGoName    string   // exported Go name of the item attribute, e.g. "Method"
	Enum          []string // sorted enum values
	EnumMap       string   // name of the enum valid map variable
	EnumValid     string   // name of the enum validation function
	MaxItems      int      // reviewed max items bound; 0 means unbounded
	MaxItemsVar   string   // name of the max-items const, "" when unbounded
	Required      bool     // true when the pinned OpenAPI marks the array required
}

// ItemRender is the per-collection list-nested-block item schema.
type ItemRender struct {
	Fields              []ItemFieldRender
	KnownKeys           []string // sorted wire keys incl idx (empty for unindexed items)
	HasFilter           bool
	HasDefaultTrue      bool
	HasClearStrings     bool
	HasItemStringArrays bool
	Unindexed           bool // true when the parent collection has no positional idx
	// IdxKind mirrors the parent collection's idx wire kind ("int" or "string").
	// It is "int" for unindexed items (no idx) and for the default integer idx.
	IdxKind string
	// HasPreserveFromGet is true when any item field is computed-only with
	// PreserveFromGet, so the merge path grafts the fresh GET value into the
	// replacement PUT.
	HasPreserveFromGet bool
}

// ItemFieldRender is one item-level attribute.
type ItemFieldRender struct {
	Name     string // stable Terraform field/block name
	WireName string // wire/JSON key; defaults to Name
	GoName   string
	Kind     string // "string", "boolean", "integer", or "object"
	GoType   string // "types.String", "types.Bool", or "types.Int64" (model field type)
	AttrType string // "types.StringType", "types.BoolType", or "types.Int64Type" (attr.Type map value)
	Required bool
	Optional bool
	// SourceRequired mirrors the pinned OpenAPI/contract wire-required flag for
	// an item field, independent of the Terraform policy (Required). A
	// source-required field (e.g. CSRF filter) rejects a missing response key
	// during decode even when its Terraform policy is optional_computed with a
	// provider default; a source-optional field with a provider default (e.g.
	// bot_deception value_check) decodes a missing key to the reviewed default.
	SourceRequired        bool
	UseState              bool   // use_state_for_unknown plan modifier for optional/computed item fields
	MaxLength             int    // UTF-8 max length when Kind=="string" and >0; else 0
	MinLength             int    // UTF-8 min length when Kind=="string" and >0; else 0
	Pattern               string // regex pattern when Kind=="string" and set; else ""
	Enum                  []string
	EnumMap               string  // name of the enum valid map variable, "" if none
	EnumValid             string  // name of the enum validation function, "" if none
	PatternVar            string  // name of the regexp var, "" if none
	PatternMessage        string  // user-facing validation message for PatternVar
	ProviderDefaultBool   *bool   // reviewed boolean provider default (filter)
	ProviderDefaultString *string // reviewed non-boolean string provider default
	ProviderDefaultInt    *int64  // reviewed integer provider default
	AllowWireNull         bool
	AllowNull             bool // true when the pinned OpenAPI marks a scalar item field nullable
	// AcceptWireNull is AllowNull || AllowWireNull, precomputed so the decode
	// template renders a single boolean literal (an explicit JSON null is
	// accepted for an optional item field that is either OpenAPI-nullable or
	// reviewed wire-nullable via the clear-string modifier).
	AcceptWireNull bool
	IsIntEnum      bool  // true when Kind == "integer" and a reviewed integer enum exists
	Min            int64 // inclusive minimum when Kind=="integer" and bounded; 0 if unset
	Max            int64 // inclusive maximum when Kind=="integer" and bounded; 0 if unset
	HasRange       bool  // true when Kind=="integer" and both min and max bounds exist (two-sided)
	HasMin         bool  // true when Kind=="integer" and a reviewed minimum exists (one- or two-sided)
	HasMax         bool  // true when Kind=="integer" and a reviewed maximum exists (one- or two-sided)
	// BoundMessage is the human-facing bound description for a malformed/
	// invalid item diagnostic; see ScalarRender.BoundMessage.
	BoundMessage string
	// ObjectFields holds the nested scalar fields when Kind == "object" (one
	// level deep). The nested object renders as a SingleNestedBlock inside the
	// item block. ObjectAttrTypes is the per-nested-object attr.Type map name.
	// ObjectKnownKeys are the sorted nested wire keys used by the nested
	// decode's fail-closed unknown-key check.
	ObjectFields    []ItemFieldRender
	ObjectAttrTypes string
	ObjectKnownKeys []string
	// SubItemArray holds the nested array-of-objects render when Kind == "array"
	// (one level deep). The nested array renders as a SingleNestedBlock
	// ownership wrapper containing an `item` ListNestedBlock inside the item
	// block, reusing the ownership omission/empty/populated semantics.
	SubItemArray *SubItemArrayRender
	// ItemScalarStringArray holds the item-level scalar-string-array render when
	// Kind == "string_array" (one level deep), e.g. known_bots
	// bad_bots_list.item.allow_list. It renders as a SingleNestedBlock
	// ownership wrapper containing an `item` ListNestedBlock carrying a single
	// synthetic string attribute, reusing the scalar-string-array omission/
	// empty/populated semantics inside the parent item.
	ItemScalarStringArray *ItemScalarStringArrayRender
	// ComputedOnly is true for reviewed backend-managed item fields (e.g.
	// api_gateway user_list.item.uuid/api_key/create_time). The schema emits
	// Computed: true only (never Optional/Required); the build path skips the
	// field (never read from config/plan/state); the decode path reads the
	// value from GET into state; and the merge path grafts the fresh GET
	// value into the PUT WireItem (PreserveFromGet).
	ComputedOnly bool
	// PreserveFromGet is true when the fresh GET value must be carried into the
	// replacement PUT (omission could clear the backend value). Used only with
	// ComputedOnly.
	PreserveFromGet bool
	// Sensitive is true when the reviewed policy marks this item field
	// sensitive (e.g. api_key). The schema emits Sensitive: true so Terraform
	// redacts the value in plan/output and state diffs. The value is never
	// printed in generated examples or diagnostics. Sensitive redacts in
	// plan/output but does NOT omit the value from Terraform state.
	Sensitive  bool
	SchemaExpr string // full schema.XxxAttribute{...} Go expression
}

// SubItemArrayRender is a nested array-of-objects inside a collection item
// (one level deep), e.g. parameter_validation rule_list.item.sub_rule_list. It
// reuses the object-item ownership semantics: an omitted wrapper preserves the
// raw remote array and keeps state null; a present empty wrapper sends [];
// a present populated wrapper replaces the complete ordered array. The nested
// item schema is scalar-only (no further nesting).
type SubItemArrayRender struct {
	WireName              string            // wire/JSON key, e.g. "sub_rule_list"
	GoName                string            // exported Go struct field name, e.g. "SubRuleList"
	LocalName             string            // lower-camel local identifier, e.g. "subRuleList"
	MaxItems              int               // reviewed max items bound; 0 means unbounded
	MaxItemsVar           string            // name of the max-items const, "" when unbounded
	CodecPrefix           string            // per-sub-array helper prefix
	ItemAttributeTypes    string            // attr.Type map name for the sub-item object
	WrapperAttributeTypes string            // attr.Type map name for the ownership wrapper
	Fields                []ItemFieldRender // sub-item scalar fields (no idx)
	KnownKeys             []string          // sorted sub-item wire keys incl idx
}

// DocsRender is the docs-page view for one resource.
type DocsRender struct {
	PageTitle          string
	Description        string
	ExampleHCL         string
	TemplateExampleHCL string
	ConfigurationNotes string
	ArgumentText       string
	ImportCommand      string
}

// buildRenderModel constructs the render-only model from a manifest.
func buildRenderModel(manifest Manifest) (RenderModel, error) {
	model := RenderModel{
		Marker:   generatedMarker,
		Manifest: manifest,
	}
	for _, resource := range manifest.Resources {
		render, err := buildResourceRender(resource)
		if err != nil {
			return RenderModel{}, fmt.Errorf("resource %q: %w", resource.TerraformName, err)
		}
		model.Resources = append(model.Resources, render)
	}
	return model, nil
}

func buildResourceRender(resource ResourceIR) (ResourceRender, error) {
	configsSchema, err := findConfigsSchema(resource.WireSchema)
	if err != nil {
		return ResourceRender{}, err
	}
	scalarPolicy := map[string]waf.FieldPolicy{}
	collectionPolicy := map[string]waf.CollectionPolicy{}
	itemStringArrayPolicy := map[string]waf.ItemStringArrayPolicy{}
	for _, field := range resource.Reviewed.Fields {
		if field.WireOnly {
			continue
		}
		scalarPolicy[field.Path] = field
	}
	for _, collection := range resource.Reviewed.Collections {
		collectionPolicy[collection.Path] = collection
	}
	for _, array := range resource.Reviewed.ItemStringArrays {
		itemStringArrayPolicy[array.Path] = array
	}

	scalars, err := buildScalars(resource, configsSchema, scalarPolicy)
	if err != nil {
		return ResourceRender{}, err
	}
	crossFieldRules, err := buildCrossFieldRules(configsSchema, scalars)
	if err != nil {
		return ResourceRender{}, err
	}
	collections, err := buildCollections(resource, configsSchema, collectionPolicy, scalarPolicy, itemStringArrayPolicy)
	if err != nil {
		return ResourceRender{}, err
	}
	scalarStringArrayPolicy := map[string]waf.ScalarStringArrayPolicy{}
	for _, array := range resource.Reviewed.ScalarStringArrays {
		scalarStringArrayPolicy[array.Path] = array
	}
	scalarStringArrays, err := buildScalarStringArrays(resource, configsSchema, scalarStringArrayPolicy)
	if err != nil {
		return ResourceRender{}, err
	}

	hasFilter := false
	hasDefaultTrue := false
	hasClearStrings := false
	needsRegexp := false
	needsStringState := false
	needsBoolState := false
	needsInt64State := false
	hasInt64Scalars := false
	hasStringScalars := false
	hasBoolScalars := false
	needsInt64Validator := false
	needsBoolStateImport := false
	needsInt64PlanModifierImport := false
	for _, scalar := range scalars {
		if scalar.UseState {
			if scalar.Kind == "string" {
				needsStringState = true
			} else if scalar.Kind == "boolean" {
				needsBoolState = true
			} else if scalar.Kind == "integer" {
				needsInt64State = true
			}
		}
		switch scalar.Kind {
		case "integer":
			hasInt64Scalars = true
			// int64validator is only imported when an integer config scalar
			// actually emits a Between/AtLeast/AtMost or OneOf validator. A
			// bound-less, enum-less integer scalar has no validator and must
			// not pull in the import (otherwise the generated file fails to
			// compile). A one-sided bound (HasMin/HasMax alone) still emits an
			// AtLeast/AtMost validator and so still requires the import.
			if scalar.HasRange || scalar.HasMin || scalar.HasMax || scalar.IsIntEnum {
				needsInt64Validator = true
			}
		case "string":
			hasStringScalars = true
			if scalar.PatternVar != "" {
				needsRegexp = true
			}
		case "boolean":
			hasBoolScalars = true
		case "object":
			// Nested config object: check sub-fields for validators and imports.
			// Do NOT set needsStringState/needsBoolState/needsInt64State here —
			// the nested object sub-fields use itemFieldSchemaExpr which has its
			// own plan modifier emission. The shared state modifiers are only
			// for top-level config scalars.
			for _, sub := range scalar.ObjectFields {
				if sub.Kind == "integer" && sub.UseState {
					needsInt64PlanModifierImport = true
				}
				if sub.Kind == "integer" && (sub.HasRange || sub.HasMin || sub.HasMax || sub.IsIntEnum) {
					needsInt64Validator = true
				}
				if sub.Kind == "string" && sub.PatternVar != "" {
					needsRegexp = true
				}
				if sub.Kind == "string" {
					hasStringScalars = true
				} else if sub.Kind == "boolean" {
					hasBoolScalars = true
				} else if sub.Kind == "integer" {
					hasInt64Scalars = true
				}
			}
		}
	}
	for _, collection := range collections {
		if collection.Item.HasFilter {
			hasFilter = true
		}
		if collection.Item.HasDefaultTrue {
			hasDefaultTrue = true
		}
		if collection.Item.HasClearStrings {
			hasClearStrings = true
		}
		for _, field := range collection.Item.Fields {
			if field.Pattern != "" {
				needsRegexp = true
			}
			if field.UseState {
				if field.Kind == "boolean" {
					needsBoolStateImport = true
				}
			}
			if field.Kind == "integer" {
				// int64validator is only imported when an item integer field
				// actually emits a Between or OneOf validator. A range-less,
				// enum-less item integer has no validator and must not pull in
				// the import. A one-sided bound (HasMin/HasMax alone) still
				// emits an AtLeast/AtMost validator and so still requires the
				// import.
				if field.HasRange || field.HasMin || field.HasMax || field.EnumMap != "" {
					needsInt64Validator = true
				}
				if field.UseState {
					needsInt64PlanModifierImport = true
				}
			}
			for _, sub := range field.ObjectFields {
				if sub.Pattern != "" {
					needsRegexp = true
				}
				if sub.UseState {
					if sub.Kind == "boolean" {
						needsBoolStateImport = true
					}
				}
				if sub.Kind == "integer" {
					if sub.HasRange || sub.HasMin || sub.HasMax || sub.EnumMap != "" {
						needsInt64Validator = true
					}
				}
			}
			if field.SubItemArray != nil {
				for _, sub := range field.SubItemArray.Fields {
					if sub.Pattern != "" {
						needsRegexp = true
					}
					if sub.UseState && sub.Kind == "boolean" {
						needsBoolStateImport = true
					}
					if sub.Kind == "integer" {
						if sub.HasRange || sub.HasMin || sub.HasMax || sub.EnumMap != "" {
							needsInt64Validator = true
						}
						if sub.UseState {
							needsInt64PlanModifierImport = true
						}
					}
				}
			}
		}
	}

	destroyModeGo := "Forget"
	if resource.Reviewed.Destroy.Mode == "disable" {
		destroyModeGo = "Disable"
	}
	templateDestroyModeGo := "Forget"
	if resource.Reviewed.TemplateDestroy.Mode == "disable" {
		templateDestroyModeGo = "Disable"
	}
	render := ResourceRender{
		TerraformName:                resource.TerraformName,
		GoName:                       resource.GoName,
		LowerCamel:                   lowerCamelIdentifier(resource.GoName),
		TypeNameSuffix:               resource.Reviewed.TypeNameSuffix,
		OperationName:                resource.Reviewed.OperationName,
		GetPath:                      resource.Source.GetPath,
		TemplateGetPath:              resource.Source.TemplateGetPath,
		DestroyModeGo:                destroyModeGo,
		DestroyField:                 resource.Reviewed.Destroy.Field,
		DestroyReason:                resource.Reviewed.Destroy.Reason,
		DestroyVerified:              resource.Reviewed.Destroy.Verified,
		DestroyDisables:              resource.Reviewed.Destroy.Mode == "disable",
		DestroyCandidate:             resource.Reviewed.Destroy.Mode == "forget" && resource.Reviewed.Destroy.Field != "",
		TemplateDestroyModeGo:        templateDestroyModeGo,
		TemplateDestroyField:         resource.Reviewed.TemplateDestroy.Field,
		TemplateDestroyReason:        resource.Reviewed.TemplateDestroy.Reason,
		TemplateDestroyVerified:      resource.Reviewed.TemplateDestroy.Verified,
		TemplateDestroyDisables:      resource.Reviewed.TemplateDestroy.Mode == "disable",
		TemplateDestroyCoupledFields: append([]string(nil), resource.Reviewed.TemplateDestroy.CoupledFields...),
		Scalars:                      scalars,
		CrossFieldRules:              crossFieldRules,
		Collections:                  collections,
		ScalarStringArrays:           scalarStringArrays,
		SharedItemFields:             sharedItemFields(collections),
		SharedKnownKeys:              sharedKnownKeys(collections),
		UsesSharedItemSchema:         usesSharedItemSchema(collections),
		Imports:                      resourceImports(scalars, collections, scalarStringArrays, needsRegexp, needsBoolState || needsBoolStateImport, needsInt64Validator, len(collections) > 0, needsInt64State || needsInt64PlanModifierImport),
		HasFilter:                    hasFilter,
		HasDefaultTrue:               hasDefaultTrue,
		HasClearStrings:              hasClearStrings,
		NeedsRegexp:                  needsRegexp,
		NeedsStringStateModifier:     needsStringState,
		NeedsBoolStateModifier:       needsBoolState,
		NeedsInt64StateModifier:      needsInt64State,
		HasInt64Scalars:              hasInt64Scalars,
		HasStringScalars:             hasStringScalars,
		HasBoolScalars:               hasBoolScalars,
		HasCollections:               len(collections) > 0,
		HasNestedCollections:         hasNestedCollections(collections),
		HasOwnership:                 len(collections) > 0 || len(scalarStringArrays) > 0,
		HasStringIdx:                 hasStringIdx(collections),
		Docs:                         buildDocsRender(resource, scalars, collections, scalarStringArrays, crossFieldRules),
	}
	render.DecodeScalarsSig = decodeScalarsSig(render.LowerCamel, scalars)
	render.DecodeScalarsReturn = "scalarsResult, diagnostics"
	render.OwnershipStruct = ownershipStruct(render.LowerCamel, collections, scalarStringArrays)
	render.OwnershipStructZero = ownershipStructZero(render.LowerCamel, collections, scalarStringArrays, scalars)
	render.OwnershipStructImported = ownershipStructImported(render.LowerCamel, collections, scalarStringArrays, scalars)
	render.OwnershipStructValues = ownershipStructValues(render.LowerCamel, collections, scalarStringArrays, scalars)
	render.ScalarsStruct = scalarsStruct(render.LowerCamel, scalars)
	render.ScalarsStructZero = scalarsStructZero(render.LowerCamel, scalars)
	render.ImportBlock = renderImportBlock(render.Imports)
	return render, nil
}

// renderImportBlock renders the import block with stdlib/third-party/local
// groups separated by blank lines so gofmt keeps the grouping.
func renderImportBlock(imports []string) string {
	stdlib := []string{}
	thirdparty := []string{}
	local := []string{}
	for _, path := range imports {
		switch {
		case strings.Contains(path, ".") && !strings.HasPrefix(path, "terraform-provider-fortiappseccloud"):
			thirdparty = append(thirdparty, path)
		case strings.HasPrefix(path, "terraform-provider-fortiappseccloud"):
			local = append(local, path)
		default:
			stdlib = append(stdlib, path)
		}
	}
	var builder strings.Builder
	first := true
	writeGroup := func(paths []string) {
		if len(paths) == 0 {
			return
		}
		if !first {
			builder.WriteString("\n")
		}
		first = false
		for _, path := range paths {
			builder.WriteString("\t\"" + path + "\"\n")
		}
	}
	writeGroup(stdlib)
	writeGroup(thirdparty)
	writeGroup(local)
	// Remove the trailing newline; the template adds its own.
	return strings.TrimRight(builder.String(), "\n")
}

func findConfigsSchema(root SchemaIR) (SchemaIR, error) {
	for _, field := range root.Fields {
		if field.Name == "configs" && field.Kind == "object" {
			return field, nil
		}
	}
	return SchemaIR{}, fmt.Errorf("PUT schema is missing the configs object")
}

func buildCrossFieldRules(configs SchemaIR, scalars []ScalarRender) ([]CrossFieldRuleRender, error) {
	if len(configs.CrossFieldRules) == 0 {
		return nil, nil
	}
	byName := make(map[string]ScalarRender, len(scalars))
	for _, scalar := range scalars {
		byName[scalar.Name] = scalar
	}
	renders := make([]CrossFieldRuleRender, 0, len(configs.CrossFieldRules))
	for _, rule := range configs.CrossFieldRules {
		configuredCondition, decodedCondition, err := renderCrossFieldCondition(rule.When, byName)
		if err != nil {
			return nil, err
		}
		render := CrossFieldRuleRender{
			ConfiguredCondition: configuredCondition,
			DecodedCondition:    decodedCondition,
		}
		switch rule.Kind {
		case "conditional_range":
			field, ok := byName[rule.Field]
			if !ok || field.Kind != "integer" || rule.Minimum == nil || rule.Maximum == nil {
				return nil, fmt.Errorf("cross-field conditional_range %q does not resolve to one rendered integer scalar", rule.Field)
			}
			render.ConfiguredKnown = configuredScalarKnown(field)
			render.DecodedKnown = decodedScalarKnown(field)
			render.ConfiguredViolation = fmt.Sprintf("values.%s.ValueInt64() < %d || values.%s.ValueInt64() > %d", field.GoName, *rule.Minimum, field.GoName, *rule.Maximum)
			decoded := decodedScalarValue(field)
			render.DecodedViolation = fmt.Sprintf("%s < %d || %s > %d", decoded, *rule.Minimum, decoded, *rule.Maximum)
			render.Message = fmt.Sprintf("%s must be between %d and %d when its enabling condition is true.", rule.Field, *rule.Minimum, *rule.Maximum)
			render.Docs = fmt.Sprintf("`%s` must be between %d and %d when its enabling condition is true.", rule.Field, *rule.Minimum, *rule.Maximum)
		case "compare":
			left, leftOK := byName[rule.Left]
			right, rightOK := byName[rule.Right]
			if !leftOK || !rightOK || left.Kind != "integer" || right.Kind != "integer" {
				return nil, fmt.Errorf("cross-field compare %q %s %q does not resolve to rendered integer scalars", rule.Left, rule.Operator, rule.Right)
			}
			render.ConfiguredKnown = crossFieldGuard(configuredScalarKnown(left), configuredScalarKnown(right))
			render.DecodedKnown = crossFieldGuard(decodedScalarKnown(left), decodedScalarKnown(right))
			configuredLeft := "values." + left.GoName + ".ValueInt64()"
			configuredRight := "values." + right.GoName + ".ValueInt64()"
			decodedLeft := decodedScalarValue(left)
			decodedRight := decodedScalarValue(right)
			violation, prose, err := crossFieldCompareExpressions(rule.Operator, configuredLeft, configuredRight, decodedLeft, decodedRight)
			if err != nil {
				return nil, err
			}
			render.ConfiguredViolation = violation[0]
			render.DecodedViolation = violation[1]
			render.Message = fmt.Sprintf("%s must be %s %s.", rule.Left, prose, rule.Right)
			render.Docs = fmt.Sprintf("`%s` must be %s `%s`%s.", rule.Left, prose, rule.Right, crossFieldWhenDocsSuffix(rule.When))
		default:
			return nil, fmt.Errorf("unsupported rendered cross-field rule kind %q", rule.Kind)
		}
		renders = append(renders, render)
		renders[len(renders)-1].ConfiguredGuard = crossFieldGuard(render.ConfiguredCondition, render.ConfiguredKnown)
		renders[len(renders)-1].DecodedGuard = crossFieldGuard(render.DecodedCondition, render.DecodedKnown)
		if renders[len(renders)-1].ConfiguredGuard != "true" {
			renders[len(renders)-1].ConfiguredGuardPrefix = renders[len(renders)-1].ConfiguredGuard + " && "
		}
		if renders[len(renders)-1].DecodedGuard != "true" {
			renders[len(renders)-1].DecodedGuardPrefix = renders[len(renders)-1].DecodedGuard + " && "
		}
	}
	return renders, nil
}

func crossFieldGuard(expressions ...string) string {
	parts := make([]string, 0, len(expressions))
	for _, expression := range expressions {
		if expression != "" && expression != "true" {
			parts = append(parts, expression)
		}
	}
	if len(parts) == 0 {
		return "true"
	}
	return strings.Join(parts, " && ")
}

func renderCrossFieldCondition(condition *CrossFieldConditionIR, scalars map[string]ScalarRender) (string, string, error) {
	if condition == nil {
		return "true", "true", nil
	}
	if len(condition.AllOf) != 0 {
		configured := make([]string, 0, len(condition.AllOf))
		decoded := make([]string, 0, len(condition.AllOf))
		for index := range condition.AllOf {
			configuredChild, decodedChild, err := renderCrossFieldCondition(&condition.AllOf[index], scalars)
			if err != nil {
				return "", "", err
			}
			configured = append(configured, "("+configuredChild+")")
			decoded = append(decoded, "("+decodedChild+")")
		}
		return strings.Join(configured, " && "), strings.Join(decoded, " && "), nil
	}
	field, ok := scalars[condition.Field]
	if !ok || field.Kind != "boolean" || condition.Equals == nil {
		return "", "", fmt.Errorf("cross-field condition %q does not resolve to one rendered boolean scalar", condition.Field)
	}
	want := strconv.FormatBool(*condition.Equals)
	configured := fmt.Sprintf("%s && values.%s.ValueBool() == %s", configuredScalarKnown(field), field.GoName, want)
	decoded := fmt.Sprintf("%s && %s == %s", decodedScalarKnown(field), decodedScalarValue(field), want)
	return configured, decoded, nil
}

func configuredScalarKnown(field ScalarRender) string {
	return fmt.Sprintf("!values.%s.IsNull() && !values.%s.IsUnknown()", field.GoName, field.GoName)
}

func decodedScalarKnown(field ScalarRender) string {
	if field.Required {
		return "true"
	}
	return "values." + field.GoName + " != nil"
}

func decodedScalarValue(field ScalarRender) string {
	if field.Required {
		return "values." + field.GoName
	}
	return "*values." + field.GoName
}

func crossFieldCompareExpressions(operator, configuredLeft, configuredRight, decodedLeft, decodedRight string) ([2]string, string, error) {
	var invalid, prose string
	switch operator {
	case "less_than":
		invalid, prose = ">=", "less than"
	case "less_than_or_equal":
		invalid, prose = ">", "less than or equal to"
	case "greater_than":
		invalid, prose = "<=", "greater than"
	case "greater_than_or_equal":
		invalid, prose = "<", "greater than or equal to"
	default:
		return [2]string{}, "", fmt.Errorf("unsupported rendered cross-field compare operator %q", operator)
	}
	return [2]string{
		configuredLeft + " " + invalid + " " + configuredRight,
		decodedLeft + " " + invalid + " " + decodedRight,
	}, prose, nil
}

func crossFieldWhenDocsSuffix(condition *CrossFieldConditionIR) string {
	if condition == nil {
		return ""
	}
	return " when the documented enabling condition is true"
}

func buildScalars(resource ResourceIR, configs SchemaIR, policy map[string]waf.FieldPolicy) ([]ScalarRender, error) {
	var scalars []ScalarRender
	for _, field := range configs.Fields {
		switch field.Kind {
		case "string", "boolean", "integer", "object":
		case "array":
			continue
		default:
			return nil, fmt.Errorf("unsupported configs scalar %q kind %q", field.Name, field.Kind)
		}
		path := "configs." + field.Name
		fieldPolicy, ok := policy[path]
		if !ok && field.Kind != "object" {
			return nil, fmt.Errorf("configs scalar %q has no reviewed policy", path)
		}
		readOnly := field.ReadOnly != nil && *field.ReadOnly
		if field.Kind != "object" && fieldPolicy.TerraformPolicy != "optional_computed" && fieldPolicy.TerraformPolicy != "computed" {
			return nil, fmt.Errorf("configs scalar %q policy %q is neither optional_computed nor computed", path, fieldPolicy.TerraformPolicy)
		}
		if field.Kind != "object" && (fieldPolicy.TerraformPolicy == "computed") != readOnly {
			return nil, fmt.Errorf("configs scalar %q computed policy does not match OpenAPI readOnly", path)
		}
		scalar := ScalarRender{
			Name:          field.Name,
			GoName:        exportedName(field.Name),
			Kind:          field.Kind,
			GoType:        goTypeFor(field.Kind),
			AttrType:      attrTypeFor(field.Kind),
			Required:      field.Required,
			ComputedOnly:  fieldPolicy.TerraformPolicy == "computed",
			UseState:      fieldPolicy.UseStateForUnknown,
			AllowNull:     fieldPolicy.AllowNull,
			AllowWireNull: fieldPolicy.AllowWireNull,
			Sensitive:     fieldPolicy.Sensitive,
		}
		if field.Kind == "object" {
			// Nested-object config fields don't have their own scalar policy;
			// their sub-fields have individual policies. Reset policy-driven
			// fields that were set from a nil fieldPolicy.
			scalar.UseState = false
			scalar.AllowNull = false
			scalar.AllowWireNull = false
			scalar.Sensitive = false
		}
		// A reviewed OpenAPI default is decoded on a missing key (not nil) so a
		// configured-default value does not perpetual-diff when the backend omits
		// default-valued keys. Mirrors the item-field decode-default behavior.
		switch field.Kind {
		case "string":
			if defaultValue, ok := stringDefault(field.Default); ok {
				scalar.HasDefault = true
				scalar.DefaultLiteral = `"` + strings.ReplaceAll(strings.ReplaceAll(defaultValue, `\`, `\\`), `"`, `\"`) + `"`
			}
		case "boolean":
			if defaultValue, ok := boolDefault(field.Default); ok {
				scalar.HasDefault = true
				if defaultValue {
					scalar.DefaultLiteral = "true"
				} else {
					scalar.DefaultLiteral = "false"
				}
			}
		case "integer":
			if defaultValue, ok := int64Default(field.Default); ok {
				scalar.HasDefault = true
				scalar.DefaultLiteral = "int64(" + strconv.FormatInt(defaultValue, 10) + ")"
			}
		case "object":
			subFields, _, err := buildNestedConfigObjectFields(resource, field, policy)
			if err != nil {
				return nil, err
			}
			scalar.ObjectFields = subFields
			scalar.ObjectAttrTypes = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(field.Name) + "AttributeTypes"
			scalar.AttrType = "types.ObjectType{AttrTypes: " + scalar.ObjectAttrTypes + "}"
		}
		scalar.WireType = scalarWireType(scalar)
		scalar.PatchType = patchTypeFor(field.Kind)
		if field.Kind == "string" {
			if field.MaxLength != nil && *field.MaxLength > 0 {
				scalar.MaxLength = *field.MaxLength
			}
			if field.MinLength != nil && *field.MinLength > 0 {
				scalar.MinLength = *field.MinLength
			}
			if field.Pattern != "" {
				scalar.Pattern = field.Pattern
				scalar.PatternVar = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(field.Name) + "Pattern"
				scalar.PatternMessage = patternValidationMessage(field.Pattern)
			}
			scalar.Enum = stringEnumValues(field.Enum)
			if len(scalar.Enum) > 0 {
				scalar.EnumMap = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(field.Name) + "Values"
				scalar.EnumValid = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(field.Name) + "Valid"
			}
			if len(fieldPolicy.WireAliases) > 0 {
				if len(scalar.Enum) == 0 {
					return nil, fmt.Errorf("configs scalar %q has wire aliases without a reviewed enum", path)
				}
				aliasKeys := make([]string, 0, len(fieldPolicy.WireAliases))
				for wireValue := range fieldPolicy.WireAliases {
					aliasKeys = append(aliasKeys, wireValue)
				}
				sort.Strings(aliasKeys)
				for _, wireValue := range aliasKeys {
					terraformValue := fieldPolicy.WireAliases[wireValue]
					if strings.TrimSpace(wireValue) == "" || wireValue == terraformValue || !stringSliceContains(scalar.Enum, wireValue) || stringSliceContains(scalar.Enum, terraformValue) {
						return nil, fmt.Errorf("configs scalar %q has invalid wire alias %q -> %q", path, wireValue, terraformValue)
					}
					for index := range scalar.Enum {
						if scalar.Enum[index] == wireValue {
							scalar.Enum[index] = terraformValue
						}
					}
					if scalar.HasDefault && scalar.DefaultLiteral == strconv.Quote(wireValue) {
						scalar.DefaultLiteral = strconv.Quote(terraformValue)
					}
					scalar.WireAliases = append(scalar.WireAliases, WireAliasRender{WireLiteral: strconv.Quote(wireValue), TerraformLiteral: strconv.Quote(terraformValue)})
				}
				sort.Strings(scalar.Enum)
			}
		} else if len(fieldPolicy.WireAliases) > 0 {
			return nil, fmt.Errorf("non-string configs scalar %q cannot declare wire aliases", path)
		}
		if field.Kind == "integer" {
			if field.Minimum != nil {
				scalar.Min = int64(*field.Minimum)
				scalar.HasMin = true
			}
			if field.Maximum != nil {
				scalar.Max = int64(*field.Maximum)
				scalar.HasMax = true
			}
			// HasRange marks a complete two-sided range; one-sided bounds
			// render as AtLeast/AtMost below so a missing endpoint is never
			// silently treated as zero.
			scalar.HasRange = scalar.HasMin && scalar.HasMax
			scalar.BoundMessage = integerBoundMessage(scalar.HasMin, scalar.HasMax, scalar.Min, scalar.Max)
			scalar.DecodeMin = scalar.Min
			scalar.DecodeMax = scalar.Max
			scalar.DecodeHasMin = scalar.HasMin
			scalar.DecodeHasMax = scalar.HasMax
			if fieldPolicy.RemoteMaximum != nil {
				if !scalar.HasMax || *fieldPolicy.RemoteMaximum <= scalar.Max {
					return nil, fmt.Errorf("configs scalar %q remote maximum must exceed its pinned configurable maximum", path)
				}
				scalar.DecodeMax = *fieldPolicy.RemoteMaximum
				scalar.DecodeHasMax = true
			}
			scalar.DecodeBoundMessage = integerBoundMessage(scalar.DecodeHasMin, scalar.DecodeHasMax, scalar.DecodeMin, scalar.DecodeMax)
			intEnum := intEnumStringValues(field.Enum)
			if len(intEnum) > 0 {
				scalar.Enum = intEnum
				scalar.IsIntEnum = true
				scalar.EnumMap = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(field.Name) + "Values"
				scalar.EnumValid = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(field.Name) + "Valid"
			}
		}
		if field.Kind != "integer" && fieldPolicy.RemoteMaximum != nil {
			return nil, fmt.Errorf("non-integer configs scalar %q cannot declare a remote maximum", path)
		}
		scalar.SchemaExpr = scalarSchemaExpr(resource, scalar)
		scalars = append(scalars, scalar)
	}
	sort.SliceStable(scalars, func(i, j int) bool { return scalars[i].Name < scalars[j].Name })
	return scalars, nil
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// buildNestedConfigObjectFields renders the scalar fields of one nested-object
// config field (one level deep), e.g. caching_compression configs.cache.
func buildNestedConfigObjectFields(resource ResourceIR, objectField SchemaIR, scalarPolicy map[string]waf.FieldPolicy) ([]ItemFieldRender, []string, error) {
	var subFields []ItemFieldRender
	var subKeys []string
	parent := "configs." + objectField.Name
	for _, sub := range objectField.Fields {
		if sub.Kind == "array" {
			// Array sub-fields (sub-collections and sub-scalar-string-arrays) are
			// handled separately by buildCollections and buildScalarStringArrays.
			continue
		}
		path := parent + "." + sub.Name
		fieldPolicy, ok := scalarPolicy[path]
		if !ok {
			return nil, nil, fmt.Errorf("nested config object field %q has no reviewed policy", path)
		}
		if sub.Kind != "string" && sub.Kind != "boolean" && sub.Kind != "integer" {
			return nil, nil, fmt.Errorf("nested config object field %q kind %q is unsupported (one level only)", path, sub.Kind)
		}
		field := ItemFieldRender{
			Name:           sub.Name,
			WireName:       reviewedWireName(sub.Name, fieldPolicy),
			GoName:         exportedName(sub.Name),
			Kind:           sub.Kind,
			GoType:         goTypeFor(sub.Kind),
			AttrType:       attrTypeFor(sub.Kind),
			UseState:       fieldPolicy.UseStateForUnknown,
			SourceRequired: sub.Required,
			AllowNull:      fieldPolicy.AllowNull,
			AcceptWireNull: fieldPolicy.AllowNull || fieldPolicy.AllowWireNull,
		}
		switch fieldPolicy.TerraformPolicy {
		case "required":
			field.Required = true
		case "optional_computed":
			field.Optional = true
		default:
			return nil, nil, fmt.Errorf("nested config object field %q policy %q is unsupported", path, fieldPolicy.TerraformPolicy)
		}
		if sub.Kind == "string" {
			if sub.MaxLength != nil && *sub.MaxLength > 0 {
				field.MaxLength = *sub.MaxLength
			}
			field.Enum = stringEnumValues(sub.Enum)
			if len(field.Enum) > 0 {
				field.EnumMap = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(objectField.Name) + exportedName(sub.Name) + "Values"
				field.EnumValid = lowerCamelIdentifier(resource.GoName) + "Config" + exportedName(objectField.Name) + exportedName(sub.Name) + "Valid"
			}
		}
		if sub.Kind == "integer" {
			if sub.Minimum != nil {
				field.Min = int64(*sub.Minimum)
				field.HasMin = true
			}
			if sub.Maximum != nil {
				field.Max = int64(*sub.Maximum)
				field.HasMax = true
			}
			field.HasRange = field.HasMin && field.HasMax
			field.BoundMessage = integerBoundMessage(field.HasMin, field.HasMax, field.Min, field.Max)
			if field.Optional {
				if defaultValue, ok := int64Default(sub.Default); ok {
					field.ProviderDefaultInt = &defaultValue
				}
			}
		}
		if field.Optional && sub.Kind == "string" {
			if defaultValue, ok := stringDefault(sub.Default); ok {
				field.ProviderDefaultString = &defaultValue
			}
		}
		field.SchemaExpr = itemFieldSchemaExpr(resource, field)
		subFields = append(subFields, field)
		subKeys = append(subKeys, field.WireName)
	}
	sort.Strings(subKeys)
	return subFields, subKeys, nil
}

func buildCollections(resource ResourceIR, configs SchemaIR, collectionPolicy map[string]waf.CollectionPolicy, scalarPolicy map[string]waf.FieldPolicy, itemStringArrayPolicy map[string]waf.ItemStringArrayPolicy) ([]CollectionRender, error) {
	var collections []CollectionRender
	for _, field := range configs.Fields {
		if field.Kind != "array" {
			continue
		}
		// Scalar-string-array collections are reviewed via the
		// ScalarStringArrays policy and rendered separately; only object-item
		// ordered collections are rendered here.
		if field.Items != nil && field.Items.Kind != "object" {
			continue
		}
		path := "configs." + field.Name
		collPolicy, ok := collectionPolicy[path]
		if !ok {
			return nil, fmt.Errorf("configs collection %q has no reviewed policy", path)
		}
		if collPolicy.WrapperBlock != field.Name {
			return nil, fmt.Errorf("configs collection %q wrapper block mismatch", path)
		}
		maxItems := 0
		if field.MaxItems != nil {
			maxItems = *field.MaxItems
		}
		if field.Items == nil || field.Items.Kind != "object" {
			return nil, fmt.Errorf("configs collection %q has no object item schema", path)
		}
		item, err := buildItemRender(resource, *field.Items, field.Name, scalarPolicy, itemStringArrayPolicy)
		if err != nil {
			return nil, fmt.Errorf("configs collection %q: %w", path, err)
		}
		item.Unindexed = collPolicy.Unindexed
		// An unindexed collection has no positional idx, so IdxKind is "int"
		// (the default/absent case) regardless of the reviewed item schema.
		if collPolicy.Unindexed {
			item.IdxKind = "int"
		}
		goName := exportedName(field.Name)
		// MaxItems 0 means the reviewed collection is unbounded (no maxItems in
		// the pinned OpenAPI). A positive bound still requires a
		// matching source maxItems; the contract validator enforces that.
		maxItemsVar := ""
		if maxItems > 0 {
			maxItemsVar = lowerCamelIdentifier(resource.GoName) + goName + "MaxItems"
		}
		codecPrefix := lowerCamelIdentifier(resource.GoName) + goName
		hasNested := false
		hasItemStringArrays := false
		for _, f := range item.Fields {
			if f.Kind == "object" {
				hasNested = true
			}
			if f.Kind == "string_array" {
				hasItemStringArrays = true
			}
		}
		collections = append(collections, CollectionRender{
			WireName:              field.Name,
			GoName:                goName,
			LocalName:             lowerCamelIdentifier(goName),
			MaxItems:              maxItems,
			MaxItemsVar:           maxItemsVar,
			Item:                  item,
			Unindexed:             collPolicy.Unindexed,
			CodecPrefix:           codecPrefix,
			ItemAttributeTypes:    codecPrefix + "ItemAttributeTypes",
			WrapperAttributeTypes: codecPrefix + "WrapperAttributeTypes",
			HasNestedObjects:      hasNested,
			HasItemStringArrays:   hasItemStringArrays,
			IdxKind:               item.IdxKind,
		})
	}
	// For nested-object config fields (e.g. caching_compression cache/compress),
	// look inside the object for nested collections.
	for _, field := range configs.Fields {
		if field.Kind != "object" || field.Fields == nil {
			continue
		}
		for _, sub := range field.Fields {
			if sub.Kind != "array" || sub.Items == nil || sub.Items.Kind != "object" {
				continue
			}
			name := field.Name + "." + sub.Name
			path := "configs." + name
			collPolicy, ok := collectionPolicy[path]
			if !ok {
				return nil, fmt.Errorf("nested configs collection %q has no reviewed policy", path)
			}
			maxItems := 0
			if sub.MaxItems != nil {
				maxItems = *sub.MaxItems
			}
			item, err := buildItemRender(resource, *sub.Items, name, scalarPolicy, itemStringArrayPolicy)
			if err != nil {
				return nil, fmt.Errorf("nested configs collection %q: %w", path, err)
			}
			item.Unindexed = collPolicy.Unindexed
			goName := exportedName(field.Name) + exportedName(sub.Name)
			maxItemsVar := ""
			if maxItems > 0 {
				maxItemsVar = lowerCamelIdentifier(resource.GoName) + goName + "MaxItems"
			}
			codecPrefix := lowerCamelIdentifier(resource.GoName) + goName
			hasNested := false
			hasItemStringArrays := false
			for _, f := range item.Fields {
				if f.Kind == "object" {
					hasNested = true
				}
				if f.Kind == "string_array" {
					hasItemStringArrays = true
				}
			}
			collections = append(collections, CollectionRender{
				WireName:              sub.Name,
				WireParent:            field.Name,
				GoName:                goName,
				LocalName:             lowerCamelIdentifier(goName),
				MaxItems:              maxItems,
				MaxItemsVar:           maxItemsVar,
				Item:                  item,
				Unindexed:             collPolicy.Unindexed,
				CodecPrefix:           codecPrefix,
				ItemAttributeTypes:    codecPrefix + "ItemAttributeTypes",
				WrapperAttributeTypes: codecPrefix + "WrapperAttributeTypes",
				HasNestedObjects:      hasNested,
				HasItemStringArrays:   hasItemStringArrays,
				IdxKind:               item.IdxKind,
			})
		}
	}
	sort.SliceStable(collections, func(i, j int) bool { return collections[i].WireName < collections[j].WireName })
	return collections, nil
}

// buildScalarStringArrays renders the reviewed scalar-string-array ownership
// collections from the configs schema. Each is a configs array of bare enum
// strings with no object item schema and no positional idx.
func buildScalarStringArrays(resource ResourceIR, configs SchemaIR, policy map[string]waf.ScalarStringArrayPolicy) ([]ScalarStringArrayRender, error) {
	var arrays []ScalarStringArrayRender
	for _, field := range configs.Fields {
		if field.Kind != "array" {
			continue
		}
		if field.Items == nil || field.Items.Kind != "string" {
			continue
		}
		path := "configs." + field.Name
		arrayPolicy, ok := policy[path]
		if !ok {
			return nil, fmt.Errorf("configs scalar string array %q has no reviewed policy", path)
		}
		if arrayPolicy.WrapperBlock != field.Name {
			return nil, fmt.Errorf("configs scalar string array %q wrapper block mismatch", path)
		}
		enum := stringEnumValues(field.Items.Enum)
		if !sortedStringsEqual(enum, sortedStringSlice(arrayPolicy.Enum)) {
			return nil, fmt.Errorf("configs scalar string array %q enum mismatch", path)
		}
		goName := exportedName(field.Name)
		render := ScalarStringArrayRender{
			WireName:      field.Name,
			GoName:        goName,
			LocalName:     lowerCamelIdentifier(goName),
			ItemAttribute: arrayPolicy.ItemAttribute,
			ItemGoName:    exportedName(arrayPolicy.ItemAttribute),
			Enum:          enum,
			MaxItems:      arrayPolicy.MaxItems,
			Required:      arrayPolicy.Required,
		}
		if len(enum) > 0 {
			render.EnumMap = lowerCamelIdentifier(resource.GoName) + exportedName(field.Name) + "Values"
			render.EnumValid = lowerCamelIdentifier(resource.GoName) + exportedName(field.Name) + "Valid"
		}
		if arrayPolicy.MaxItems > 0 {
			render.MaxItemsVar = lowerCamelIdentifier(resource.GoName) + exportedName(field.Name) + "MaxItems"
		}
		arrays = append(arrays, render)
	}
	sort.SliceStable(arrays, func(i, j int) bool { return arrays[i].WireName < arrays[j].WireName })
	return arrays, nil
}

func buildItemRender(resource ResourceIR, itemSchema SchemaIR, collectionName string, scalarPolicy map[string]waf.FieldPolicy, itemStringArrayPolicy map[string]waf.ItemStringArrayPolicy) (ItemRender, error) {
	// Multiple sibling nested array-of-objects fields per item are supported
	// (e.g. api_gateway user_list.item.ip_list + referer_list). Each nested
	// array carries its own per-item ownership mask, so the build/decode/merge
	// logic threads one mask per nested array rather than one shared mask.
	var fields []ItemFieldRender
	var knownKeys []string
	hasFilter := false
	hasDefaultTrue := false
	hasClearStrings := false
	hasPreserveFromGet := false
	idxKind := "int"
	for _, itemField := range itemSchema.Fields {
		path := "configs." + collectionName + ".item." + itemField.Name
		if itemField.Name == "idx" {
			if itemField.Kind != "integer" && itemField.Kind != "string" {
				return ItemRender{}, fmt.Errorf("item field %q must be an integer or string, got %q", path, itemField.Kind)
			}
			if itemField.Kind == "string" {
				idxKind = "string"
			}
			knownKeys = append(knownKeys, "idx")
			continue
		}
		wireName := itemField.Name
		terraformName := itemField.Name
		if fieldPolicy, ok := scalarPolicy[path]; ok {
			wireName = reviewedWireName(itemField.Name, fieldPolicy)
			terraformName = reviewedTerraformName(itemField.Name, fieldPolicy)
		}
		switch itemField.Kind {
		case "object":
			subFields, subKeys, err := buildNestedObjectFields(resource, itemField, collectionName, scalarPolicy)
			if err != nil {
				return ItemRender{}, err
			}
			attrTypesName := lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(itemField.Name) + "AttributeTypes"
			field := ItemFieldRender{
				Name:            terraformName,
				WireName:        wireName,
				GoName:          exportedName(terraformName),
				Kind:            "object",
				GoType:          "types.Object",
				AttrType:        "types.ObjectType{AttrTypes: " + attrTypesName + "}",
				Required:        itemField.Required,
				Optional:        !itemField.Required,
				ObjectFields:    subFields,
				ObjectAttrTypes: attrTypesName,
				ObjectKnownKeys: subKeys,
			}
			field.SchemaExpr = nestedObjectBlockSchemaExpr(resource, field)
			fields = append(fields, field)
			knownKeys = append(knownKeys, wireName)
			continue
		case "array":
			if itemField.Items == nil {
				return ItemRender{}, fmt.Errorf("configs.%s.item.%s array is missing items", collectionName, itemField.Name)
			}
			if itemField.Items.Kind == "string" {
				// Item-level scalar-string-array field (e.g. known_bots
				// bad_bots_list.item.allow_list): render as an ownership wrapper
				// of item blocks carrying a synthetic string attribute, reusing
				// the scalar-string-array omission/empty/populated semantics
				// inside the parent item.
				strArray, err := buildItemStringArray(resource, itemField, collectionName, itemStringArrayPolicy)
				if err != nil {
					return ItemRender{}, err
				}
				strArray.WireName = wireName
				field := ItemFieldRender{
					Name:                  terraformName,
					WireName:              wireName,
					GoName:                exportedName(terraformName),
					Kind:                  "string_array",
					GoType:                "types.Object",
					AttrType:              "types.ObjectType{AttrTypes: " + strArray.WrapperAttributeTypes + "}",
					Required:              itemField.Required,
					Optional:              !itemField.Required,
					ItemScalarStringArray: strArray,
				}
				field.SchemaExpr = itemStringArrayBlockSchemaExpr(resource, field)
				fields = append(fields, field)
				knownKeys = append(knownKeys, wireName)
				continue
			}
			if itemField.Required {
				return ItemRender{}, fmt.Errorf("configs.%s.item.%s is a required array; required nested arrays are not yet supported (only optional ownership wrappers)", collectionName, itemField.Name)
			}
			subArray, err := buildSubItemArray(resource, itemField, collectionName, scalarPolicy)
			if err != nil {
				return ItemRender{}, err
			}
			subArray.WireName = wireName
			field := ItemFieldRender{
				Name:         terraformName,
				WireName:     wireName,
				GoName:       exportedName(terraformName),
				Kind:         "array",
				GoType:       "types.Object",
				AttrType:     "types.ObjectType{AttrTypes: " + subArray.WrapperAttributeTypes + "}",
				Required:     itemField.Required,
				Optional:     !itemField.Required,
				SubItemArray: subArray,
			}
			field.SchemaExpr = subItemArrayBlockSchemaExpr(resource, field)
			fields = append(fields, field)
			knownKeys = append(knownKeys, wireName)
			continue
		case "string", "boolean", "integer":
		default:
			return ItemRender{}, fmt.Errorf("item field %q kind %q is unsupported", path, itemField.Kind)
		}
		fieldPolicy, ok := scalarPolicy[path]
		if !ok {
			return ItemRender{}, fmt.Errorf("item field %q has no reviewed policy", path)
		}
		field := ItemFieldRender{
			Name:           terraformName,
			WireName:       reviewedWireName(itemField.Name, fieldPolicy),
			GoName:         exportedName(terraformName),
			Kind:           itemField.Kind,
			GoType:         goTypeFor(itemField.Kind),
			AttrType:       attrTypeFor(itemField.Kind),
			UseState:       fieldPolicy.UseStateForUnknown,
			AllowNull:      fieldPolicy.AllowNull,
			SourceRequired: itemField.Required,
		}
		switch fieldPolicy.TerraformPolicy {
		case "required":
			field.Required = true
		case "optional_computed":
			field.Optional = true
		case "computed":
			// Computed-only (backend-managed) item fields: Computed schema
			// (never config), carried from the fresh GET into the PUT, never
			// read from config/plan/state. Only optional item string fields are
			// supported; reject other kinds until separately reviewed.
			if itemField.Kind != "string" {
				return ItemRender{}, fmt.Errorf("item field %q has computed policy but kind %q is unsupported (only string)", path, itemField.Kind)
			}
			field.ComputedOnly = true
			field.PreserveFromGet = fieldPolicy.PreserveFromGet
			field.Sensitive = fieldPolicy.Sensitive
			if fieldPolicy.PreserveFromGet {
				hasPreserveFromGet = true
			}
		default:
			return ItemRender{}, fmt.Errorf("item field %q policy %q is unsupported", path, fieldPolicy.TerraformPolicy)
		}
		if itemField.Kind == "string" {
			if itemField.MaxLength != nil && *itemField.MaxLength > 0 {
				field.MaxLength = *itemField.MaxLength
			}
			if itemField.MinLength != nil && *itemField.MinLength > 0 {
				field.MinLength = *itemField.MinLength
			}
			if itemField.Pattern != "" {
				field.Pattern = itemField.Pattern
				field.PatternVar = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(itemField.Name) + "Pattern"
				field.PatternMessage = patternValidationMessage(itemField.Pattern)
			}
			field.Enum = stringEnumValues(itemField.Enum)
			if len(field.Enum) > 0 {
				field.EnumMap = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(itemField.Name) + "Values"
				field.EnumValid = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(itemField.Name) + "Valid"
			}
			// An optional string item field with a reviewed OpenAPI default
			// (e.g. rewriting_requests protocol default "HTTP") sends that
			// default when the practitioner omits it, and the unchanged-
			// projection canonicalization treats the default and an absent
			// field as equal. Mirror the integer/boolean provider-default
			// pattern so the default flows to encode, decode, and the matcher.
			if field.Optional {
				if defaultValue, ok := stringDefault(itemField.Default); ok {
					field.ProviderDefaultString = &defaultValue
				}
			}
		}
		if itemField.Kind == "integer" {
			if itemField.Minimum != nil {
				field.Min = int64(*itemField.Minimum)
				field.HasMin = true
			}
			if itemField.Maximum != nil {
				field.Max = int64(*itemField.Maximum)
				field.HasMax = true
			}
			field.HasRange = field.HasMin && field.HasMax
			field.BoundMessage = integerBoundMessage(field.HasMin, field.HasMax, field.Min, field.Max)
			field.Enum = intEnumStringValues(itemField.Enum)
			if len(field.Enum) > 0 {
				field.IsIntEnum = true
				field.EnumMap = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(itemField.Name) + "Values"
				field.EnumValid = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(itemField.Name) + "Valid"
			}
			// An optional integer item field with a reviewed OpenAPI default
			// sends that default when the practitioner omits it, mirroring the
			// boolean filter provider-default pattern, so the backend does not
			// store 0 in place of the reviewed default.
			if field.Optional {
				if defaultValue, ok := int64Default(itemField.Default); ok {
					field.ProviderDefaultInt = &defaultValue
				}
			}
		}
		if fieldPolicy.ProviderDefault != nil && itemField.Kind == "boolean" {
			field.ProviderDefaultBool = fieldPolicy.ProviderDefault
			if *fieldPolicy.ProviderDefault {
				hasDefaultTrue = true
			} else {
				hasFilter = true
			}
		}
		if fieldPolicy.AllowWireNull && itemField.Kind == "string" {
			field.AllowWireNull = true
			hasClearStrings = true
		}
		field.AcceptWireNull = field.AllowNull || field.AllowWireNull
		field.SchemaExpr = itemFieldSchemaExpr(resource, field)
		fields = append(fields, field)
		knownKeys = append(knownKeys, field.WireName)
	}
	if len(fields) == 0 {
		return ItemRender{}, fmt.Errorf("item schema has no non-idx fields")
	}
	sort.Strings(knownKeys)
	return ItemRender{
		Fields:             fields,
		KnownKeys:          knownKeys,
		HasFilter:          hasFilter,
		HasDefaultTrue:     hasDefaultTrue,
		HasClearStrings:    hasClearStrings,
		IdxKind:            idxKind,
		HasPreserveFromGet: hasPreserveFromGet,
	}, nil
}

// buildNestedObjectFields renders the scalar fields of one nested-object item
// field (one level deep). It returns the sub-field renders and the sorted
// nested wire keys (without the parent object prefix).
func buildNestedObjectFields(resource ResourceIR, objectField SchemaIR, collectionName string, scalarPolicy map[string]waf.FieldPolicy) ([]ItemFieldRender, []string, error) {
	var subFields []ItemFieldRender
	var subKeys []string
	parent := "configs." + collectionName + ".item." + objectField.Name
	for _, sub := range objectField.Fields {
		path := parent + "." + sub.Name
		fieldPolicy, ok := scalarPolicy[path]
		if !ok {
			return nil, nil, fmt.Errorf("nested object field %q has no reviewed policy", path)
		}
		if sub.Kind != "string" && sub.Kind != "boolean" && sub.Kind != "integer" {
			return nil, nil, fmt.Errorf("nested object field %q kind %q is unsupported (one level only)", path, sub.Kind)
		}
		field := ItemFieldRender{
			Name:           sub.Name,
			WireName:       reviewedWireName(sub.Name, fieldPolicy),
			GoName:         exportedName(sub.Name),
			Kind:           sub.Kind,
			GoType:         goTypeFor(sub.Kind),
			AttrType:       attrTypeFor(sub.Kind),
			UseState:       fieldPolicy.UseStateForUnknown,
			AllowNull:      fieldPolicy.AllowNull,
			AcceptWireNull: fieldPolicy.AllowNull,
			SourceRequired: sub.Required,
		}
		switch fieldPolicy.TerraformPolicy {
		case "required":
			field.Required = true
		case "optional_computed":
			field.Optional = true
		default:
			return nil, nil, fmt.Errorf("nested object field %q policy %q is unsupported", path, fieldPolicy.TerraformPolicy)
		}
		if sub.Kind == "string" {
			if sub.MaxLength != nil && *sub.MaxLength > 0 {
				field.MaxLength = *sub.MaxLength
			}
			if sub.MinLength != nil && *sub.MinLength > 0 {
				field.MinLength = *sub.MinLength
			}
			field.Enum = stringEnumValues(sub.Enum)
			if len(field.Enum) > 0 {
				field.EnumMap = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(objectField.Name) + exportedName(sub.Name) + "Values"
				field.EnumValid = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(objectField.Name) + exportedName(sub.Name) + "Valid"
			}
			// An optional nested string field with a reviewed OpenAPI default
			// sends that default when omitted so the backend stores the
			// reviewed value (e.g. nested type defaults to "string").
			if field.Optional {
				if defaultValue, ok := stringDefault(sub.Default); ok {
					field.ProviderDefaultString = &defaultValue
				}
			}
		}
		if sub.Kind == "integer" {
			if sub.Minimum != nil {
				field.Min = int64(*sub.Minimum)
				field.HasMin = true
			}
			if sub.Maximum != nil {
				field.Max = int64(*sub.Maximum)
				field.HasMax = true
			}
			field.HasRange = field.HasMin && field.HasMax
			field.BoundMessage = integerBoundMessage(field.HasMin, field.HasMax, field.Min, field.Max)
			field.Enum = intEnumStringValues(sub.Enum)
			if len(field.Enum) > 0 {
				field.IsIntEnum = true
				field.EnumMap = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(objectField.Name) + exportedName(sub.Name) + "Values"
				field.EnumValid = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(objectField.Name) + exportedName(sub.Name) + "Valid"
			}
		}
		field.SchemaExpr = itemFieldSchemaExpr(resource, field)
		subFields = append(subFields, field)
		subKeys = append(subKeys, field.WireName)
	}
	if len(subFields) == 0 {
		return nil, nil, fmt.Errorf("nested object %q has no fields", parent)
	}
	sort.SliceStable(subFields, func(i, j int) bool { return subFields[i].Name < subFields[j].Name })
	sort.Strings(subKeys)
	return subFields, subKeys, nil
}

// buildSubItemArray renders a nested array-of-objects item field (one level
// deep). The nested array's items are scalar-only; each sub-item field reuses
// the scalar item-field rendering so constraints (ranges, lengths, defaults,
// use_state_for_unknown) flow through identically.
func buildSubItemArray(resource ResourceIR, arrayField SchemaIR, collectionName string, scalarPolicy map[string]waf.FieldPolicy) (*SubItemArrayRender, error) {
	if arrayField.Items == nil || arrayField.Items.Kind != "object" {
		return nil, fmt.Errorf("configs.%s.item.%s is not an object-item array", collectionName, arrayField.Name)
	}
	itemSchema := *arrayField.Items
	var fields []ItemFieldRender
	var knownKeys []string
	for _, subField := range itemSchema.Fields {
		path := "configs." + collectionName + ".item." + arrayField.Name + ".item." + subField.Name
		if subField.Name == "idx" {
			if subField.Kind != "integer" {
				return nil, fmt.Errorf("sub-item field %q must be an integer", path)
			}
			knownKeys = append(knownKeys, "idx")
			continue
		}
		if subField.Kind != "string" && subField.Kind != "boolean" && subField.Kind != "integer" {
			return nil, fmt.Errorf("sub-item field %q kind %q is unsupported (scalars only, one level)", path, subField.Kind)
		}
		fieldPolicy, ok := scalarPolicy[path]
		if !ok {
			return nil, fmt.Errorf("sub-item field %q has no reviewed policy", path)
		}
		field := ItemFieldRender{
			Name:           subField.Name,
			WireName:       reviewedWireName(subField.Name, fieldPolicy),
			GoName:         exportedName(subField.Name),
			Kind:           subField.Kind,
			GoType:         goTypeFor(subField.Kind),
			AttrType:       attrTypeFor(subField.Kind),
			UseState:       fieldPolicy.UseStateForUnknown,
			AllowNull:      fieldPolicy.AllowNull,
			SourceRequired: subField.Required,
		}
		switch fieldPolicy.TerraformPolicy {
		case "required":
			field.Required = true
		case "optional_computed":
			field.Optional = true
		default:
			return nil, fmt.Errorf("sub-item field %q policy %q is unsupported", path, fieldPolicy.TerraformPolicy)
		}
		if subField.Kind == "string" {
			if subField.MaxLength != nil && *subField.MaxLength > 0 {
				field.MaxLength = *subField.MaxLength
			}
			if subField.MinLength != nil && *subField.MinLength > 0 {
				field.MinLength = *subField.MinLength
			}
			if subField.Pattern != "" {
				field.Pattern = subField.Pattern
				field.PatternVar = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(arrayField.Name) + exportedName(subField.Name) + "Pattern"
				field.PatternMessage = patternValidationMessage(subField.Pattern)
			}
			field.Enum = stringEnumValues(subField.Enum)
			if len(field.Enum) > 0 {
				field.EnumMap = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(arrayField.Name) + exportedName(subField.Name) + "Values"
				field.EnumValid = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(arrayField.Name) + exportedName(subField.Name) + "Valid"
			}
			if fieldPolicy.AllowWireNull && subField.Kind == "string" {
				field.AllowWireNull = true
			}
			// An optional nested-string sub-item field with a reviewed OpenAPI
			// default sends that default when omitted so the backend stores the
			// reviewed value (e.g. arg_type defaults to "data-type").
			if field.Optional {
				if defaultValue, ok := stringDefault(subField.Default); ok {
					field.ProviderDefaultString = &defaultValue
				}
			}
		}
		if subField.Kind == "integer" {
			if subField.Minimum != nil {
				field.Min = int64(*subField.Minimum)
				field.HasMin = true
			}
			if subField.Maximum != nil {
				field.Max = int64(*subField.Maximum)
				field.HasMax = true
			}
			field.HasRange = field.HasMin && field.HasMax
			field.BoundMessage = integerBoundMessage(field.HasMin, field.HasMax, field.Min, field.Max)
			field.Enum = intEnumStringValues(subField.Enum)
			if len(field.Enum) > 0 {
				field.IsIntEnum = true
				field.EnumMap = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(arrayField.Name) + exportedName(subField.Name) + "Values"
				field.EnumValid = lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + exportedName(arrayField.Name) + exportedName(subField.Name) + "Valid"
			}
			if field.Optional {
				if defaultValue, ok := int64Default(subField.Default); ok {
					field.ProviderDefaultInt = &defaultValue
				}
			}
		}
		if fieldPolicy.ProviderDefault != nil && subField.Kind == "boolean" {
			field.ProviderDefaultBool = fieldPolicy.ProviderDefault
		}
		field.AcceptWireNull = field.AllowNull || field.AllowWireNull
		field.SchemaExpr = itemFieldSchemaExpr(resource, field)
		fields = append(fields, field)
		knownKeys = append(knownKeys, field.WireName)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("configs.%s.item.%s item schema has no non-idx fields", collectionName, arrayField.Name)
	}
	sort.Strings(knownKeys)
	goName := exportedName(arrayField.Name)
	codecPrefix := lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + goName
	maxItems := 0
	if arrayField.MaxItems != nil {
		maxItems = *arrayField.MaxItems
	}
	render := &SubItemArrayRender{
		WireName:              arrayField.Name,
		GoName:                goName,
		LocalName:             lowerCamelIdentifier(goName),
		MaxItems:              maxItems,
		CodecPrefix:           codecPrefix,
		ItemAttributeTypes:    codecPrefix + "ItemAttributeTypes",
		WrapperAttributeTypes: codecPrefix + "WrapperAttributeTypes",
		Fields:                fields,
		KnownKeys:             knownKeys,
	}
	if maxItems > 0 {
		render.MaxItemsVar = codecPrefix + "MaxItems"
	}
	return render, nil
}

// subItemArrayBlockSchemaExpr builds the Go expression for a nested
// array-of-objects item field rendered as a SingleNestedBlock ownership wrapper
// containing an `item` ListNestedBlock.
func subItemArrayBlockSchemaExpr(resource ResourceIR, field ItemFieldRender) string {
	sub := field.SubItemArray
	var builder strings.Builder
	builder.WriteString("schema.SingleNestedBlock{\n")
	fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", field.Name+" ownership wrapper. Omit it to preserve the prior GET value opaquely (the provider merges the fresh GET's nested array into the outgoing item) and keep the wrapper null in state; use an empty wrapper to send []; use a populated wrapper to replace the complete array.")
	builder.WriteString("\t\t\t\t\t\tBlocks: map[string]schema.Block{\n")
	builder.WriteString("\t\t\t\t\t\t\t\"item\": schema.ListNestedBlock{\n")
	if sub.MaxItemsVar != "" {
		fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\tValidators: []validator.List{listvalidator.SizeAtMost(%s)},\n", sub.MaxItemsVar)
	}
	fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\tMarkdownDescription: %q,\n", "Complete ordered "+field.Name+" items. Terraform order controls generated one-based indices.")
	builder.WriteString("\t\t\t\t\t\t\t\tNestedObject: schema.NestedBlockObject{\n")
	builder.WriteString("\t\t\t\t\t\t\t\t\tAttributes: map[string]schema.Attribute{\n")
	for _, f := range sub.Fields {
		fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\t\t\t\"%s\": %s,\n", f.Name, f.SchemaExpr)
	}
	builder.WriteString("\t\t\t\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t}")
	return builder.String()
}

// buildItemStringArray renders one item-level scalar-string-array field (one
// level deep), e.g. known_bots bad_bots_list.item.allow_list. It reuses the
// scalar-string-array ownership semantics inside the parent item: an omitted
// wrapper preserves the raw remote array and keeps state null; a present empty
// wrapper sends []; a present populated wrapper replaces the complete ordered
// array. There is no positional idx and no max-items bound when MaxItems is 0.
func buildItemStringArray(resource ResourceIR, arrayField SchemaIR, collectionName string, policy map[string]waf.ItemStringArrayPolicy) (*ItemScalarStringArrayRender, error) {
	path := "configs." + collectionName + ".item." + arrayField.Name
	arrayPolicy, ok := policy[path]
	if !ok {
		return nil, fmt.Errorf("item string array %q has no reviewed policy", path)
	}
	if arrayPolicy.WrapperBlock != arrayField.Name {
		return nil, fmt.Errorf("item string array %q wrapper block mismatch", path)
	}
	enum := stringEnumValues(arrayField.Items.Enum)
	if !sortedStringsEqual(enum, sortedStringSlice(arrayPolicy.Enum)) {
		return nil, fmt.Errorf("item string array %q enum mismatch", path)
	}
	if arrayField.Required != arrayPolicy.Required {
		return nil, fmt.Errorf("item string array %q required mismatch", path)
	}
	itemMaxLength := 0
	if arrayField.Items.MaxLength != nil && *arrayField.Items.MaxLength > 0 {
		itemMaxLength = *arrayField.Items.MaxLength
	}
	if itemMaxLength != arrayPolicy.ItemMaxLength {
		return nil, fmt.Errorf("item string array %q item_max_length = %d, want %d", path, itemMaxLength, arrayPolicy.ItemMaxLength)
	}
	goName := exportedName(arrayField.Name)
	codecPrefix := lowerCamelIdentifier(resource.GoName) + exportedName(strings.ReplaceAll(collectionName, ".", "")) + goName
	render := &ItemScalarStringArrayRender{
		WireName:              arrayField.Name,
		GoName:                goName,
		LocalName:             lowerCamelIdentifier(goName),
		ItemAttribute:         arrayPolicy.ItemAttribute,
		ItemGoName:            exportedName(arrayPolicy.ItemAttribute),
		Enum:                  enum,
		MaxItems:              arrayPolicy.MaxItems,
		Required:              arrayPolicy.Required,
		ItemMaxLength:         itemMaxLength,
		CodecPrefix:           codecPrefix,
		ItemAttributeTypes:    codecPrefix + "ItemAttributeTypes",
		WrapperAttributeTypes: codecPrefix + "WrapperAttributeTypes",
	}
	if len(enum) > 0 {
		render.EnumMap = codecPrefix + "Values"
		render.EnumValid = codecPrefix + "Valid"
	}
	if arrayPolicy.MaxItems > 0 {
		render.MaxItemsVar = codecPrefix + "MaxItems"
	}
	return render, nil
}

// itemStringArrayBlockSchemaExpr builds the Go expression for an item-level
// scalar-string-array field rendered as a schema.SingleNestedBlock ownership
// wrapper containing an `item` ListNestedBlock with one synthetic string attr.
func itemStringArrayBlockSchemaExpr(resource ResourceIR, field ItemFieldRender) string {
	arr := field.ItemScalarStringArray
	var builder strings.Builder
	builder.WriteString("schema.SingleNestedBlock{\n")
	fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", field.Name+" ownership wrapper. Omit it to preserve the prior GET value opaquely (the provider merges the fresh GET's nested array into the outgoing item) and keep the wrapper null in state; use an empty wrapper to send []; use a populated wrapper to replace the complete array.")
	builder.WriteString("\t\t\t\t\t\tBlocks: map[string]schema.Block{\n")
	builder.WriteString("\t\t\t\t\t\t\t\"item\": schema.ListNestedBlock{\n")
	if arr.MaxItemsVar != "" {
		fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\tValidators: []validator.List{listvalidator.SizeAtMost(%s)},\n", arr.MaxItemsVar)
	}
	fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\tMarkdownDescription: %q,\n", "Complete ordered "+field.Name+" string values in Terraform order.")
	builder.WriteString("\t\t\t\t\t\t\t\tNestedObject: schema.NestedBlockObject{\n")
	builder.WriteString("\t\t\t\t\t\t\t\t\tAttributes: map[string]schema.Attribute{\n")
	fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\t\t\t\"%s\": schema.StringAttribute{\n", arr.ItemAttribute)
	builder.WriteString("\t\t\t\t\t\t\t\t\t\t\tRequired:            true,\n")
	if len(arr.Enum) > 0 {
		fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\t\t\t\tMarkdownDescription: %q,\n", "One of the reviewed "+arr.WireName+" enum values.")
	} else {
		fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\t\t\t\tMarkdownDescription: %q,\n", "A reviewed string value.")
	}
	// Emit string validators: the enum OneOf and/or the per-item UTF-8
	// maximum length. Both may apply (enum + maxLength). The stringvalidator
	// import is gated on needsStringValidators, which already returns true
	// when any item string field (including item-string-array items) carries
	// a maxLength or enum.
	if len(arr.Enum) > 0 || arr.ItemMaxLength > 0 {
		builder.WriteString("\t\t\t\t\t\t\t\t\t\t\tValidators:          []validator.String{")
		needComma := false
		if len(arr.Enum) > 0 {
			fmt.Fprintf(&builder, "stringvalidator.OneOf(%s)", enumOneOfArgs(arr.Enum))
			needComma = true
		}
		if arr.ItemMaxLength > 0 {
			if needComma {
				builder.WriteString(", ")
			}
			fmt.Fprintf(&builder, "stringvalidator.UTF8LengthAtMost(%d)", arr.ItemMaxLength)
		}
		builder.WriteString("},\n")
	}
	builder.WriteString("\t\t\t\t\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t}")
	return builder.String()
}

// nestedObjectBlockSchemaExpr builds the Go expression for a nested-object
// item field rendered as a schema.SingleNestedBlock.
func nestedObjectBlockSchemaExpr(resource ResourceIR, field ItemFieldRender) string {
	var builder strings.Builder
	builder.WriteString("schema.SingleNestedBlock{\n")
	fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", field.Name+" exception match criteria.")
	builder.WriteString("\t\t\t\t\t\tAttributes: map[string]schema.Attribute{\n")
	for _, sub := range field.ObjectFields {
		fmt.Fprintf(&builder, "\t\t\t\t\t\t\t\"%s\": %s,\n", sub.Name, sub.SchemaExpr)
	}
	builder.WriteString("\t\t\t\t\t\t},\n")
	builder.WriteString("\t\t\t\t\t}")
	return builder.String()
}

// integerBoundMessage returns the human-facing bound description for a
// malformed/invalid diagnostic. A two-sided range produces "between min and
// max"; a min-only bound produces "at least min"; a max-only bound produces
// "at most max". It returns the empty string when no bound is present.
func integerBoundMessage(hasMin, hasMax bool, min, max int64) string {
	switch {
	case hasMin && hasMax:
		return fmt.Sprintf("between %d and %d", min, max)
	case hasMin:
		return fmt.Sprintf("at least %d", min)
	case hasMax:
		return fmt.Sprintf("at most %d", max)
	}
	return ""
}

// int64Default extracts a reviewed integer default from a SchemaIR Default
// (json.Number, int, int64, or float64). It returns the value and true only
// when the default is a finite integer, so optional item integer fields can
// send the reviewed default instead of 0 when omitted.
func int64Default(value any) (int64, bool) {
	switch v := value.(type) {
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			f, ferr := v.Float64()
			if ferr != nil || f != float64(int64(f)) {
				return 0, false
			}
			return int64(f), true
		}
		return parsed, true
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int64(v), true
	}
	return 0, false
}

// stringDefault extracts a reviewed string default from a SchemaIR Default.
func stringDefault(value any) (string, bool) {
	if s, ok := value.(string); ok {
		return s, true
	}
	return "", false
}

// boolDefault extracts a reviewed boolean default from a SchemaIR Default.
func boolDefault(value any) (bool, bool) {
	if b, ok := value.(bool); ok {
		return b, true
	}
	return false, false
}

// intEnumStringValues returns the string form of an integer enum so it can be
// rendered as int64validator.OneOf arguments alongside string enums.
func intEnumStringValues(enum []any) []string {
	values := make([]string, 0, len(enum))
	for _, value := range enum {
		if number, ok := value.(json.Number); ok {
			values = append(values, number.String())
		}
	}
	sort.Strings(values)
	return values
}

// intEnumOneOfArgs renders the comma-separated unquoted arguments for an
// int64validator.OneOf(...) call (integer enum values are numeric literals).
func intEnumOneOfArgs(values []string) string {
	return strings.Join(values, ", ")
}

// resourceImports returns the sorted Go imports the codec needs.
func resourceImports(scalars []ScalarRender, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender, needsRegexp, needsBoolState, needsInt64Validator, hasCollections bool, needsInt64PlanModifier bool) []string {
	set := map[string]struct{}{}
	add := func(path string) { set[path] = struct{}{} }
	add("bytes")
	add("context")
	add("encoding/json")
	add("fmt")
	if needsRegexp {
		add("regexp")
	}
	if hasCollections {
		add("sort")
		add("strings")
	}
	if needsUTF8(scalars, collections) {
		add("unicode/utf8")
	}
	if hasCollections || hasBoundedScalarStringArrays(scalarStringArrays) {
		add("github.com/hashicorp/terraform-plugin-framework-validators/listvalidator")
	}
	if needsInt64Validator {
		add("github.com/hashicorp/terraform-plugin-framework-validators/int64validator")
	}
	if hasStringIdx(collections) {
		add("strconv")
	}
	if needsStringValidators(scalars, collections, scalarStringArrays) {
		add("github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator")
	}
	add("github.com/hashicorp/terraform-plugin-framework/attr")
	add("github.com/hashicorp/terraform-plugin-framework/diag")
	add("github.com/hashicorp/terraform-plugin-framework/resource")
	add("github.com/hashicorp/terraform-plugin-framework/resource/schema")
	if needsBoolState {
		add("github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier")
	}
	if needsInt64PlanModifier {
		add("github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier")
	}
	add("github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier")
	add("github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier")
	add("github.com/hashicorp/terraform-plugin-framework/schema/validator")
	add("github.com/hashicorp/terraform-plugin-framework/tfsdk")
	add("github.com/hashicorp/terraform-plugin-framework/types")
	add("github.com/hashicorp/terraform-plugin-framework/types/basetypes")
	add("terraform-provider-fortiappseccloud/internal/client")
	add("terraform-provider-fortiappseccloud/internal/locking")
	add("terraform-provider-fortiappseccloud/internal/resources/wafmodule")

	imports := make([]string, 0, len(set))
	for path := range set {
		imports = append(imports, path)
	}
	sortImports(imports)
	return imports
}

func needsStringValidators(scalars []ScalarRender, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender) bool {
	for _, scalar := range scalars {
		if len(scalar.Enum) != 0 || scalar.MaxLength > 0 || scalar.MinLength > 0 {
			return true
		}
		// Check nested config object sub-fields for string validators.
		for _, sub := range scalar.ObjectFields {
			if sub.MaxLength > 0 || sub.MinLength > 0 || sub.Pattern != "" || len(sub.Enum) != 0 {
				return true
			}
		}
	}
	for _, collection := range collections {
		for _, field := range collection.Item.Fields {
			if field.MaxLength > 0 || field.MinLength > 0 || field.Pattern != "" || len(field.Enum) != 0 {
				return true
			}
			for _, sub := range field.ObjectFields {
				if sub.MaxLength > 0 || sub.MinLength > 0 || sub.Pattern != "" || len(sub.Enum) != 0 {
					return true
				}
			}
			if field.SubItemArray != nil {
				for _, sub := range field.SubItemArray.Fields {
					if sub.MaxLength > 0 || sub.MinLength > 0 || sub.Pattern != "" || len(sub.Enum) != 0 {
						return true
					}
				}
			}
			if field.ItemScalarStringArray != nil {
				if len(field.ItemScalarStringArray.Enum) != 0 || field.ItemScalarStringArray.ItemMaxLength > 0 {
					return true
				}
			}
		}
	}
	for _, array := range scalarStringArrays {
		if len(array.Enum) != 0 {
			return true
		}
	}
	return false
}

// hasBoundedScalarStringArrays reports whether any scalar-string-array
// collection carries a reviewed max-items bound, which emits a
// listvalidator.SizeAtMost and so requires the listvalidator import.
func hasBoundedScalarStringArrays(arrays []ScalarStringArrayRender) bool {
	for _, array := range arrays {
		if array.MaxItems > 0 {
			return true
		}
	}
	return false
}

// needsUTF8 reports whether the generated codec references unicode/utf8, which
// happens for config scalar strings with a max length (response decode), for
// object-item string fields with a max/min length or clear-string optional item
// fields, and for nested object sub-field string lengths. The shared
// PlannedOptionalString/DecodeOptionalString helpers (emitted whenever there
// are collections) also reference utf8 behind a maximum>0 guard, so any
// collection resource requires the import.
func needsUTF8(scalars []ScalarRender, collections []CollectionRender) bool {
	if len(collections) > 0 {
		return true
	}
	for _, scalar := range scalars {
		if scalar.Kind == "string" && (scalar.MaxLength > 0 || scalar.MinLength > 0) {
			return true
		}
	}
	for _, collection := range collections {
		for _, field := range collection.Item.Fields {
			if field.Kind == "string" && (field.MaxLength > 0 || field.MinLength > 0 || field.AllowWireNull) {
				return true
			}
			for _, sub := range field.ObjectFields {
				if sub.Kind == "string" && (sub.MaxLength > 0 || sub.MinLength > 0) {
					return true
				}
			}
			if field.SubItemArray != nil {
				for _, sub := range field.SubItemArray.Fields {
					if sub.Kind == "string" && (sub.MaxLength > 0 || sub.MinLength > 0 || sub.AllowWireNull) {
						return true
					}
				}
			}
		}
	}
	return false
}

// sortedStringSlice returns a sorted copy of a string slice.
func sortedStringSlice(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

// sortImports orders stdlib imports first, then third-party, then local.
func sortImports(imports []string) {
	stdlib := []string{}
	thirdparty := []string{}
	local := []string{}
	for _, path := range imports {
		switch {
		case strings.Contains(path, ".") && !strings.HasPrefix(path, "terraform-provider-fortiappseccloud"):
			thirdparty = append(thirdparty, path)
		case strings.HasPrefix(path, "terraform-provider-fortiappseccloud"):
			local = append(local, path)
		default:
			stdlib = append(stdlib, path)
		}
	}
	sort.Strings(stdlib)
	sort.Strings(thirdparty)
	sort.Strings(local)
	result := make([]string, 0, len(imports))
	result = append(result, stdlib...)
	result = append(result, thirdparty...)
	result = append(result, local...)
	copy(imports, result)
}

// sharedItemFields returns the item fields from the first collection. All
// collections of one resource share the same item schema, so the typed model
// and attribute-type maps are emitted once.
func sharedItemFields(collections []CollectionRender) []ItemFieldRender {
	if len(collections) == 0 {
		return nil
	}
	return collections[0].Item.Fields
}

// usesSharedItemSchema reports whether every collection shares one item
// schema (identical item field names, kinds, and known keys), so the shared
// item model/wire/attribute-types are emitted and used. Per-collection item
// schemas (e.g. known_attacks, known_bots) return false.
func usesSharedItemSchema(collections []CollectionRender) bool {
	if len(collections) <= 1 {
		return len(collections) == 1
	}
	first := collections[0]
	for _, c := range collections[1:] {
		if len(c.Item.Fields) != len(first.Item.Fields) || len(c.Item.KnownKeys) != len(first.Item.KnownKeys) {
			return false
		}
		for i, f := range first.Item.Fields {
			if c.Item.Fields[i].Name != f.Name || c.Item.Fields[i].WireName != f.WireName || c.Item.Fields[i].Kind != f.Kind {
				return false
			}
		}
	}
	return true
}

func reviewedWireName(sourceName string, policy waf.FieldPolicy) string {
	if policy.WireName != "" {
		return policy.WireName
	}
	return sourceName
}

func reviewedTerraformName(sourceName string, policy waf.FieldPolicy) string {
	if policy.TerraformName != "" {
		return policy.TerraformName
	}
	return sourceName
}

func hasNestedCollections(collections []CollectionRender) bool {
	for _, collection := range collections {
		if collection.WireParent != "" {
			return true
		}
	}
	return false
}

// hasStringIdx reports whether any collection's wire-only positional idx is
// a JSON string (IdxKind == "string").
func hasStringIdx(collections []CollectionRender) bool {
	for _, c := range collections {
		if c.IdxKind == "string" {
			return true
		}
	}
	return false
}

// sharedKnownKeys returns the known wire keys from the first collection.
func sharedKnownKeys(collections []CollectionRender) []string {
	if len(collections) == 0 {
		return nil
	}
	return collections[0].Item.KnownKeys
}

// goTypeFor returns the Framework typed model type for a schema kind.
func goTypeFor(kind string) string {
	switch kind {
	case "boolean":
		return "types.Bool"
	case "string":
		return "types.String"
	case "integer":
		return "types.Int64"
	case "object":
		return "types.Object"
	default:
		return "types.String"
	}
}

// attrTypeFor returns the attr.Type value for a schema kind.
func attrTypeFor(kind string) string {
	switch kind {
	case "boolean":
		return "types.BoolType"
	case "string":
		return "types.StringType"
	case "integer":
		return "types.Int64Type"
	case "object":
		return "types.ObjectType"
	default:
		return "types.StringType"
	}
}

// lowerCamelIdentifier converts an exported Go name to initialism-aware
// lowerCamelCase (CSRFProtection -> csrfProtection, URLAccess -> urlAccess).
// The leading run of uppercase letters is treated as an initialism and fully
// lower-cased; the uppercase letter beginning the next word is preserved.
func lowerCamelIdentifier(goName string) string {
	if goName == "" {
		return ""
	}
	runes := []rune(goName)
	upperEnd := 0
	for upperEnd < len(runes) && isUpper(runes[upperEnd]) {
		upperEnd++
	}
	if upperEnd <= 1 {
		return strings.ToLower(string(runes[0])) + string(runes[1:])
	}
	if upperEnd == len(runes) {
		return strings.ToLower(goName)
	}
	initialism := runes[:upperEnd-1]
	rest := runes[upperEnd-1:]
	var builder strings.Builder
	for _, r := range initialism {
		builder.WriteRune(toLower(r))
	}
	for _, r := range rest {
		builder.WriteRune(r)
	}
	return builder.String()
}

func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func toLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// exportedName converts a snake_case Terraform attribute name to an exported
// Go struct field name (url -> URL, name -> Name, action -> Action).
// Known initialism segments (url, id) are fully upper-cased to match Go
// convention and the existing CSRF symbols.
// sanitizeCollectionName removes dots from a nested collection name
// (e.g. "cache.rule_list" -> "cache_rule_list") so it can be used in
// Go identifiers. The exportedName function capitalizes each segment, but
// dots in the middle produce invalid Go identifiers.
func sanitizeCollectionName(name string) string {
	return strings.ReplaceAll(name, ".", "_")
}

func exportedName(name string) string {
	var builder strings.Builder
	capitalizeNext := true
	for _, r := range name {
		if r == '_' {
			capitalizeNext = true
			continue
		}
		if capitalizeNext {
			builder.WriteRune(toUpper(r))
			capitalizeNext = false
		} else {
			builder.WriteRune(r)
		}
	}
	result := builder.String()
	// Apply known initialism segments after building, so url/UrlList -> URL/URLList.
	// Longer keys are applied first so "EpId" wins over the "Id" suffix.
	for _, pair := range exportedInitialismPairs {
		result = strings.ReplaceAll(result, pair.from, pair.to)
	}
	return result
}

// exportedInitialismPairs is the ordered list of substring replacements applied
// to the simple capitalized name. Longer keys precede their substrings so
// "EpId" is rewritten before the standalone "Id" -> "ID" rule.
var exportedInitialismPairs = []struct{ from, to string }{
	{"EpId", "EPID"},
	{"Url", "URL"},
	{"Id", "ID"},
}

func toUpper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - ('a' - 'A')
	}
	return r
}

// stringEnumValues returns sorted string enum values from a SchemaIR enum.
func stringEnumValues(enum []any) []string {
	values := make([]string, 0, len(enum))
	for _, value := range enum {
		if s, ok := value.(string); ok {
			values = append(values, s)
		}
	}
	sort.Strings(values)
	return values
}

// buildDocsRender constructs the docs page view for one resource.
func buildDocsRender(resource ResourceIR, scalars []ScalarRender, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender, crossFieldRules []CrossFieldRuleRender) DocsRender {
	operation := resource.Reviewed.OperationName
	return DocsRender{
		PageTitle:          resource.TerraformName + " Resource - fortiappseccloud",
		Description:        "Configures " + operation + " for one FortiAppSec Cloud WAF application, with direct settings or template inheritance.",
		ExampleHCL:         docsExampleHCL(resource, scalars, collections, scalarStringArrays),
		TemplateExampleHCL: templateDocsExampleHCL(resource, scalars, collections, scalarStringArrays),
		ConfigurationNotes: docsConfigurationNotes(resource.TerraformName),
		ArgumentText:       docsArgumentText(resource, scalars, collections, scalarStringArrays, crossFieldRules),
		ImportCommand:      "terraform import " + resource.TerraformName + ".example application-endpoint-id",
	}
}

func templateDocsExampleHCL(resource ResourceIR, scalars []ScalarRender, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender) string {
	example := docsExampleHCL(resource, scalars, collections, scalarStringArrays)
	templateName := "fortiappseccloud_waf_template_" + strings.TrimPrefix(resource.Reviewed.TypeNameSuffix, "waf_")
	example = strings.Replace(example, `resource "`+resource.TerraformName+`"`, `resource "`+templateName+`"`, 1)
	example = strings.Replace(example, `  ep_id    = fortiappseccloud_waf_app.example.ep_id`+"\n", `  template_id = fortiappseccloud_waf_template.example.template_id`+"\n", 1)
	example = strings.Replace(example, `  ep_id    = "application-endpoint-id"`+"\n", `  template_id = fortiappseccloud_waf_template.example.template_id`+"\n", 1)
	example = strings.Replace(example, "  template = false\n\n", "\n", 1)
	return example
}

func docsExampleHCL(resource ResourceIR, scalars []ScalarRender, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender) string {
	if example, ok := reviewedDocsExamples[resource.TerraformName]; ok {
		example = strings.ReplaceAll(example, "fortiappseccloud_waf_app.app_example.ep_id", "fortiappseccloud_waf_app.example.ep_id")
		return strings.TrimSpace(example) + "\n"
	}
	return schemaCoverageDocsExampleHCL(resource, scalars, collections, scalarStringArrays)
}

// schemaCoverageDocsExampleHCL is retained as a deterministic fallback for a
// newly reviewed generator resource. Current public resources must all have a
// reviewed example fixture; tests fail if any resource reaches this fallback.
func schemaCoverageDocsExampleHCL(resource ResourceIR, scalars []ScalarRender, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "resource \"%s\" \"example\" {\n", resource.TerraformName)
	builder.WriteString("  ep_id    = \"application-endpoint-id\"\n")
	builder.WriteString("  template = false\n\n")
	builder.WriteString("  configs {\n")
	for _, scalar := range scalars {
		if scalar.ComputedOnly {
			continue
		}
		if scalar.Kind == "string" && len(scalar.Enum) > 0 {
			fmt.Fprintf(&builder, "    %s = \"%s\"\n", scalar.Name, scalar.Enum[0])
		} else if scalar.Kind == "boolean" {
			fmt.Fprintf(&builder, "    %s = true\n", scalar.Name)
		}
	}
	if len(collections) > 0 || len(scalarStringArrays) > 0 {
		builder.WriteString("\n")
	}
	for _, collection := range collections {
		fmt.Fprintf(&builder, "    %s {\n", collection.WireName)
		// Every collection gets a populated item block so the example covers
		// every required item field (the review discipline requires this).
		builder.WriteString("      item {\n")
		for _, field := range collection.Item.Fields {
			switch {
			case field.Kind == "boolean" && field.ProviderDefaultBool != nil:
				fmt.Fprintf(&builder, "        %s = true\n", field.Name)
			case field.Kind == "boolean" && field.Required:
				fmt.Fprintf(&builder, "        %s = true\n", field.Name)
			case field.Kind == "string" && len(field.Enum) > 0:
				fmt.Fprintf(&builder, "        %s = \"%s\"\n", field.Name, field.Enum[0])
			case field.Kind == "string" && field.Required:
				example := "example"
				if field.Name == "url" {
					example = "/checkout"
				} else if field.Name == "name" {
					example = "example-rule"
				} else if field.Name == "sig_id" {
					example = "030000010"
				} else if field.Pattern != "" {
					// Fall back to a pattern-safe value for any other required
					// patterned string so the example is not self-rejected.
					example = patternSafeExample(field.Pattern, "example")
				}
				fmt.Fprintf(&builder, "        %s = %q\n", field.Name, example)
			case field.Kind == "string" && field.Optional:
				// Pick an example value that satisfies any reviewed pattern so
				// the generated example is not rejected by its own schema
				// validator (e.g. ^/.*$ -> /example, ^\d{5}$ -> 00000).
				fmt.Fprintf(&builder, "        %s = %q\n", field.Name, patternSafeExample(field.Pattern, "example"))
			case field.Kind == "integer" && field.Required:
				fmt.Fprintf(&builder, "        %s = %d\n", field.Name, field.Min)
			case field.Kind == "object" && field.Required:
				fmt.Fprintf(&builder, "        %s {\n", field.Name)
				for _, sub := range field.ObjectFields {
					switch {
					case sub.Kind == "boolean":
						fmt.Fprintf(&builder, "          %s = true\n", sub.Name)
					case sub.Kind == "string" && len(sub.Enum) > 0:
						fmt.Fprintf(&builder, "          %s = \"%s\"\n", sub.Name, sub.Enum[0])
					case sub.Kind == "string":
						fmt.Fprintf(&builder, "          %s = \"example\"\n", sub.Name)
					}
				}
				fmt.Fprintf(&builder, "        }\n")
			case field.Kind == "array" && field.SubItemArray != nil:
				// A nested array-of-objects item field: emit one populated
				// sub-item block covering its required fields.
				fmt.Fprintf(&builder, "        %s {\n", field.Name)
				builder.WriteString("          item {\n")
				for _, sub := range field.SubItemArray.Fields {
					switch {
					case sub.Kind == "boolean":
						fmt.Fprintf(&builder, "            %s = true\n", sub.Name)
					case sub.Kind == "string" && len(sub.Enum) > 0:
						fmt.Fprintf(&builder, "            %s = \"%s\"\n", sub.Name, sub.Enum[0])
					case sub.Kind == "string" && sub.Required:
						fmt.Fprintf(&builder, "            %s = %q\n", sub.Name, patternSafeExample(sub.Pattern, "example"))
					case sub.Kind == "string" && sub.Optional:
						fmt.Fprintf(&builder, "            %s = %q\n", sub.Name, patternSafeExample(sub.Pattern, "example"))
					case sub.Kind == "integer":
						example := sub.Min
						if sub.ProviderDefaultInt != nil {
							example = *sub.ProviderDefaultInt
						}
						fmt.Fprintf(&builder, "            %s = %d\n", sub.Name, example)
					}
				}
				builder.WriteString("          }\n")
				fmt.Fprintf(&builder, "        }\n")
			}
		}
		builder.WriteString("      }\n")
		builder.WriteString("    }\n")
	}
	for _, array := range scalarStringArrays {
		fmt.Fprintf(&builder, "    %s {\n", array.WireName)
		if len(array.Enum) > 0 {
			fmt.Fprintf(&builder, "      item {\n        %s = \"%s\"\n      }\n", array.ItemAttribute, array.Enum[0])
		}
		builder.WriteString("    }\n")
	}
	builder.WriteString("  }\n")
	builder.WriteString("}\n")
	return builder.String()
}

func docsArgumentText(resource ResourceIR, scalars []ScalarRender, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender, crossFieldRules []CrossFieldRuleRender) string {
	operation := resource.Reviewed.OperationName
	var builder strings.Builder
	fmt.Fprintf(&builder, "- `ep_id` (Required, Forces replacement) — Application endpoint ID. Import uses this exact value and it must contain a non-whitespace character.\n")
	fmt.Fprintf(&builder, "- `template` (Required) — Whether effective configuration is inherited from the attached template.\n")
	fmt.Fprintf(&builder, "- `configs` (Block) — Required when `template = false` and forbidden when `template = true`. State keeps this block null when template inheritance is enabled.\n")
	for _, scalar := range scalars {
		if scalar.ComputedOnly {
			fmt.Fprintf(&builder, "  - `%s` (Computed) — API-derived read-only value.\n", scalar.Name)
			continue
		}
		switch scalar.Kind {
		case "string":
			description := "Sets " + humanizeDocsName(scalar.Name) + ". "
			constraints := "Omission preserves the current value."
			if scalar.MaxLength > 0 {
				constraints = fmt.Sprintf("At most %d UTF-8 characters. Omission preserves the current value.", scalar.MaxLength)
			}
			if scalar.Pattern != "" {
				constraints = fmt.Sprintf("Must match `%s`. %s", scalar.Pattern, constraints)
			}
			if len(scalar.Enum) > 0 {
				constraints = "One of " + enumBacktickList(scalar.Enum) + ". Omission preserves the current value."
				if scalar.MaxLength > 0 {
					constraints = fmt.Sprintf("One of %s, at most %d UTF-8 characters. Omission preserves the current value.", enumBacktickList(scalar.Enum), scalar.MaxLength)
				}
			}
			if scalar.Sensitive {
				constraints = "Sensitive. " + constraints
			}
			fmt.Fprintf(&builder, "  - `%s` (Optional, Computed) — %s%s\n", scalar.Name, description, constraints)
		case "boolean":
			description := "Controls " + humanizeDocsName(scalar.Name) + " for " + operation + "."
			if scalar.Name == "status" {
				description = "Enables or disables " + operation + "."
			}
			fmt.Fprintf(&builder, "  - `%s` (Optional, Computed) — %s Omission preserves the current value.\n", scalar.Name, description)
		case "integer":
			description := "Sets " + humanizeDocsName(scalar.Name) + ". "
			constraints := "Omission preserves the current value."
			switch {
			case scalar.HasMin && scalar.HasMax:
				constraints = fmt.Sprintf("Between %d and %d. Omission preserves the current value.", scalar.Min, scalar.Max)
			case scalar.HasMin:
				constraints = fmt.Sprintf("At least %d. Omission preserves the current value.", scalar.Min)
			case scalar.HasMax:
				constraints = fmt.Sprintf("At most %d. Omission preserves the current value.", scalar.Max)
			}
			if len(scalar.Enum) > 0 {
				constraints = "One of " + enumBacktickList(scalar.Enum) + ". Omission preserves the current value."
			}
			fmt.Fprintf(&builder, "  - `%s` (Optional, Computed) — %s%s\n", scalar.Name, description, constraints)
		case "object":
			fmt.Fprintf(&builder, "  - `%s` (Optional Block) — %s settings. Omission preserves the current nested object.\n", scalar.Name, humanizeDocsName(scalar.Name))
			for _, field := range scalar.ObjectFields {
				required := "Optional, Computed"
				if field.Required {
					required = "Required"
				}
				constraints := docsItemConstraints(field)
				fmt.Fprintf(&builder, "    - `%s.%s` (%s%s) — %s.\n", scalar.Name, field.Name, required, constraints, fieldDescription(field))
			}
		}
	}
	if len(crossFieldRules) != 0 {
		builder.WriteString("  - Cross-field constraints:\n")
		for _, rule := range crossFieldRules {
			fmt.Fprintf(&builder, "    - %s\n", rule.Docs)
		}
	}
	if len(collections) > 0 {
		builder.WriteString("  - Collection ownership — Each block below contains ordered `item` blocks. Omitting a collection block preserves the complete raw remote array and keeps the block null in state. A present empty block sends `[]`. A present block with items replaces the complete array in Terraform order.\n")
		for _, collection := range collections {
			bound := ""
			if collection.MaxItems > 0 {
				bound = fmt.Sprintf(", at most %d items", collection.MaxItems)
			}
			fmt.Fprintf(&builder, "    - `%s` (Optional Block%s) — Owns the ordered `%s.item` blocks.\n", collection.WireName, bound, collection.WireName)
			for _, field := range collection.Item.Fields {
				switch {
				case field.Kind == "boolean" && field.ProviderDefaultBool != nil:
					defaultStr := "false"
					if *field.ProviderDefaultBool {
						defaultStr = "true"
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (Optional, Computed) — %s. Defaults to `%s` for a newly configured item.\n", collection.WireName, field.Name, collectionFieldDescription(collection.WireName, field), defaultStr)
				case field.Kind == "boolean" && field.Required:
					fmt.Fprintf(&builder, "      - `%s.item.%s` (Required) — %s.\n", collection.WireName, field.Name, collectionFieldDescription(collection.WireName, field))
				case field.Kind == "boolean" && field.Optional:
					fmt.Fprintf(&builder, "      - `%s.item.%s` (Optional, Computed) — %s. Omission preserves the current value.\n", collection.WireName, field.Name, collectionFieldDescription(collection.WireName, field))
				case field.Kind == "string" && field.Required:
					constraints := "Required"
					if field.MinLength > 0 {
						constraints += fmt.Sprintf(", minimum %d UTF-8 characters", field.MinLength)
					}
					if field.MaxLength > 0 {
						constraints += fmt.Sprintf(", maximum %d UTF-8 characters", field.MaxLength)
					}
					if field.Pattern != "" {
						constraints += fmt.Sprintf(", matching `%s`", field.Pattern)
					}
					if len(field.Enum) > 0 {
						constraints += ", one of " + enumBacktickList(field.Enum)
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (%s) — %s.\n", collection.WireName, field.Name, constraints, collectionFieldDescription(collection.WireName, field))
				case field.Kind == "string" && field.Optional:
					constraints := "Optional, Computed"
					if field.MinLength > 0 {
						constraints += fmt.Sprintf(", minimum %d UTF-8 characters", field.MinLength)
					}
					if field.MaxLength > 0 {
						constraints += fmt.Sprintf(", maximum %d UTF-8 characters", field.MaxLength)
					}
					if field.Pattern != "" {
						constraints += fmt.Sprintf(", matching `%s`", field.Pattern)
					}
					if len(field.Enum) > 0 {
						constraints += ", one of " + enumBacktickList(field.Enum)
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (%s) — %s.\n", collection.WireName, field.Name, constraints, collectionFieldDescription(collection.WireName, field))
				case field.Kind == "integer" && field.Required:
					constraints := "Required"
					if field.HasRange {
						constraints += fmt.Sprintf(", between %d and %d", field.Min, field.Max)
					}
					if len(field.Enum) > 0 {
						constraints += ", one of " + enumBacktickList(field.Enum)
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (%s) — %s.\n", collection.WireName, field.Name, constraints, collectionFieldDescription(collection.WireName, field))
				case field.Kind == "integer" && field.Optional:
					constraints := "Optional, Computed"
					switch {
					case field.HasRange:
						constraints += fmt.Sprintf(", between %d and %d", field.Min, field.Max)
					case field.HasMin && field.HasMax:
						constraints += fmt.Sprintf(", between %d and %d", field.Min, field.Max)
					case field.HasMin:
						constraints += fmt.Sprintf(", at least %d", field.Min)
					case field.HasMax:
						constraints += fmt.Sprintf(", at most %d", field.Max)
					}
					if field.ProviderDefaultInt != nil {
						constraints += fmt.Sprintf(", default %d", *field.ProviderDefaultInt)
					}
					if len(field.Enum) > 0 {
						constraints += ", one of " + enumBacktickList(field.Enum)
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (%s) — %s.\n", collection.WireName, field.Name, constraints, collectionFieldDescription(collection.WireName, field))
				case field.Kind == "object":
					blockKind := "Optional Block"
					if field.Required {
						blockKind = "Required Block"
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (%s) — Nested %s match criteria.\n", collection.WireName, field.Name, blockKind, humanizeDocsName(field.Name))
					for _, sub := range field.ObjectFields {
						subRequired := "Optional, Computed"
						if sub.Required {
							subRequired = "Required"
						}
						subConstraints := ""
						if sub.MaxLength > 0 {
							subConstraints = fmt.Sprintf(", maximum %d UTF-8 characters", sub.MaxLength)
						}
						if len(sub.Enum) > 0 {
							subConstraints += ", one of " + enumBacktickList(sub.Enum)
						}
						fmt.Fprintf(&builder, "        - `%s.item.%s.%s` (%s%s) — %s.\n", collection.WireName, field.Name, sub.Name, subRequired, subConstraints, fieldDescription(sub))
					}
				case field.Kind == "array" && field.SubItemArray != nil:
					subArray := field.SubItemArray
					blockKind := "Optional Block"
					if field.Required {
						blockKind = "Required Block"
					}
					bound := ""
					if subArray.MaxItems > 0 {
						bound = fmt.Sprintf(", at most %d items", subArray.MaxItems)
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (%s%s) — Ownership wrapper for ordered `%s.item.%s.item` blocks. Omitting the wrapper preserves the prior GET value opaquely (the provider merges the fresh GET's nested array into the outgoing item) and keeps the wrapper null in state; a present empty wrapper sends []; a present populated wrapper replaces the complete array.\n", collection.WireName, field.Name, blockKind, bound, collection.WireName, field.Name)
					for _, sub := range subArray.Fields {
						subRequired := "Optional, Computed"
						if sub.Required {
							subRequired = "Required"
						}
						subConstraints := ""
						switch {
						case sub.Kind == "string":
							if sub.MinLength > 0 {
								subConstraints += fmt.Sprintf(", minimum %d UTF-8 characters", sub.MinLength)
							}
							if sub.MaxLength > 0 {
								subConstraints += fmt.Sprintf(", maximum %d UTF-8 characters", sub.MaxLength)
							}
							if sub.Pattern != "" {
								subConstraints += fmt.Sprintf(", matching `%s`", sub.Pattern)
							}
							if len(sub.Enum) > 0 {
								subConstraints += ", one of " + enumBacktickList(sub.Enum)
							}
						case sub.Kind == "integer":
							switch {
							case sub.HasRange:
								subConstraints += fmt.Sprintf(", between %d and %d", sub.Min, sub.Max)
							case sub.HasMin && sub.HasMax:
								subConstraints += fmt.Sprintf(", between %d and %d", sub.Min, sub.Max)
							case sub.HasMin:
								subConstraints += fmt.Sprintf(", at least %d", sub.Min)
							case sub.HasMax:
								subConstraints += fmt.Sprintf(", at most %d", sub.Max)
							}
							if sub.ProviderDefaultInt != nil {
								subConstraints += fmt.Sprintf(", default %d", *sub.ProviderDefaultInt)
							}
							if len(sub.Enum) > 0 {
								subConstraints += ", one of " + enumBacktickList(sub.Enum)
							}
						}
						fmt.Fprintf(&builder, "        - `%s.item.%s.item.%s` (%s%s) — %s.\n", collection.WireName, field.Name, sub.Name, subRequired, subConstraints, fieldDescription(sub))
					}
				case field.Kind == "string_array" && field.ItemScalarStringArray != nil:
					arr := field.ItemScalarStringArray
					bound := ""
					if arr.MaxItems > 0 {
						bound = fmt.Sprintf(", at most %d items", arr.MaxItems)
					}
					itemBound := ""
					if arr.ItemMaxLength > 0 {
						itemBound = fmt.Sprintf(", each at most %d UTF-8 characters", arr.ItemMaxLength)
					}
					enumNote := ""
					if len(arr.Enum) > 0 {
						enumNote = ", each one of " + enumBacktickList(arr.Enum)
					}
					fmt.Fprintf(&builder, "      - `%s.item.%s` (Optional Block%s) — Ownership wrapper for ordered `%s.item.%s.item` blocks. Omitting the wrapper preserves the prior GET value opaquely (the provider merges the fresh GET's nested array into the outgoing item) and keeps the wrapper null in state; a present empty wrapper sends []; a present populated wrapper replaces the complete array.\n", collection.WireName, field.Name, bound, collection.WireName, field.Name)
					fmt.Fprintf(&builder, "        - `%s.item.%s.item.%s` (Required%s%s) — A reviewed string value.\n", collection.WireName, field.Name, arr.ItemAttribute, itemBound, enumNote)
				}
			}
		}
	}
	if len(scalarStringArrays) > 0 {
		enumOrFree := "a single enum string"
		for _, array := range scalarStringArrays {
			if len(array.Enum) == 0 {
				enumOrFree = "a single string value"
				break
			}
		}
		fmt.Fprintf(&builder, "  - Scalar collection ownership — Each block below contains ordered `item` blocks carrying %s. Omitting a collection block preserves the complete raw remote array and keeps the block null in state. A present empty block sends `[]`. A present block with items replaces the complete array in Terraform order.\n", enumOrFree)
		for _, array := range scalarStringArrays {
			missing := ""
			if array.Required {
				missing = " The pinned schema marks this array required, so a missing remote array fails closed when Terraform owns it."
			}
			bound := ""
			if array.MaxItems > 0 {
				bound = fmt.Sprintf(", at most %d items", array.MaxItems)
			}
			fmt.Fprintf(&builder, "    - `%s` (Optional Block%s) — Owns the ordered `%s.item` blocks.%s\n", array.WireName, bound, array.WireName, missing)
			if len(array.Enum) > 0 {
				fmt.Fprintf(&builder, "      - `%s.item.%s` (Required) — One value per `item` block; one of %s.\n", array.WireName, array.ItemAttribute, enumBacktickList(array.Enum))
			} else {
				fmt.Fprintf(&builder, "      - `%s.item.%s` (Required) — One string value per `item` block.\n", array.WireName, array.ItemAttribute)
			}
		}
	}
	// The idx footer is only emitted when there is at least one object-item
	// collection: bare scalar-string-array collections have no positional idx,
	// so the idx paragraph does not apply to a resource whose only ownership
	// collection is a scalar-string-array.
	hasObjectItemCollection := len(collections) > 0
	hasNestedSubItemArray := false
	for _, collection := range collections {
		for _, field := range collection.Item.Fields {
			if field.SubItemArray != nil {
				hasNestedSubItemArray = true
			}
		}
	}
	if !hasObjectItemCollection {
		return builder.String()
	}
	if hasNestedSubItemArray {
		builder.WriteString("\nThe wire-only `idx` field is never exposed. The provider regenerates sequential one-based indices independently for each list, validates imported or owned response indices, and sorts state by `idx`. Unknown nested item keys fail closed for owned and imported arrays; omitted top-level collection wrappers remain opaque and are preserved unchanged. Nested sub-item array wrappers, when omitted, preserve the prior GET value opaquely and keep the wrapper null in state.\n")
	} else {
		builder.WriteString("\nThe wire-only `idx` field is never exposed. The provider regenerates sequential one-based indices independently for each list, validates imported or owned response indices, and sorts state by `idx`. Unknown nested item keys fail closed for owned and imported arrays; omitted top-level collection wrappers remain opaque and are preserved unchanged.\n")
	}
	return builder.String()
}

func fieldDescription(field ItemFieldRender) string {
	switch field.Name {
	case "url":
		return "Request URL"
	case "url_type":
		return "Whether the url field is matched as a literal string or a backend-validated regular expression"
	case "name":
		if field.AllowWireNull {
			return "Parameter name"
		}
		return "Rule name"
	case "value":
		return "Parameter value"
	case "action":
		return "Action for detected rule violations"
	default:
		return humanizeDocsName(field.Name)
	}
}

func collectionFieldDescription(collectionName string, field ItemFieldRender) string {
	switch {
	case collectionName == "content_type_list" && field.Name == "type":
		return "Response content type eligible for caching or compression"
	case collectionName == "cookie_list" && field.Name == "name":
		return "Cookie name used by the caching or compression policy"
	default:
		return fieldDescription(field)
	}
}

func humanizeDocsName(name string) string {
	words := strings.ReplaceAll(name, "_", " ")
	if words == "" {
		return words
	}
	return strings.ToUpper(words[:1]) + words[1:]
}

func docsItemConstraints(field ItemFieldRender) string {
	var constraints []string
	if field.MinLength > 0 {
		constraints = append(constraints, fmt.Sprintf("minimum %d UTF-8 characters", field.MinLength))
	}
	if field.MaxLength > 0 {
		constraints = append(constraints, fmt.Sprintf("maximum %d UTF-8 characters", field.MaxLength))
	}
	if field.Pattern != "" {
		constraints = append(constraints, fmt.Sprintf("matching `%s`", field.Pattern))
	}
	if field.HasRange || (field.HasMin && field.HasMax) {
		constraints = append(constraints, fmt.Sprintf("between %d and %d", field.Min, field.Max))
	} else if field.HasMin {
		constraints = append(constraints, fmt.Sprintf("at least %d", field.Min))
	} else if field.HasMax {
		constraints = append(constraints, fmt.Sprintf("at most %d", field.Max))
	}
	if len(field.Enum) > 0 {
		constraints = append(constraints, "one of "+enumBacktickList(field.Enum))
	}
	if field.ProviderDefaultInt != nil {
		constraints = append(constraints, fmt.Sprintf("default %d", *field.ProviderDefaultInt))
	}
	if len(constraints) == 0 {
		return ""
	}
	return ", " + strings.Join(constraints, ", ")
}

func enumBacktickList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, "`"+value+"`")
	}
	return strings.Join(quoted, ", ")
}

// decodeScalarsSig builds the return signature for the DecodeScalars helper:
// the scalars result struct plus diag.Diagnostics.
func decodeScalarsSig(lowerCamel string, scalars []ScalarRender) string {
	return "(" + scalarsStruct(lowerCamel, scalars) + ", diag.Diagnostics)"
}

// scalarsStruct returns the scalars result struct type name.
func scalarsStruct(lowerCamel string, scalars []ScalarRender) string {
	return lowerCamel + "Scalars"
}

// scalarsStructZero returns the zero-value struct literal for the scalars result.
func scalarsStructZero(lowerCamel string, scalars []ScalarRender) string {
	return scalarsStruct(lowerCamel, scalars) + "{}"
}

// ownershipStruct returns the owned-set struct type name.
func ownershipStruct(lowerCamel string, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender) string {
	return lowerCamel + "OwnershipSet"
}

// ownershipStructZero returns the struct literal with every collection false.
func ownershipStructZero(lowerCamel string, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender, scalars []ScalarRender) string {
	return structLiteral(lowerCamel, collections, scalarStringArrays, scalars, "false")
}

// ownershipStructImported returns the struct literal with every collection true.
func ownershipStructImported(lowerCamel string, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender, scalars []ScalarRender) string {
	return structLiteral(lowerCamel, collections, scalarStringArrays, scalars, "true")
}

// ownershipStructValues returns the struct literal populated from the configs model.
func ownershipStructValues(lowerCamel string, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender, scalars []ScalarRender) string {
	var builder strings.Builder
	builder.WriteString(ownershipStruct(lowerCamel, collections, scalarStringArrays))
	builder.WriteString("{")
	first := true
	writeField := func(goName string) {
		if !first {
			builder.WriteString(", ")
		}
		first = false
		builder.WriteString(goName)
		builder.WriteString(": !configs.")
		builder.WriteString(goName)
		builder.WriteString(".IsNull()")
	}
	for _, collection := range collections {
		writeField(collection.GoName)
	}
	for _, array := range scalarStringArrays {
		writeField(array.GoName)
	}
	for _, scalar := range scalars {
		if scalar.Kind == "object" {
			writeField(scalar.GoName)
		}
	}
	builder.WriteString("}, diagnostics")
	return builder.String()
}

func structLiteral(lowerCamel string, collections []CollectionRender, scalarStringArrays []ScalarStringArrayRender, scalars []ScalarRender, value string) string {
	var builder strings.Builder
	builder.WriteString(ownershipStruct(lowerCamel, collections, scalarStringArrays))
	builder.WriteString("{")
	first := true
	writeField := func(goName string) {
		if !first {
			builder.WriteString(", ")
		}
		first = false
		builder.WriteString(goName)
		builder.WriteString(": ")
		builder.WriteString(value)
	}
	for _, collection := range collections {
		writeField(collection.GoName)
	}
	for _, array := range scalarStringArrays {
		writeField(array.GoName)
	}
	builder.WriteString("}, diagnostics")
	return builder.String()
}

// patchTypeFor returns the non-pointer Go wire type used by the PUT patch
// struct's client.Optional[T]. Nullable read semantics never change the patch
// type, which stays string/bool/int64 so ConfiguredString/Bool/Int64 apply.
func patchTypeFor(kind string) string {
	switch kind {
	case "boolean":
		return "bool"
	case "integer":
		return "int64"
	case "object":
		return "json.RawMessage"
	default:
		return "string"
	}
}

// scalarWireType returns the Go wire type for a schema kind. An optional
// scalar (not required) uses a pointer type so a missing/null remote value
// decodes to nil and flattens to null state; a required scalar uses the
// non-pointer type.
func scalarWireType(scalar ScalarRender) string {
	optional := !scalar.Required
	switch scalar.Kind {
	case "boolean":
		if optional {
			return "*bool"
		}
		return "bool"
	case "string":
		if optional {
			return "*string"
		}
		return "string"
	case "integer":
		if optional {
			return "*int64"
		}
		return "int64"
	case "object":
		// Nested config objects are carried as json.RawMessage (the whole
		// nested object is marshaled/unmarshaled as raw JSON, like collections).
		return "json.RawMessage"
	default:
		if optional {
			return "*string"
		}
		return "string"
	}
}

// scalarSchemaExpr builds the Go expression for a configs-level scalar
// schema.XxxAttribute{...}.
func scalarSchemaExpr(resource ResourceIR, scalar ScalarRender) string {
	var builder strings.Builder
	switch scalar.Kind {
	case "string":
		builder.WriteString("schema.StringAttribute{\n")
		if scalar.ComputedOnly {
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
		} else {
			builder.WriteString("\t\t\t\t\t\tOptional:            true,\n")
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
		}
		if scalar.Sensitive {
			builder.WriteString("\t\t\t\t\t\tSensitive:           true,\n")
		}
		if scalar.ComputedOnly {
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: \"Read-only value derived by the API for %s.\",\n", scalar.Name)
		} else {
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: \"Omission preserves the current %s value.\",\n", scalar.Name)
		}
		if !scalar.ComputedOnly {
			var validators []string
			if scalar.MaxLength > 0 {
				validators = append(validators, fmt.Sprintf("stringvalidator.UTF8LengthAtMost(%d)", scalar.MaxLength))
			}
			if scalar.MinLength > 0 {
				validators = append(validators, fmt.Sprintf("stringvalidator.UTF8LengthAtLeast(%d)", scalar.MinLength))
			}
			if scalar.PatternVar != "" {
				validators = append(validators, fmt.Sprintf("stringvalidator.RegexMatches(%s, %q)", scalar.PatternVar, scalar.PatternMessage))
			}
			if scalar.EnumMap != "" {
				validators = append(validators, fmt.Sprintf("stringvalidator.OneOf(%s)", enumOneOfArgs(scalar.Enum)))
			}
			if len(validators) > 0 {
				fmt.Fprintf(&builder, "\t\t\t\t\t\tValidators:          []validator.String{%s},\n", strings.Join(validators, ", "))
			}
			if scalar.UseState {
				builder.WriteString("\t\t\t\t\t\tPlanModifiers:       stringStateModifier,\n")
			}
		}
		builder.WriteString("\t\t\t\t\t}")
	case "boolean":
		builder.WriteString("schema.BoolAttribute{\n")
		if scalar.ComputedOnly {
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
		} else {
			builder.WriteString("\t\t\t\t\t\tOptional:            true,\n")
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
		}
		fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: \"Omission preserves the current %s value.\",\n", scalar.Name)
		if scalar.UseState {
			builder.WriteString("\t\t\t\t\t\tPlanModifiers:       boolStateModifier,\n")
		}
		builder.WriteString("\t\t\t\t\t}")
	case "integer":
		builder.WriteString("schema.Int64Attribute{\n")
		if scalar.ComputedOnly {
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: \"Read-only value derived by the API for %s.\",\n", scalar.Name)
		} else {
			builder.WriteString("\t\t\t\t\t\tOptional:            true,\n")
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: \"Omission preserves the current %s value.\",\n", scalar.Name)
		}
		var scalarIntValidators []string
		if !scalar.ComputedOnly && scalar.HasRange {
			scalarIntValidators = append(scalarIntValidators, fmt.Sprintf("int64validator.Between(%d, %d)", scalar.Min, scalar.Max))
		} else if !scalar.ComputedOnly && (scalar.HasMin || scalar.HasMax) {
			// One-sided bounds render as AtLeast/AtMost so a missing endpoint
			// is never silently treated as zero.
			if scalar.HasMin {
				scalarIntValidators = append(scalarIntValidators, fmt.Sprintf("int64validator.AtLeast(%d)", scalar.Min))
			}
			if scalar.HasMax {
				scalarIntValidators = append(scalarIntValidators, fmt.Sprintf("int64validator.AtMost(%d)", scalar.Max))
			}
		}
		if !scalar.ComputedOnly && scalar.IsIntEnum {
			scalarIntValidators = append(scalarIntValidators, fmt.Sprintf("int64validator.OneOf(%s)", intEnumOneOfArgs(scalar.Enum)))
		}
		if len(scalarIntValidators) > 0 {
			fmt.Fprintf(&builder, "\t\t\t\t\t\tValidators:          []validator.Int64{%s},\n", strings.Join(scalarIntValidators, ", "))
		}
		if scalar.UseState {
			builder.WriteString("\t\t\t\t\t\tPlanModifiers:       int64StateModifier,\n")
		}
		builder.WriteString("\t\t\t\t\t}")
	case "object":
		// Nested composite config object (e.g. caching_compression cache/compress).
		// Rendered as a SingleNestedBlock with the object's scalar sub-fields as
		// attributes and its sub-collections/sub-scalar-string-arrays as nested
		// blocks within it.
		builder.WriteString("schema.SingleNestedBlock{\n")
		fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", scalar.Name+" configuration. Omission preserves the current value.")
		builder.WriteString("\t\t\t\t\t\tAttributes: map[string]schema.Attribute{\n")
		for _, sub := range scalar.ObjectFields {
			fmt.Fprintf(&builder, "\t\t\t\t\t\t\t%q: %s,\n", sub.Name, sub.SchemaExpr)
		}
		builder.WriteString("\t\t\t\t\t\t},\n")
		builder.WriteString("\t\t\t\t\t}")
	}
	return builder.String()
}

// itemFieldSchemaExpr builds the Go expression for an item-level
// schema.XxxAttribute{...}.
func itemFieldSchemaExpr(resource ResourceIR, field ItemFieldRender) string {
	var builder strings.Builder
	switch field.Kind {
	case "string":
		builder.WriteString("schema.StringAttribute{\n")
		if field.ComputedOnly {
			// Computed-only (backend-managed) item fields: Computed only (never
			// Optional/Required), no config validators, no plan modifiers. The
			// value is decoded from GET into state and grafted from the fresh
			// GET into the PUT; it is never read from config/plan/state.
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
			if field.Sensitive {
				builder.WriteString("\t\t\t\t\t\tSensitive:           true,\n")
			}
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", itemFieldDescription(field))
			builder.WriteString("\t\t\t\t\t}")
			break
		}
		if field.Required {
			builder.WriteString("\t\t\t\t\t\tRequired:            true,\n")
		} else {
			builder.WriteString("\t\t\t\t\t\tOptional:            true,\n")
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
		}
		fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", itemFieldDescription(field))
		var validators []string
		if field.MaxLength > 0 {
			validators = append(validators, fmt.Sprintf("stringvalidator.UTF8LengthAtMost(%d)", field.MaxLength))
		}
		if field.MinLength > 0 {
			validators = append(validators, fmt.Sprintf("stringvalidator.UTF8LengthAtLeast(%d)", field.MinLength))
		}
		if field.PatternVar != "" {
			validators = append(validators, fmt.Sprintf("stringvalidator.RegexMatches(%s, %q)", field.PatternVar, field.PatternMessage))
		}
		if field.EnumMap != "" {
			validators = append(validators, fmt.Sprintf("stringvalidator.OneOf(%s)", enumOneOfArgs(field.Enum)))
		}
		if len(validators) > 0 {
			fmt.Fprintf(&builder, "\t\t\t\t\t\tValidators:          []validator.String{%s},\n", strings.Join(validators, ", "))
		}
		if field.AllowWireNull {
			fmt.Fprintf(&builder, "\t\t\t\t\t\tPlanModifiers:       []planmodifier.String{%sClearStringModifier{}},\n", lowerCamelIdentifier(resource.GoName))
		} else if field.UseState && field.Optional {
			builder.WriteString("\t\t\t\t\t\tPlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},\n")
		}
		builder.WriteString("\t\t\t\t\t}")
	case "boolean":
		builder.WriteString("schema.BoolAttribute{\n")
		if field.ProviderDefaultBool != nil {
			builder.WriteString("\t\t\t\t\t\tOptional:            true,\n")
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", itemFieldDescription(field))
			modifier := "DefaultFalseModifier"
			if *field.ProviderDefaultBool {
				modifier = "DefaultTrueModifier"
			}
			fmt.Fprintf(&builder, "\t\t\t\t\t\tPlanModifiers:       []planmodifier.Bool{%s%s{}},\n", lowerCamelIdentifier(resource.GoName), modifier)
		} else if field.Optional {
			builder.WriteString("\t\t\t\t\t\tOptional:            true,\n")
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", itemFieldDescription(field))
			if field.UseState {
				builder.WriteString("\t\t\t\t\t\tPlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},\n")
			}
		} else {
			builder.WriteString("\t\t\t\t\t\tRequired:            true,\n")
			fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", itemFieldDescription(field))
		}
		builder.WriteString("\t\t\t\t\t}")
	case "integer":
		builder.WriteString("schema.Int64Attribute{\n")
		if field.Required {
			builder.WriteString("\t\t\t\t\t\tRequired:            true,\n")
		} else {
			builder.WriteString("\t\t\t\t\t\tOptional:            true,\n")
			builder.WriteString("\t\t\t\t\t\tComputed:            true,\n")
		}
		fmt.Fprintf(&builder, "\t\t\t\t\t\tMarkdownDescription: %q,\n", itemFieldDescription(field))
		var intValidators []string
		if field.HasRange {
			intValidators = append(intValidators, fmt.Sprintf("int64validator.Between(%d, %d)", field.Min, field.Max))
		} else if field.HasMin || field.HasMax {
			// One-sided bounds render as AtLeast/AtMost so a missing endpoint
			// is never silently treated as zero.
			if field.HasMin {
				intValidators = append(intValidators, fmt.Sprintf("int64validator.AtLeast(%d)", field.Min))
			}
			if field.HasMax {
				intValidators = append(intValidators, fmt.Sprintf("int64validator.AtMost(%d)", field.Max))
			}
		}
		if field.EnumMap != "" {
			intValidators = append(intValidators, fmt.Sprintf("int64validator.OneOf(%s)", intEnumOneOfArgs(field.Enum)))
		}
		if len(intValidators) > 0 {
			fmt.Fprintf(&builder, "\t\t\t\t\t\tValidators:          []validator.Int64{%s},\n", strings.Join(intValidators, ", "))
		}
		if field.UseState && field.Optional {
			builder.WriteString("\t\t\t\t\t\tPlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},\n")
		}
		builder.WriteString("\t\t\t\t\t}")
	}
	return builder.String()
}

func patternValidationMessage(pattern string) string {
	if pattern == `^/.*$` {
		return "must begin with /"
	}
	return "must match " + pattern
}

// patternSafeExample returns a docs-example string value that satisfies the
// reviewed regex pattern, so the generated example HCL is not rejected by its
// own schema validator. It handles the two reviewed patterns in use today
// (^/.*$ and ^\d{5}$) and falls back to the provided default for any other
// pattern (which must be reviewed before a new patterned example is needed).
func patternSafeExample(pattern, fallback string) string {
	switch {
	case pattern == "" || pattern == `^.*$`:
		return fallback
	case pattern == `^/.*$` || strings.HasPrefix(pattern, "^/"):
		return "/example"
	case strings.Contains(pattern, `\d`):
		return "00000"
	}
	return fallback
}

func itemFieldDescription(field ItemFieldRender) string {
	if field.Kind == "boolean" && field.ProviderDefaultBool != nil {
		defaultStr := "false"
		if *field.ProviderDefaultBool {
			defaultStr = "true"
		}
		return fmt.Sprintf("Whether this item `%s` is enabled. Defaults to %s for a newly configured item.", field.Name, defaultStr)
	}
	maxLen := field.MaxLength
	switch field.Name {
	case "url":
		if maxLen > 0 && field.Pattern != "" {
			return fmt.Sprintf("Request URL beginning with /, at most %d UTF-8 characters.", maxLen)
		}
		if maxLen > 0 {
			return fmt.Sprintf("Request URL, at most %d UTF-8 characters.", maxLen)
		}
		return "Request URL."
	case "name":
		if field.AllowWireNull {
			if maxLen > 0 {
				return fmt.Sprintf("Optional parameter name, at most %d UTF-8 characters. Omission removes the field from a managed item.", maxLen)
			}
			return "Optional parameter name. Omission removes the field from a managed item."
		}
		if maxLen > 0 {
			return fmt.Sprintf("The rule name, at most %d UTF-8 characters.", maxLen)
		}
		return "The rule name."
	case "value":
		if maxLen > 0 {
			return fmt.Sprintf("Optional parameter value, at most %d UTF-8 characters. Omission removes the field from a managed item.", maxLen)
		}
		return "Optional parameter value. Omission removes the field from a managed item."
	case "action":
		return "Action for detected rule violations."
	case "url_type":
		return "Selects literal string or regular-expression matching. String URLs must begin with /; regular-expression syntax is validated by the backend. Reviewed backend-only discriminator absent from the pinned OpenAPI schema."
	default:
		return field.Name
	}
}

// enumOneOfArgs renders the comma-separated quoted arguments for a
// stringvalidator.OneOf(...) call.
func enumOneOfArgs(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, `"`+value+`"`)
	}
	return strings.Join(quoted, ", ")
}
