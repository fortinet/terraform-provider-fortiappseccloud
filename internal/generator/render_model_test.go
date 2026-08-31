package generator

import (
	"os"
	"reflect"
	"strings"
	"testing"

	profile "terraform-provider-fortiappseccloud/internal/generator/profile/waf"
)

// TestLowerCamelIdentifier verifies the initialism-aware lowerCamel conversion
// used to derive codec identifiers from exported Go names.
func TestLowerCamelIdentifier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		goName string
		want   string
	}{
		{"CSRFProtection", "csrfProtection"},
		{"URLAccess", "urlAccess"},
		{"ID", "id"},
		{"HTTP", "http"},
		{"Name", "name"},
		{"AccountTakeover", "accountTakeover"},
	}
	for _, tc := range cases {
		if got := lowerCamelIdentifier(tc.goName); got != tc.want {
			t.Errorf("lowerCamelIdentifier(%q) = %q, want %q", tc.goName, got, tc.want)
		}
	}
}

// TestExportedName verifies snake_case-to-exported Go name conversion.
func TestExportedName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		snake string
		want  string
	}{
		{"url", "URL"},
		{"action", "Action"},
		{"page_list", "PageList"},
		{"rule_list", "RuleList"},
		{"ep_id", "EPID"},
		{"url_list", "URLList"},
		{"name", "Name"},
	}
	for _, tc := range cases {
		if got := exportedName(tc.snake); got != tc.want {
			t.Errorf("exportedName(%q) = %q, want %q", tc.snake, got, tc.want)
		}
	}
}

// TestBuildRenderModel verifies the render model derives correctly from a
// real manifest with two reviewed resources.
func TestBuildRenderModel(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}

	requestLimits := findResourceRender(t, model, "fortiappseccloud_waf_request_limits")
	headerLineNumber := findScalar(t, requestLimits.Scalars, "header_line_num")
	if headerLineNumber.Max != 500 || headerLineNumber.DecodeMax != 500 || !headerLineNumber.DecodeHasMax {
		t.Errorf("request_limits header_line_num = %#v, want OpenAPI 26.3.a max 500", headerLineNumber)
	}
	derivedWindow := findScalar(t, requestLimits.Scalars, "max_setting_initial_window_size")
	if !derivedWindow.ComputedOnly || !strings.Contains(derivedWindow.SchemaExpr, "Computed:") || strings.Contains(derivedWindow.SchemaExpr, "Optional:") {
		t.Errorf("request_limits derived window = %#v, want computed-only", derivedWindow)
	}
	if len(requestLimits.CrossFieldRules) != 1 {
		t.Fatalf("request_limits cross-field rules = %d, want 1", len(requestLimits.CrossFieldRules))
	}
	if len(model.Resources) != 25 {
		t.Fatalf("Resources = %d, want 25", len(model.Resources))
	}
	csrf := findResourceRender(t, model, "fortiappseccloud_waf_csrf_protection")
	if csrf.DestroyModeGo != "Disable" || csrf.DestroyField != "status" || !csrf.DestroyVerified || !csrf.DestroyDisables || csrf.DestroyCandidate {
		t.Fatalf("CSRF destroy render = %#v", csrf)
	}
	caching := findResourceRender(t, model, "fortiappseccloud_waf_caching_compression")
	if caching.DestroyField != "" || caching.DestroyCandidate || caching.DestroyDisables {
		t.Fatalf("caching/compression destroy render = %#v", caching)
	}
	if !reflect.DeepEqual(caching.TemplateDestroyCoupledFields, []string{"cache.status", "compress.status"}) {
		t.Fatalf("caching/compression template coupled fields = %#v", caching.TemplateDestroyCoupledFields)
	}
	if !caching.HasNestedCollections {
		t.Fatal("caching/compression should record flattened collections with nested wire parents")
	}
	for name, parent := range map[string]string{
		"content_type_list": "compress",
		"cookie_list":       "cache",
		"rule_list":         "cache",
	} {
		collection := findCollection(t, caching.Collections, name)
		if collection.WireParent != parent {
			t.Errorf("caching/compression %s WireParent = %q, want %q", name, collection.WireParent, parent)
		}
	}
	for _, scalar := range caching.Scalars {
		if scalar.Kind != "object" {
			continue
		}
		status := findItemField(t, scalar.ObjectFields, "status")
		if status == nil || !status.Optional || status.Required || !status.SourceRequired {
			t.Errorf("caching/compression %s.status = %#v, want optional Terraform field with required wire decode", scalar.Name, status)
		}
	}
	cachingSource, err := os.ReadFile("../resources/generated/waf/resource_caching_compression.go")
	if err != nil {
		t.Fatalf("read committed caching_compression resource: %v", err)
	}
	for _, needle := range []string{
		`cachingCompressionNestedConfigRaw(result.Configs["compress"], "content_type_list")`,
		`setNested("cache", "cookie_list", patch.CacheCookieList.Items)`,
		`setNested("cache", "rule_list", patch.CacheRuleList.Items)`,
		`PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}`,
		`CoupledFields: []string{`,
		`"cache.status"`,
		`"compress.status"`,
	} {
		if !strings.Contains(string(cachingSource), needle) {
			t.Errorf("caching/compression generated source missing nested wire operation %q", needle)
		}
	}
	if csrf.LowerCamel != "csrfProtection" {
		t.Errorf("CSRF LowerCamel = %q, want csrfProtection", csrf.LowerCamel)
	}
	if len(csrf.Scalars) != 2 {
		t.Fatalf("CSRF Scalars = %d, want 2", len(csrf.Scalars))
	}
	if len(csrf.Collections) != 2 {
		t.Fatalf("CSRF Collections = %d, want 2", len(csrf.Collections))
	}
	if csrf.HasFilter != true {
		t.Error("CSRF HasFilter should be true")
	}
	if csrf.HasClearStrings != true {
		t.Error("CSRF HasClearStrings should be true")
	}
	if !csrf.NeedsStringStateModifier || !csrf.NeedsBoolStateModifier {
		t.Error("CSRF should need both state modifiers")
	}
	// CSRF action enum must produce an enum map and valid function.
	action := findScalar(t, csrf.Scalars, "action")
	if action.EnumMap != "csrfProtectionConfigActionValues" || action.EnumValid != "csrfProtectionConfigActionValid" || len(action.Enum) != 3 {
		t.Errorf("CSRF action enum = %q %q %v", action.EnumMap, action.EnumValid, action.Enum)
	}
	// CSRF page_list max items = 256.
	pageList := findCollection(t, csrf.Collections, "page_list")
	if pageList.MaxItems != 256 || pageList.LocalName != "pageList" {
		t.Errorf("CSRF page_list = %#v", pageList)
	}
	urlList := findCollection(t, csrf.Collections, "url_list")
	if urlList.LocalName != "urlList" {
		t.Errorf("CSRF url_list LocalName = %q, want urlList", urlList.LocalName)
	}
	// CSRF url item field has pattern, max 255.
	urlField := findItemField(t, csrf.SharedItemFields, "url")
	if urlField.Pattern == "" || urlField.PatternVar != "csrfProtectionPageListURLPattern" || urlField.PatternMessage != "must begin with /" || urlField.MaxLength != 255 || !urlField.Required {
		t.Errorf("CSRF url field = %#v", urlField)
	}
	// CSRF name item field is optional with AllowWireNull, max 63.
	nameField := findItemField(t, csrf.SharedItemFields, "name")
	if !nameField.AllowWireNull || nameField.MaxLength != 63 || !nameField.Optional {
		t.Errorf("CSRF name field = %#v", nameField)
	}
	// CSRF filter has provider default false.
	filterField := findItemField(t, csrf.SharedItemFields, "filter")
	if filterField.ProviderDefaultBool == nil || *filterField.ProviderDefaultBool != false {
		t.Errorf("CSRF filter field = %#v", filterField)
	}

	urlAccess := findResourceRender(t, model, "fortiappseccloud_waf_url_access")
	if urlAccess.LowerCamel != "urlAccess" {
		t.Errorf("URLAccess LowerCamel = %q, want urlAccess", urlAccess.LowerCamel)
	}
	if len(urlAccess.Scalars) != 1 {
		t.Fatalf("URLAccess Scalars = %d, want 1", len(urlAccess.Scalars))
	}
	if len(urlAccess.Collections) != 1 {
		t.Fatalf("URLAccess Collections = %d, want 1", len(urlAccess.Collections))
	}
	if urlAccess.HasFilter {
		t.Error("URLAccess HasFilter should be false")
	}
	if urlAccess.HasClearStrings {
		t.Error("URLAccess HasClearStrings should be false")
	}
	if urlAccess.NeedsStringStateModifier {
		t.Error("URLAccess should not need string state modifier (no string scalars)")
	}
	if !urlAccess.NeedsBoolStateModifier {
		t.Error("URLAccess should need bool state modifier (status uses state)")
	}
	// URL access rule_list max items = 12.
	ruleList := findCollection(t, urlAccess.Collections, "rule_list")
	if ruleList.MaxItems != 12 {
		t.Errorf("URLAccess rule_list MaxItems = %d, want 12", ruleList.MaxItems)
	}
	// URL access action is required with enum pass/alert_deny/deny_no_log/continue.
	actionField := findItemField(t, urlAccess.SharedItemFields, "action")
	if !actionField.Required || len(actionField.Enum) != 4 {
		t.Errorf("URLAccess action field = %#v", actionField)
	}
	if actionField.EnumMap != "urlAccessRuleListActionValues" || actionField.EnumValid != "urlAccessRuleListActionValid" {
		t.Errorf("URLAccess action enum symbols = %q / %q", actionField.EnumMap, actionField.EnumValid)
	}
	// URL access name is required, max 39.
	nameField = findItemField(t, urlAccess.SharedItemFields, "name")
	if !nameField.Required || nameField.MaxLength != 39 {
		t.Errorf("URLAccess name field = %#v", nameField)
	}
	// URL access url is required, max 255, NO pattern.
	urlField = findItemField(t, urlAccess.SharedItemFields, "url")
	if !urlField.Required || urlField.MaxLength != 255 || urlField.Pattern != "" {
		t.Errorf("URLAccess url field = %#v", urlField)
	}
	// URL access has no filter or clear-string modifiers.
	if findItemField(t, urlAccess.SharedItemFields, "filter") != nil {
		t.Error("URLAccess should not have a filter field")
	}
	if findItemField(t, urlAccess.SharedItemFields, "value") != nil {
		t.Error("URLAccess should not have a value field")
	}
	// URL access url_type is a backend-enriched required enum field. The
	// backend evidence pins only the enum (regex|string), so url_type carries
	// no invented pattern; KnownKeys now include idx, action, name, url,
	// url_type.
	urlTypeField := findItemField(t, urlAccess.SharedItemFields, "url_type")
	if urlTypeField == nil {
		t.Fatal("URLAccess should have a backend-enriched url_type field")
	}
	if !urlTypeField.Required || len(urlTypeField.Enum) != 2 || urlTypeField.Pattern != "" {
		t.Errorf("URLAccess url_type field = %#v, want required enum without an invented pattern", urlTypeField)
	}
	if urlTypeField.EnumMap != "urlAccessRuleListURLTypeValues" || urlTypeField.EnumValid != "urlAccessRuleListURLTypeValid" {
		t.Errorf("URLAccess url_type enum symbols = %q / %q", urlTypeField.EnumMap, urlTypeField.EnumValid)
	}
	if len(urlAccess.SharedKnownKeys) != 5 {
		t.Errorf("URLAccess KnownKeys = %v, want 5 keys", urlAccess.SharedKnownKeys)
	}
	if !strings.Contains(urlAccess.Docs.ArgumentText, "— Rule name.") || strings.Contains(urlAccess.Docs.ArgumentText, "— Parameter name.") {
		t.Errorf("URLAccess argument text contains the wrong name description: %q", urlAccess.Docs.ArgumentText)
	}
	// url_type has no pattern and url has no pattern, so URLAccess must not
	// import regexp solely for the backend-enriched url_type field.
	if strings.Contains(urlAccess.ImportBlock, `"regexp"`) {
		t.Error("URLAccess should not import regexp when no item field carries a pattern")
	}
}

// TestRenderModelDeterministic verifies the render model is stable across runs.
func TestRenderModelDeterministic(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	first, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Resources) != len(second.Resources) {
		t.Fatal("render model resource count differs across runs")
	}
	for i := range first.Resources {
		if first.Resources[i].LowerCamel != second.Resources[i].LowerCamel {
			t.Fatalf("resource %d LowerCamel differs: %q vs %q", i, first.Resources[i].LowerCamel, second.Resources[i].LowerCamel)
		}
		if first.Resources[i].ImportBlock != second.Resources[i].ImportBlock {
			t.Fatalf("resource %d ImportBlock differs", i)
		}
	}
}

// TestImportBlockGrouping verifies import blocks separate stdlib, third-party,
// and local imports so gofmt preserves the grouping.
func TestImportBlockGrouping(t *testing.T) {
	t.Parallel()
	block := renderImportBlock([]string{
		"context",
		"github.com/hashicorp/terraform-plugin-framework/types",
		"terraform-provider-fortiappseccloud/internal/client",
		"sort",
	})
	if !strings.Contains(block, "\n\t\"sort\"\n") {
		t.Error("stdlib imports not grouped correctly")
	}
	if !strings.Contains(block, "github.com/hashicorp") {
		t.Error("third-party imports missing")
	}
	if !strings.Contains(block, "terraform-provider-fortiappseccloud") {
		t.Error("local imports missing")
	}
}

// TestEnumOneOfArgs verifies the OneOf validator argument formatting.
func TestEnumOneOfArgs(t *testing.T) {
	t.Parallel()
	got := enumOneOfArgs([]string{"alert", "alert_deny", "deny_no_log"})
	want := `"alert", "alert_deny", "deny_no_log"`
	if got != want {
		t.Errorf("enumOneOfArgs = %q, want %q", got, want)
	}
}

// TestRenderModelGraphQLItemConstraints verifies the generator carries integer
// ranges and use_state_for_unknown onto GraphQL protection item fields, which
// were previously lost during rendering.
func TestRenderModelGraphQLItemConstraints(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	graphql := findResourceRender(t, model, "fortiappseccloud_waf_graphql_protection")
	if len(graphql.Collections) != 1 {
		t.Fatalf("GraphQL collections = %d, want 1", len(graphql.Collections))
	}
	fields := itemFieldIndex(graphql.Collections[0].Item.Fields)

	// graphql_data_size pins 0..10240 and must render Between + UseState.
	graphqlDataSize, ok := fields["graphql_data_size"]
	if !ok {
		t.Fatal("missing graphql_data_size item field")
	}
	if !graphqlDataSize.HasRange || graphqlDataSize.Min != 0 || graphqlDataSize.Max != 10240 {
		t.Errorf("graphql_data_size range = %v/%d/%d, want HasRange 0..10240", graphqlDataSize.HasRange, graphqlDataSize.Min, graphqlDataSize.Max)
	}
	if !graphqlDataSize.UseState {
		t.Error("graphql_data_size should carry use_state_for_unknown")
	}
	if !strings.Contains(graphqlDataSize.SchemaExpr, "int64validator.Between(0, 10240)") {
		t.Errorf("graphql_data_size schema missing Between validator: %s", graphqlDataSize.SchemaExpr)
	}
	if !strings.Contains(graphqlDataSize.SchemaExpr, "int64planmodifier.UseStateForUnknown()") {
		t.Errorf("graphql_data_size schema missing UseStateForUnknown modifier: %s", graphqlDataSize.SchemaExpr)
	}

	// name is required with maxLength 40 and emits UTF8LengthAtMost(40).
	name, ok := fields["name"]
	if !ok {
		t.Fatal("missing name item field")
	}
	if !name.Required || name.MaxLength != 40 {
		t.Errorf("name = %#v, want required MaxLength 40", name)
	}
	if !strings.Contains(name.SchemaExpr, "stringvalidator.UTF8LengthAtMost(40)") {
		t.Errorf("name schema missing UTF8LengthAtMost(40): %s", name.SchemaExpr)
	}

	// GraphQL must import int64validator for the item integer Between validators.
	if !strings.Contains(graphql.ImportBlock, `"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"`) {
		t.Errorf("GraphQL should import int64validator for item range validators: %s", graphql.ImportBlock)
	}
}

// TestRenderModelHttpHeaderSecurityScalars verifies the generator renders
// maximum-length validators on HTTP header security config scalars and uses a
// nullable *string wire type for the nullable referrer_policy_header_value.
func TestRenderModelHttpHeaderSecurityScalars(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	httpHeader := findResourceRender(t, model, "fortiappseccloud_waf_http_header_security")

	headerValue := findScalar(t, httpHeader.Scalars, "header_value")
	if headerValue.MaxLength != 1023 {
		t.Errorf("header_value MaxLength = %d, want 1023", headerValue.MaxLength)
	}
	if !strings.Contains(headerValue.SchemaExpr, "stringvalidator.UTF8LengthAtMost(1023)") {
		t.Errorf("header_value schema missing UTF8LengthAtMost(1023): %s", headerValue.SchemaExpr)
	}

	referrer := findScalar(t, httpHeader.Scalars, "referrer_policy_header_value")
	if referrer.MaxLength != 64 || !referrer.AllowNull {
		t.Errorf("referrer_policy_header_value = %#v, want MaxLength 64 AllowNull true", referrer)
	}
	if referrer.WireType != "*string" {
		t.Errorf("referrer_policy_header_value WireType = %q, want *string for nullable scalar", referrer.WireType)
	}
	if referrer.PatchType != "string" {
		t.Errorf("referrer_policy_header_value PatchType = %q, want string", referrer.PatchType)
	}
	if !strings.Contains(referrer.SchemaExpr, "stringvalidator.UTF8LengthAtMost(64)") {
		t.Errorf("referrer_policy_header_value schema missing UTF8LengthAtMost(64): %s", referrer.SchemaExpr)
	}
	if !strings.Contains(referrer.SchemaExpr, "stringvalidator.OneOf(") {
		t.Errorf("referrer_policy_header_value schema missing enum validator: %s", referrer.SchemaExpr)
	}
}

// TestRenderModelKnownAttacksSigIdMinLength verifies the nine-character minimum
// on the known_attacks sig_id item field is carried through rendering.
func TestRenderModelKnownAttacksSigIdMinLength(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	knownAttacks := findResourceRender(t, model, "fortiappseccloud_waf_known_attacks")
	sig := findCollection(t, knownAttacks.Collections, "sig_except_rules")
	sigID := findItemField(t, sig.Item.Fields, "sig_id")
	if sigID == nil {
		t.Fatal("missing sig_id item field")
	}
	if sigID.MinLength != 9 || sigID.MaxLength != 9 {
		t.Errorf("sig_id length = min %d max %d, want 9/9", sigID.MinLength, sigID.MaxLength)
	}
	if !strings.Contains(sigID.SchemaExpr, "stringvalidator.UTF8LengthAtLeast(9)") {
		t.Errorf("sig_id schema missing UTF8LengthAtLeast(9): %s", sigID.SchemaExpr)
	}
	if !strings.Contains(sigID.SchemaExpr, "stringvalidator.UTF8LengthAtMost(9)") {
		t.Errorf("sig_id schema missing UTF8LengthAtMost(9): %s", sigID.SchemaExpr)
	}

	// Nested objects carry known keys for the recursive fail-closed check.
	cookie := findItemField(t, sig.Item.Fields, "cookie")
	if cookie == nil {
		t.Fatal("missing cookie nested object field")
	}
	if len(cookie.ObjectKnownKeys) == 0 {
		t.Error("cookie nested object should carry ObjectKnownKeys for the fail-closed check")
	}
}

// TestScalarSchemaExprRendersMinLength verifies the scalar schema expression
// renders a UTF8LengthAtLeast validator when a config scalar carries a reviewed
// MinLength, so the MinLength constraint is wired end-to-end into the schema
// (the response-decode MinLength check is rendered by the template). No current
// config scalar pins a minimum, so this exercises the capability directly.
func TestScalarSchemaExprRendersMinLength(t *testing.T) {
	t.Parallel()
	resource := ResourceIR{GoName: "Example", Reviewed: profile.ResourceOverride{}}
	scalar := ScalarRender{
		Name:      "example",
		GoName:    "Example",
		Kind:      "string",
		GoType:    "types.String",
		AttrType:  "types.StringType",
		MinLength: 5,
		MaxLength: 10,
	}
	expr := scalarSchemaExpr(resource, scalar)
	if !strings.Contains(expr, "stringvalidator.UTF8LengthAtLeast(5)") {
		t.Errorf("scalar schema missing MinLength validator: %s", expr)
	}
	if !strings.Contains(expr, "stringvalidator.UTF8LengthAtMost(10)") {
		t.Errorf("scalar schema missing MaxLength validator: %s", expr)
	}
}

// TestScalarSchemaExprRendersOneSidedIntegerBounds verifies that a config
// integer scalar with only a minimum or only a maximum renders an AtLeast or
// AtMost validator (never Between with a zeroed missing endpoint), and that a
// two-sided range still renders Between. No current resource pins a one-sided
// bound, so this exercises the generic capability directly to prevent the
// one-sided enrichment defect (Between(min,0) / Between(0,max)) regressing.
func TestScalarSchemaExprRendersOneSidedIntegerBounds(t *testing.T) {
	t.Parallel()
	resource := ResourceIR{GoName: "Example", Reviewed: profile.ResourceOverride{}}
	base := ScalarRender{
		Name:     "example",
		GoName:   "Example",
		Kind:     "integer",
		GoType:   "types.Int64",
		AttrType: "types.Int64Type",
	}

	minOnly := base
	minOnly.HasMin = true
	minOnly.Min = 5
	minExpr := scalarSchemaExpr(resource, minOnly)
	if !strings.Contains(minExpr, "int64validator.AtLeast(5)") {
		t.Errorf("min-only scalar missing AtLeast(5): %s", minExpr)
	}
	if strings.Contains(minExpr, "int64validator.Between(") || strings.Contains(minExpr, "AtMost(") {
		t.Errorf("min-only scalar emitted Between or AtMost (must not): %s", minExpr)
	}

	maxOnly := base
	maxOnly.HasMax = true
	maxOnly.Max = 30
	maxExpr := scalarSchemaExpr(resource, maxOnly)
	if !strings.Contains(maxExpr, "int64validator.AtMost(30)") {
		t.Errorf("max-only scalar missing AtMost(30): %s", maxExpr)
	}
	if strings.Contains(maxExpr, "int64validator.Between(") || strings.Contains(maxExpr, "AtLeast(") {
		t.Errorf("max-only scalar emitted Between or AtLeast (must not): %s", maxExpr)
	}

	both := base
	both.HasMin = true
	both.HasMax = true
	both.Min = 1
	both.Max = 100
	both.HasRange = true
	bothExpr := scalarSchemaExpr(resource, both)
	if !strings.Contains(bothExpr, "int64validator.Between(1, 100)") {
		t.Errorf("two-sided scalar missing Between(1, 100): %s", bothExpr)
	}
	if strings.Contains(bothExpr, "AtLeast(") || strings.Contains(bothExpr, "AtMost(") {
		t.Errorf("two-sided scalar emitted AtLeast/AtMost (must use Between): %s", bothExpr)
	}
}

// TestRenderModelRequestLimitsAllowMethodsRequired verifies the required
// scalar-string-array flag is carried through rendering.
func TestRenderModelRequestLimitsAllowMethodsRequired(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requestLimits := findResourceRender(t, model, "fortiappseccloud_waf_request_limits")
	if len(requestLimits.ScalarStringArrays) != 1 {
		t.Fatalf("ScalarStringArrays = %d, want 1", len(requestLimits.ScalarStringArrays))
	}
	allowMethods := requestLimits.ScalarStringArrays[0]
	if allowMethods.WireName != "allow_methods" || !allowMethods.Required {
		t.Errorf("allow_methods = %#v, want required", allowMethods)
	}
	// The generated docs must document allow_methods and its method item
	// attribute; the docs model previously ignored scalar-string arrays entirely.
	if !strings.Contains(requestLimits.Docs.ArgumentText, "allow_methods") {
		t.Errorf("request_limits docs missing allow_methods: %s", requestLimits.Docs.ArgumentText)
	}
	if !strings.Contains(requestLimits.Docs.ArgumentText, "allow_methods.item.method") {
		t.Errorf("request_limits docs missing allow_methods.item.method item attribute: %s", requestLimits.Docs.ArgumentText)
	}
	if !strings.Contains(requestLimits.Docs.ExampleHCL, "allow_methods") {
		t.Errorf("request_limits example HCL missing allow_methods: %s", requestLimits.Docs.ExampleHCL)
	}
}

func TestRenderModelTemplateExamplesReuseTypedConfigs(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range model.Resources {
		example := resource.Docs.TemplateExampleHCL
		wantType := `resource "fortiappseccloud_waf_template_` + strings.TrimPrefix(resource.TypeNameSuffix, "waf_") + `"`
		if !strings.Contains(example, wantType) || !strings.Contains(example, "template_id = fortiappseccloud_waf_template.example.template_id") {
			t.Errorf("%s template example has the wrong identity:\n%s", resource.TerraformName, example)
		}
		if strings.Contains(example, "ep_id") || strings.Contains(example, "  template =") {
			t.Errorf("%s template example retained app-only fields:\n%s", resource.TerraformName, example)
		}
		appConfigs := strings.Index(resource.Docs.ExampleHCL, "  configs {")
		templateConfigs := strings.Index(example, "  configs {")
		if appConfigs < 0 || templateConfigs < 0 ||
			resource.Docs.ExampleHCL[appConfigs:] != example[templateConfigs:] {
			t.Errorf("%s template example did not preserve the complete typed configs example", resource.TerraformName)
		}
	}
}

// TestRenderModelGraphQLItemDefaultsDocumented verifies the generated docs
// mention the reviewed integer item defaults and required fields.
func TestRenderModelGraphQLItemDefaultsDocumented(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	graphql := findResourceRender(t, model, "fortiappseccloud_waf_graphql_protection")
	for _, needle := range []string{"name", "request_url", "field_number", "graphql_data_size"} {
		if !strings.Contains(graphql.Docs.ArgumentText, needle) {
			t.Errorf("graphql docs missing %q: %s", needle, graphql.Docs.ArgumentText)
		}
	}
}

func readOpenAPIForTest(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func findResourceRender(t *testing.T, model RenderModel, name string) ResourceRender {
	t.Helper()
	for _, r := range model.Resources {
		if r.TerraformName == name {
			return r
		}
	}
	t.Fatalf("resource %q not found in render model", name)
	return ResourceRender{}
}

func findScalar(t *testing.T, scalars []ScalarRender, name string) ScalarRender {
	t.Helper()
	for _, s := range scalars {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("scalar %q not found", name)
	return ScalarRender{}
}

func findCollection(t *testing.T, collections []CollectionRender, wireName string) CollectionRender {
	t.Helper()
	for _, c := range collections {
		if c.WireName == wireName {
			return c
		}
	}
	t.Fatalf("collection %q not found", wireName)
	return CollectionRender{}
}

func findItemField(t *testing.T, fields []ItemFieldRender, name string) *ItemFieldRender {
	t.Helper()
	for i := range fields {
		if fields[i].Name == name {
			return &fields[i]
		}
	}
	return nil
}

func itemFieldIndex(fields []ItemFieldRender) map[string]ItemFieldRender {
	index := make(map[string]ItemFieldRender, len(fields))
	for i := range fields {
		index[fields[i].Name] = fields[i]
	}
	return index
}

// TestRenderModelBotDeceptionBiometricsWaitingRoom pins the render-model facts
// for the fourteenth/fifteenth/sixteenth generated resources: per-collection
// item schemas (bot_deception and biometrics have two collections with
// different item schemas), the biometrics bounded integer config scalars, the
// waiting_room rule_type pattern + single collection, and example-HCL coverage
// of the required item fields.
func TestRenderModelBotDeceptionBiometricsWaitingRoom(t *testing.T) {
	t.Parallel()
	openAPI := readOpenAPIForTest(t)
	manifest, err := BuildManifest(openAPI, profile.DefaultOverridesJSON)
	if err != nil {
		t.Fatal(err)
	}
	model, err := buildRenderModel(manifest)
	if err != nil {
		t.Fatal(err)
	}

	// requireNoIdxAttribute asserts the wire-only positional idx is never
	// rendered as a Terraform item attribute for the given collection.
	requireNoIdxAttribute := func(t *testing.T, label string, c CollectionRender) {
		t.Helper()
		if idx := findItemField(t, c.Item.Fields, "idx"); idx != nil {
			t.Errorf("%s unexpectedly renders wire-only idx: %#v", label, idx)
		}
	}
	// requireExampleCoversRequiredItemFields asserts every required item field
	// of every collection appears in the resource's generated example HCL.
	requireExampleCoversRequiredItemFields := func(t *testing.T, label, example string, cols []CollectionRender) {
		t.Helper()
		for _, c := range cols {
			for _, f := range c.Item.Fields {
				if !f.Required {
					continue
				}
				if !strings.Contains(example, f.Name) {
					t.Errorf("%s example HCL missing required item field %s.%s: %s", label, c.WireName, f.Name, example)
				}
			}
		}
	}

	// --- bot_deception: two collections with different item schemas ---
	botDeception := findResourceRender(t, model, "fortiappseccloud_waf_bot_deception")
	if len(botDeception.Collections) != 2 {
		t.Fatalf("bot_deception collections = %d, want 2", len(botDeception.Collections))
	}
	urlList := findCollection(t, botDeception.Collections, "url_list")
	if urlList.MaxItems != 12 {
		t.Errorf("bot_deception url_list MaxItems = %d, want 12", urlList.MaxItems)
	}
	urlField := findItemField(t, urlList.Item.Fields, "url")
	if urlField == nil || !urlField.Required || urlField.MaxLength != 255 {
		t.Errorf("bot_deception url_list.url = %#v, want required max 255", urlField)
	}
	requireNoIdxAttribute(t, "bot_deception url_list", urlList)
	exceptionList := findCollection(t, botDeception.Collections, "exception_list")
	if exceptionList.MaxItems != 128 {
		t.Errorf("bot_deception exception_list MaxItems = %d, want 128", exceptionList.MaxItems)
	}
	requireNoIdxAttribute(t, "bot_deception exception_list", exceptionList)
	for _, name := range []string{"concatenate_type", "match_target", "operator"} {
		f := findItemField(t, exceptionList.Item.Fields, name)
		if f == nil || !f.Required {
			t.Errorf("bot_deception exception_list.%s = %#v, want required", name, f)
		}
	}
	valueCheck := findItemField(t, exceptionList.Item.Fields, "value_check")
	if valueCheck == nil || valueCheck.ProviderDefaultBool == nil || *valueCheck.ProviderDefaultBool != false {
		t.Errorf("bot_deception exception_list.value_check = %#v, want provider default false", valueCheck)
	}
	requireExampleCoversRequiredItemFields(t, "bot_deception", botDeception.Docs.ExampleHCL, botDeception.Collections)

	// --- biometrics_based_detection: bounded integer config scalars + same two collections ---
	bio := findResourceRender(t, model, "fortiappseccloud_waf_biometrics_based_detection")
	if len(bio.Collections) != 2 {
		t.Fatalf("biometrics collections = %d, want 2", len(bio.Collections))
	}
	botEffectTime := findScalar(t, bio.Scalars, "bot_effect_time")
	if !botEffectTime.HasRange || botEffectTime.Min != 1 || botEffectTime.Max != 5 {
		t.Errorf("biometrics bot_effect_time = %#v, want range 1..5", botEffectTime)
	}
	eventCollectTime := findScalar(t, bio.Scalars, "event_collect_time")
	if !eventCollectTime.HasRange || eventCollectTime.Min != 10 || eventCollectTime.Max != 60 {
		t.Errorf("biometrics event_collect_time = %#v, want range 10..60", eventCollectTime)
	}
	// biometrics has bounded int64 config scalars, so it must still import
	// int64validator (the import-gating fix must not drop it here).
	if !sliceContains(bio.Imports, "github.com/hashicorp/terraform-plugin-framework-validators/int64validator") {
		t.Errorf("biometrics imports = %v, want int64validator (has bounded int64 scalars)", bio.Imports)
	}
	for _, c := range bio.Collections {
		requireNoIdxAttribute(t, "biometrics "+c.WireName, c)
	}
	bioException := findCollection(t, bio.Collections, "exception_list")
	if bioException.MaxItems != 128 {
		t.Errorf("biometrics exception_list MaxItems = %d, want 128", bioException.MaxItems)
	}
	bioMatchTarget := findItemField(t, bioException.Item.Fields, "match_target")
	if bioMatchTarget == nil || !bioMatchTarget.Required {
		t.Errorf("biometrics exception_list.match_target = %#v, want required", bioMatchTarget)
	}
	requireExampleCoversRequiredItemFields(t, "biometrics", bio.Docs.ExampleHCL, bio.Collections)

	// --- waiting_room: single collection, rule_type pattern, no int64 range ---
	waitingRoom := findResourceRender(t, model, "fortiappseccloud_waf_waiting_room")
	if len(waitingRoom.Collections) != 1 {
		t.Fatalf("waiting_room collections = %d, want 1", len(waitingRoom.Collections))
	}
	bypassRules := findCollection(t, waitingRoom.Collections, "bypass_rules")
	if bypassRules.MaxItems != 100 {
		t.Errorf("waiting_room bypass_rules MaxItems = %d, want 100", bypassRules.MaxItems)
	}
	requireNoIdxAttribute(t, "waiting_room bypass_rules", bypassRules)
	ruleType := findItemField(t, bypassRules.Item.Fields, "rule_type")
	if ruleType == nil || !ruleType.Required || ruleType.MaxLength != 64 || ruleType.Pattern == "" {
		t.Errorf("waiting_room bypass_rules.rule_type = %#v, want required max 64 with pattern", ruleType)
	}
	ruleValue := findItemField(t, bypassRules.Item.Fields, "rule_value")
	if ruleValue == nil || !ruleValue.Required {
		t.Errorf("waiting_room bypass_rules.rule_value = %#v, want required", ruleValue)
	}
	requireExampleCoversRequiredItemFields(t, "waiting_room", waitingRoom.Docs.ExampleHCL, waitingRoom.Collections)

	for _, name := range []string{"total_active_users", "new_users_per_min"} {
		s := findScalar(t, waitingRoom.Scalars, name)
		if s.HasMin || s.HasMax {
			t.Errorf("waiting_room %s = %#v, want conditional extension bounds only", name, s)
		}
	}
	session := findScalar(t, waitingRoom.Scalars, "session_duration")
	if !session.HasRange || session.Min != 1 || session.Max != 30 {
		t.Errorf("waiting_room session_duration = %#v, want range 1..30", session)
	}
	if len(waitingRoom.CrossFieldRules) != 3 {
		t.Fatalf("waiting_room cross-field rules = %d, want 3", len(waitingRoom.CrossFieldRules))
	}
	if !sliceContains(waitingRoom.Imports, "github.com/hashicorp/terraform-plugin-framework-validators/int64validator") {
		t.Errorf("waiting_room imports = %v, want int64validator", waitingRoom.Imports)
	}
	if !waitingRoom.HasInt64Scalars {
		t.Error("waiting_room HasInt64Scalars = false, want true (emits the ConfiguredInt64 build helper)")
	}
	waitingRoomSource, err := os.ReadFile("../resources/generated/waf/resource_waiting_room.go")
	if err != nil {
		t.Fatalf("read committed waiting_room resource: %v", err)
	}
	if !strings.Contains(string(waitingRoomSource), "func waitingRoomConfiguredInt64(") {
		t.Error("waiting_room generated resource missing the ConfiguredInt64 build helper")
	}
	if !strings.Contains(string(waitingRoomSource), "int64validator.Between(1, 30)") {
		t.Error("waiting_room generated resource missing the session_duration Between(1, 30) validator")
	}

	// --- 2026-07-20 slice: five new generated resources (16 -> 21) ---
	// For every new resource: every collection's wire-only idx is absent from
	// the Terraform schema, every required item field appears in the generated
	// example HCL, and the reviewed bounds/patterns/defaults/sensitive flag are
	// pinned end-to-end. The two new generator capabilities (enum sort+dedup
	// normalization, sensitive scalars) and the scoped idx-default-0 exemption
	// are exercised here.
	newResources := []string{
		"fortiappseccloud_waf_mitb_protection",
		"fortiappseccloud_waf_threshold_detection",
		"fortiappseccloud_waf_ml_bot_detection",
		"fortiappseccloud_waf_file_protection",
		"fortiappseccloud_waf_mobile_api_protection",
	}
	for _, name := range newResources {
		r := findResourceRender(t, model, name)
		for _, c := range r.Collections {
			requireNoIdxAttribute(t, name+" "+c.WireName, c)
		}
		requireExampleCoversRequiredItemFields(t, name, r.Docs.ExampleHCL, r.Collections)
	}

	// mitb_protection: scalar patterns on optional config strings + two
	// bounded all-scalar collections.
	mitb := findResourceRender(t, model, "fortiappseccloud_waf_mitb_protection")
	if len(mitb.Collections) != 2 {
		t.Fatalf("mitb_protection collections = %d, want 2", len(mitb.Collections))
	}
	for _, want := range []string{"request_url", "post_url"} {
		s := findScalar(t, mitb.Scalars, want)
		if s.MaxLength != 255 || s.Pattern == "" || s.PatternVar == "" {
			t.Errorf("mitb %s = %#v, want max 255 with pattern+var", want, s)
		}
	}
	mitbParam := findCollection(t, mitb.Collections, "param_list")
	if mitbParam.MaxItems != 256 {
		t.Errorf("mitb param_list MaxItems = %d, want 256", mitbParam.MaxItems)
	}
	mitbParamName := findItemField(t, mitbParam.Item.Fields, "name")
	if mitbParamName == nil || !mitbParamName.Required || mitbParamName.MaxLength != 63 {
		t.Errorf("mitb param_list.name = %#v, want required max 63", mitbParamName)
	}
	mitbDomain := findCollection(t, mitb.Collections, "domain_list")
	if mitbDomain.MaxItems != 256 {
		t.Errorf("mitb domain_list MaxItems = %d, want 256", mitbDomain.MaxItems)
	}
	// The mitb generated resource must enforce the scalar pattern in the
	// schema (RegexMatches) and in build and decode (MatchString).
	mitbSource, err := os.ReadFile("../resources/generated/waf/resource_mitb_protection.go")
	if err != nil {
		t.Fatalf("read committed mitb_protection resource: %v", err)
	}
	if !strings.Contains(string(mitbSource), "RegexMatches(mitbProtectionConfigRequestURLPattern") {
		t.Error("mitb_protection generated resource missing request_url RegexMatches schema validator")
	}
	// The scalar pattern must be enforced in BOTH the build (ConfiguredString)
	// and the response decode (optional string decode branch), so the
	// MatchString call must appear at least twice.
	if got := strings.Count(string(mitbSource), "mitbProtectionConfigRequestURLPattern.MatchString"); got < 2 {
		t.Errorf("mitb_protection request_url MatchString count = %d, want >= 2 (build + decode)", got)
	}

	// threshold_detection: integer config-scalar ranges + one reused
	// BotExceptionRuleList collection.
	threshold := findResourceRender(t, model, "fortiappseccloud_waf_threshold_detection")
	if len(threshold.Collections) != 1 {
		t.Fatalf("threshold_detection collections = %d, want 1", len(threshold.Collections))
	}
	occurrence := findScalar(t, threshold.Scalars, "occurrence")
	if !occurrence.HasRange || occurrence.Min != 1 || occurrence.Max != 100 {
		t.Errorf("threshold_detection occurrence = %#v, want range 1..100", occurrence)
	}
	rangeScalar := findScalar(t, threshold.Scalars, "range")
	if !rangeScalar.HasRange || rangeScalar.Min != 1 || rangeScalar.Max != 60 {
		t.Errorf("threshold_detection range = %#v, want range 1..60", rangeScalar)
	}
	thresholdException := findCollection(t, threshold.Collections, "exception_list")
	if thresholdException.MaxItems != 128 {
		t.Errorf("threshold_detection exception_list MaxItems = %d, want 128", thresholdException.MaxItems)
	}

	// ml_bot_detection: required integer config scalar anomaly_count 1..3,
	// optional block_duration 1..3600, three collections reusing IpList /
	// UrlPattern (max 127, ^/.*$) / BotExceptionRuleList. The optional
	// url_list.item.url pattern must enforce in schema AND build/decode.
	ml := findResourceRender(t, model, "fortiappseccloud_waf_ml_bot_detection")
	if len(ml.Collections) != 3 {
		t.Fatalf("ml_bot_detection collections = %d, want 3", len(ml.Collections))
	}
	mlAction := findScalar(t, ml.Scalars, "action")
	if len(mlAction.WireAliases) != 1 || mlAction.WireAliases[0].WireLiteral != `"client-id-block-period"` || mlAction.WireAliases[0].TerraformLiteral != `"block_period"` {
		t.Errorf("ml_bot_detection action wire aliases = %#v", mlAction.WireAliases)
	}
	anomaly := findScalar(t, ml.Scalars, "anomaly_count")
	if !anomaly.HasRange || anomaly.Min != 1 || anomaly.Max != 3 || !anomaly.Required {
		t.Errorf("ml_bot_detection anomaly_count = %#v, want required range 1..3", anomaly)
	}
	blockDuration := findScalar(t, ml.Scalars, "block_duration")
	if !blockDuration.HasRange || blockDuration.Min != 1 || blockDuration.Max != 3600 {
		t.Errorf("ml_bot_detection block_duration = %#v, want range 1..3600", blockDuration)
	}
	mlURL := findCollection(t, ml.Collections, "url_list")
	mlURLField := findItemField(t, mlURL.Item.Fields, "url")
	if mlURLField == nil || mlURLField.MaxLength != 127 || mlURLField.Pattern == "" || mlURLField.PatternVar == "" {
		t.Errorf("ml_bot_detection url_list.url = %#v, want optional max 127 with pattern+var", mlURLField)
	}
	if mlURL.MaxItems != 30 {
		t.Errorf("ml_bot_detection url_list MaxItems = %d, want 30", mlURL.MaxItems)
	}
	mlSource, err := os.ReadFile("../resources/generated/waf/resource_ml_bot_detection.go")
	if err != nil {
		t.Fatalf("read committed ml_bot_detection resource: %v", err)
	}
	if !strings.Contains(string(mlSource), "RegexMatches(mlBotDetectionURLListURLPattern") {
		t.Error("ml_bot_detection generated resource missing url_list.item.url RegexMatches schema validator")
	}
	if !strings.Contains(string(mlSource), `if patch.Action.Value == "block_period" {`) ||
		!strings.Contains(string(mlSource), `patch.Action.Value = "client-id-block-period"`) {
		t.Error("ml_bot_detection generated resource missing configured Terraform-to-wire action mapping")
	}
	// The optional item-string pattern must be enforced in BOTH the build and
	// the response decode, so MatchString must appear at least twice.
	if got := strings.Count(string(mlSource), "mlBotDetectionURLListURLPattern.MatchString"); got < 2 {
		t.Errorf("ml_bot_detection url_list.item.url MatchString count = %d, want >= 2 (build + decode)", got)
	}

	// file_protection: enum dedup (FileType.type is the duplicate-bearing
	// pinned OpenAPI enum, normalized to 122 unique values), the scoped
	// idx-default-0 exemption on custom_file_types and its
	// file_content_match_rule sub-item, the scalar url pattern, the
	// file_types.item.tid ^\d{5}$ pattern (optional item string), and the
	// nested file_content_match_rule.item.offset range 0..4096.
	file := findResourceRender(t, model, "fortiappseccloud_waf_file_protection")
	if len(file.Collections) != 2 {
		t.Fatalf("file_protection collections = %d, want 2", len(file.Collections))
	}
	fileTypes := findCollection(t, file.Collections, "file_types")
	if fileTypes.MaxItems != 0 {
		t.Errorf("file_protection file_types MaxItems = %d, want 0 (unbounded)", fileTypes.MaxItems)
	}
	fileTid := findItemField(t, fileTypes.Item.Fields, "tid")
	if fileTid == nil || fileTid.Pattern == "" || fileTid.PatternVar == "" {
		t.Errorf("file_protection file_types.tid = %#v, want pattern+var", fileTid)
	}
	customFileTypes := findCollection(t, file.Collections, "custom_file_types")
	if customFileTypes.MaxItems != 12 {
		t.Errorf("file_protection custom_file_types MaxItems = %d, want 12", customFileTypes.MaxItems)
	}
	matchRules := findItemField(t, customFileTypes.Item.Fields, "file_content_match_rule")
	if matchRules == nil || matchRules.WireName != "match_rules" || matchRules.SubItemArray == nil || matchRules.SubItemArray.WireName != "match_rules" {
		t.Errorf("file_protection file_content_match_rule = %#v, want stable Terraform name mapped to match_rules", matchRules)
	}
	fileURL := findScalar(t, file.Scalars, "url")
	if fileURL.MaxLength != 255 || fileURL.Pattern != "" || fileURL.PatternVar != "" {
		t.Errorf("file_protection url scalar = %#v, want native max 255 without pattern", fileURL)
	}
	for _, name := range []string{"json_key_field", "json_key_for_filename"} {
		field := findScalar(t, file.Scalars, name)
		if !field.AllowWireNull || field.AllowNull {
			t.Errorf("file_protection %s = %#v, want response-only null tolerance", name, field)
		}
	}
	fileSource, err := os.ReadFile("../resources/generated/waf/resource_file_protection.go")
	if err != nil {
		t.Fatalf("read committed file_protection resource: %v", err)
	}
	if !strings.Contains(string(fileSource), "UTF8LengthAtMost(255)") {
		t.Error("file_protection generated resource missing url UTF8LengthAtMost(255) validator")
	}
	// The duplicate-bearing FileType.type enum is deduped to 122 unique
	// values in the contract; the generated map literal must not contain
	// duplicate keys (which would be a Go compile error).
	if strings.Count(string(fileSource), `"AIN Archive Data(.ain)": {}`) != 1 {
		t.Errorf("file_protection generated enum map does not dedupe 'AIN Archive Data(.ain)' (want exactly one key)")
	}
	// The tid pattern must enforce in schema AND build AND decode.
	if !strings.Contains(string(fileSource), "RegexMatches(fileProtectionFileTypesTidPattern") {
		t.Error("file_protection generated resource missing tid RegexMatches schema validator")
	}
	if got := strings.Count(string(fileSource), "fileProtectionFileTypesTidPattern.MatchString"); got < 2 {
		t.Errorf("file_protection tid MatchString count = %d, want >= 2 (build + decode)", got)
	}
	for _, needle := range []string{
		`FileContentMatchRule json.RawMessage ` + "`json:\"match_rules,omitempty\"`",
		`itemObj["match_rules"]`,
		`match["match_rules"]`,
	} {
		if !strings.Contains(string(fileSource), needle) {
			t.Errorf("file_protection generated source missing match_rules wire mapping %q", needle)
		}
	}
	// The nested offset range is documented.
	if !strings.Contains(file.Docs.ArgumentText, "between 0 and 4096, default 0") {
		t.Errorf("file_protection docs missing nested offset range/default: %q", file.Docs.ArgumentText)
	}

	// mobile_api_protection: sensitive scalar token_secret. The generated
	// schema must emit Sensitive: true, the docs must note it is sensitive,
	// and no literal secret appears in the example HCL or docs.
	mobile := findResourceRender(t, model, "fortiappseccloud_waf_mobile_api_protection")
	if len(mobile.Collections) != 1 {
		t.Fatalf("mobile_api_protection collections = %d, want 1", len(mobile.Collections))
	}
	tokenSecret := findScalar(t, mobile.Scalars, "token_secret")
	if !tokenSecret.Sensitive || tokenSecret.MaxLength != 127 {
		t.Errorf("mobile_api_protection token_secret = %#v, want sensitive max 127", tokenSecret)
	}
	mobileSource, err := os.ReadFile("../resources/generated/waf/resource_mobile_api_protection.go")
	if err != nil {
		t.Fatalf("read committed mobile_api_protection resource: %v", err)
	}
	if !strings.Contains(string(mobileSource), "\"token_secret\": schema.StringAttribute{") ||
		!strings.Contains(string(mobileSource), "Sensitive:           true,") {
		t.Error("mobile_api_protection generated resource missing Sensitive: true on token_secret")
	}
	if strings.Contains(mobile.Docs.ExampleHCL, "TOKEN_SECRET") {
		t.Errorf("mobile_api_protection docs example leaks the literal token_secret default: %q", mobile.Docs.ExampleHCL)
	}
	if !strings.Contains(mobile.Docs.ArgumentText, "Sensitive") {
		t.Errorf("mobile_api_protection docs argument text missing Sensitive note: %q", mobile.Docs.ArgumentText)
	}
}

// sliceContains reports whether the sorted import slice contains path.
func sliceContains(imports []string, path string) bool {
	for _, imp := range imports {
		if imp == path {
			return true
		}
	}
	return false
}
