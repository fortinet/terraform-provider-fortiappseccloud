package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestCSRFProtectionContract(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}

	var document struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode OpenAPI baseline: %v", err)
	}

	appPath := document.Paths["/waf/apps/{ep_id}/csrf_protection"]
	if appPath == nil {
		t.Fatal("CSRF protection app path is absent")
	}
	if got := responseSchemaRef(t, appPath["get"], "200"); got != "#/components/schemas/GetCSRFProtection" {
		t.Fatalf("GET response ref = %q", got)
	}
	if got := requestSchemaRef(t, appPath["put"]); got != "#/components/schemas/PutCSRFProtection" {
		t.Fatalf("PUT request ref = %q", got)
	}
	if _, ok := appPath["delete"]; ok {
		t.Fatal("CSRF protection app path unexpectedly has a DELETE operation")
	}

	templatePath := document.Paths["/waf/template/{template_id}/csrf_protection"]
	if templatePath == nil {
		t.Fatal("CSRF protection template path is absent")
	}
	if _, ok := templatePath["delete"]; ok {
		t.Fatal("CSRF protection template path unexpectedly has a DELETE operation")
	}

	var getWrapper objectSchema
	if err := json.Unmarshal(document.Components.Schemas["GetCSRFProtection"], &getWrapper); err != nil {
		t.Fatalf("decode GetCSRFProtection: %v", err)
	}
	if len(getWrapper.Required) != 0 {
		t.Fatalf("GetCSRFProtection required = %#v, want none", getWrapper.Required)
	}
	if got := getWrapper.Properties["result"].Ref; got != "#/components/schemas/PutCSRFProtection" {
		t.Fatalf("result ref = %q", got)
	}

	var envelope objectSchema
	if err := json.Unmarshal(document.Components.Schemas["PutCSRFProtection"], &envelope); err != nil {
		t.Fatalf("decode PutCSRFProtection: %v", err)
	}
	sort.Strings(envelope.Required)
	if !reflect.DeepEqual(envelope.Required, []string{"configs", "template"}) {
		t.Fatalf("PutCSRFProtection required = %#v", envelope.Required)
	}
	if got := envelope.Properties["configs"].Ref; got != "#/components/schemas/CSRFProtection" {
		t.Fatalf("configs ref = %q", got)
	}

	var protection objectSchema
	if err := json.Unmarshal(document.Components.Schemas["CSRFProtection"], &protection); err != nil {
		t.Fatalf("decode CSRFProtection: %v", err)
	}
	sort.Strings(protection.Required)
	if !reflect.DeepEqual(protection.Required, []string{"action", "status"}) {
		t.Fatalf("CSRFProtection required = %#v", protection.Required)
	}

	action := protection.Properties["action"]
	if got := action.Default; got != "alert" {
		t.Fatalf("action default = %#v, want alert", got)
	}
	if !reflect.DeepEqual(action.Enum, []any{"alert", "alert_deny", "deny_no_log"}) {
		t.Fatalf("action enum = %#v", action.Enum)
	}
	if got := protection.Properties["status"].Default; !reflect.DeepEqual(got, false) {
		t.Fatalf("status default = %#v, want false", got)
	}

	for _, field := range []string{"page_list", "url_list"} {
		property := protection.Properties[field]
		if property.MaxItems != 256 {
			t.Errorf("%s maxItems = %d, want 256", field, property.MaxItems)
		}
		if property.Items == nil {
			t.Errorf("%s items are absent", field)
			continue
		}
		if got := property.Items.Ref; got != "#/components/schemas/CSRFParameter" {
			t.Errorf("%s item ref = %q", field, got)
		}
	}

	var parameter objectSchema
	if err := json.Unmarshal(document.Components.Schemas["CSRFParameter"], &parameter); err != nil {
		t.Fatalf("decode CSRFParameter: %v", err)
	}
	sort.Strings(parameter.Required)
	if !reflect.DeepEqual(parameter.Required, []string{"filter", "url"}) {
		t.Fatalf("CSRFParameter required = %#v", parameter.Required)
	}
	if got := parameter.Properties["filter"].Default; !reflect.DeepEqual(got, false) {
		t.Fatalf("filter default = %#v, want false", got)
	}

	url := parameter.Properties["url"]
	if url.MaxLength != 255 {
		t.Errorf("url maxLength = %d, want 255", url.MaxLength)
	}
	if url.Pattern != `^/.*$` {
		t.Errorf("url pattern = %q, want %q", url.Pattern, `^/.*$`)
	}
	if got := parameter.Properties["name"].MaxLength; got != 63 {
		t.Errorf("name maxLength = %d, want 63", got)
	}
	if got := parameter.Properties["value"].MaxLength; got != 255 {
		t.Errorf("value maxLength = %d, want 255", got)
	}

	idx := parameter.Properties["idx"]
	if got := idx.Default; !reflect.DeepEqual(got, float64(1)) {
		t.Errorf("idx default = %#v, want 1", got)
	}
	if idx.Minimum != nil {
		t.Errorf("idx minimum = %v, want absent", *idx.Minimum)
	}
	if idx.Maximum != nil {
		t.Errorf("idx maximum = %v, want absent", *idx.Maximum)
	}
	if idx.ReadOnly != nil {
		t.Errorf("idx readOnly = %v, want absent", *idx.ReadOnly)
	}
}

func TestCSRFProtectionScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{
			Method:       "GET",
			Path:         "/waf/apps/{ep_id}/csrf_protection",
			Disposition:  DispositionResourceRead,
			Owner:        "fortiappseccloud_waf_csrf_protection",
			ClientMethod: "GetWAFModule",
		},
		{
			Method:       "PUT",
			Path:         "/waf/apps/{ep_id}/csrf_protection",
			Disposition:  DispositionResourceWrite,
			Owner:        "fortiappseccloud_waf_csrf_protection",
			ClientMethod: "PutWAFModule",
		},
		{
			Method:       "GET",
			Path:         "/waf/template/{template_id}/csrf_protection",
			Disposition:  DispositionResourceRead,
			Owner:        "fortiappseccloud_waf_template_csrf_protection",
			ClientMethod: "GetWAFTemplateModule",
		},
		{
			Method:       "PUT",
			Path:         "/waf/template/{template_id}/csrf_protection",
			Disposition:  DispositionResourceWrite,
			Owner:        "fortiappseccloud_waf_template_csrf_protection",
			ClientMethod: "PutWAFTemplateModule",
		},
	}
	if !reflect.DeepEqual(CSRFProtectionScope, want) {
		t.Fatalf("CSRFProtectionScope = %#v, want %#v", CSRFProtectionScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}

	for _, classification := range CSRFProtectionScope {
		operation, ok := document.Find(classification.Method, classification.Path)
		if !ok {
			t.Errorf("classification missing from OpenAPI: %s %s", classification.Method, classification.Path)
			continue
		}
		if classification.Disposition != DispositionDeferred && classification.ClientMethod == "" {
			t.Errorf("managed classification lacks client method: %s %s", classification.Method, classification.Path)
		}

		if !operation.Public {
			t.Errorf("classification is non-public: %s %s", classification.Method, classification.Path)
		}
	}
}
