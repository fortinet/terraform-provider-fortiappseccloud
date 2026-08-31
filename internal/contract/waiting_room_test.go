package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestWaitingRoomScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/waiting_room", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_waiting_room", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/waiting_room", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_waiting_room", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/waiting_room", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_waiting_room", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/waiting_room", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_waiting_room", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(WaitingRoomScope, want) {
		t.Fatalf("WaitingRoomScope = %#v, want %#v", WaitingRoomScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range WaitingRoomScope {
		operation, ok := document.Find(classification.Method, classification.Path)
		if !ok {
			t.Errorf("classification missing from OpenAPI: %s %s", classification.Method, classification.Path)
			continue
		}
		if !operation.Public {
			t.Errorf("classification is non-public: %s %s", classification.Method, classification.Path)
		}
	}
}

func TestWaitingRoomResourceContract(t *testing.T) {
	t.Parallel()

	if WaitingRoomResource.TerraformName != "fortiappseccloud_waf_waiting_room" {
		t.Fatalf("TerraformName = %q", WaitingRoomResource.TerraformName)
	}
	if WaitingRoomResource.GoName != "WaitingRoom" || WaitingRoomResource.TypeNameSuffix != "waf_waiting_room" {
		t.Fatalf("resource identity = %#v", WaitingRoomResource)
	}
	if !reflect.DeepEqual(WaitingRoomResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", WaitingRoomResource.ExpectedMethods)
	}
	// Eight config scalars.
	if len(WaitingRoomResource.Schema.ConfigFields) != 8 {
		t.Fatalf("ConfigFields = %d, want 8", len(WaitingRoomResource.Schema.ConfigFields))
	}
	// path and status are required; the other six are optional with defaults.
	path := findConfigField(WaitingRoomResource.Schema.ConfigFields, "path")
	if path == nil || !path.Required || !path.HasDefault || path.Default != "/.*" {
		t.Fatalf("path = %#v, want required default /.*", path)
	}
	status := findConfigField(WaitingRoomResource.Schema.ConfigFields, "status")
	if status == nil || !status.Required || !status.HasDefault || status.Default != false {
		t.Fatalf("status = %#v, want required default false", status)
	}
	// Two ranges are conditional and therefore live only in the cross-field
	// extension; session_duration remains an unconditional JSON-schema range.
	for _, name := range []string{"total_active_users", "new_users_per_min"} {
		f := findConfigField(WaitingRoomResource.Schema.ConfigFields, name)
		if f == nil || f.Required || !f.HasDefault {
			t.Fatalf("%s = %#v, want optional with default", name, f)
		}
		if f.Minimum != nil || f.Maximum != nil {
			t.Fatalf("%s has unconditional bounds %#v..%#v", name, f.Minimum, f.Maximum)
		}
	}
	session := findConfigField(WaitingRoomResource.Schema.ConfigFields, "session_duration")
	if session == nil || session.Minimum == nil || *session.Minimum != 1 || session.Maximum == nil || *session.Maximum != 30 {
		t.Fatalf("session_duration = %#v, want unconditional range 1..30", session)
	}
	if len(WaitingRoomResource.Schema.BackendEnrichedConfigScalarConstraints) != 0 {
		t.Fatalf("obsolete backend enrichment markers remain: %#v", WaitingRoomResource.Schema.BackendEnrichedConfigScalarConstraints)
	}
	// One collection, bounded (100) and indexed.
	if len(WaitingRoomResource.Schema.Collections) != 1 {
		t.Fatalf("Collections = %d, want 1", len(WaitingRoomResource.Schema.Collections))
	}
	bypassRules := WaitingRoomResource.findCollection("bypass_rules")
	if bypassRules == nil || bypassRules.MaxItems != 100 || bypassRules.Unindexed {
		t.Fatalf("bypass_rules = %#v, want MaxItems 100 Unindexed false", bypassRules)
	}
	bypassItemFields := WaitingRoomResource.Schema.CollectionItemFields["bypass_rules"]
	if bypassItemFields == nil {
		t.Fatal("missing bypass_rules CollectionItemFields")
	}
	ruleType := findItemFieldByName(bypassItemFields, "rule_type")
	if ruleType == nil || !ruleType.Required || ruleType.MaxLength != 64 || len(ruleType.Enum) != 1 || ruleType.Enum[0] != "source-ip" {
		t.Fatalf("bypass_rules rule_type = %#v, want required enum [source-ip] max 64", ruleType)
	}
	ruleValue := findItemFieldByName(bypassItemFields, "rule_value")
	if ruleValue == nil || !ruleValue.Required {
		t.Fatalf("bypass_rules rule_value = %#v, want required", ruleValue)
	}
	idx := findItemFieldByName(bypassItemFields, "idx")
	if idx == nil || !idx.HasDefault || idx.Default != 1 {
		t.Fatalf("bypass_rules idx = %#v, want default 1", idx)
	}
}
