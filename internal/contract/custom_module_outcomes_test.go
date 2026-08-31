package contract

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestReviewedCustomModuleOutcomePartition proves the plan's 16 custom pairs
// have exactly one truthful local outcome: served resource, served read-only
// data source with excluded PUT, or reviewed explicit exclusion. It prevents a module
// from silently disappearing between the three independently maintained
// evidence sets.
func TestReviewedCustomModuleOutcomePartition(t *testing.T) {
	t.Parallel()

	wantModules := []string{
		"anomaly_detection",
		"ca_certificate",
		"cors_protection",
		"crl_certificate",
		"custom_rule",
		"global_trust_list_parameter",
		"inter_certificate",
		"ip_protection",
		"log_settings",
		"ml_api_protection",
		"modules",
		"routings",
		"server_ca",
		"server_crl",
		"signature_exception",
		"sni_certificate",
	}

	type outcome struct {
		kind  string
		owner string
	}
	outcomes := make(map[string]outcome, len(wantModules))
	add := func(module, kind, owner string) {
		t.Helper()
		if strings.TrimSpace(module) == "" || strings.TrimSpace(owner) == "" {
			t.Errorf("incomplete %s outcome: module=%q owner=%q", kind, module, owner)
			return
		}
		if previous, duplicate := outcomes[module]; duplicate {
			t.Errorf("module %q has overlapping %s and %s outcomes", module, previous.kind, kind)
			return
		}
		outcomes[module] = outcome{kind: kind, owner: owner}
	}

	for _, contract := range ReviewedCustomResourceContracts() {
		add(contract.Module, "resource", contract.TerraformName)
	}
	for _, contract := range ReviewedDataSourceContracts() {
		module := strings.TrimPrefix(contract.PublicPath, "/waf/apps/{ep_id}/")
		add(module, "data_source", contract.TerraformName)
	}
	for _, contract := range ReviewedUnsupportedCustomModuleContracts() {
		add(contract.Module, "unsupported", contract.TerraformName)
	}

	gotModules := make([]string, 0, len(outcomes))
	for module, outcome := range outcomes {
		gotModules = append(gotModules, module)
		if wantOwner := appModuleOwner(module); outcome.owner != wantOwner {
			t.Errorf("%s %s owner = %q, inventory owner = %q", outcome.kind, module, outcome.owner, wantOwner)
		}
	}
	sort.Strings(gotModules)
	if !reflect.DeepEqual(gotModules, wantModules) {
		t.Fatalf("reviewed custom-module outcome partition = %#v, want %#v", gotModules, wantModules)
	}

	wantKindCounts := map[string]int{"resource": 7, "data_source": 2, "unsupported": 7}
	gotKindCounts := make(map[string]int)
	for _, outcome := range outcomes {
		gotKindCounts[outcome.kind]++
	}
	if !reflect.DeepEqual(gotKindCounts, wantKindCounts) {
		t.Fatalf("custom-module outcome counts = %#v, want %#v", gotKindCounts, wantKindCounts)
	}
}
