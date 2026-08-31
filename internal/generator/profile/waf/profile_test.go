package waf

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeOverridesAcceptsReviewedProfile(t *testing.T) {
	t.Parallel()

	overrides, err := DecodeOverrides(DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("DecodeOverrides() error = %v", err)
	}
	if len(overrides.Resources) != 25 {
		t.Fatalf("resources = %d, want 25", len(overrides.Resources))
	}
	got := make([]string, 0, len(overrides.Resources))
	for _, resource := range overrides.Resources {
		got = append(got, resource.TerraformName)
	}
	want := []string{CSRFResourceName, URLAccessResourceName, RequestLimitsResourceName, KnownAttacksResourceName, HttpHeaderSecurityResourceName, GraphQLProtectionResourceName, JSONProtectionResourceName, ParameterValidationResourceName, WebSocketSecurityResourceName, InformationLeakageResourceName, DDoSPreventionResourceName, CookieSecurityResourceName, KnownBotsResourceName, BotDeceptionResourceName, BiometricsBasedDetectionResourceName, WaitingRoomResourceName, MITBProtectionResourceName, ThresholdDetectionResourceName, MLBotDetectionResourceName, FileProtectionResourceName, MobileAPIProtectionResourceName, XMLProtectionPolicyResourceName, RewritingRequestsResourceName, APIGatewayResourceName, CachingCompressionResourceName}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resource names = %#v, want %#v", got, want)
	}
	var activeDisables int
	for _, resource := range overrides.Resources {
		wantTemplateReason := templateDestroyVerifiedReason
		wantCoupledFields := []string(nil)
		if resource.TerraformName == CachingCompressionResourceName {
			wantTemplateReason = templateCachingCompressionDestroyReason
			wantCoupledFields = []string{"cache.status", "compress.status"}
		}
		if resource.TemplateDestroy.Mode != "disable" || !resource.TemplateDestroy.Verified ||
			resource.TemplateDestroy.Field != "status" || resource.TemplateDestroy.Reason != wantTemplateReason ||
			!orderedStringsEqual(resource.TemplateDestroy.CoupledFields, wantCoupledFields) {
			t.Fatalf("%s template destroy policy = %#v, want verified status disable", resource.TerraformName, resource.TemplateDestroy)
		}
		if resource.Destroy.Field == "status" {
			if resource.Destroy.Mode != "disable" || !resource.Destroy.Verified {
				t.Fatalf("%s destroy policy = %#v, want verified disable", resource.TerraformName, resource.Destroy)
			}
			activeDisables++
		}
	}
	if activeDisables != 24 {
		t.Fatalf("active standalone status disables = %d, want 24", activeDisables)
	}
	caching := findOverride(overrides, CachingCompressionResourceName)
	if caching.Destroy.Mode != "forget" || caching.Destroy.Verified ||
		caching.Destroy.Field != "" || caching.Destroy.Reason != noSafeStatusDestroyReason {
		t.Fatalf("caching/compression destroy policy = %#v", caching.Destroy)
	}
	if !orderedStringsEqual(caching.TemplateDestroy.CoupledFields, []string{"cache.status", "compress.status"}) {
		t.Fatalf("caching/compression template coupled fields = %#v", caching.TemplateDestroy.CoupledFields)
	}
	urlAccess := findOverride(overrides, URLAccessResourceName)
	if urlAccess.GoName != "URLAccess" || urlAccess.TypeNameSuffix != "waf_url_access" ||
		urlAccess.GetPath != URLAccessPath || len(urlAccess.Collections) != 1 ||
		urlAccess.Collections[0].Path != "configs.rule_list" {
		t.Fatalf("URL access resource = %#v", urlAccess)
	}
}

func TestDecodeOverridesRejectsUnknownAndTrailingData(t *testing.T) {
	t.Parallel()

	unknown := strings.Replace(string(DefaultOverridesJSON), `"resources": [`, `"unexpected": true, "resources": [`, 1)
	if _, err := DecodeOverrides([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-key error = %v", err)
	}
	for _, suffix := range []string{` {}`, ` x`, ` {`} {
		if _, err := DecodeOverrides(append(append([]byte(nil), DefaultOverridesJSON...), []byte(suffix)...)); err == nil {
			t.Fatalf("DecodeOverrides() accepted trailing data %q", suffix)
		}
	}
}

func TestDecodeOverridesRejectsReviewedPolicyDrift(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		resource int
		mutate   func(map[string]any)
	}{
		"CSRF type suffix": {resource: 0, mutate: func(resource map[string]any) {
			resource["type_name_suffix"] = "csrf_protection"
		}},
		"CSRF filter default": {resource: 0, mutate: func(resource map[string]any) {
			fieldByPath(resource, "configs.page_list.item.filter")["provider_default"] = true
		}},
		"CSRF optional null policy": {resource: 0, mutate: func(resource map[string]any) {
			fieldByPath(resource, "configs.page_list.item.name")["allow_wire_null"] = false
		}},
		"URL action requiredness": {resource: 1, mutate: func(resource map[string]any) {
			fieldByPath(resource, "configs.rule_list.item.action")["terraform_policy"] = "optional_computed"
		}},
		"URL action state policy": {resource: 1, mutate: func(resource map[string]any) {
			fieldByPath(resource, "configs.rule_list.item.action")["use_state_for_unknown"] = true
		}},
		"URL wrapper name": {resource: 1, mutate: func(resource map[string]any) {
			collectionByPath(resource, "configs.rule_list")["wrapper_block"] = "rules"
		}},
		"URL hidden index": {resource: 1, mutate: func(resource map[string]any) {
			collectionByPath(resource, "configs.rule_list")["hidden_index"] = "exposed_idx"
		}},
		"URL destroy unverified": {resource: 1, mutate: func(resource map[string]any) {
			resource["destroy"].(map[string]any)["verified"] = false
		}},
		"URL destroy field": {resource: 1, mutate: func(resource map[string]any) {
			resource["destroy"].(map[string]any)["field"] = "enabled"
		}},
		"URL template destroy unverified": {resource: 1, mutate: func(resource map[string]any) {
			resource["template_destroy"].(map[string]any)["verified"] = false
		}},
		"URL template destroy field": {resource: 1, mutate: func(resource map[string]any) {
			resource["template_destroy"].(map[string]any)["field"] = "enabled"
		}},
		"caching standalone status": {resource: 24, mutate: func(resource map[string]any) {
			destroy := resource["destroy"].(map[string]any)
			destroy["field"] = "status"
			destroy["reason"] = forgetDestroyReason
		}},
		"caching template coupled fields missing": {resource: 24, mutate: func(resource map[string]any) {
			delete(resource["template_destroy"].(map[string]any), "coupled_fields")
		}},
		"caching template coupled field drift": {resource: 24, mutate: func(resource map[string]any) {
			resource["template_destroy"].(map[string]any)["coupled_fields"] = []any{"cache.status", "cache.status"}
		}},
		"known_bots bad_bots_list unindexed flipped to indexed": {resource: 12, mutate: func(resource map[string]any) {
			c := collectionByPath(resource, "configs.bad_bots_list")
			c["unindexed"] = false
			c["hidden_index"] = "sequential_one_based_idx"
		}},
		"known_bots exception_list unindexed flipped to unindexed": {resource: 12, mutate: func(resource map[string]any) {
			c := collectionByPath(resource, "configs.exception_list")
			c["unindexed"] = true
			c["hidden_index"] = "none"
		}},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			profile := decodedProfile(t)
			resource := profile["resources"].([]any)[test.resource].(map[string]any)
			test.mutate(resource)
			encoded, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeOverrides(encoded); err == nil {
				t.Fatal("DecodeOverrides() accepted reviewed policy drift")
			}
		})
	}
}

func TestDecodeOverridesAcceptsIndividuallyVerifiedPromotion(t *testing.T) {
	t.Parallel()

	profile := decodedProfile(t)
	resource := profile["resources"].([]any)[0].(map[string]any)
	destroy := resource["destroy"].(map[string]any)
	destroy["mode"] = "disable"
	destroy["verified"] = true
	destroy["reason"] = "CSRF status=false disable and exact restoration live-verified on a disposable application"
	destroy["provenance"] = "Exact endpoint-specific live record."
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	overrides, err := DecodeOverrides(encoded)
	if err != nil {
		t.Fatalf("DecodeOverrides() rejected an individually verified promotion: %v", err)
	}
	promoted := findOverride(overrides, CSRFResourceName)
	if promoted.Destroy.Mode != "disable" || !promoted.Destroy.Verified || promoted.Destroy.Field != "status" {
		t.Fatalf("promoted destroy policy = %#v", promoted.Destroy)
	}
}

func TestDecodeOverridesRejectsResourceSetDrift(t *testing.T) {
	t.Parallel()

	t.Run("collision", func(t *testing.T) {
		profile := decodedProfile(t)
		resources := profile["resources"].([]any)
		profile["resources"] = append(resources, resources[0])
		encoded, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeOverrides(encoded); err == nil || !strings.Contains(err.Error(), "collision") {
			t.Fatalf("collision error = %v", err)
		}
	})

	t.Run("missing reviewed resource", func(t *testing.T) {
		profile := decodedProfile(t)
		profile["resources"] = profile["resources"].([]any)[:1]
		encoded, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeOverrides(encoded); err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("missing-resource error = %v", err)
		}
	})
}

// OpenAPI 26.3.a carries url_type natively, so no reviewed resource retains a
// backend-only field addition.
func TestDecodeOverridesHasNoObsoleteBackendAdditions(t *testing.T) {
	t.Parallel()

	overrides, err := DecodeOverrides(DefaultOverridesJSON)
	if err != nil {
		t.Fatalf("DecodeOverrides() error = %v", err)
	}
	for _, resource := range overrides.Resources {
		if len(resource.BackendFieldAdditions) != 0 {
			t.Fatalf("%s retains %d backend additions", resource.TerraformName, len(resource.BackendFieldAdditions))
		}
	}
}

func TestDecodeOverridesRejectsObsoleteBackendAddition(t *testing.T) {
	t.Parallel()
	profile := decodedProfile(t)
	resource := profile["resources"].([]any)[1].(map[string]any)
	resource["backend_field_additions"] = []any{map[string]any{
		"path": "configs.rule_list.item.url_type", "kind": "string", "required": true,
		"enum": []any{"regex", "string"}, "provenance": "obsolete",
	}}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOverrides(encoded); err == nil || !strings.Contains(err.Error(), "not part of the reviewed backend additions") {
		t.Fatalf("DecodeOverrides() error = %v, want obsolete-addition rejection", err)
	}
}

func decodedProfile(t *testing.T) map[string]any {
	t.Helper()
	var profile map[string]any
	if err := json.Unmarshal(DefaultOverridesJSON, &profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func fieldByPath(resource map[string]any, path string) map[string]any {
	for _, raw := range resource["fields"].([]any) {
		field := raw.(map[string]any)
		if field["path"] == path {
			return field
		}
	}
	panic("missing field " + path)
}

func collectionByPath(resource map[string]any, path string) map[string]any {
	for _, raw := range resource["collections"].([]any) {
		collection := raw.(map[string]any)
		if collection["path"] == path {
			return collection
		}
	}
	panic("missing collection " + path)
}

// findOverride returns the reviewed resource override with the given Terraform
// name, so tests do not depend on the alphabetical ResourceOverride ordering
// imposed by normalizeOverrides.
func findOverride(overrides Overrides, name string) ResourceOverride {
	for _, resource := range overrides.Resources {
		if resource.TerraformName == name {
			return resource
		}
	}
	panic("missing override " + name)
}
