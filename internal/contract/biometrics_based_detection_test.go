package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestBiometricsBasedDetectionScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/biometrics_based_detection", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_biometrics_based_detection", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/biometrics_based_detection", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_biometrics_based_detection", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/biometrics_based_detection", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_biometrics_based_detection", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/biometrics_based_detection", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_biometrics_based_detection", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(BiometricsBasedDetectionScope, want) {
		t.Fatalf("BiometricsBasedDetectionScope = %#v, want %#v", BiometricsBasedDetectionScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range BiometricsBasedDetectionScope {
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

func TestBiometricsBasedDetectionResourceContract(t *testing.T) {
	t.Parallel()

	if BiometricsBasedDetectionResource.TerraformName != "fortiappseccloud_waf_biometrics_based_detection" {
		t.Fatalf("TerraformName = %q", BiometricsBasedDetectionResource.TerraformName)
	}
	if BiometricsBasedDetectionResource.GoName != "BiometricsBasedDetection" || BiometricsBasedDetectionResource.TypeNameSuffix != "waf_biometrics_based_detection" {
		t.Fatalf("resource identity = %#v", BiometricsBasedDetectionResource)
	}
	if !reflect.DeepEqual(BiometricsBasedDetectionResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", BiometricsBasedDetectionResource.ExpectedMethods)
	}
	// Nine config scalars.
	if len(BiometricsBasedDetectionResource.Schema.ConfigFields) != 9 {
		t.Fatalf("ConfigFields = %d, want 9", len(BiometricsBasedDetectionResource.Schema.ConfigFields))
	}
	// Two bounded integer config scalars carry reviewed ranges.
	botEffectTime := findConfigField(BiometricsBasedDetectionResource.Schema.ConfigFields, "bot_effect_time")
	if botEffectTime == nil || !botEffectTime.HasDefault || botEffectTime.Default != 5 ||
		botEffectTime.Minimum == nil || *botEffectTime.Minimum != 1 ||
		botEffectTime.Maximum == nil || *botEffectTime.Maximum != 5 {
		t.Fatalf("bot_effect_time = %#v, want default 5 range 1..5", botEffectTime)
	}
	eventCollectTime := findConfigField(BiometricsBasedDetectionResource.Schema.ConfigFields, "event_collect_time")
	if eventCollectTime == nil || !eventCollectTime.HasDefault || eventCollectTime.Default != 15 ||
		eventCollectTime.Minimum == nil || *eventCollectTime.Minimum != 10 ||
		eventCollectTime.Maximum == nil || *eventCollectTime.Maximum != 60 {
		t.Fatalf("event_collect_time = %#v, want default 15 range 10..60", eventCollectTime)
	}
	// Two collections, both indexed and bounded.
	if len(BiometricsBasedDetectionResource.Schema.Collections) != 2 {
		t.Fatalf("Collections = %d, want 2", len(BiometricsBasedDetectionResource.Schema.Collections))
	}
	urlList := BiometricsBasedDetectionResource.findCollection("url_list")
	if urlList == nil || urlList.MaxItems != 12 || urlList.Unindexed {
		t.Fatalf("url_list = %#v, want MaxItems 12 Unindexed false", urlList)
	}
	exceptionList := BiometricsBasedDetectionResource.findCollection("exception_list")
	if exceptionList == nil || exceptionList.MaxItems != 128 || exceptionList.Unindexed {
		t.Fatalf("exception_list = %#v, want MaxItems 128 Unindexed false", exceptionList)
	}
	// Per-collection item schemas mirror bot deception.
	urlItemFields := BiometricsBasedDetectionResource.Schema.CollectionItemFields["url_list"]
	if urlItemFields == nil {
		t.Fatal("missing url_list CollectionItemFields")
	}
	urlField := findItemFieldByName(urlItemFields, "url")
	if urlField == nil || !urlField.Required || urlField.MaxLength != 255 {
		t.Fatalf("url_list url = %#v, want required max 255", urlField)
	}
	exceptionItemFields := BiometricsBasedDetectionResource.Schema.CollectionItemFields["exception_list"]
	if exceptionItemFields == nil {
		t.Fatal("missing exception_list CollectionItemFields")
	}
	for _, name := range []string{"concatenate_type", "match_target", "operator"} {
		f := findItemFieldByName(exceptionItemFields, name)
		if f == nil || !f.Required {
			t.Fatalf("exception_list %s = %#v, want required", name, f)
		}
	}
}

func findConfigField(fields []CandidateFieldConstraint, name string) *CandidateFieldConstraint {
	for i := range fields {
		if fields[i].Name == name {
			return &fields[i]
		}
	}
	return nil
}
