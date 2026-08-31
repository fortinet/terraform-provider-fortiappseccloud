package contract

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPinnedWAFContract(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}

	if document.Version != BaselineVersion {
		t.Fatalf("version = %q, want %q", document.Version, BaselineVersion)
	}
	if document.SHA256 != BaselineSHA256 {
		t.Fatalf("SHA-256 = %q, want %q", document.SHA256, BaselineSHA256)
	}
	if document.PathCount != 155 {
		t.Fatalf("WAF path count = %d, want 155", document.PathCount)
	}
	if len(document.Operations) != 262 {
		t.Fatalf("WAF operation count = %d, want 262", len(document.Operations))
	}
	if _, ok := document.Find("GET", "/general/asset_groups/{group_uuid}"); ok {
		t.Fatal("out-of-scope asset-group operation leaked into the WAF generator contract")
	}
}

func TestApplicationExtraDomainsLimit(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					MaxItems *int `json:"maxItems"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode OpenAPI baseline: %v", err)
	}
	extraDomains, ok := document.Components.Schemas["Application"].Properties["extra_domains"]
	if !ok || extraDomains.MaxItems == nil {
		t.Fatal("Application.extra_domains is missing maxItems")
	}
	if got := *extraDomains.MaxItems; got != 9 {
		t.Fatalf("Application.extra_domains maxItems = %d, want 9", got)
	}
}

func TestInitialScopeExistsInPinnedContract(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}

	seen := make(map[string]struct{}, len(InitialScope))
	for _, classification := range InitialScope {
		key := classification.Method + " " + classification.Path
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate initial classification %s", key)
		}
		seen[key] = struct{}{}

		operation, ok := document.Find(classification.Method, classification.Path)
		if !ok {
			t.Errorf("initial classification %s is absent from OpenAPI", key)
			continue
		}
		if !operation.Public {
			t.Errorf("initial classification %s is tagged non-public", key)
		}
		if classification.Owner == "" || classification.ClientMethod == "" {
			t.Errorf("initial classification %s is missing owner/client metadata", key)
		}
	}
}

func TestNonPublicTagClassification(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}

	operation, ok := document.Find("POST", "/waf/misc/check-ip-region")
	if !ok {
		t.Fatal("POST /waf/misc/check-ip-region is absent from OpenAPI")
	}
	if operation.Public {
		t.Fatal("POST /waf/misc/check-ip-region was not marked non-public")
	}
}
