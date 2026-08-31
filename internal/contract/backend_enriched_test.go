package contract

import (
	"reflect"
	"testing"
)

// OpenAPI 26.3.a carries url_type natively, so URL access no longer needs a
// backend-only schema addition.
func TestURLAccessUsesNativeOpenAPIURLType(t *testing.T) {
	t.Parallel()

	if len(URLAccessCandidate.Schema.BackendEnrichedItemFields) != 0 {
		t.Fatalf("URLAccess BackendEnrichedItemFields = %d, want 0", len(URLAccessCandidate.Schema.BackendEnrichedItemFields))
	}
	want := CandidateFieldConstraint{
		Name: "url_type", Kind: "string", Required: true, HasDefault: true,
		Default: "string", Enum: []string{"regex", "string"},
	}
	var got *CandidateFieldConstraint
	for index := range URLAccessCandidate.Schema.ItemFields {
		if URLAccessCandidate.Schema.ItemFields[index].Name == "url_type" {
			got = &URLAccessCandidate.Schema.ItemFields[index]
			break
		}
	}
	if got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("native url_type = %#v, want %#v", got, want)
	}
}

func TestImplementedGeneratedResourcesClonesNativeURLType(t *testing.T) {
	t.Parallel()

	resources := ImplementedGeneratedResources()
	if len(resources) != 25 {
		t.Fatalf("implemented generated resources = %d, want 25", len(resources))
	}
	urlAccess := resources[1]
	urlAccess.Schema.ItemFields[3].Enum[0] = "mutated"
	if URLAccessCandidate.Schema.ItemFields[3].Enum[0] != "regex" {
		t.Fatal("ImplementedGeneratedResources exposed mutable native item field storage")
	}
}
