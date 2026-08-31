package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGlobalTrustListGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/global_trust_list_parameter" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Basic token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"status":false,"trust_list":[{"idx":1,"name":"old","status":true,"url":"/old"}],"future_config":{"keep":true}},"future_envelope":"keep"}}`)
		case http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&putBody); err != nil {
				t.Errorf("decode PUT body: %v", err)
			}
			fmt.Fprint(w, `{"detail":"Module updated"}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	document, err := apiClient.GetGlobalTrustList(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetGlobalTrustList() error = %v", err)
	}
	if document.Config.Status == nil || *document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if len(document.Config.TrustList) != 1 {
		t.Fatalf("trust_list = %#v, want 1 raw item", document.Config.TrustList)
	}
	decoded, err := DecodeGlobalTrustListEntries(document.Config.TrustList)
	if err != nil {
		t.Fatalf("DecodeGlobalTrustListEntries: %v", err)
	}
	if len(decoded) != 1 || decoded[0].Name != "old" {
		t.Fatalf("decoded trust_list = %#v", decoded)
	}
	if decoded[0].URL == nil || *decoded[0].URL != "/old" {
		t.Fatalf("decoded trust_list url = %#v", decoded[0].URL)
	}

	updated := document.Result.Clone()
	if err := updated.SetConfig("status", true); err != nil {
		t.Fatalf("SetConfig(status) error = %v", err)
	}
	one, two := "/one", "/two"
	entries := []GlobalTrustListEntry{
		{Name: "one", URL: &one},
		{Name: "two", URL: &two},
	}
	for index := range entries {
		entries[index].IDX = index + 1
		status := index != 1
		entries[index].Status = &status
	}
	if err := updated.SetConfig("trust_list", entries); err != nil {
		t.Fatalf("SetConfig(trust_list) error = %v", err)
	}
	if err := apiClient.PutGlobalTrustList(context.Background(), "app/id", updated); err != nil {
		t.Fatalf("PutGlobalTrustList() error = %v", err)
	}

	if _, ok := putBody["future_envelope"]; !ok {
		t.Fatalf("PUT body lost future_envelope: %s", mustJSON(putBody))
	}
	if _, ok := putBody["template"]; ok {
		t.Fatalf("PUT body emitted a template field; this endpoint has no template: %s", mustJSON(putBody))
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(putBody["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	if _, ok := configs["future_config"]; !ok {
		t.Fatalf("PUT configs lost future_config: %s", mustJSON(configs))
	}
	var status bool
	if err := json.Unmarshal(configs["status"], &status); err != nil || !status {
		t.Fatalf("PUT status = %s, error = %v", configs["status"], err)
	}
	var putEntries []GlobalTrustListEntry
	if err := json.Unmarshal(configs["trust_list"], &putEntries); err != nil {
		t.Fatalf("decode trust_list: %v", err)
	}
	if len(putEntries) != 2 || putEntries[0].IDX != 1 || putEntries[1].IDX != 2 ||
		putEntries[0].Name != "one" || putEntries[1].Name != "two" {
		t.Fatalf("PUT trust_list = %#v", putEntries)
	}
	if putEntries[0].URL == nil || *putEntries[0].URL != "/one" || putEntries[1].URL == nil || *putEntries[1].URL != "/two" {
		t.Fatalf("PUT trust_list urls = %#v / %#v", putEntries[0].URL, putEntries[1].URL)
	}
}

func TestGlobalTrustListDecodeMissingStatusRejects(t *testing.T) {
	t.Parallel()

	var document GlobalTrustListDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"trust_list":[]}}}`), &document); err == nil {
		t.Fatal("Unmarshal accepted a missing status")
	}
}

func TestGlobalTrustListDecodeMissingConfigsRejects(t *testing.T) {
	t.Parallel()

	var document GlobalTrustListDocument
	if err := json.Unmarshal([]byte(`{"result":{"template":false}}`), &document); err == nil {
		t.Fatal("Unmarshal accepted a missing configs object")
	}
}

func TestGlobalTrustListDecodeAbsentTrustListIsNil(t *testing.T) {
	t.Parallel()

	var document GlobalTrustListDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true}}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.Status == nil || !*document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if document.Config.TrustList != nil {
		t.Fatalf("trust_list = %#v, want nil", document.Config.TrustList)
	}
}

// TestGlobalTrustListDecodeExplicitNullTrustListRejects guards the OpenAPI
// fact that trust_list is not declared nullable (no allow_none); an explicit
// JSON null is malformed, not an ownership signal. (Valid control: absent key
// decodes to nil in TestGlobalTrustListDecodeAbsentTrustListIsNil.)
func TestGlobalTrustListDecodeExplicitNullTrustListRejects(t *testing.T) {
	t.Parallel()

	var document GlobalTrustListDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"trust_list":null}}}`), &document); err == nil {
		t.Fatal("Unmarshal accepted an explicit null trust_list")
	}
}

func TestGlobalTrustListDecodeEmptyTrustList(t *testing.T) {
	t.Parallel()

	var document GlobalTrustListDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"trust_list":[]}}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.TrustList == nil || len(document.Config.TrustList) != 0 {
		t.Fatalf("trust_list = %#v, want non-nil empty", document.Config.TrustList)
	}
}

// rawItems extracts the raw trust_list items from a GET response so the strict
// owned/imported decode path (DecodeGlobalTrustListEntries) can be exercised.
func rawItems(t *testing.T, body string) []json.RawMessage {
	t.Helper()
	var document GlobalTrustListDocument
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	return document.Config.TrustList
}

// TestGlobalTrustListStrictDecodeFailClosedUnknownItemKey guards the invariant
// that unknown nested item keys fail closed when Terraform owns/imports the
// collection. A valid control with only reviewed keys must decode cleanly.
func TestGlobalTrustListStrictDecodeFailClosedUnknownItemKey(t *testing.T) {
	t.Parallel()

	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"ok","url":"/ok"}]}}}`)); err != nil {
		t.Fatalf("valid control decode error = %v", err)
	}
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"bad","future_key":"x"}]}}}`)); err == nil {
		t.Fatal("strict decode accepted an unknown trust_list item key")
	}
}

func TestGlobalTrustListStrictDecodeRejectsNonPositiveIdx(t *testing.T) {
	t.Parallel()

	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":0,"name":"bad"}]}}}`)); err == nil {
		t.Fatal("strict decode accepted a non-positive idx")
	}
}

func TestGlobalTrustListStrictDecodeRejectsDuplicateIdx(t *testing.T) {
	t.Parallel()

	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"a"},{"idx":1,"name":"b"}]}}}`)); err == nil {
		t.Fatal("strict decode accepted a duplicate idx")
	}
}

func TestGlobalTrustListStrictDecodeSortsByIdx(t *testing.T) {
	t.Parallel()

	entries, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":2,"name":"b"},{"idx":1,"name":"a"}]}}}`))
	if err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if len(entries) != 2 || entries[0].IDX != 1 || entries[1].IDX != 2 {
		t.Fatalf("trust_list not sorted by idx = %#v", entries)
	}
}

// TestGlobalTrustListStrictDecodeRejectsItemFieldNulls guards that explicit
// JSON null for idx/name/status/url is rejected (not nullable in OpenAPI).
// A valid control with present fields decodes cleanly.
func TestGlobalTrustListStrictDecodeRejectsItemFieldNulls(t *testing.T) {
	t.Parallel()

	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"n","url":null}]}}}`)); err == nil {
		t.Fatal("strict decode accepted a null url")
	}
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"n","status":null}]}}}`)); err == nil {
		t.Fatal("strict decode accepted a null status")
	}
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":null,"name":"n"}]}}}`)); err == nil {
		t.Fatal("strict decode accepted a null idx")
	}
}

// TestGlobalTrustListStrictDecodeRequiresName guards that name is a reviewed
// required non-empty field on owned/imported reads. Missing, null, and empty
// names are rejected; a present name decodes cleanly (control).
func TestGlobalTrustListStrictDecodeRequiresName(t *testing.T) {
	t.Parallel()

	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1}]}}}`)); err == nil {
		t.Fatal("strict decode accepted a missing name")
	}
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":null}]}}}`)); err == nil {
		t.Fatal("strict decode accepted a null name")
	}
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":""}]}}}`)); err == nil {
		t.Fatal("strict decode accepted an empty name")
	}
}

func TestGlobalTrustListStrictDecodeRejectsOverlongName(t *testing.T) {
	t.Parallel()

	body := `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"` + repeatStr("n", 64) + `"}]}}}`
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, body)); err == nil {
		t.Fatal("strict decode accepted an over-length name")
	}
}

// TestGlobalTrustListStrictDecodeAcceptsMaxNameUTF8Control proves a name of
// exactly 63 UTF-8 characters (including multibyte) decodes cleanly — the
// bound is counted in runes, not bytes.
func TestGlobalTrustListStrictDecodeAcceptsMaxNameUTF8Control(t *testing.T) {
	t.Parallel()

	// 62 'n' bytes + 1 multibyte rune (é, 2 bytes) = 63 runes, 64 bytes.
	name := repeatStr("n", 62) + "é"
	body := `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"` + name + `"}]}}}`
	entries, err := DecodeGlobalTrustListEntries(rawItems(t, body))
	if err != nil {
		t.Fatalf("strict decode rejected a 63-rune name: %v", err)
	}
	if entries[0].Name != name {
		t.Fatalf("decoded name = %q", entries[0].Name)
	}
}

func TestGlobalTrustListStrictDecodeRejectsOverlongURL(t *testing.T) {
	t.Parallel()

	body := `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"n","url":"/` + repeatStr("u", 255) + `"}]}}}`
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, body)); err == nil {
		t.Fatal("strict decode accepted an over-length url")
	}
}

// TestGlobalTrustListStrictDecodeAcceptsMaxURLControl proves a url of exactly
// 255 UTF-8 runes (the reviewed bound) decodes cleanly through the same strict
// decoder that rejects the 256-rune case above.
func TestGlobalTrustListStrictDecodeAcceptsMaxURLControl(t *testing.T) {
	t.Parallel()

	// "/" (1 rune) + 254 'u' = 255 runes.
	body := `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"n","url":"/` + repeatStr("u", 254) + `"}]}}}`
	entries, err := DecodeGlobalTrustListEntries(rawItems(t, body))
	if err != nil {
		t.Fatalf("strict decode rejected a 255-rune url: %v", err)
	}
	if entries[0].URL == nil || *entries[0].URL != "/"+repeatStr("u", 254) {
		t.Fatalf("decoded url = %#v", entries[0].URL)
	}
}

func TestGlobalTrustListStrictDecodeRejectsTooManyEntries(t *testing.T) {
	t.Parallel()

	items := ""
	for i := 1; i <= 31; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"name":"n%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"trust_list":[` + items + `]}}}`
	if _, err := DecodeGlobalTrustListEntries(rawItems(t, body)); err == nil {
		t.Fatal("strict decode accepted more than 30 entries")
	}
}

// TestGlobalTrustListStrictDecodeAcceptsMaxEntriesControl proves exactly 30
// entries (the reviewed bound) decode cleanly through the same strict decoder
// that rejects the 31-entry case above.
func TestGlobalTrustListStrictDecodeAcceptsMaxEntriesControl(t *testing.T) {
	t.Parallel()

	items := ""
	for i := 1; i <= 30; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"name":"n%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"trust_list":[` + items + `]}}}`
	entries, err := DecodeGlobalTrustListEntries(rawItems(t, body))
	if err != nil {
		t.Fatalf("strict decode rejected 30 entries: %v", err)
	}
	if len(entries) != 30 {
		t.Fatalf("decoded %d entries, want 30", len(entries))
	}
}

// TestGlobalTrustListDocumentDecodePreservesUnknownItemKey proves the client
// (lenient) decode preserves an unknown item key opaquely so an omitted
// Terraform wrapper can carry it forward; the strict decode rejects it.
func TestGlobalTrustListDocumentDecodePreservesUnknownItemKey(t *testing.T) {
	t.Parallel()

	items := rawItems(t, `{"result":{"configs":{"status":true,"trust_list":[{"idx":1,"name":"n","future_key":"x"}]}}}`)
	if len(items) != 1 {
		t.Fatalf("lenient decode dropped the unknown-key item: %#v", items)
	}
	if _, err := DecodeGlobalTrustListEntries(items); err == nil {
		t.Fatal("strict decode accepted an unknown key that the lenient decode preserved")
	}
}

func TestGlobalTrustListEmptyEndpointErrors(t *testing.T) {
	t.Parallel()

	apiClient, err := New(context.Background(), Config{BaseURL: "https://example.test", APIToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetGlobalTrustList(context.Background(), ""); err == nil {
		t.Fatal("GetGlobalTrustList() accepted an empty ep_id")
	}
	if err := apiClient.PutGlobalTrustList(context.Background(), "", GlobalTrustListResult{}); err == nil {
		t.Fatal("PutGlobalTrustList() accepted an empty ep_id")
	}
}

func repeatStr(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}
