package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPProtectionGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/ip_protection" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Basic token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"status":false,"ip_reputation":true,"geo_ip_mode":"block","block_country_list":["United States"],"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)
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

	document, err := apiClient.GetIPProtection(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetIPProtection() error = %v", err)
	}
	if document.Config.Status == nil || *document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if document.Config.GeoIPMode == nil || *document.Config.GeoIPMode != "block" {
		t.Fatalf("geo_ip_mode = %#v", document.Config.GeoIPMode)
	}
	if len(document.Config.BlockCountryList) != 1 || document.Config.BlockCountryList[0] != "United States" {
		t.Fatalf("block_country_list = %#v", document.Config.BlockCountryList)
	}
	if len(document.Config.IPList) != 1 {
		t.Fatalf("ip_list = %#v, want 1 raw item", document.Config.IPList)
	}
	decoded, err := DecodeIPProtectionIPList(document.Config.IPList)
	if err != nil {
		t.Fatalf("DecodeIPProtectionIPList: %v", err)
	}
	if len(decoded) != 1 || decoded[0].IP != "10.0.0.1" || decoded[0].Type != "trust-ip" {
		t.Fatalf("decoded ip_list = %#v", decoded)
	}

	updated := document.Result.Clone()
	if err := updated.SetConfig("status", true); err != nil {
		t.Fatalf("SetConfig(status) error = %v", err)
	}
	// The PUT/write shape omits wire-only idx per the pinned PutIPProtection
	// schema; only type and ip are sent.
	entries := []IPProtectionIPListPutEntry{{Type: "block-ip", IP: "192.0.2.1"}, {IP: "192.0.2.2"}}
	if err := updated.SetConfig("ip_list", entries); err != nil {
		t.Fatalf("SetConfig(ip_list) error = %v", err)
	}
	if err := apiClient.PutIPProtection(context.Background(), "app/id", updated); err != nil {
		t.Fatalf("PutIPProtection() error = %v", err)
	}

	if _, ok := putBody["future_envelope"]; !ok {
		t.Fatalf("PUT body lost future_envelope: %s", mustJSON(putBody))
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
	// The PUT body must NOT carry wire-only idx on ip_list items; the pinned
	// PutIPProtection schema omits idx (idx is GET-only). Decode into the PUT
	// shape and assert no idx key appears in the raw JSON.
	var putEntries []IPProtectionIPListPutEntry
	if err := json.Unmarshal(configs["ip_list"], &putEntries); err != nil {
		t.Fatalf("decode ip_list: %v", err)
	}
	if len(putEntries) != 2 ||
		putEntries[0].IP != "192.0.2.1" || putEntries[1].IP != "192.0.2.2" {
		t.Fatalf("PUT ip_list = %#v", putEntries)
	}
	if putEntries[0].Type != "block-ip" {
		t.Fatalf("PUT ip_list[0].type = %q, want block-ip", putEntries[0].Type)
	}
	var rawPutItems []map[string]json.RawMessage
	if err := json.Unmarshal(configs["ip_list"], &rawPutItems); err != nil {
		t.Fatalf("decode raw ip_list: %v", err)
	}
	for i, item := range rawPutItems {
		if _, hasIdx := item["idx"]; hasIdx {
			t.Fatalf("PUT ip_list item %d carries wire-only idx; the PUT shape must omit it: %s", i, mustJSON(item))
		}
	}
}

func TestIPProtectionDecodeMissingRequiredRejects(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"result":{"configs":{"ip_reputation":true},"template":false}}`,
		`{"result":{"configs":{"status":true},"template":false}}`,
		`{"result":{"template":false}}`,
	} {
		if err := json.Unmarshal([]byte(body), &IPProtectionDocument{}); err == nil {
			t.Fatalf("Unmarshal accepted a missing required scalar: %s", body)
		}
	}
}

func rawIPProtectionItems(t *testing.T, body string) []json.RawMessage {
	t.Helper()
	var document IPProtectionDocument
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	return document.Config.IPList
}

func TestIPProtectionDecodeAbsentIPListIsNil(t *testing.T) {
	t.Parallel()

	var document IPProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"ip_reputation":true},"template":false}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.IPList != nil {
		t.Fatalf("ip_list = %#v, want nil", document.Config.IPList)
	}
}

func TestIPProtectionDecodeExplicitNullIPListRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":null},"template":false}}`), &IPProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted an explicit null ip_list")
	}
}

func TestIPProtectionDecodeExplicitNullOptionalRejects(t *testing.T) {
	t.Parallel()

	bodies := map[string]string{
		"geo_ip_mode":        `{"result":{"configs":{"status":true,"ip_reputation":true,"geo_ip_mode":null},"template":false}}`,
		"block_country_list": `{"result":{"configs":{"status":true,"ip_reputation":true,"block_country_list":null},"template":false}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := json.Unmarshal([]byte(body), &IPProtectionDocument{}); err == nil {
				t.Fatalf("Unmarshal accepted an explicit null for %s", name)
			}
		})
	}
}

func TestIPProtectionDecodeRejectsUnsupportedEnums(t *testing.T) {
	t.Parallel()

	valid := `{"result":{"configs":{"status":true,"ip_reputation":true,"geo_ip_mode":"allow","ip_list":[{"idx":1,"type":"allow-only-ip","ip":"198.51.100.1"}]},"template":false}}`
	var document IPProtectionDocument
	if err := json.Unmarshal([]byte(valid), &document); err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	if _, err := DecodeIPProtectionIPList(document.Config.IPList); err != nil {
		t.Fatalf("valid strict control error = %v", err)
	}

	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"ip_reputation":true,"geo_ip_mode":"deny"},"template":false}}`), &IPProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted unsupported geo_ip_mode")
	}
	items := rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"deny-ip","ip":"198.51.100.1"}]},"template":false}}`)
	if _, err := DecodeIPProtectionIPList(items); err == nil {
		t.Fatal("strict decode accepted unsupported ip_list type")
	}
}

func TestIPProtectionStrictDecodeFailClosedUnknownItemKey(t *testing.T) {
	t.Parallel()

	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1"}]},"template":false}}`)); err != nil {
		t.Fatalf("valid control decode error = %v", err)
	}
	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1","future_key":"x"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted an unknown ip_list item key")
	}
}

func TestIPProtectionStrictDecodeRejectsNonPositiveIdx(t *testing.T) {
	t.Parallel()

	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":0,"ip":"10.0.0.1"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a non-positive idx")
	}
}

func TestIPProtectionStrictDecodeRejectsDuplicateIdx(t *testing.T) {
	t.Parallel()

	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"ip":"10.0.0.1"},{"idx":1,"ip":"10.0.0.2"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a duplicate idx")
	}
}

func TestIPProtectionStrictDecodeSortsByIdx(t *testing.T) {
	t.Parallel()

	entries, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":2,"ip":"10.0.0.2"},{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`))
	if err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if len(entries) != 2 || entries[0].IDX != 1 || entries[1].IDX != 2 {
		t.Fatalf("ip_list not sorted by idx = %#v", entries)
	}
}

func TestIPProtectionStrictDecodeFiltersProductionNullPlaceholders(t *testing.T) {
	t.Parallel()

	items := rawIPProtectionItems(t, `{"result":{"configs":{"status":false,"ip_reputation":false,"ip_list":[{"idx":1,"type":"trust-ip","ip":"1.1.1.1"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":false}}`)
	entries, err := DecodeIPProtectionIPList(items)
	if err != nil {
		t.Fatalf("strict decode production canonical form: %v", err)
	}
	if len(entries) != 1 || entries[0].IDX != 1 || entries[0].Type != "trust-ip" || entries[0].IP != "1.1.1.1" {
		t.Fatalf("active entries = %#v, want only the configured trust-ip slot", entries)
	}

	allNull := rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":null},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":null}]},"template":false}}`)
	entries, err = DecodeIPProtectionIPList(allNull)
	if err != nil {
		t.Fatalf("strict decode all-null canonical form: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("all-null canonical form decoded active entries = %#v, want empty", entries)
	}
}

func TestIPProtectionStrictDecodeSupportsEachActiveRuleTypeWithPlaceholders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		active string
	}{
		{name: "trust", active: "trust-ip"},
		{name: "block", active: "block-ip"},
		{name: "allow only", active: "allow-only-ip"},
	}
	ruleTypes := []string{"trust-ip", "block-ip", "allow-only-ip"}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			raw := make([]json.RawMessage, 0, len(ruleTypes))
			for index, ruleType := range ruleTypes {
				ip := "null"
				if ruleType == test.active {
					ip = `"1.1.1.1"`
				}
				raw = append(raw, json.RawMessage(fmt.Sprintf(`{"idx":%d,"type":%q,"ip":%s}`, index+1, ruleType, ip)))
			}
			entries, err := DecodeIPProtectionIPList(raw)
			if err != nil {
				t.Fatalf("strict decode %s active slot: %v", test.active, err)
			}
			if len(entries) != 1 || entries[0].Type != test.active || entries[0].IP != "1.1.1.1" {
				t.Fatalf("active entries = %#v, want one %s entry", entries, test.active)
			}
		})
	}
}

func TestIPProtectionStrictDecodeRejectsMalformedNullPlaceholders(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing idx":      `{"type":"trust-ip","ip":null}`,
		"missing type":     `{"idx":1,"ip":null}`,
		"null idx":         `{"idx":null,"type":"trust-ip","ip":null}`,
		"null type":        `{"idx":1,"type":null,"ip":null}`,
		"invalid type":     `{"idx":1,"type":"deny-ip","ip":null}`,
		"non-positive idx": `{"idx":0,"type":"trust-ip","ip":null}`,
		"unknown key":      `{"idx":1,"type":"trust-ip","ip":null,"future_key":"x"}`,
	}
	for name, item := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeIPProtectionIPList([]json.RawMessage{json.RawMessage(item)}); err == nil {
				t.Fatalf("strict decode accepted malformed null placeholder: %s", item)
			}
		})
	}
}

func TestIPProtectionStrictDecodeRejectsOtherItemFieldNulls(t *testing.T) {
	t.Parallel()

	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":null,"ip":"10.0.0.1"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a null idx")
	}
	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":null,"ip":"10.0.0.1"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a null type")
	}
}

func TestIPProtectionStrictDecodeRequiresIP(t *testing.T) {
	t.Parallel()

	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a missing ip")
	}
	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"ip":""}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted an empty ip")
	}
}

func TestIPProtectionStrictDecodeRejectsTooManyEntries(t *testing.T) {
	t.Parallel()

	items := ""
	for i := 1; i <= 257; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"ip":"10.0.0.%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[` + items + `]},"template":false}}`
	if _, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, body)); err == nil {
		t.Fatal("strict decode accepted more than 256 entries")
	}
}

func TestIPProtectionStrictDecodeAcceptsMaxEntriesControl(t *testing.T) {
	t.Parallel()

	items := ""
	for i := 1; i <= 256; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"ip":"10.0.0.%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[` + items + `]},"template":false}}`
	entries, err := DecodeIPProtectionIPList(rawIPProtectionItems(t, body))
	if err != nil {
		t.Fatalf("strict decode rejected 256 entries: %v", err)
	}
	if len(entries) != 256 {
		t.Fatalf("decoded %d entries, want 256", len(entries))
	}
}

func TestIPProtectionDocumentDecodePreservesUnknownItemKey(t *testing.T) {
	t.Parallel()

	items := rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"ip":"10.0.0.1","future_key":"x"}]},"template":false}}`)
	if len(items) != 1 {
		t.Fatalf("lenient decode dropped the unknown-key item: %#v", items)
	}
	if _, err := DecodeIPProtectionIPList(items); err == nil {
		t.Fatal("strict decode accepted an unknown key that the lenient decode preserved")
	}
}

func TestPrepareIPProtectionIPListForPut(t *testing.T) {
	t.Parallel()

	items := rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1","future_key":"x"},{"idx":2,"type":"block-ip","ip":null},{"idx":3,"type":"allow-only-ip","ip":"10.0.0.2"}]},"template":false}}`)
	prepared, err := PrepareIPProtectionIPListForPut(items)
	if err != nil {
		t.Fatalf("PrepareIPProtectionIPListForPut: %v", err)
	}
	if len(prepared) != 2 {
		t.Fatalf("prepared length = %d, want 2 active items", len(prepared))
	}
	for i, item := range prepared {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(item, &object); err != nil {
			t.Fatalf("decode prepared item %d: %v", i, err)
		}
		if _, hasIdx := object["idx"]; hasIdx {
			t.Fatalf("prepared item %d still carries idx: %s", i, string(item))
		}
		if string(object["ip"]) != `"10.0.0.1"` && i == 0 {
			t.Fatalf("prepared item %d lost ip: %s", i, string(item))
		}
	}
	// The unknown future_key on item 0 is preserved opaquely.
	var first map[string]json.RawMessage
	if err := json.Unmarshal(prepared[0], &first); err != nil {
		t.Fatalf("decode prepared item 0: %v", err)
	}
	if _, hasFuture := first["future_key"]; !hasFuture {
		t.Fatalf("prepared item 0 lost the unknown future_key: %s", string(prepared[0]))
	}
	if _, hasType := first["type"]; !hasType {
		t.Fatalf("prepared item 0 lost type: %s", string(prepared[0]))
	}

	// Empty and nil inputs pass through unchanged.
	if got, err := PrepareIPProtectionIPListForPut(nil); err != nil || got != nil {
		t.Fatalf("nil input = %#v err=%v, want nil", got, err)
	}
	if got, err := PrepareIPProtectionIPListForPut([]json.RawMessage{}); err != nil || len(got) != 0 {
		t.Fatalf("empty input = %#v err=%v, want empty", got, err)
	}
}

func TestPrepareIPProtectionIPListForPutRejectsMalformedPlaceholders(t *testing.T) {
	t.Parallel()

	for name, item := range map[string]string{
		"missing ip":       `{"idx":1,"type":"trust-ip"}`,
		"missing idx":      `{"type":"trust-ip","ip":null}`,
		"missing type":     `{"idx":1,"ip":null}`,
		"non-positive idx": `{"idx":0,"type":"trust-ip","ip":null}`,
		"unknown key":      `{"idx":1,"type":"trust-ip","ip":null,"future_key":"x"}`,
		"null item":        `null`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := PrepareIPProtectionIPListForPut([]json.RawMessage{json.RawMessage(item)}); err == nil {
				t.Fatalf("PrepareIPProtectionIPListForPut accepted malformed item: %s", item)
			}
		})
	}
}

func TestPrepareIPProtectionIPListForPutRejectsDuplicateExplicitIndices(t *testing.T) {
	t.Parallel()

	items := rawIPProtectionItems(t, `{"result":{"configs":{"status":true,"ip_reputation":true,"ip_list":[{"idx":1,"type":"trust-ip","ip":"10.0.0.1","future_key":"x"},{"idx":1,"type":"block-ip","ip":null}]},"template":false}}`)
	if _, err := PrepareIPProtectionIPListForPut(items); err == nil {
		t.Fatal("PrepareIPProtectionIPListForPut accepted duplicate active/placeholder indices")
	}
}

func TestNormalizeIPProtectionResultForPutPreservesEnvelopeAndConvertsGETItems(t *testing.T) {
	t.Parallel()

	var document WAFModuleDocument
	if err := json.Unmarshal([]byte(`{
		"result": {
			"template": false,
			"future_envelope": {"keep": true},
			"configs": {
				"status": true,
				"ip_reputation": true,
				"future_config": {"keep": true},
				"ip_list": [
					{"idx": 1, "type": "trust-ip", "ip": "10.0.0.1", "future_key": "keep"},
					{"idx": 2, "type": "block-ip", "ip": null}
				]
			}
		}
	}`), &document); err != nil {
		t.Fatalf("decode result fixture: %v", err)
	}

	normalized, err := NormalizeIPProtectionResultForPut(document.Result)
	if err != nil {
		t.Fatalf("NormalizeIPProtectionResultForPut() error = %v", err)
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		t.Fatalf("encode normalized result: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode normalized result: %v", err)
	}
	if _, ok := envelope["future_envelope"]; !ok {
		t.Fatal("normalized result lost future_envelope")
	}
	if _, ok := normalized.Configs["future_config"]; !ok {
		t.Fatal("normalized result lost future_config")
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(normalized.Configs["ip_list"], &items); err != nil {
		t.Fatalf("decode normalized ip_list: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("normalized ip_list length = %d, want 1", len(items))
	}
	if _, ok := items[0]["idx"]; ok {
		t.Fatal("normalized active item retained GET-only idx")
	}
	if _, ok := items[0]["future_key"]; !ok {
		t.Fatal("normalized active item lost an opaque field")
	}
}

func TestIPProtectionEmptyEndpointErrors(t *testing.T) {
	t.Parallel()

	apiClient, err := New(context.Background(), Config{BaseURL: "https://example.test", APIToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetIPProtection(context.Background(), ""); err == nil {
		t.Fatal("GetIPProtection() accepted an empty ep_id")
	}
	if err := apiClient.PutIPProtection(context.Background(), "", WAFModuleResult{}); err == nil {
		t.Fatal("PutIPProtection() accepted an empty ep_id")
	}
}
