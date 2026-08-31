package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnomalyDetectionGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/anomaly_detection" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Basic token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"status":false,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)
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

	document, err := apiClient.GetAnomalyDetection(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetAnomalyDetection() error = %v", err)
	}
	if document.Config.Status == nil || *document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if document.Config.Action == nil || *document.Config.Action != "alert" {
		t.Fatalf("action = %#v", document.Config.Action)
	}
	if len(document.Config.IPList) != 1 {
		t.Fatalf("ip_list = %#v, want 1 raw item", document.Config.IPList)
	}
	decoded, err := DecodeAnomalyDetectionIPList(document.Config.IPList)
	if err != nil {
		t.Fatalf("DecodeAnomalyDetectionIPList: %v", err)
	}
	if len(decoded) != 1 || decoded[0].IP != "10.0.0.1" {
		t.Fatalf("decoded ip_list = %#v", decoded)
	}

	updated := document.Result.Clone()
	if err := updated.SetConfig("status", true); err != nil {
		t.Fatalf("SetConfig(status) error = %v", err)
	}
	entries := []AnomalyDetectionIPListEntry{{IDX: 1, IP: "192.0.2.1"}, {IDX: 2, IP: "192.0.2.2"}}
	if err := updated.SetConfig("ip_list", entries); err != nil {
		t.Fatalf("SetConfig(ip_list) error = %v", err)
	}
	if err := apiClient.PutAnomalyDetection(context.Background(), "app/id", updated); err != nil {
		t.Fatalf("PutAnomalyDetection() error = %v", err)
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
	var putEntries []AnomalyDetectionIPListEntry
	if err := json.Unmarshal(configs["ip_list"], &putEntries); err != nil {
		t.Fatalf("decode ip_list: %v", err)
	}
	if len(putEntries) != 2 || putEntries[0].IDX != 1 || putEntries[1].IDX != 2 ||
		putEntries[0].IP != "192.0.2.1" || putEntries[1].IP != "192.0.2.2" {
		t.Fatalf("PUT ip_list = %#v", putEntries)
	}
}

func TestAnomalyDetectionDecodeMissingScalarRejects(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"result":{"configs":{"action":"alert","ip_list_type":"Block"},"template":false}}`,
		`{"result":{"configs":{"status":true,"ip_list_type":"Block"},"template":false}}`,
		`{"result":{"configs":{"status":true,"action":"alert"},"template":false}}`,
		`{"result":{"template":false}}`,
	} {
		if err := json.Unmarshal([]byte(body), &AnomalyDetectionDocument{}); err == nil {
			t.Fatalf("Unmarshal accepted a missing scalar: %s", body)
		}
	}
}

func TestAnomalyDetectionDecodeRejectsMalformedAndUnsupportedScalars(t *testing.T) {
	t.Parallel()

	valid := `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block"},"template":false}}`
	if err := json.Unmarshal([]byte(valid), &AnomalyDetectionDocument{}); err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	for name, body := range map[string]string{
		"null status":              `{"result":{"configs":{"status":null,"action":"alert","ip_list_type":"Block"},"template":false}}`,
		"wrong status type":        `{"result":{"configs":{"status":"true","action":"alert","ip_list_type":"Block"},"template":false}}`,
		"null action":              `{"result":{"configs":{"status":true,"action":null,"ip_list_type":"Block"},"template":false}}`,
		"wrong action type":        `{"result":{"configs":{"status":true,"action":1,"ip_list_type":"Block"},"template":false}}`,
		"unsupported action":       `{"result":{"configs":{"status":true,"action":"deny","ip_list_type":"Block"},"template":false}}`,
		"null IP list type":        `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":null},"template":false}}`,
		"wrong IP list type":       `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":false},"template":false}}`,
		"unsupported IP list type": `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Allow"},"template":false}}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := json.Unmarshal([]byte(body), &AnomalyDetectionDocument{}); err == nil {
				t.Fatal("Unmarshal accepted malformed or unsupported scalar")
			}
		})
	}
}

// rawIPItems extracts the raw ip_list items from a GET response so the strict
// owned/imported decode path (DecodeAnomalyDetectionIPList) can be exercised.
func rawIPItems(t *testing.T, body string) []json.RawMessage {
	t.Helper()
	var document AnomalyDetectionDocument
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	return document.Config.IPList
}

func TestAnomalyDetectionDecodeAbsentIPListIsNil(t *testing.T) {
	t.Parallel()

	var document AnomalyDetectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block"},"template":false}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.IPList != nil {
		t.Fatalf("ip_list = %#v, want nil", document.Config.IPList)
	}
}

func TestAnomalyDetectionDecodeExplicitNullIPListRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":null},"template":false}}`), &AnomalyDetectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted an explicit null ip_list")
	}
}

func TestAnomalyDetectionDecodeEmptyIPList(t *testing.T) {
	t.Parallel()

	var document AnomalyDetectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[]},"template":false}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.IPList == nil || len(document.Config.IPList) != 0 {
		t.Fatalf("ip_list = %#v, want non-nil empty", document.Config.IPList)
	}
}

func TestAnomalyDetectionStrictDecodeFailClosedUnknownItemKey(t *testing.T) {
	t.Parallel()

	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`)); err != nil {
		t.Fatalf("valid control decode error = %v", err)
	}
	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1","future_key":"x"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted an unknown ip_list item key")
	}
}

func TestAnomalyDetectionStrictDecodeRejectsNonPositiveIdx(t *testing.T) {
	t.Parallel()

	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":0,"ip":"10.0.0.1"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a non-positive idx")
	}
}

func TestAnomalyDetectionStrictDecodeRejectsDuplicateIdx(t *testing.T) {
	t.Parallel()

	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"},{"idx":1,"ip":"10.0.0.2"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a duplicate idx")
	}
}

func TestAnomalyDetectionStrictDecodeSortsByIdx(t *testing.T) {
	t.Parallel()

	entries, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":2,"ip":"10.0.0.2"},{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`))
	if err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if len(entries) != 2 || entries[0].IDX != 1 || entries[1].IDX != 2 {
		t.Fatalf("ip_list not sorted by idx = %#v", entries)
	}
}

func TestAnomalyDetectionStrictDecodeRejectsItemFieldNulls(t *testing.T) {
	t.Parallel()

	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":null}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a null ip")
	}
	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":null,"ip":"10.0.0.1"}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a null idx")
	}
}

func TestAnomalyDetectionStrictDecodeRequiresIP(t *testing.T) {
	t.Parallel()

	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted a missing ip")
	}
	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":""}]},"template":false}}`)); err == nil {
		t.Fatal("strict decode accepted an empty ip")
	}
}

func TestAnomalyDetectionStrictDecodeRejectsTooManyEntries(t *testing.T) {
	t.Parallel()

	items := ""
	for i := 1; i <= 31; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"ip":"10.0.0.%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[` + items + `]},"template":false}}`
	if _, err := DecodeAnomalyDetectionIPList(rawIPItems(t, body)); err == nil {
		t.Fatal("strict decode accepted more than 30 entries")
	}
}

func TestAnomalyDetectionStrictDecodeAcceptsMaxEntriesControl(t *testing.T) {
	t.Parallel()

	items := ""
	for i := 1; i <= 30; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"ip":"10.0.0.%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[` + items + `]},"template":false}}`
	entries, err := DecodeAnomalyDetectionIPList(rawIPItems(t, body))
	if err != nil {
		t.Fatalf("strict decode rejected 30 entries: %v", err)
	}
	if len(entries) != 30 {
		t.Fatalf("decoded %d entries, want 30", len(entries))
	}
}

func TestAnomalyDetectionDocumentDecodePreservesUnknownItemKey(t *testing.T) {
	t.Parallel()

	items := rawIPItems(t, `{"result":{"configs":{"status":true,"action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1","future_key":"x"}]},"template":false}}`)
	if len(items) != 1 {
		t.Fatalf("lenient decode dropped the unknown-key item: %#v", items)
	}
	if _, err := DecodeAnomalyDetectionIPList(items); err == nil {
		t.Fatal("strict decode accepted an unknown key that the lenient decode preserved")
	}
}

func TestAnomalyDetectionEmptyEndpointErrors(t *testing.T) {
	t.Parallel()

	apiClient, err := New(context.Background(), Config{BaseURL: "https://example.test", APIToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetAnomalyDetection(context.Background(), ""); err == nil {
		t.Fatal("GetAnomalyDetection() accepted an empty ep_id")
	}
	if err := apiClient.PutAnomalyDetection(context.Background(), "", WAFModuleResult{}); err == nil {
		t.Fatal("PutAnomalyDetection() accepted an empty ep_id")
	}
}
