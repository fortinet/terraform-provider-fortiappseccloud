package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMlApiProtectionGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()
	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/ml_api_protection" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"status":false,"threat_action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}],"path_list":[{"idx":1,"type":"plain","pattern":"/api"}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)
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
	apiClient, err := New(context.Background(), Config{BaseURL: server.URL, APIToken: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	document, err := apiClient.GetMlApiProtection(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetMlApiProtection() error = %v", err)
	}
	if document.Config.Status == nil || *document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if len(document.Config.IPList) != 1 {
		t.Fatalf("ip_list = %#v, want 1", document.Config.IPList)
	}
	decoded, err := DecodeMlApiProtectionIPList(document.Config.IPList)
	if err != nil {
		t.Fatalf("DecodeMlApiProtectionIPList: %v", err)
	}
	if len(decoded) != 1 || decoded[0].IP != "10.0.0.1" {
		t.Fatalf("decoded ip_list = %#v", decoded)
	}
	decodedPaths, err := DecodeMlApiProtectionPathList(document.Config.PathList)
	if err != nil {
		t.Fatalf("DecodeMlApiProtectionPathList: %v", err)
	}
	if len(decodedPaths) != 1 || decodedPaths[0].Type != "plain" || decodedPaths[0].Pattern != "/api" {
		t.Fatalf("decoded path_list = %#v", decodedPaths)
	}
	updated := document.Result.Clone()
	if err := updated.SetConfig("status", true); err != nil {
		t.Fatalf("SetConfig(status) error = %v", err)
	}
	if err := apiClient.PutMlApiProtection(context.Background(), "app/id", updated); err != nil {
		t.Fatalf("PutMlApiProtection() error = %v", err)
	}
	if _, ok := putBody["future_envelope"]; !ok {
		t.Fatalf("PUT body lost future_envelope")
	}
}

func TestMlApiProtectionDecodeMissingRequiredRejects(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"result":{"configs":{"threat_action":"alert","ip_list_type":"Block"},"template":false}}`,
		`{"result":{"configs":{"status":true,"ip_list_type":"Block"},"template":false}}`,
		`{"result":{"configs":{"status":true,"threat_action":"alert"},"template":false}}`,
		`{"result":{"template":false}}`,
	} {
		if err := json.Unmarshal([]byte(body), &MlApiProtectionDocument{}); err == nil {
			t.Fatalf("Unmarshal accepted a missing required scalar: %s", body)
		}
	}
}

func TestMlApiProtectionDecodeRejectsMalformedAndUnsupportedScalars(t *testing.T) {
	t.Parallel()

	valid := `{"result":{"configs":{"status":true,"threat_action":"disable","ip_list_type":"Trust"},"template":false}}`
	if err := json.Unmarshal([]byte(valid), &MlApiProtectionDocument{}); err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	for name, body := range map[string]string{
		"null status":               `{"result":{"configs":{"status":null,"threat_action":"alert","ip_list_type":"Block"},"template":false}}`,
		"wrong status type":         `{"result":{"configs":{"status":"true","threat_action":"alert","ip_list_type":"Block"},"template":false}}`,
		"null threat action":        `{"result":{"configs":{"status":true,"threat_action":null,"ip_list_type":"Block"},"template":false}}`,
		"unsupported threat action": `{"result":{"configs":{"status":true,"threat_action":"deny","ip_list_type":"Block"},"template":false}}`,
		"null IP list type":         `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":null},"template":false}}`,
		"unsupported IP list type":  `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Allow"},"template":false}}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := json.Unmarshal([]byte(body), &MlApiProtectionDocument{}); err == nil {
				t.Fatal("Unmarshal accepted malformed or unsupported scalar")
			}
		})
	}
}

func TestMlApiProtectionDecodeExplicitNullListRejects(t *testing.T) {
	t.Parallel()
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","ip_list":null},"template":false}}`), &MlApiProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted an explicit null ip_list")
	}
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","path_list":null},"template":false}}`), &MlApiProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted an explicit null path_list")
	}
}

func TestMlApiProtectionStrictDecodeIPFailClosedUnknownKey(t *testing.T) {
	t.Parallel()
	var doc MlApiProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1"}]},"template":false}}`), &doc); err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	if _, err := DecodeMlApiProtectionIPList(doc.Config.IPList); err != nil {
		t.Fatalf("valid control decode error = %v", err)
	}
	// Negative: unknown key — decode leniently then strict-reject
	var docBad MlApiProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","ip_list":[{"idx":1,"ip":"10.0.0.1","future_key":"x"}]},"template":false}}`), &docBad); err != nil {
		t.Fatalf("lenient unmarshal error = %v", err)
	}
	if _, err := DecodeMlApiProtectionIPList(docBad.Config.IPList); err == nil {
		t.Fatal("strict decode accepted an unknown ip_list item key")
	}
}

func TestMlApiProtectionStrictDecodePathFailClosedUnknownKey(t *testing.T) {
	t.Parallel()
	var doc MlApiProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","path_list":[{"idx":1,"type":"plain","pattern":"/api"}]},"template":false}}`), &doc); err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	if _, err := DecodeMlApiProtectionPathList(doc.Config.PathList); err != nil {
		t.Fatalf("valid control decode error = %v", err)
	}
	// Negative: unknown key — decode leniently then strict-reject
	var docBad MlApiProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","path_list":[{"idx":1,"type":"plain","pattern":"/api","future_key":"x"}]},"template":false}}`), &docBad); err != nil {
		t.Fatalf("lenient unmarshal error = %v", err)
	}
	if _, err := DecodeMlApiProtectionPathList(docBad.Config.PathList); err == nil {
		t.Fatal("strict decode accepted an unknown path_list item key")
	}
}

func TestMlApiProtectionStrictDecodeValidatesIPFields(t *testing.T) {
	t.Parallel()

	for name, items := range map[string][]json.RawMessage{
		"null item":        {json.RawMessage(`null`)},
		"malformed item":   {json.RawMessage(`[]`)},
		"null idx":         {json.RawMessage(`{"idx":null,"ip":"198.51.100.1"}`)},
		"non-positive idx": {json.RawMessage(`{"idx":0,"ip":"198.51.100.1"}`)},
		"duplicate idx":    {json.RawMessage(`{"idx":1,"ip":"198.51.100.1"}`), json.RawMessage(`{"idx":1,"ip":"198.51.100.2"}`)},
		"missing IP":       {json.RawMessage(`{"idx":1}`)},
		"null IP":          {json.RawMessage(`{"idx":1,"ip":null}`)},
		"empty IP":         {json.RawMessage(`{"idx":1,"ip":""}`)},
		"wrong IP type":    {json.RawMessage(`{"idx":1,"ip":1}`)},
	} {
		name, items := name, items
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeMlApiProtectionIPList(items); err == nil {
				t.Fatal("strict decode accepted malformed IP item")
			}
		})
	}

	entries, err := DecodeMlApiProtectionIPList([]json.RawMessage{
		json.RawMessage(`{"idx":2,"ip":"198.51.100.2"}`),
		json.RawMessage(`{"idx":1,"ip":"198.51.100.1"}`),
	})
	if err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	if entries[0].IDX != 1 || entries[1].IDX != 2 {
		t.Fatalf("entries not sorted by idx: %#v", entries)
	}
}

func TestMlApiProtectionStrictDecodeValidatesPathFields(t *testing.T) {
	t.Parallel()

	for name, items := range map[string][]json.RawMessage{
		"null item":          {json.RawMessage(`null`)},
		"malformed item":     {json.RawMessage(`[]`)},
		"null idx":           {json.RawMessage(`{"idx":null,"type":"plain","pattern":"/api"}`)},
		"non-positive idx":   {json.RawMessage(`{"idx":0,"type":"plain","pattern":"/api"}`)},
		"duplicate idx":      {json.RawMessage(`{"idx":1,"type":"plain","pattern":"/one"}`), json.RawMessage(`{"idx":1,"type":"regular","pattern":"/two"}`)},
		"missing type":       {json.RawMessage(`{"idx":1,"pattern":"/api"}`)},
		"null type":          {json.RawMessage(`{"idx":1,"type":null,"pattern":"/api"}`)},
		"unsupported type":   {json.RawMessage(`{"idx":1,"type":"regex","pattern":"/api"}`)},
		"missing pattern":    {json.RawMessage(`{"idx":1,"type":"plain"}`)},
		"null pattern":       {json.RawMessage(`{"idx":1,"type":"plain","pattern":null}`)},
		"empty pattern":      {json.RawMessage(`{"idx":1,"type":"plain","pattern":""}`)},
		"invalid pattern":    {json.RawMessage(`{"idx":1,"type":"plain","pattern":"api"}`)},
		"wrong pattern type": {json.RawMessage(`{"idx":1,"type":"plain","pattern":1}`)},
	} {
		name, items := name, items
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeMlApiProtectionPathList(items); err == nil {
				t.Fatal("strict decode accepted malformed path item")
			}
		})
	}

	entries, err := DecodeMlApiProtectionPathList([]json.RawMessage{
		json.RawMessage(`{"idx":2,"type":"regular","pattern":"/two"}`),
		json.RawMessage(`{"idx":1,"type":"plain","pattern":"/one"}`),
	})
	if err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	if entries[0].IDX != 1 || entries[1].IDX != 2 {
		t.Fatalf("entries not sorted by idx: %#v", entries)
	}
}

func TestMlApiProtectionStrictDecodeIPRejectsTooMany(t *testing.T) {
	t.Parallel()
	items := ""
	for i := 1; i <= 31; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"ip":"10.0.0.%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","ip_list":[` + items + `]},"template":false}}`
	var doc MlApiProtectionDocument
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := DecodeMlApiProtectionIPList(doc.Config.IPList); err == nil {
		t.Fatal("strict decode accepted >30 ip entries")
	}
}

func TestMlApiProtectionStrictDecodeIPAcceptsMaxControl(t *testing.T) {
	t.Parallel()
	items := ""
	for i := 1; i <= 30; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"ip":"10.0.0.%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","ip_list":[` + items + `]},"template":false}}`
	var doc MlApiProtectionDocument
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entries, err := DecodeMlApiProtectionIPList(doc.Config.IPList)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 30 {
		t.Fatalf("decoded %d, want 30", len(entries))
	}
}

func TestMlApiProtectionStrictDecodePathRejectsTooMany(t *testing.T) {
	t.Parallel()
	items := ""
	for i := 1; i <= 31; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"type":"plain","pattern":"/p%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","path_list":[` + items + `]},"template":false}}`
	var doc MlApiProtectionDocument
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := DecodeMlApiProtectionPathList(doc.Config.PathList); err == nil {
		t.Fatal("strict decode accepted >30 path entries")
	}
}

func TestMlApiProtectionStrictDecodePathAcceptsMaxControl(t *testing.T) {
	t.Parallel()
	items := ""
	for i := 1; i <= 30; i++ {
		if i > 1 {
			items += ","
		}
		items += fmt.Sprintf(`{"idx":%d,"type":"plain","pattern":"/p%d"}`, i, i)
	}
	body := `{"result":{"configs":{"status":true,"threat_action":"alert","ip_list_type":"Block","path_list":[` + items + `]},"template":false}}`
	var doc MlApiProtectionDocument
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entries, err := DecodeMlApiProtectionPathList(doc.Config.PathList)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 30 {
		t.Fatalf("decoded %d, want 30", len(entries))
	}
}

func TestMlApiProtectionEmptyEndpointErrors(t *testing.T) {
	t.Parallel()
	apiClient, err := New(context.Background(), Config{BaseURL: "https://example.test", APIToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetMlApiProtection(context.Background(), ""); err == nil {
		t.Fatal("GetMlApiProtection() accepted an empty ep_id")
	}
	if err := apiClient.PutMlApiProtection(context.Background(), "", WAFModuleResult{}); err == nil {
		t.Fatal("PutMlApiProtection() accepted an empty ep_id")
	}
}
