package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomRuleGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/custom_rule" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"status":false,"rule_list":[{"idx":1,"name":"old","action":"alert","filter_list":[{"idx":1,"type":"source-ip-filter","ip":"10.0.0.1"}]}],"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)
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

	document, err := apiClient.GetCustomRule(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetCustomRule() error = %v", err)
	}
	if document.Config.Status == nil || *document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if len(document.Config.RuleList) != 1 {
		t.Fatalf("rule_list = %#v, want 1 raw item", document.Config.RuleList)
	}

	updated := document.Result.Clone()
	updated.Template = false
	if err := updated.SetConfig("status", true); err != nil {
		t.Fatalf("SetConfig(status) error = %v", err)
	}
	if err := apiClient.PutCustomRule(context.Background(), "app/id", updated); err != nil {
		t.Fatalf("PutCustomRule() error = %v", err)
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
}

func TestCustomRuleDecodeMissingStatusRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"result":{"configs":{"rule_list":[]},"template":false}}`), &CustomRuleDocument{}); err == nil {
		t.Fatal("Unmarshal accepted a missing status")
	}
}

func TestCustomRuleDecodeExplicitNullRuleListRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"rule_list":null},"template":false}}`), &CustomRuleDocument{}); err == nil {
		t.Fatal("Unmarshal accepted an explicit null rule_list")
	}
}

func TestCustomRuleDecodeAbsentRuleListIsNil(t *testing.T) {
	t.Parallel()

	var document CustomRuleDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true},"template":false}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.RuleList != nil {
		t.Fatalf("rule_list = %#v, want nil", document.Config.RuleList)
	}
}

func TestCustomRuleStrictDecodeFailClosedUnknownItemKey(t *testing.T) {
	t.Parallel()

	// Valid control
	if _, err := DecodeCustomRuleRuleList([]json.RawMessage{json.RawMessage(`{"idx":1,"name":"ok","action":"alert"}`)}); err != nil {
		t.Fatalf("valid control decode error = %v", err)
	}
	// Negative: unknown key
	if _, err := DecodeCustomRuleRuleList([]json.RawMessage{json.RawMessage(`{"idx":1,"name":"bad","action":"alert","future_key":"x"}`)}); err == nil {
		t.Fatal("strict decode accepted an unknown rule_list item key")
	}
}

func TestCustomRuleStrictDecodeRejectsTooManyEntries(t *testing.T) {
	t.Parallel()

	items := make([]json.RawMessage, 25)
	for i := 0; i < 25; i++ {
		items[i] = json.RawMessage(fmt.Sprintf(`{"idx":%d,"name":"n%d","action":"alert"}`, i+1, i+1))
	}
	if _, err := DecodeCustomRuleRuleList(items); err == nil {
		t.Fatal("strict decode accepted more than 24 entries")
	}
}

func TestCustomRuleStrictDecodeAcceptsMaxEntriesControl(t *testing.T) {
	t.Parallel()

	items := make([]json.RawMessage, 24)
	for i := 0; i < 24; i++ {
		items[i] = json.RawMessage(fmt.Sprintf(`{"idx":%d,"name":"n%d","action":"alert"}`, i+1, i+1))
	}
	decoded, err := DecodeCustomRuleRuleList(items)
	if err != nil {
		t.Fatalf("strict decode rejected 24 entries: %v", err)
	}
	if len(decoded) != 24 {
		t.Fatalf("decoded %d entries, want 24", len(decoded))
	}
}

func TestCustomRuleStrictDecodeValidatesRuleFieldsAndOrdering(t *testing.T) {
	t.Parallel()

	decoded, err := DecodeCustomRuleRuleList([]json.RawMessage{
		json.RawMessage(`{"idx":2,"name":"second","action":"alert_deny","block_period":3600,"challenge":"disabled"}`),
		json.RawMessage(`{"idx":1,"name":"first","action":"alert","block_period":1,"challenge":"real-browser-enforcement","filter_list":[]}`),
	})
	if err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	if !strings.Contains(string(decoded[0]), `"first"`) || !strings.Contains(string(decoded[1]), `"second"`) {
		t.Fatalf("decoded order = %s / %s, want idx order", decoded[0], decoded[1])
	}

	tests := map[string][]json.RawMessage{
		"null item":              {json.RawMessage(`null`)},
		"malformed item":         {json.RawMessage(`[]`)},
		"null idx":               {json.RawMessage(`{"idx":null,"name":"x","action":"alert"}`)},
		"non-positive idx":       {json.RawMessage(`{"idx":0,"name":"x","action":"alert"}`)},
		"duplicate idx":          {json.RawMessage(`{"idx":1,"name":"x","action":"alert"}`), json.RawMessage(`{"idx":1,"name":"y","action":"alert"}`)},
		"missing name":           {json.RawMessage(`{"idx":1,"action":"alert"}`)},
		"null name":              {json.RawMessage(`{"idx":1,"name":null,"action":"alert"}`)},
		"empty name":             {json.RawMessage(`{"idx":1,"name":"","action":"alert"}`)},
		"overlong UTF-8 name":    {json.RawMessage(fmt.Sprintf(`{"idx":1,"name":"%s","action":"alert"}`, strings.Repeat("界", CustomRuleNameMaxLen+1)))},
		"missing action":         {json.RawMessage(`{"idx":1,"name":"x"}`)},
		"null action":            {json.RawMessage(`{"idx":1,"name":"x","action":null}`)},
		"unsupported action":     {json.RawMessage(`{"idx":1,"name":"x","action":"drop"}`)},
		"low block period":       {json.RawMessage(`{"idx":1,"name":"x","action":"alert","block_period":0}`)},
		"high block period":      {json.RawMessage(`{"idx":1,"name":"x","action":"alert","block_period":3601}`)},
		"malformed block period": {json.RawMessage(`{"idx":1,"name":"x","action":"alert","block_period":"60"}`)},
		"unsupported challenge":  {json.RawMessage(`{"idx":1,"name":"x","action":"alert","challenge":"unknown"}`)},
		"null filter list":       {json.RawMessage(`{"idx":1,"name":"x","action":"alert","filter_list":null}`)},
		"malformed filter list":  {json.RawMessage(`{"idx":1,"name":"x","action":"alert","filter_list":{}}`)},
	}
	for name, items := range tests {
		name, items := name, items
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeCustomRuleRuleList(items); err == nil {
				t.Fatal("strict decode accepted malformed rule fields")
			}
		})
	}
}

func TestCustomRuleStrictDecodeFilterFailClosedUnknownKey(t *testing.T) {
	t.Parallel()

	// Valid control
	if err := DecodeCustomRuleFilterList([]json.RawMessage{json.RawMessage(`{"idx":1,"type":"source-ip-filter","ip":"10.0.0.1"}`)}); err != nil {
		t.Fatalf("valid control decode error = %v", err)
	}
	// Negative: unknown filter key
	if err := DecodeCustomRuleFilterList([]json.RawMessage{json.RawMessage(`{"idx":1,"type":"source-ip-filter","future_key":"x"}`)}); err == nil {
		t.Fatal("strict decode accepted an unknown filter key")
	}
}

func TestCustomRuleStrictDecodeFilterRejectsTooManyEntries(t *testing.T) {
	t.Parallel()

	items := make([]json.RawMessage, 201)
	for i := 0; i < 201; i++ {
		items[i] = json.RawMessage(fmt.Sprintf(`{"idx":%d,"type":"source-ip-filter"}`, i+1))
	}
	if err := DecodeCustomRuleFilterList(items); err == nil {
		t.Fatal("strict decode accepted more than 200 filter entries")
	}
}

func TestCustomRuleStrictDecodeFilterAcceptsMaxEntriesControl(t *testing.T) {
	t.Parallel()

	items := make([]json.RawMessage, 200)
	for i := 0; i < 200; i++ {
		items[i] = json.RawMessage(fmt.Sprintf(`{"idx":%d,"type":"source-ip-filter"}`, i+1))
	}
	if err := DecodeCustomRuleFilterList(items); err != nil {
		t.Fatalf("strict decode rejected 200 filter entries: %v", err)
	}
}

func TestCustomRuleStrictDecodeValidatesFilterFields(t *testing.T) {
	t.Parallel()

	valid := json.RawMessage(`{
		"idx":1,
		"type":"time-range-filter",
		"reverse_match":false,
		"ip":"198.51.100.1",
		"username":"user",
		"url":"/",
		"name":"name",
		"value":"value",
		"header_check":true,
		"header_type":"custom",
		"header_name":"X-Test",
		"header_value":"value",
		"header_reverse_match":false,
		"method_check":true,
		"method_value":"GET",
		"method_reverse_match":false,
		"http_hline_missing_check":false,
		"http_hline_empty_check":false,
		"content_types":["application/json"],
		"code":"200",
		"cross_site_scripting":false,
		"sql_injection":false,
		"generic_attacks":false,
		"known_exploits":false,
		"trojans":false,
		"limit":1,
		"timeout":0,
		"occurrence":1,
		"within":1,
		"time_type":"daily",
		"start":"00:00",
		"end":"23:59",
		"country_list":["United States"],
		"match_exclusively":false
	}`)
	if err := DecodeCustomRuleFilterList([]json.RawMessage{valid}); err != nil {
		t.Fatalf("valid control error = %v", err)
	}

	tests := map[string][]json.RawMessage{
		"null item":                {json.RawMessage(`null`)},
		"malformed item":           {json.RawMessage(`[]`)},
		"null idx":                 {json.RawMessage(`{"idx":null,"type":"source-ip-filter"}`)},
		"non-positive idx":         {json.RawMessage(`{"idx":0,"type":"source-ip-filter"}`)},
		"duplicate idx":            {json.RawMessage(`{"idx":1,"type":"source-ip-filter"}`), json.RawMessage(`{"idx":1,"type":"user-filter"}`)},
		"missing type":             {json.RawMessage(`{"idx":1}`)},
		"null type":                {json.RawMessage(`{"idx":1,"type":null}`)},
		"unsupported type":         {json.RawMessage(`{"idx":1,"type":"future-filter"}`)},
		"null optional":            {json.RawMessage(`{"idx":1,"type":"source-ip-filter","ip":null}`)},
		"malformed bool":           {json.RawMessage(`{"idx":1,"type":"source-ip-filter","reverse_match":"false"}`)},
		"malformed string":         {json.RawMessage(`{"idx":1,"type":"source-ip-filter","ip":10}`)},
		"overlong UTF-8 username":  {json.RawMessage(fmt.Sprintf(`{"idx":1,"type":"user-filter","username":"%s"}`, strings.Repeat("界", CustomRuleUsernameMaxLen+1)))},
		"unsupported header type":  {json.RawMessage(`{"idx":1,"type":"http-header-filter","header_type":"other"}`)},
		"malformed content types":  {json.RawMessage(`{"idx":1,"type":"content-type","content_types":"application/json"}`)},
		"unsupported content type": {json.RawMessage(`{"idx":1,"type":"content-type","content_types":["other/type"]}`)},
		"malformed code":           {json.RawMessage(`{"idx":1,"type":"response-code","code":200}`)},
		"non-numeric code":         {json.RawMessage(`{"idx":1,"type":"response-code","code":"OK"}`)},
		"low limit":                {json.RawMessage(`{"idx":1,"type":"access-limit-filter","limit":0}`)},
		"high limit":               {json.RawMessage(`{"idx":1,"type":"access-limit-filter","limit":65536}`)},
		"low occurrence":           {json.RawMessage(`{"idx":1,"type":"occurrence","occurrence":0}`)},
		"high occurrence":          {json.RawMessage(`{"idx":1,"type":"occurrence","occurrence":100001}`)},
		"low within":               {json.RawMessage(`{"idx":1,"type":"occurrence","within":0}`)},
		"high within":              {json.RawMessage(`{"idx":1,"type":"occurrence","within":601}`)},
		"unsupported time type":    {json.RawMessage(`{"idx":1,"type":"time-range-filter","time_type":"weekly"}`)},
		"malformed country list":   {json.RawMessage(`{"idx":1,"type":"source-ip-filter","country_list":"Taiwan"}`)},
	}
	for name, items := range tests {
		name, items := name, items
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := DecodeCustomRuleFilterList(items); err == nil {
				t.Fatal("strict decode accepted malformed filter fields")
			}
		})
	}
}

func TestCustomRuleEmptyEndpointErrors(t *testing.T) {
	t.Parallel()

	apiClient, err := New(context.Background(), Config{BaseURL: "https://example.test", APIToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetCustomRule(context.Background(), ""); err == nil {
		t.Fatal("GetCustomRule() accepted an empty ep_id")
	}
	if err := apiClient.PutCustomRule(context.Background(), "", WAFModuleResult{}); err == nil {
		t.Fatal("PutCustomRule() accepted an empty ep_id")
	}
}
