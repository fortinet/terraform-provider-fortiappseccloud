package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContentRoutingGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/routings" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"status":false,"policy_list":[{"idx":1,"name":"old","server_pool":"old_pool","is_default":true,"rule_list":[{"idx":1,"match_object":"http-host","match_condition":"match-sub","value":"old.example","future_rule_key":"keep"}],"future_policy_key":"keep"}],"future_envelope":"keep"}}`)
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

	document, err := apiClient.GetContentRouting(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetContentRouting() error = %v", err)
	}
	if document.Config.Status == nil || *document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if len(document.Config.PolicyList) != 1 {
		t.Fatalf("policy_list = %#v, want 1 raw item", document.Config.PolicyList)
	}

	updated := document.Result.Clone()
	updated.Status = true
	if err := apiClient.PutContentRouting(context.Background(), "app/id", updated); err != nil {
		t.Fatalf("PutContentRouting() error = %v", err)
	}

	if _, ok := putBody["future_envelope"]; !ok {
		t.Fatalf("PUT body lost future_envelope: %s", mustJSON(putBody))
	}
	// Unknown nested keys must survive (unknown=INCLUDE).
	var policy []map[string]json.RawMessage
	if err := json.Unmarshal(putBody["policy_list"], &policy); err != nil {
		t.Fatalf("decode policy_list: %v", err)
	}
	if len(policy) != 1 {
		t.Fatalf("policy_list length = %d, want 1", len(policy))
	}
	if _, ok := policy[0]["future_policy_key"]; !ok {
		t.Fatal("PUT policy_list lost future_policy_key")
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(policy[0]["rule_list"], &rules); err != nil {
		t.Fatalf("decode rule_list: %v", err)
	}
	if _, ok := rules[0]["future_rule_key"]; !ok {
		t.Fatal("PUT rule_list lost future_rule_key")
	}
	var status bool
	if err := json.Unmarshal(putBody["status"], &status); err != nil || !status {
		t.Fatalf("PUT status = %s, error = %v", putBody["status"], err)
	}
}

func TestContentRoutingDecodeMissingStatusRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"result":{"policy_list":[]}}`), &ContentRoutingDocument{}); err == nil {
		t.Fatal("Unmarshal accepted a missing status")
	}
}

func TestContentRoutingDecodeRejectsMalformedKnownFields(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"null status":       `{"result":{"status":null,"policy_list":[]}}`,
		"wrong status type": `{"result":{"status":"true","policy_list":[]}}`,
		"wrong result type": `{"result":[]}`,
		"wrong list type":   `{"result":{"status":true,"policy_list":{}}}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := json.Unmarshal([]byte(body), &ContentRoutingDocument{}); err == nil {
				t.Fatal("Unmarshal accepted a malformed known field")
			}
		})
	}
}

func TestContentRoutingDecodeMissingResultRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"status":false}`), &ContentRoutingDocument{}); err == nil {
		t.Fatal("Unmarshal accepted a missing result object")
	}
}

func TestContentRoutingDecodeAbsentPolicyListIsNil(t *testing.T) {
	t.Parallel()

	var document ContentRoutingDocument
	if err := json.Unmarshal([]byte(`{"result":{"status":true}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.PolicyList != nil {
		t.Fatalf("policy_list = %#v, want nil", document.Config.PolicyList)
	}
}

func TestContentRoutingDecodeNullPolicyListIsNil(t *testing.T) {
	t.Parallel()

	var document ContentRoutingDocument
	if err := json.Unmarshal([]byte(`{"result":{"status":true,"policy_list":null}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.PolicyList != nil {
		t.Fatalf("policy_list = %#v, want nil", document.Config.PolicyList)
	}
}

func TestContentRoutingOwnedPolicyListValidation(t *testing.T) {
	t.Parallel()

	valid := []json.RawMessage{json.RawMessage(`{
		"idx":1,
		"name":"policy",
		"server_pool":"pool",
		"is_default":false,
		"future_policy_key":{"preserve":true},
		"rule_list":[{
			"idx":1,
			"match_object":"http-request",
			"match_condition":"match-end",
			"match_expression":".html",
			"name":"name",
			"value":"value",
			"concatenate":"or",
			"reverse":false,
			"start_ip":"198.51.100.1",
			"end_ip":"198.51.100.2",
			"ip_list":"198.51.100.1",
			"name_match_condition":"equal",
			"value_match_condition":"match-reg",
			"x509_subject_name":"CN=example",
			"future_rule_key":"preserve"
		}]
	}`)}
	if err := ValidateContentRoutingPolicyList(valid); err != nil {
		t.Fatalf("valid unknown-preserving control error = %v", err)
	}

	tests := map[string][]json.RawMessage{
		"null policy":             {json.RawMessage(`null`)},
		"malformed policy":        {json.RawMessage(`[]`)},
		"null policy idx":         {json.RawMessage(`{"idx":null,"name":"p"}`)},
		"non-positive policy idx": {json.RawMessage(`{"idx":0,"name":"p"}`)},
		"duplicate policy idx":    {json.RawMessage(`{"idx":1,"name":"p1"}`), json.RawMessage(`{"idx":1,"name":"p2"}`)},
		"missing policy name":     {json.RawMessage(`{"idx":1}`)},
		"null policy name":        {json.RawMessage(`{"idx":1,"name":null}`)},
		"empty policy name":       {json.RawMessage(`{"idx":1,"name":""}`)},
		"wrong server pool type":  {json.RawMessage(`{"idx":1,"name":"p","server_pool":1}`)},
		"null is default":         {json.RawMessage(`{"idx":1,"name":"p","is_default":null}`)},
		"wrong is default type":   {json.RawMessage(`{"idx":1,"name":"p","is_default":"false"}`)},
		"null rule list":          {json.RawMessage(`{"idx":1,"name":"p","rule_list":null}`)},
		"wrong rule list type":    {json.RawMessage(`{"idx":1,"name":"p","rule_list":{}}`)},
		"null rule":               {json.RawMessage(`{"idx":1,"name":"p","rule_list":[null]}`)},
		"malformed rule":          {json.RawMessage(`{"idx":1,"name":"p","rule_list":[[]]}`)},
		"null rule idx":           {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":null}]}`)},
		"non-positive rule idx":   {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":0}]}`)},
		"duplicate rule idx":      {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1},{"idx":1}]}`)},
		"wrong string type":       {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"match_expression":1}]}`)},
		"null string field":       {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"name":null}]}`)},
		"unsupported object":      {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"match_object":"path"}]}`)},
		"unsupported condition":   {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"match_condition":"contains"}]}`)},
		"unsupported concatenate": {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"concatenate":"xor"}]}`)},
		"unsupported name match":  {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"name_match_condition":"contains"}]}`)},
		"unsupported value match": {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"value_match_condition":"contains"}]}`)},
		"null reverse":            {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"reverse":null}]}`)},
		"wrong reverse type":      {json.RawMessage(`{"idx":1,"name":"p","rule_list":[{"idx":1,"reverse":"false"}]}`)},
	}
	for name, items := range tests {
		name, items := name, items
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateContentRoutingPolicyList(items); err == nil {
				t.Fatal("owned validator accepted malformed known fields")
			}
		})
	}
}

func TestContentRoutingEmptyEndpointErrors(t *testing.T) {
	t.Parallel()

	apiClient, err := New(context.Background(), Config{BaseURL: "https://example.test", APIToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetContentRouting(context.Background(), ""); err == nil {
		t.Fatal("GetContentRouting() accepted an empty ep_id")
	}
	if err := apiClient.PutContentRouting(context.Background(), "", ContentRoutingResult{}); err == nil {
		t.Fatal("PutContentRouting() accepted an empty ep_id")
	}
}
