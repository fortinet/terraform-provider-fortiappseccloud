package contract

import (
	"os"
	"reflect"
	"testing"
)

func TestDDoSPreventionScopeClassification(t *testing.T) {
	t.Parallel()

	want := []Classification{
		{Method: "GET", Path: "/waf/apps/{ep_id}/ddos_prevention", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_ddos_prevention", ClientMethod: "GetWAFModule"},
		{Method: "PUT", Path: "/waf/apps/{ep_id}/ddos_prevention", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_ddos_prevention", ClientMethod: "PutWAFModule"},
		{Method: "GET", Path: "/waf/template/{template_id}/ddos_prevention", Disposition: DispositionResourceRead, Owner: "fortiappseccloud_waf_template_ddos_prevention", ClientMethod: "GetWAFTemplateModule"},
		{Method: "PUT", Path: "/waf/template/{template_id}/ddos_prevention", Disposition: DispositionResourceWrite, Owner: "fortiappseccloud_waf_template_ddos_prevention", ClientMethod: "PutWAFTemplateModule"},
	}
	if !reflect.DeepEqual(DDoSPreventionScope, want) {
		t.Fatalf("DDoSPreventionScope = %#v, want %#v", DDoSPreventionScope, want)
	}

	data, err := os.ReadFile("../../openapi_spec/openapi.json")
	if err != nil {
		t.Fatalf("read OpenAPI baseline: %v", err)
	}
	document, err := ParseOpenAPI(data)
	if err != nil {
		t.Fatalf("ParseOpenAPI() error = %v", err)
	}
	for _, classification := range DDoSPreventionScope {
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

func TestDDoSPreventionResourceContract(t *testing.T) {
	t.Parallel()

	if DDoSPreventionResource.TerraformName != "fortiappseccloud_waf_ddos_prevention" {
		t.Fatalf("TerraformName = %q", DDoSPreventionResource.TerraformName)
	}
	if DDoSPreventionResource.GoName != "DDoSPrevention" || DDoSPreventionResource.TypeNameSuffix != "waf_ddos_prevention" {
		t.Fatalf("resource identity = %#v", DDoSPreventionResource)
	}
	if !reflect.DeepEqual(DDoSPreventionResource.ExpectedMethods, []string{"GET", "PUT"}) {
		t.Fatalf("ExpectedMethods = %#v", DDoSPreventionResource.ExpectedMethods)
	}
	if DDoSPreventionResource.Refs.CollectionItem != "" {
		t.Fatalf("Refs = %#v, want no shared collection item", DDoSPreventionResource.Refs)
	}
	// Twelve config scalars: eleven required plus the optional block_period.
	if len(DDoSPreventionResource.Schema.ConfigFields) != 12 {
		t.Fatalf("ConfigFields = %d, want 12", len(DDoSPreventionResource.Schema.ConfigFields))
	}
	// No object-item collections.
	if len(DDoSPreventionResource.Schema.Collections) != 0 {
		t.Fatalf("Collections = %d, want 0", len(DDoSPreventionResource.Schema.Collections))
	}
	// action enum of four values, required, default block_period.
	action := DDoSPreventionResource.findConfig("action")
	if action == nil || !action.Required || !action.HasDefault || action.Default != "block_period" || len(action.Enum) != 4 {
		t.Fatalf("action = %#v, want required 4-value enum default block_period", action)
	}
	// challenge enum of three values, required, default real-browser-enforcement.
	challenge := DDoSPreventionResource.findConfig("challenge")
	if challenge == nil || !challenge.Required || !challenge.HasDefault || challenge.Default != "real-browser-enforcement" || len(challenge.Enum) != 3 {
		t.Fatalf("challenge = %#v, want required 3-value enum default real-browser-enforcement", challenge)
	}
	// block_period is the only optional config scalar: default 600, range 1-3600.
	blockPeriod := DDoSPreventionResource.findConfig("block_period")
	if blockPeriod == nil {
		t.Fatal("missing block_period config field")
	}
	if blockPeriod.Required {
		t.Fatalf("block_period required = true, want false (optional)")
	}
	if !blockPeriod.HasDefault || blockPeriod.Default != 600 {
		t.Fatalf("block_period default = %#v, want 600", blockPeriod.Default)
	}
	if blockPeriod.Minimum == nil || *blockPeriod.Minimum != 1 || blockPeriod.Maximum == nil || *blockPeriod.Maximum != 3600 {
		t.Fatalf("block_period range = %#v, want 1..3600", blockPeriod)
	}
	// http_request_limit bounded integer default 1000 range 1..65535.
	httpRequestLimit := DDoSPreventionResource.findConfig("http_request_limit")
	if httpRequestLimit == nil || !httpRequestLimit.Required || !httpRequestLimit.HasDefault || httpRequestLimit.Default != 1000 ||
		httpRequestLimit.Minimum == nil || *httpRequestLimit.Minimum != 1 || httpRequestLimit.Maximum == nil || *httpRequestLimit.Maximum != 65535 {
		t.Fatalf("http_request_limit = %#v, want required default 1000 range 1..65535", httpRequestLimit)
	}
	// tcp_conn_num_limit bounded integer default 10 range 10..65535 (min == default).
	tcpConnNumLimit := DDoSPreventionResource.findConfig("tcp_conn_num_limit")
	if tcpConnNumLimit == nil || tcpConnNumLimit.Default != 10 ||
		tcpConnNumLimit.Minimum == nil || *tcpConnNumLimit.Minimum != 10 || tcpConnNumLimit.Maximum == nil || *tcpConnNumLimit.Maximum != 65535 {
		t.Fatalf("tcp_conn_num_limit = %#v, want default 10 range 10..65535", tcpConnNumLimit)
	}
	// One scalar-string-array: ip_exception, free-form (no enum), unbounded, optional.
	if len(DDoSPreventionResource.Schema.ScalarStringArrays) != 1 {
		t.Fatalf("ScalarStringArrays = %d, want 1", len(DDoSPreventionResource.Schema.ScalarStringArrays))
	}
	ipException := DDoSPreventionResource.Schema.ScalarStringArrays[0]
	if ipException.Name != "ip_exception" || ipException.ItemAttribute != "ip" || len(ipException.Enum) != 0 || ipException.MaxItems != 0 || ipException.Required {
		t.Fatalf("ip_exception = %#v, want free-form unbounded optional", ipException)
	}
}

func (r ReviewedCandidate) findConfig(name string) *CandidateFieldConstraint {
	for i := range r.Schema.ConfigFields {
		if r.Schema.ConfigFields[i].Name == name {
			return &r.Schema.ConfigFields[i]
		}
	}
	return nil
}
