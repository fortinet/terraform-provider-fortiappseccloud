package client

import (
	"encoding/json"
	"testing"
)

func TestCustomModuleStrictDecodersApplyReviewedItemDefaults(t *testing.T) {
	t.Parallel()

	global, err := DecodeGlobalTrustListEntries([]json.RawMessage{
		json.RawMessage(`{"name":"entry"}`),
	})
	if err != nil {
		t.Fatalf("global trust-list default control error = %v", err)
	}
	if len(global) != 1 || global[0].IDX != 1 || global[0].Status != nil || global[0].URL != nil {
		t.Fatalf("global trust-list defaults = %#v", global)
	}

	anomaly, err := DecodeAnomalyDetectionIPList([]json.RawMessage{
		json.RawMessage(`{"ip":"198.51.100.1"}`),
	})
	if err != nil {
		t.Fatalf("anomaly-detection default control error = %v", err)
	}
	if len(anomaly) != 1 || anomaly[0].IDX != 1 {
		t.Fatalf("anomaly-detection defaults = %#v", anomaly)
	}

	ipProtection, err := DecodeIPProtectionIPList([]json.RawMessage{
		json.RawMessage(`{"ip":"198.51.100.1"}`),
	})
	if err != nil {
		t.Fatalf("IP-protection default control error = %v", err)
	}
	if len(ipProtection) != 1 || ipProtection[0].IDX != 1 || ipProtection[0].Type != "trust-ip" {
		t.Fatalf("IP-protection defaults = %#v", ipProtection)
	}

	mlIPs, err := DecodeMlApiProtectionIPList([]json.RawMessage{
		json.RawMessage(`{"ip":"198.51.100.1"}`),
	})
	if err != nil {
		t.Fatalf("ML API IP-list default control error = %v", err)
	}
	if len(mlIPs) != 1 || mlIPs[0].IDX != 1 {
		t.Fatalf("ML API IP-list defaults = %#v", mlIPs)
	}

	mlPaths, err := DecodeMlApiProtectionPathList([]json.RawMessage{
		json.RawMessage(`{"type":"plain","pattern":"/api"}`),
	})
	if err != nil {
		t.Fatalf("ML API path-list default control error = %v", err)
	}
	if len(mlPaths) != 1 || mlPaths[0].IDX != 1 {
		t.Fatalf("ML API path-list defaults = %#v", mlPaths)
	}

	if _, err := DecodeCustomRuleRuleList([]json.RawMessage{
		json.RawMessage(`{"name":"rule","action":"alert","filter_list":[{"type":"source-ip-filter","ip":"198.51.100.1"}]}`),
	}); err != nil {
		t.Fatalf("custom-rule default-index control error = %v", err)
	}

	if err := ValidateContentRoutingPolicyList([]json.RawMessage{
		json.RawMessage(`{"name":"first","rule_list":[{"match_object":"http-request"}]}`),
		json.RawMessage(`{"name":"second","rule_list":[{"match_object":"http-host"}]}`),
	}); err != nil {
		t.Fatalf("content-routing positional-index control error = %v", err)
	}
}
