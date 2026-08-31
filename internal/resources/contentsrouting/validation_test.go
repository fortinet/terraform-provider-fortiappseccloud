package contentsrouting

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestValidateRoutingRuleVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule ruleItemModel
	}{
		{"url parameter", routingRuleWith("url-parameter", func(r *ruleItemModel) {
			r.NameMatchCondition = types.StringValue("equal")
			r.Name = types.StringValue("tenant")
			r.ValueMatchCondition = types.StringValue("match-reg")
			r.Value = types.StringValue(".+")
		})},
		{"http cookie", routingRuleWith("http-cookie", func(r *ruleItemModel) {
			r.NameMatchCondition = types.StringValue("equal")
			r.Name = types.StringValue("session")
			r.ValueMatchCondition = types.StringValue("match-begin")
			r.Value = types.StringValue("prod-")
		})},
		{"http header", routingRuleWith("http-header", func(r *ruleItemModel) {
			r.NameMatchCondition = types.StringValue("equal")
			r.Name = types.StringValue("X-Tenant")
			r.ValueMatchCondition = types.StringValue("equal")
			r.Value = types.StringValue("blue")
		})},
		{"http host", expressionRoutingRule("http-host")},
		{"http request", expressionRoutingRule("http-request")},
		{"http referer", expressionRoutingRule("http-referer")},
		{"https sni", expressionRoutingRule("https-sni")},
		{"source ipv4 range", routingRuleWith("source-ip", func(r *ruleItemModel) {
			r.MatchCondition = types.StringValue("ip-range")
			r.StartIP = types.StringValue("192.0.2.1")
			r.EndIP = types.StringValue("192.0.2.10")
		})},
		{"source ip list", routingRuleWith("source-ip", func(r *ruleItemModel) {
			r.MatchCondition = types.StringValue("ip-list")
			r.IPList = types.StringValue("192.0.2.1,198.51.100.2")
		})},
		{"x509 subject", routingRuleWith("x509-certificate-Subject", func(r *ruleItemModel) {
			r.X509SubjectName = types.StringValue("CN")
			r.ValueMatchCondition = types.StringValue("equal")
			r.MatchExpression = types.StringValue("client.example")
		})},
		{"x509 extension", routingRuleWith("x509-certificate-Extension", func(r *ruleItemModel) {
			r.ValueMatchCondition = types.StringValue("match-reg")
			r.Value = types.StringValue(".+")
		})},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if err := validateRoutingRule(testCase.rule, 1, 1); err != nil {
				t.Fatalf("validateRoutingRule() error = %v", err)
			}
		})
	}
}

func TestValidateRoutingRuleRejectsInvalidVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rule      ruleItemModel
		wantError string
	}{
		{"missing object", ruleItemModel{}, "requires match_object"},
		{
			"missing object field",
			routingRuleWith("http-host", func(r *ruleItemModel) { r.MatchCondition = types.StringValue("equal") }),
			"requires match_expression",
		},
		{
			"contradictory field",
			routingRuleWith("http-host", func(r *ruleItemModel) {
				r.MatchCondition = types.StringValue("equal")
				r.MatchExpression = types.StringValue("example.com")
				r.StartIP = types.StringValue("192.0.2.1")
			}),
			`field "start_ip" does not belong`,
		},
		{
			"host with ip condition",
			routingRuleWith("http-host", func(r *ruleItemModel) {
				r.MatchCondition = types.StringValue("ip-range")
				r.MatchExpression = types.StringValue("example.com")
			}),
			`is not valid for match_object "http-host"`,
		},
		{
			"source range missing end",
			routingRuleWith("source-ip", func(r *ruleItemModel) {
				r.MatchCondition = types.StringValue("ip-range")
				r.StartIP = types.StringValue("192.0.2.1")
			}),
			"requires end_ip",
		},
		{
			"source list with range fields",
			routingRuleWith("source-ip", func(r *ruleItemModel) {
				r.MatchCondition = types.StringValue("ip-list")
				r.IPList = types.StringValue("192.0.2.1")
				r.StartIP = types.StringValue("192.0.2.1")
			}),
			"start_ip/end_ip are valid only",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := validateRoutingRule(testCase.rule, 2, 3)
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("validateRoutingRule() error = %v, want substring %q", err, testCase.wantError)
			}
		})
	}
}

func TestValidateContentRoutingRejectsMultipleDefaults(t *testing.T) {
	t.Parallel()

	nullRules := types.ObjectNull(ruleListWrapperObjectTypes().AttrTypes)
	model := resourceModel{
		Status: types.BoolValue(true),
		PolicyList: testPolicyListWrapper(t,
			testPolicyItem(t, "first", "pool-a", true, nullRules),
			testPolicyItem(t, "second", "pool-b", true, nullRules),
		),
	}
	err := validateCrossFields(context.Background(), model)
	if err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("validateCrossFields() error = %v, want single-default error", err)
	}
}

func routingRuleWith(matchObject string, mutate func(*ruleItemModel)) ruleItemModel {
	rule := ruleItemModel{MatchObject: types.StringValue(matchObject)}
	if mutate != nil {
		mutate(&rule)
	}
	return rule
}

func expressionRoutingRule(matchObject string) ruleItemModel {
	return routingRuleWith(matchObject, func(rule *ruleItemModel) {
		rule.MatchCondition = types.StringValue("match-reg")
		rule.MatchExpression = types.StringValue(".+")
	})
}
