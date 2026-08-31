package customrule

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestValidateFilterCrossFieldsVariants(t *testing.T) {
	t.Parallel()

	contentTypes, diagnostics := types.ListValueFrom(context.Background(), types.StringType, []string{"application/json"})
	if diagnostics.HasError() {
		t.Fatalf("ListValueFrom(content_types) diagnostics = %v", diagnostics)
	}
	countries, diagnostics := types.ListValueFrom(context.Background(), types.StringType, []string{"Taiwan"})
	if diagnostics.HasError() {
		t.Fatalf("ListValueFrom(country_list) diagnostics = %v", diagnostics)
	}
	tests := []struct {
		name   string
		filter filterItemModel
	}{
		{"source ip", filterWith("source-ip-filter", func(f *filterItemModel) { f.IP = types.StringValue("192.0.2.1") })},
		{"user", filterWith("user-filter", func(f *filterItemModel) { f.Username = types.StringValue("alice") })},
		{"url", filterWith("url-filter", func(f *filterItemModel) { f.URL = types.StringValue("/admin") })},
		{"parameter", filterWith("parameter", func(f *filterItemModel) {
			f.Name = types.StringValue("token")
			f.Value = types.StringValue(".+")
		})},
		{"http header", filterWith("http-header-filter", func(f *filterItemModel) {
			f.HeaderCheck = types.BoolValue(true)
			f.HeaderName = types.StringValue("Authorization")
		})},
		{"content type", filterWith("content-type", func(f *filterItemModel) { f.ContentTypes = contentTypes })},
		{"response code", filterWith("response-code", func(f *filterItemModel) { f.ResponseCode = types.Int64Value(403) })},
		{"security rules", filterWith("security-rules", func(f *filterItemModel) { f.SqlInjection = types.BoolValue(true) })},
		{"access limit", filterWith("access-limit-filter", func(f *filterItemModel) { f.Limit = types.Int64Value(100) })},
		{"packet interval", filterWith("packet-interval", func(f *filterItemModel) { f.Timeout = types.Int64Value(5) })},
		{"http transaction", filterWith("http-transaction", func(f *filterItemModel) { f.Timeout = types.Int64Value(10) })},
		{"occurrence", filterWith("occurrence", func(f *filterItemModel) {
			f.Occurrence = types.Int64Value(5)
			f.Within = types.Int64Value(60)
		})},
		{"daily time range", filterWith("time-range-filter", func(f *filterItemModel) {
			f.TimeType = types.StringValue("daily")
			f.Start = types.StringValue("00:00")
			f.End = types.StringValue("23:59")
		})},
		{"once time range", filterWith("time-range-filter", func(f *filterItemModel) {
			f.TimeType = types.StringValue("once")
			f.Start = types.StringValue("08:30 2026/07/23")
			f.End = types.StringValue("17:45 2026/07/23")
		})},
		{"geo", filterWith("geo-filter", func(f *filterItemModel) {
			f.CountryList = countries
			f.MatchExclusively = types.BoolValue(false)
		})},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if err := validateFilterCrossFields(testCase.filter, 1, 1); err != nil {
				t.Fatalf("validateFilterCrossFields() error = %v", err)
			}
		})
	}
}

func TestValidateFilterCrossFieldsRejectsContradictions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		filter    filterItemModel
		wantError string
	}{
		{
			"field from another discriminator",
			filterWith("url-filter", func(f *filterItemModel) {
				f.URL = types.StringValue("/admin")
				f.IP = types.StringValue("192.0.2.1")
			}),
			`field "ip" does not belong`,
		},
		{
			"unsupported geo field",
			filterWith("source-ip-filter", func(f *filterItemModel) {
				f.IP = types.StringValue("192.0.2.1")
				f.MatchExclusively = types.BoolValue(true)
			}),
			`field "match_exclusively" does not belong`,
		},
		{
			"missing required field",
			filterWith("user-filter", nil),
			`requires username`,
		},
		{
			"empty content types",
			filterWith("content-type", func(f *filterItemModel) {
				f.ContentTypes = types.ListValueMust(types.StringType, nil)
			}),
			`requires a non-empty content_types list`,
		},
		{
			"header checks conflict",
			filterWith("http-header-filter", func(f *filterItemModel) {
				f.HeaderCheck = types.BoolValue(true)
				f.HttpHlineMissing = types.BoolValue(true)
				f.HttpHlineEmpty = types.BoolValue(true)
			}),
			`cannot enable both`,
		},
		{
			"daily format",
			filterWith("time-range-filter", func(f *filterItemModel) {
				f.TimeType = types.StringValue("daily")
				f.Start = types.StringValue("8:00")
				f.End = types.StringValue("17:00")
			}),
			`must use format "15:04"`,
		},
		{
			"once calendar validity",
			filterWith("time-range-filter", func(f *filterItemModel) {
				f.TimeType = types.StringValue("once")
				f.Start = types.StringValue("08:00 2026/02/30")
				f.End = types.StringValue("17:00 2026/03/01")
			}),
			`is not a valid time`,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := validateFilterCrossFields(testCase.filter, 2, 3)
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("validateFilterCrossFields() error = %v, want substring %q", err, testCase.wantError)
			}
		})
	}
}

func TestValidateRuleCrossFieldsActionCoupling(t *testing.T) {
	t.Parallel()

	nullFilters := types.ObjectNull(filterListWrapperObjectTypes().AttrTypes)
	tests := []struct {
		name      string
		rule      ruleItemModel
		wantError string
	}{
		{
			"period block with duration",
			ruleItemModel{
				Action:      types.StringValue("block_period"),
				BlockPeriod: types.Int64Value(60),
				Challenge:   types.StringValue("captcha-enforcement"),
				FilterList:  nullFilters,
			},
			"",
		},
		{
			"period block missing duration",
			ruleItemModel{Action: types.StringValue("block_period"), FilterList: nullFilters},
			"requires block_period",
		},
		{
			"duration on another action",
			ruleItemModel{
				Action:      types.StringValue("alert_deny"),
				BlockPeriod: types.Int64Value(60),
				FilterList:  nullFilters,
			},
			`valid only when action is "block_period"`,
		},
		{
			"challenge is action independent",
			ruleItemModel{
				Action:     types.StringValue("alert"),
				Challenge:  types.StringValue("real-browser-enforcement"),
				FilterList: nullFilters,
			},
			"",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := validateRuleCrossFields(context.Background(), testCase.rule, 1)
			if testCase.wantError == "" {
				if err != nil {
					t.Fatalf("validateRuleCrossFields() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("validateRuleCrossFields() error = %v, want substring %q", err, testCase.wantError)
			}
		})
	}
}

func filterWith(filterType string, mutate func(*filterItemModel)) filterItemModel {
	filter := filterItemModel{
		Type:         types.StringValue(filterType),
		ContentTypes: types.ListNull(types.StringType),
		CountryList:  types.ListNull(types.StringType),
	}
	if mutate != nil {
		mutate(&filter)
	}
	return filter
}
