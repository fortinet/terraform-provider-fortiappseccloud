package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"unicode/utf8"
)

// CustomRuleConfig is the typed known projection of the custom-rule config.
// Required: status. rule_list is the raw item array (lenient) preserved
// opaquely when the Terraform wrapper is omitted.
type CustomRuleConfig struct {
	Status   *bool
	RuleList []json.RawMessage
}

// CustomRuleDocument retains the complete raw module envelope (via the shared
// WAFModuleResult template/configs envelope) and typed known config.
type CustomRuleDocument struct {
	Result WAFModuleResult
	Config CustomRuleConfig
}

func (d *CustomRuleDocument) UnmarshalJSON(data []byte) error {
	var module WAFModuleDocument
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	config, err := decodeCustomRuleConfig(module.Result.Configs)
	if err != nil {
		return err
	}
	d.Result = module.Result
	d.Config = config
	return nil
}

func decodeCustomRuleConfig(configs map[string]json.RawMessage) (CustomRuleConfig, error) {
	config := CustomRuleConfig{}
	status, err := requireBool(configs, "status", "custom rule")
	if err != nil {
		return CustomRuleConfig{}, err
	}
	config.Status = &status

	ruleList, ok := configs["rule_list"]
	if !ok {
		return config, nil
	}
	if isJSONNull(ruleList) {
		return CustomRuleConfig{}, fmt.Errorf("decode custom rule config rule_list: explicit null is not accepted (field is not nullable)")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(ruleList, &items); err != nil {
		return CustomRuleConfig{}, fmt.Errorf("decode custom rule config rule_list: %w", err)
	}
	config.RuleList = items
	return config, nil
}

// CustomRule review constants pinned from OpenAPI 26.3.a.
const (
	CustomRuleRuleListMaxEntries   = 24
	CustomRuleFilterListMaxEntries = 200
	CustomRuleNameMaxLen           = 40
	CustomRuleUsernameMaxLen       = 63
	CustomRuleBlockPeriodMin       = 1
	CustomRuleBlockPeriodMax       = 3600
)

// CustomRuleKnownItemKeys are the only keys a rule_list item may carry.
var CustomRuleKnownItemKeys = map[string]struct{}{
	"idx":          {},
	"name":         {},
	"action":       {},
	"block_period": {},
	"challenge":    {},
	"filter_list":  {},
}

// CustomRuleKnownFilterKeys are the only keys a filter_list item may carry.
var CustomRuleKnownFilterKeys = map[string]struct{}{
	"idx": {}, "type": {}, "reverse_match": {}, "ip": {}, "username": {}, "url": {},
	"name": {}, "value": {}, "header_check": {}, "header_type": {}, "header_name": {},
	"header_value": {}, "header_reverse_match": {}, "method_check": {}, "method_value": {},
	"method_reverse_match": {}, "http_hline_missing_check": {}, "http_hline_empty_check": {},
	"content_types": {}, "code": {}, "cross_site_scripting": {}, "sql_injection": {},
	"generic_attacks": {}, "known_exploits": {}, "trojans": {}, "limit": {}, "timeout": {},
	"occurrence": {}, "within": {}, "time_type": {}, "start": {}, "end": {},
	"country_list": {}, "match_exclusively": {},
}

var customRuleActions = map[string]struct{}{
	"alert": {}, "alert_deny": {}, "block_period": {}, "deny_no_log": {},
}

var customRuleChallenges = map[string]struct{}{
	"real-browser-enforcement": {}, "disabled": {}, "captcha-enforcement": {},
}

var customRuleFilterTypes = map[string]struct{}{
	"source-ip-filter": {}, "user-filter": {}, "url-filter": {}, "parameter": {},
	"http-header-filter": {}, "content-type": {}, "response-code": {},
	"security-rules": {}, "access-limit-filter": {}, "packet-interval": {},
	"http-transaction": {}, "occurrence": {}, "time-range-filter": {}, "geo-filter": {},
}

var customRuleContentTypes = map[string]struct{}{
	"text/plain": {}, "text/html": {}, "text/xml": {}, "application/xml": {},
	"application/soap+xml": {}, "application/json": {},
}

// DecodeCustomRuleRuleList applies STRICT decoding to the raw rule_list items:
// unknown and null fields fail closed, reviewed required fields and scalar
// constraints are enforced, idx values are positive/unique, and the result is
// sorted by idx. Cross-field discriminator/coupling rules are intentionally
// outside this decoder because the reviewed public contract does not define
// them safely.
func DecodeCustomRuleRuleList(items []json.RawMessage) ([]json.RawMessage, error) {
	if len(items) > CustomRuleRuleListMaxEntries {
		return nil, fmt.Errorf("decode custom rule rule_list: %d items exceeds limit %d", len(items), CustomRuleRuleListMaxEntries)
	}
	type indexedRule struct {
		idx int
		raw json.RawMessage
	}
	decoded := make([]indexedRule, 0, len(items))
	seenIdx := make(map[int]struct{}, len(items))
	for _, item := range items {
		if isJSONNull(item) {
			return nil, fmt.Errorf("decode custom rule rule_list: null item")
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err != nil {
			return nil, fmt.Errorf("decode custom rule rule_list item: %w", err)
		}
		for key := range obj {
			if _, ok := CustomRuleKnownItemKeys[key]; !ok {
				return nil, fmt.Errorf("decode custom rule rule_list item: unknown key %q (fail closed)", key)
			}
		}
		idx := 1
		if _, err := decodeCustomRuleNonNullField(obj, "idx", "rule_list item", &idx); err != nil {
			return nil, err
		}
		if idx < 1 {
			return nil, fmt.Errorf("decode custom rule rule_list: idx %d is not positive", idx)
		}
		if _, duplicate := seenIdx[idx]; duplicate {
			return nil, fmt.Errorf("decode custom rule rule_list: duplicate idx %d", idx)
		}
		seenIdx[idx] = struct{}{}

		var name string
		present, err := decodeCustomRuleNonNullField(obj, "name", "rule_list item", &name)
		if err != nil {
			return nil, err
		}
		if !present || name == "" {
			return nil, fmt.Errorf("decode custom rule rule_list item name: missing or empty (field is required)")
		}
		if utf8.RuneCountInString(name) > CustomRuleNameMaxLen {
			return nil, fmt.Errorf("decode custom rule rule_list item name: %d UTF-8 characters exceeds limit %d", utf8.RuneCountInString(name), CustomRuleNameMaxLen)
		}

		var action string
		present, err = decodeCustomRuleNonNullField(obj, "action", "rule_list item", &action)
		if err != nil {
			return nil, err
		}
		if !present {
			return nil, fmt.Errorf("decode custom rule rule_list item action: missing (field is required)")
		}
		if _, ok := customRuleActions[action]; !ok {
			return nil, fmt.Errorf("decode custom rule rule_list item action: unsupported value %q", action)
		}

		var blockPeriod int
		if present, err = decodeCustomRuleNonNullField(obj, "block_period", "rule_list item", &blockPeriod); err != nil {
			return nil, err
		} else if present && (blockPeriod < CustomRuleBlockPeriodMin || blockPeriod > CustomRuleBlockPeriodMax) {
			return nil, fmt.Errorf("decode custom rule rule_list item block_period: %d out of range [%d, %d]", blockPeriod, CustomRuleBlockPeriodMin, CustomRuleBlockPeriodMax)
		}

		var challenge string
		if present, err = decodeCustomRuleNonNullField(obj, "challenge", "rule_list item", &challenge); err != nil {
			return nil, err
		} else if present {
			if _, ok := customRuleChallenges[challenge]; !ok {
				return nil, fmt.Errorf("decode custom rule rule_list item challenge: unsupported value %q", challenge)
			}
		}

		var filters []json.RawMessage
		if present, err = decodeCustomRuleNonNullField(obj, "filter_list", "rule_list item", &filters); err != nil {
			return nil, err
		} else if present {
			if err := DecodeCustomRuleFilterList(filters); err != nil {
				return nil, err
			}
		}
		decoded = append(decoded, indexedRule{idx: idx, raw: item})
	}
	sort.SliceStable(decoded, func(i, j int) bool { return decoded[i].idx < decoded[j].idx })
	result := make([]json.RawMessage, 0, len(decoded))
	for _, rule := range decoded {
		result = append(result, rule.raw)
	}
	return result, nil
}

// DecodeCustomRuleFilterList applies STRICT decoding to raw filter_list items:
// fail-closed unknown/null/malformed fields, required type, positive/unique
// indices, reviewed field enums/ranges, and the 200-item bound. It deliberately
// does not enforce type-dependent field combinations.
func DecodeCustomRuleFilterList(items []json.RawMessage) error {
	if len(items) > CustomRuleFilterListMaxEntries {
		return fmt.Errorf("decode custom rule filter_list: %d items exceeds limit %d", len(items), CustomRuleFilterListMaxEntries)
	}
	seenIdx := make(map[int]struct{}, len(items))
	for _, item := range items {
		if isJSONNull(item) {
			return fmt.Errorf("decode custom rule filter_list: null item")
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err != nil {
			return fmt.Errorf("decode custom rule filter_list item: %w", err)
		}
		for key := range obj {
			if _, ok := CustomRuleKnownFilterKeys[key]; !ok {
				return fmt.Errorf("decode custom rule filter_list item: unknown key %q (fail closed)", key)
			}
		}
		idx := 1
		if _, err := decodeCustomRuleNonNullField(obj, "idx", "filter_list item", &idx); err != nil {
			return err
		}
		if idx < 1 {
			return fmt.Errorf("decode custom rule filter_list: idx %d is not positive", idx)
		}
		if _, duplicate := seenIdx[idx]; duplicate {
			return fmt.Errorf("decode custom rule filter_list: duplicate idx %d", idx)
		}
		seenIdx[idx] = struct{}{}

		var filterType string
		present, err := decodeCustomRuleNonNullField(obj, "type", "filter_list item", &filterType)
		if err != nil {
			return err
		}
		if !present {
			return fmt.Errorf("decode custom rule filter_list item type: missing (field is required)")
		}
		if _, ok := customRuleFilterTypes[filterType]; !ok {
			return fmt.Errorf("decode custom rule filter_list item type: unsupported value %q", filterType)
		}

		for _, name := range []string{
			"reverse_match", "header_check", "header_reverse_match", "method_check",
			"method_reverse_match", "http_hline_missing_check", "http_hline_empty_check",
			"cross_site_scripting", "sql_injection", "generic_attacks", "known_exploits",
			"trojans", "match_exclusively",
		} {
			var value bool
			if _, err := decodeCustomRuleNonNullField(obj, name, "filter_list item", &value); err != nil {
				return err
			}
		}
		for _, name := range []string{
			"ip", "url", "name", "value", "header_name", "header_value",
			"method_value", "start", "end",
		} {
			var value string
			if _, err := decodeCustomRuleNonNullField(obj, name, "filter_list item", &value); err != nil {
				return err
			}
		}

		var username string
		if present, err = decodeCustomRuleNonNullField(obj, "username", "filter_list item", &username); err != nil {
			return err
		} else if present && utf8.RuneCountInString(username) > CustomRuleUsernameMaxLen {
			return fmt.Errorf("decode custom rule filter_list item username: %d UTF-8 characters exceeds limit %d", utf8.RuneCountInString(username), CustomRuleUsernameMaxLen)
		}

		var headerType string
		if present, err = decodeCustomRuleNonNullField(obj, "header_type", "filter_list item", &headerType); err != nil {
			return err
		} else if present && headerType != "predefined" && headerType != "custom" {
			return fmt.Errorf("decode custom rule filter_list item header_type: unsupported value %q", headerType)
		}

		var contentTypes []string
		if present, err = decodeCustomRuleNonNullField(obj, "content_types", "filter_list item", &contentTypes); err != nil {
			return err
		} else if present {
			for _, contentType := range contentTypes {
				if _, ok := customRuleContentTypes[contentType]; !ok {
					return fmt.Errorf("decode custom rule filter_list item content_types: unsupported value %q", contentType)
				}
			}
		}

		var countryList []string
		if _, err := decodeCustomRuleNonNullField(obj, "country_list", "filter_list item", &countryList); err != nil {
			return err
		}

		var responseCode string
		if present, err = decodeCustomRuleNonNullField(obj, "code", "filter_list item", &responseCode); err != nil {
			return err
		} else if present {
			if _, parseErr := strconv.ParseInt(responseCode, 10, 64); parseErr != nil {
				return fmt.Errorf("decode custom rule filter_list item code: %q is not an integer string", responseCode)
			}
		}

		for _, integerField := range []struct {
			name string
			min  int
			max  int
		}{
			{name: "limit", min: 1, max: 65535},
			{name: "timeout"},
			{name: "occurrence", min: 1, max: 100000},
			{name: "within", min: 1, max: 600},
		} {
			var value int
			present, err := decodeCustomRuleNonNullField(obj, integerField.name, "filter_list item", &value)
			if err != nil {
				return err
			}
			if present && integerField.min != 0 && (value < integerField.min || value > integerField.max) {
				return fmt.Errorf("decode custom rule filter_list item %s: %d out of range [%d, %d]", integerField.name, value, integerField.min, integerField.max)
			}
		}

		var timeType string
		if present, err = decodeCustomRuleNonNullField(obj, "time_type", "filter_list item", &timeType); err != nil {
			return err
		} else if present && timeType != "daily" && timeType != "once" {
			return fmt.Errorf("decode custom rule filter_list item time_type: unsupported value %q", timeType)
		}
	}
	return nil
}

func decodeCustomRuleNonNullField(object map[string]json.RawMessage, name, label string, target any) (bool, error) {
	raw, ok := object[name]
	if !ok {
		return false, nil
	}
	if isJSONNull(raw) {
		return true, fmt.Errorf("decode custom rule %s %s: explicit null is not accepted (field is not nullable)", label, name)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return true, fmt.Errorf("decode custom rule %s %s: %w", label, name, err)
	}
	return true, nil
}

// GetCustomRule returns the complete custom-rule module document.
func (c *Client) GetCustomRule(ctx context.Context, epID string) (CustomRuleDocument, error) {
	if epID == "" {
		return CustomRuleDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response CustomRuleDocument
	err := c.doJSON(ctx, Operation{Name: "get custom rule", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/custom_rule", nil, nil, &response, true)
	return response, err
}

// PutCustomRule replaces the complete custom-rule module envelope.
func (c *Client) PutCustomRule(ctx context.Context, epID string, result WAFModuleResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put custom rule", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/custom_rule", nil, result, nil, true)
}
