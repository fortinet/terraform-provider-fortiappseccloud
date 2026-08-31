package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	// ContentRoutingMaxPolicies and ContentRoutingMaxRules are the reviewed
	// limits in the FortiAppSec Cloud Content Routing guide.
	ContentRoutingMaxPolicies = 32
	ContentRoutingMaxRules    = 32
)

// ContentRoutingConfig is the typed known projection of the content-routing
// config. The envelope is flat {status, policy_list} (no template/configs).
// policy_list is decoded as raw items (lenient) preserving unknown keys per
// the resource's reviewed opaque-preservation ownership policy.
type ContentRoutingConfig struct {
	Status     *bool
	PolicyList []json.RawMessage
}

// ContentRoutingDocument retains the complete raw envelope and typed known
// config fields. The envelope has no template/configs wrapper.
type ContentRoutingDocument struct {
	Result ContentRoutingResult
	Config ContentRoutingConfig
}

// ContentRoutingResult is the complete PUT envelope. Raw fields are retained so
// future API properties survive GET-merge-PUT updates.
type ContentRoutingResult struct {
	Status     bool
	PolicyList []json.RawMessage
	raw        map[string]json.RawMessage
}

func (d *ContentRoutingDocument) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode content routing response: %w", err)
	}
	if len(envelope.Result) == 0 || isJSONNull(envelope.Result) {
		return fmt.Errorf("decode content routing response: missing result object")
	}
	if err := json.Unmarshal(envelope.Result, &d.Result); err != nil {
		return fmt.Errorf("decode content routing result: %w", err)
	}
	config, err := decodeContentRoutingConfig(d.Result.raw)
	if err != nil {
		return err
	}
	d.Config = config
	return nil
}

func (r *ContentRoutingResult) UnmarshalJSON(data []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("decode content routing result: %w", err)
	}
	statusRaw, ok := object["status"]
	if !ok || isJSONNull(statusRaw) {
		return fmt.Errorf("decode content routing result: missing status")
	}
	if err := json.Unmarshal(statusRaw, &r.Status); err != nil {
		return fmt.Errorf("decode content routing result status: %w", err)
	}
	// policy_list is present in the GET example even though the OpenAPI schema
	// (GetContentRoutingResult) omits it; trust the example.
	if policyListRaw, ok := object["policy_list"]; ok && !isJSONNull(policyListRaw) {
		if err := json.Unmarshal(policyListRaw, &r.PolicyList); err != nil {
			return fmt.Errorf("decode content routing result policy_list: %w", err)
		}
	}
	r.raw = cloneRawMap(object)
	return nil
}

func (r ContentRoutingResult) MarshalJSON() ([]byte, error) {
	object := cloneRawMap(r.raw)
	if object == nil {
		object = make(map[string]json.RawMessage)
	}
	status, err := json.Marshal(r.Status)
	if err != nil {
		return nil, fmt.Errorf("encode content routing status: %w", err)
	}
	object["status"] = status
	if r.PolicyList != nil {
		policyList, err := json.Marshal(r.PolicyList)
		if err != nil {
			return nil, fmt.Errorf("encode content routing policy_list: %w", err)
		}
		object["policy_list"] = policyList
	}
	return json.Marshal(object)
}

// Clone returns a deep copy suitable for a presence-aware merge.
func (r ContentRoutingResult) Clone() ContentRoutingResult {
	clone := ContentRoutingResult{
		Status: r.Status,
		raw:    cloneRawMap(r.raw),
	}
	if r.PolicyList != nil {
		// Deep copy, preserving nil-vs-empty distinction. append(nil, ...)
		// with zero elements returns nil, so allocate explicitly.
		clone.PolicyList = make([]json.RawMessage, len(r.PolicyList))
		copy(clone.PolicyList, r.PolicyList)
	}
	return clone
}

func decodeContentRoutingConfig(raw map[string]json.RawMessage) (ContentRoutingConfig, error) {
	config := ContentRoutingConfig{}
	statusRaw, ok := raw["status"]
	if !ok || isJSONNull(statusRaw) {
		return ContentRoutingConfig{}, fmt.Errorf("decode content routing config: missing status")
	}
	var status bool
	if err := json.Unmarshal(statusRaw, &status); err != nil {
		return ContentRoutingConfig{}, fmt.Errorf("decode content routing config status: %w", err)
	}
	config.Status = &status
	if policyListRaw, ok := raw["policy_list"]; ok && !isJSONNull(policyListRaw) {
		var items []json.RawMessage
		if err := json.Unmarshal(policyListRaw, &items); err != nil {
			return ContentRoutingConfig{}, fmt.Errorf("decode content routing config policy_list: %w", err)
		}
		config.PolicyList = items
	}
	return config, nil
}

// ValidateContentRoutingPolicyList applies strict validation to the known
// fields of an owned/imported policy_list while allowing unknown nested keys,
// matching the reviewed opaque-preservation contract. It validates JSON
// types, non-nullability, reviewed enums, required policy names, and
// positive/unique indices. Resource configuration applies the reviewed
// cross-field rule-variant and single-default-policy relationships separately;
// this response decoder intentionally accepts legacy remote combinations.
func ValidateContentRoutingPolicyList(items []json.RawMessage) error {
	seenPolicyIdx := make(map[int]struct{}, len(items))
	for position, item := range items {
		if isJSONNull(item) {
			return fmt.Errorf("decode content routing policy_list: null item")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(item, &object); err != nil {
			return fmt.Errorf("decode content routing policy_list item: %w", err)
		}

		idx := position + 1
		if _, err := decodeContentRoutingNonNullField(object, "idx", "policy_list item", &idx); err != nil {
			return err
		}
		if idx < 1 {
			return fmt.Errorf("decode content routing policy_list: idx %d is not positive", idx)
		}
		if _, duplicate := seenPolicyIdx[idx]; duplicate {
			return fmt.Errorf("decode content routing policy_list: duplicate idx %d", idx)
		}
		seenPolicyIdx[idx] = struct{}{}

		var name string
		present, err := decodeContentRoutingNonNullField(object, "name", "policy_list item", &name)
		if err != nil {
			return err
		}
		if !present || name == "" {
			return fmt.Errorf("decode content routing policy_list item name: missing or empty (reviewed Terraform ownership field)")
		}

		var serverPool string
		if _, err := decodeContentRoutingNonNullField(object, "server_pool", "policy_list item", &serverPool); err != nil {
			return err
		}
		var isDefault bool
		if _, err := decodeContentRoutingNonNullField(object, "is_default", "policy_list item", &isDefault); err != nil {
			return err
		}
		var rules []json.RawMessage
		if present, err = decodeContentRoutingNonNullField(object, "rule_list", "policy_list item", &rules); err != nil {
			return err
		} else if present {
			if err := validateContentRoutingRuleList(rules); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateContentRoutingRuleList(items []json.RawMessage) error {
	seenRuleIdx := make(map[int]struct{}, len(items))
	for position, item := range items {
		if isJSONNull(item) {
			return fmt.Errorf("decode content routing rule_list: null item")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(item, &object); err != nil {
			return fmt.Errorf("decode content routing rule_list item: %w", err)
		}

		idx := position + 1
		if _, err := decodeContentRoutingNonNullField(object, "idx", "rule_list item", &idx); err != nil {
			return err
		}
		if idx < 1 {
			return fmt.Errorf("decode content routing rule_list: idx %d is not positive", idx)
		}
		if _, duplicate := seenRuleIdx[idx]; duplicate {
			return fmt.Errorf("decode content routing rule_list: duplicate idx %d", idx)
		}
		seenRuleIdx[idx] = struct{}{}

		for _, name := range []string{
			"match_expression", "name", "value", "start_ip", "end_ip",
			"ip_list", "x509_subject_name",
		} {
			var value string
			if _, err := decodeContentRoutingNonNullField(object, name, "rule_list item", &value); err != nil {
				return err
			}
		}

		for _, enumField := range []struct {
			name    string
			allowed []string
		}{
			{
				name: "match_object",
				allowed: []string{
					"http-cookie", "http-header", "http-host", "http-referer",
					"http-request", "https-sni", "source-ip", "url-parameter",
					"x509-certificate-Subject", "x509-certificate-Extension",
				},
			},
			{
				name: "match_condition",
				allowed: []string{
					"match-begin", "match-end", "match-sub", "match-domain",
					"match-dir", "match-reg", "ip-range", "ip-range6", "equal", "ip-list",
				},
			},
			{name: "concatenate", allowed: []string{"and", "or"}},
			{
				name:    "name_match_condition",
				allowed: []string{"match-begin", "match-end", "match-sub", "equal", "match-reg"},
			},
			{
				name:    "value_match_condition",
				allowed: []string{"match-begin", "match-end", "match-sub", "equal", "match-reg"},
			},
		} {
			var value string
			present, err := decodeContentRoutingNonNullField(object, enumField.name, "rule_list item", &value)
			if err != nil {
				return err
			}
			if present {
				if err := validateReviewedEnum("content routing rule_list item "+enumField.name, value, enumField.allowed...); err != nil {
					return err
				}
			}
		}

		var reverse bool
		if _, err := decodeContentRoutingNonNullField(object, "reverse", "rule_list item", &reverse); err != nil {
			return err
		}
	}
	return nil
}

func decodeContentRoutingNonNullField(object map[string]json.RawMessage, name, label string, target any) (bool, error) {
	raw, ok := object[name]
	if !ok {
		return false, nil
	}
	if isJSONNull(raw) {
		return true, fmt.Errorf("decode content routing %s %s: explicit null is not accepted (field is not nullable)", label, name)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return true, fmt.Errorf("decode content routing %s %s: %w", label, name, err)
	}
	return true, nil
}

// GetContentRouting returns the complete content-routing document.
func (c *Client) GetContentRouting(ctx context.Context, epID string) (ContentRoutingDocument, error) {
	if epID == "" {
		return ContentRoutingDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response ContentRoutingDocument
	err := c.doJSON(ctx, Operation{Name: "get content routing", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/routings", nil, nil, &response, true)
	return response, err
}

// PutContentRouting replaces the complete content-routing envelope.
func (c *Client) PutContentRouting(ctx context.Context, epID string, result ContentRoutingResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put content routing", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/routings", nil, result, nil, true)
}
