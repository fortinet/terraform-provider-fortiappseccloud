package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

// MlApiProtectionConfig is the typed known projection of the ML API protection
// config. Required: status, threat_action, ip_list_type. Optional: ip_list,
// path_list (both raw item arrays preserved opaquely when the wrapper is omitted).
type MlApiProtectionConfig struct {
	Status       *bool
	ThreatAction *string
	IPListType   *string
	IPList       []json.RawMessage
	PathList     []json.RawMessage
}

// MlApiProtectionDocument retains the complete raw module envelope (via the
// shared WAFModuleResult template/configs envelope) and typed known config.
type MlApiProtectionDocument struct {
	Result WAFModuleResult
	Config MlApiProtectionConfig
}

func (d *MlApiProtectionDocument) UnmarshalJSON(data []byte) error {
	var module WAFModuleDocument
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	config, err := decodeMlApiProtectionConfig(module.Result.Configs)
	if err != nil {
		return err
	}
	d.Result = module.Result
	d.Config = config
	return nil
}

// MlApiProtection review constants pinned from OpenAPI 26.3.a.
const (
	MlApiProtectionIPListMaxEntries   = 30
	MlApiProtectionPathListMaxEntries = 30
)

var mlApiProtectionKnownIPItemKeys = map[string]struct{}{
	"idx": {}, "ip": {},
}

var mlApiProtectionKnownPathItemKeys = map[string]struct{}{
	"idx": {}, "type": {}, "pattern": {},
}

func decodeMlApiProtectionConfig(configs map[string]json.RawMessage) (MlApiProtectionConfig, error) {
	config := MlApiProtectionConfig{}
	status, err := requireBool(configs, "status", "ml api protection")
	if err != nil {
		return MlApiProtectionConfig{}, err
	}
	config.Status = &status

	threatAction, err := requireString(configs, "threat_action", "ml api protection")
	if err != nil {
		return MlApiProtectionConfig{}, err
	}
	if err := validateReviewedEnum("ml api protection threat_action", threatAction, "alert", "alert_deny", "disable"); err != nil {
		return MlApiProtectionConfig{}, err
	}
	config.ThreatAction = &threatAction

	ipListType, err := requireString(configs, "ip_list_type", "ml api protection")
	if err != nil {
		return MlApiProtectionConfig{}, err
	}
	if err := validateReviewedEnum("ml api protection ip_list_type", ipListType, "Trust", "Block"); err != nil {
		return MlApiProtectionConfig{}, err
	}
	config.IPListType = &ipListType

	if raw, ok := configs["ip_list"]; ok {
		if isJSONNull(raw) {
			return MlApiProtectionConfig{}, fmt.Errorf("decode ml api protection config ip_list: explicit null is not accepted (field is not nullable)")
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return MlApiProtectionConfig{}, fmt.Errorf("decode ml api protection config ip_list: %w", err)
		}
		config.IPList = items
	}
	if raw, ok := configs["path_list"]; ok {
		if isJSONNull(raw) {
			return MlApiProtectionConfig{}, fmt.Errorf("decode ml api protection config path_list: explicit null is not accepted (field is not nullable)")
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return MlApiProtectionConfig{}, fmt.Errorf("decode ml api protection config path_list: %w", err)
		}
		config.PathList = items
	}
	return config, nil
}

// MlApiProtectionIPListEntry is one reviewed ip_list item.
type MlApiProtectionIPListEntry struct {
	IDX int    `json:"idx"`
	IP  string `json:"ip"`
}

// MlApiProtectionPathListEntry is one reviewed path_list item.
type MlApiProtectionPathListEntry struct {
	IDX     int    `json:"idx"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

// DecodeMlApiProtectionIPList applies STRICT decoding to the raw ip_list items.
func DecodeMlApiProtectionIPList(items []json.RawMessage) ([]MlApiProtectionIPListEntry, error) {
	if len(items) > MlApiProtectionIPListMaxEntries {
		return nil, fmt.Errorf("decode ml api protection ip_list: %d items exceeds limit %d", len(items), MlApiProtectionIPListMaxEntries)
	}
	entries := make([]MlApiProtectionIPListEntry, 0, len(items))
	seenIdx := make(map[int]struct{}, len(items))
	for _, item := range items {
		entry, err := decodeMlApiProtectionIPListEntry(item)
		if err != nil {
			return nil, err
		}
		if entry.IDX < 1 {
			return nil, fmt.Errorf("decode ml api protection ip_list: idx %d is not positive", entry.IDX)
		}
		if _, dup := seenIdx[entry.IDX]; dup {
			return nil, fmt.Errorf("decode ml api protection ip_list: duplicate idx %d", entry.IDX)
		}
		seenIdx[entry.IDX] = struct{}{}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].IDX < entries[j].IDX })
	return entries, nil
}

func decodeMlApiProtectionIPListEntry(item json.RawMessage) (MlApiProtectionIPListEntry, error) {
	if isJSONNull(item) {
		return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list: null item")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(item, &object); err != nil {
		return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list item: %w", err)
	}
	for key := range object {
		if _, ok := mlApiProtectionKnownIPItemKeys[key]; !ok {
			return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list item: unknown key %q (fail closed)", key)
		}
	}
	entry := MlApiProtectionIPListEntry{IDX: 1}
	if raw, ok := object["idx"]; ok {
		if isJSONNull(raw) {
			return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list item idx: explicit null is not accepted (field is not nullable)")
		}
		if err := json.Unmarshal(raw, &entry.IDX); err != nil {
			return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list item idx: %w", err)
		}
	}
	ipRaw, hasIP := object["ip"]
	if !hasIP || isJSONNull(ipRaw) {
		return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list item ip: missing or null (ip is a reviewed required non-empty field)")
	}
	if err := json.Unmarshal(ipRaw, &entry.IP); err != nil {
		return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list item ip: %w", err)
	}
	if entry.IP == "" {
		return MlApiProtectionIPListEntry{}, fmt.Errorf("decode ml api protection ip_list item ip: must be non-empty")
	}
	return entry, nil
}

// DecodeMlApiProtectionPathList applies STRICT decoding to the raw path_list items.
func DecodeMlApiProtectionPathList(items []json.RawMessage) ([]MlApiProtectionPathListEntry, error) {
	if len(items) > MlApiProtectionPathListMaxEntries {
		return nil, fmt.Errorf("decode ml api protection path_list: %d items exceeds limit %d", len(items), MlApiProtectionPathListMaxEntries)
	}
	entries := make([]MlApiProtectionPathListEntry, 0, len(items))
	seenIdx := make(map[int]struct{}, len(items))
	for _, item := range items {
		entry, err := decodeMlApiProtectionPathListEntry(item)
		if err != nil {
			return nil, err
		}
		if entry.IDX < 1 {
			return nil, fmt.Errorf("decode ml api protection path_list: idx %d is not positive", entry.IDX)
		}
		if _, dup := seenIdx[entry.IDX]; dup {
			return nil, fmt.Errorf("decode ml api protection path_list: duplicate idx %d", entry.IDX)
		}
		seenIdx[entry.IDX] = struct{}{}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].IDX < entries[j].IDX })
	return entries, nil
}

func decodeMlApiProtectionPathListEntry(item json.RawMessage) (MlApiProtectionPathListEntry, error) {
	if isJSONNull(item) {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list: null item")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(item, &object); err != nil {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item: %w", err)
	}
	for key := range object {
		if _, ok := mlApiProtectionKnownPathItemKeys[key]; !ok {
			return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item: unknown key %q (fail closed)", key)
		}
	}
	entry := MlApiProtectionPathListEntry{IDX: 1}
	if raw, ok := object["idx"]; ok {
		if isJSONNull(raw) {
			return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item idx: explicit null is not accepted (field is not nullable)")
		}
		if err := json.Unmarshal(raw, &entry.IDX); err != nil {
			return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item idx: %w", err)
		}
	}
	typeRaw, hasType := object["type"]
	if !hasType || isJSONNull(typeRaw) {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item type: missing or null (type is required)")
	}
	if err := json.Unmarshal(typeRaw, &entry.Type); err != nil {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item type: %w", err)
	}
	if err := validateReviewedEnum("ml api protection path_list item type", entry.Type, "plain", "regular"); err != nil {
		return MlApiProtectionPathListEntry{}, err
	}
	patternRaw, hasPattern := object["pattern"]
	if !hasPattern || isJSONNull(patternRaw) {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item pattern: missing or null (pattern is required)")
	}
	if err := json.Unmarshal(patternRaw, &entry.Pattern); err != nil {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item pattern: %w", err)
	}
	if entry.Pattern == "" {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item pattern: must be non-empty")
	}
	if len(entry.Pattern) > 0 && entry.Pattern[0] != '/' {
		return MlApiProtectionPathListEntry{}, fmt.Errorf("decode ml api protection path_list item pattern: must start with /")
	}
	return entry, nil
}

// GetMlApiProtection returns the complete ML API protection module document.
func (c *Client) GetMlApiProtection(ctx context.Context, epID string) (MlApiProtectionDocument, error) {
	if epID == "" {
		return MlApiProtectionDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response MlApiProtectionDocument
	err := c.doJSON(ctx, Operation{Name: "get ml api protection", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/ml_api_protection", nil, nil, &response, true)
	return response, err
}

// PutMlApiProtection replaces the complete ML API protection module envelope.
func (c *Client) PutMlApiProtection(ctx context.Context, epID string, result WAFModuleResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put ml api protection", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/ml_api_protection", nil, result, nil, true)
}
