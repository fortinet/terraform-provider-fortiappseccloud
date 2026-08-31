package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

// AnomalyDetectionConfig is the typed known projection of the anomaly-detection
// config. status/action/ip_list_type are the reviewed required scalars; ip_list
// is the raw item array (lenient) preserved opaquely when the Terraform wrapper
// is omitted. Strict ip_list decoding is exported as
// DecodeAnomalyDetectionIPList and applied by the resource only when it owns
// or imports the collection.
type AnomalyDetectionConfig struct {
	Status     *bool
	Action     *string
	IPListType *string
	IPList     []json.RawMessage
}

// AnomalyDetectionDocument retains the complete raw module envelope (via the
// shared WAFModuleResult template/configs envelope) and typed known config.
type AnomalyDetectionDocument struct {
	Result WAFModuleResult
	Config AnomalyDetectionConfig
}

func (d *AnomalyDetectionDocument) UnmarshalJSON(data []byte) error {
	var module WAFModuleDocument
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	config, err := decodeAnomalyDetectionConfig(module.Result.Configs)
	if err != nil {
		return err
	}
	d.Result = module.Result
	d.Config = config
	return nil
}

// AnomalyDetection review constants pinned from OpenAPI 26.3.a.
// ip_list maxItems is 30. The IpList.ip schema carries no maxLength, so no IP
// length bound is enforced
// here (only non-empty, since OpenAPI marks ip required).
const (
	AnomalyDetectionIPListMaxEntries = 30
)

// anomalyDetectionKnownItemKeys are the only keys an ip_list item may carry.
// Unknown keys fail closed when Terraform owns or imports the collection.
var anomalyDetectionKnownItemKeys = map[string]struct{}{
	"idx": {},
	"ip":  {},
}

func decodeAnomalyDetectionConfig(configs map[string]json.RawMessage) (AnomalyDetectionConfig, error) {
	config := AnomalyDetectionConfig{}
	status, ok := configs["status"]
	if !ok || isJSONNull(status) {
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config: missing status")
	}
	var statusValue bool
	if err := json.Unmarshal(status, &statusValue); err != nil {
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config status: %w", err)
	}
	config.Status = &statusValue

	action, ok := configs["action"]
	if !ok || isJSONNull(action) {
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config: missing action")
	}
	var actionValue string
	if err := json.Unmarshal(action, &actionValue); err != nil {
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config action: %w", err)
	}
	if err := validateReviewedEnum("anomaly detection config action", actionValue, "alert", "alert_deny"); err != nil {
		return AnomalyDetectionConfig{}, err
	}
	config.Action = &actionValue

	ipListType, ok := configs["ip_list_type"]
	if !ok || isJSONNull(ipListType) {
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config: missing ip_list_type")
	}
	var ipListTypeValue string
	if err := json.Unmarshal(ipListType, &ipListTypeValue); err != nil {
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config ip_list_type: %w", err)
	}
	if err := validateReviewedEnum("anomaly detection config ip_list_type", ipListTypeValue, "Trust", "Block"); err != nil {
		return AnomalyDetectionConfig{}, err
	}
	config.IPListType = &ipListTypeValue

	ipList, ok := configs["ip_list"]
	if !ok {
		// ip_list absent: no entries. The resource preserves the raw remote
		// array opaquely when the Terraform wrapper is omitted.
		return config, nil
	}
	if isJSONNull(ipList) {
		// OpenAPI does not declare ip_list nullable; an explicit
		// JSON null is malformed, not an ownership signal.
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config ip_list: explicit null is not accepted (field is not nullable)")
	}
	// Lenient decode: preserve raw items so an omitted wrapper opaquely preserves
	// unknown remote item keys. Strict decoding is applied by
	// DecodeAnomalyDetectionIPList only when the resource owns/imports the list.
	var items []json.RawMessage
	if err := json.Unmarshal(ipList, &items); err != nil {
		return AnomalyDetectionConfig{}, fmt.Errorf("decode anomaly detection config ip_list: %w", err)
	}
	config.IPList = items
	return config, nil
}

// AnomalyDetectionIPListEntry is one reviewed ip_list item. The wire-only idx
// is regenerated one-based in Terraform order on write and never exposed in
// state. ip is a reviewed required non-empty field (OpenAPI marks it required).
type AnomalyDetectionIPListEntry struct {
	IDX int    `json:"idx"`
	IP  string `json:"ip"`
}

// DecodeAnomalyDetectionIPList applies STRICT decoding to the raw ip_list
// items: fail-closed unknown item keys, reject explicit-null item fields (not
// nullable in OpenAPI), require a non-empty ip (OpenAPI marks ip required),
// positive-unique idx validation, idx sort, and the reviewed 30-item bound. The
// OpenAPI carries no IpList.ip maxLength, so no IP length bound is enforced.
// The resource calls this only when it owns or imports the list.
func DecodeAnomalyDetectionIPList(items []json.RawMessage) ([]AnomalyDetectionIPListEntry, error) {
	if len(items) > AnomalyDetectionIPListMaxEntries {
		return nil, fmt.Errorf("decode anomaly detection ip_list: %d items exceeds limit %d", len(items), AnomalyDetectionIPListMaxEntries)
	}
	entries := make([]AnomalyDetectionIPListEntry, 0, len(items))
	seenIdx := make(map[int]struct{}, len(items))
	for _, item := range items {
		entry, err := decodeAnomalyDetectionIPListEntry(item)
		if err != nil {
			return nil, err
		}
		if entry.IDX < 1 {
			return nil, fmt.Errorf("decode anomaly detection ip_list: idx %d is not positive", entry.IDX)
		}
		if _, dup := seenIdx[entry.IDX]; dup {
			return nil, fmt.Errorf("decode anomaly detection ip_list: duplicate idx %d", entry.IDX)
		}
		seenIdx[entry.IDX] = struct{}{}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].IDX < entries[j].IDX })
	return entries, nil
}

func decodeAnomalyDetectionIPListEntry(item json.RawMessage) (AnomalyDetectionIPListEntry, error) {
	if isJSONNull(item) {
		return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list: null item")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(item, &object); err != nil {
		return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list item: %w", err)
	}
	for key := range object {
		if _, ok := anomalyDetectionKnownItemKeys[key]; !ok {
			return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list item: unknown key %q (fail closed)", key)
		}
	}
	entry := AnomalyDetectionIPListEntry{IDX: 1}
	if raw, ok := object["idx"]; ok {
		if isJSONNull(raw) {
			return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list item idx: explicit null is not accepted (field is not nullable)")
		}
		if err := json.Unmarshal(raw, &entry.IDX); err != nil {
			return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list item idx: %w", err)
		}
	}
	ipRaw, hasIP := object["ip"]
	if !hasIP || isJSONNull(ipRaw) {
		return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list item ip: missing or null (ip is a reviewed required non-empty field)")
	}
	if err := json.Unmarshal(ipRaw, &entry.IP); err != nil {
		return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list item ip: %w", err)
	}
	if entry.IP == "" {
		return AnomalyDetectionIPListEntry{}, fmt.Errorf("decode anomaly detection ip_list item ip: must be non-empty")
	}
	return entry, nil
}

// GetAnomalyDetection returns the complete anomaly-detection module document.
func (c *Client) GetAnomalyDetection(ctx context.Context, epID string) (AnomalyDetectionDocument, error) {
	if epID == "" {
		return AnomalyDetectionDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response AnomalyDetectionDocument
	err := c.doJSON(ctx, Operation{Name: "get anomaly detection", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/anomaly_detection", nil, nil, &response, true)
	return response, err
}

// PutAnomalyDetection replaces the complete anomaly-detection module envelope.
func (c *Client) PutAnomalyDetection(ctx context.Context, epID string, result WAFModuleResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put anomaly detection", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/anomaly_detection", nil, result, nil, true)
}
