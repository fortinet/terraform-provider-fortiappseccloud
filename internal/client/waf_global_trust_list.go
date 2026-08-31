package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"unicode/utf8"
)

// GlobalTrustListEntry is one reviewed trust-list item. The wire-only idx is
// regenerated as a one-based Terraform-order index on write and is never
// exposed in Terraform state. Name is a reviewed required Terraform-policy
// field (OpenAPI marks it optional with only maxLength, but an entry
// without a name has no useful identity); URL and Status are presence-aware
// (omitted vs empty) via pointers.
type GlobalTrustListEntry struct {
	IDX    int     `json:"idx"`
	Name   string  `json:"name"`
	Status *bool   `json:"status,omitempty"`
	URL    *string `json:"url,omitempty"`
}

// GlobalTrustListConfig is the typed known projection of the global trust-list
// parameter config. The envelope has configs but NO template, so this module
// does not use the shared WAFModuleResult template/configs envelope.
//
// TrustList holds the raw trust_list items as received from the remote (absent
// → nil; present → raw items). The client decodes trust_list LENIENTLY so an
// omitted Terraform ownership wrapper can preserve unknown remote item keys
// opaquely. The resource applies STRICT decoding (fail-closed unknown keys, idx
// validation, bounds, required name) only when it owns or imports the
// collection, via DecodeGlobalTrustListEntries.
type GlobalTrustListConfig struct {
	Status    *bool
	TrustList []json.RawMessage
}

// GlobalTrustListResult is the complete PUT envelope. Raw fields are retained
// so future API properties survive GET-merge-PUT updates; only the reviewed
// configs fields are typed.
type GlobalTrustListResult struct {
	Configs map[string]json.RawMessage
	raw     map[string]json.RawMessage
}

// GlobalTrustListDocument retains the complete raw module envelope and typed
// known config fields.
type GlobalTrustListDocument struct {
	Result GlobalTrustListResult
	Config GlobalTrustListConfig
}

func (d *GlobalTrustListDocument) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode global trust list response: %w", err)
	}
	if len(envelope.Result) == 0 || isJSONNull(envelope.Result) {
		return fmt.Errorf("decode global trust list response: missing result object")
	}
	if err := json.Unmarshal(envelope.Result, &d.Result); err != nil {
		return fmt.Errorf("decode global trust list result: %w", err)
	}
	config, err := decodeGlobalTrustListConfig(d.Result.Configs)
	if err != nil {
		return err
	}
	d.Config = config
	return nil
}

func (r *GlobalTrustListResult) UnmarshalJSON(data []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("decode global trust list result: %w", err)
	}
	configs, ok := object["configs"]
	if !ok || isJSONNull(configs) {
		return fmt.Errorf("decode global trust list result: missing configs object")
	}
	var configObject map[string]json.RawMessage
	if err := json.Unmarshal(configs, &configObject); err != nil {
		return fmt.Errorf("decode global trust list configs: %w", err)
	}
	// global_trust_list_parameter has NO template field; the envelope is
	// {configs: {...}} only. Do not require or emit template.
	r.Configs = cloneRawMap(configObject)
	r.raw = cloneRawMap(object)
	return nil
}

func (r GlobalTrustListResult) MarshalJSON() ([]byte, error) {
	object := cloneRawMap(r.raw)
	if object == nil {
		object = make(map[string]json.RawMessage)
	}
	configs, err := json.Marshal(r.Configs)
	if err != nil {
		return nil, fmt.Errorf("encode global trust list configs: %w", err)
	}
	object["configs"] = configs
	return json.Marshal(object)
}

// Clone returns a deep copy suitable for a presence-aware merge.
func (r GlobalTrustListResult) Clone() GlobalTrustListResult {
	return GlobalTrustListResult{
		Configs: cloneRawMap(r.Configs),
		raw:     cloneRawMap(r.raw),
	}
}

// SetConfig replaces one known config field without disturbing unknown fields.
func (r *GlobalTrustListResult) SetConfig(name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode global trust list config %q: %w", name, err)
	}
	if r.Configs == nil {
		r.Configs = make(map[string]json.RawMessage)
	}
	r.Configs[name] = encoded
	return nil
}

// GlobalTrustList review constants pinned from OpenAPI 26.3.a.
const (
	GlobalTrustListMaxEntries = 30
	GlobalTrustListNameMaxLen = 63
	GlobalTrustListURLMaxLen  = 255
)

// globalTrustListKnownItemKeys are the only keys a trust_list item may carry.
// Unknown keys fail closed when Terraform owns or imports the collection.
var globalTrustListKnownItemKeys = map[string]struct{}{
	"idx":    {},
	"name":   {},
	"status": {},
	"url":    {},
}

func decodeGlobalTrustListConfig(configs map[string]json.RawMessage) (GlobalTrustListConfig, error) {
	config := GlobalTrustListConfig{}
	status, ok := configs["status"]
	if !ok || isJSONNull(status) {
		return GlobalTrustListConfig{}, fmt.Errorf("decode global trust list config: missing status")
	}
	var statusValue bool
	if err := json.Unmarshal(status, &statusValue); err != nil {
		return GlobalTrustListConfig{}, fmt.Errorf("decode global trust list config status: %w", err)
	}
	config.Status = &statusValue

	trustList, ok := configs["trust_list"]
	if !ok {
		// trust_list absent: no entries. The resource preserves the raw remote
		// array opaquely when the Terraform wrapper is omitted.
		return config, nil
	}
	if isJSONNull(trustList) {
		// OpenAPI does not declare trust_list nullable; an
		// explicit JSON null is malformed, not an ownership signal.
		return GlobalTrustListConfig{}, fmt.Errorf("decode global trust list config trust_list: explicit null is not accepted (field is not nullable)")
	}
	// Lenient decode: preserve the raw items so an omitted Terraform wrapper can
	// opaquely preserve unknown remote item keys. Strict decoding (fail-closed
	// unknown keys, idx validation, bounds, required name) is applied by
	// DecodeGlobalTrustListEntries only when the resource owns/imports the list.
	var items []json.RawMessage
	if err := json.Unmarshal(trustList, &items); err != nil {
		return GlobalTrustListConfig{}, fmt.Errorf("decode global trust list config trust_list: %w", err)
	}
	config.TrustList = items
	return config, nil
}

// DecodeGlobalTrustListEntries applies STRICT decoding to the raw trust_list
// items: fail-closed unknown item keys, reject explicit-null item fields
// (idx/name/status/url are not nullable in OpenAPI), require a non-empty
// name (reviewed required Terraform-policy field), positive-unique idx
// validation, idx sort, and the reviewed 30-item / name(63) / url(255) bounds
// counted in UTF-8 runes (matching the schema's UTF8LengthAtMost). The resource
// calls this only when it owns or imports the collection.
func DecodeGlobalTrustListEntries(items []json.RawMessage) ([]GlobalTrustListEntry, error) {
	if len(items) > GlobalTrustListMaxEntries {
		return nil, fmt.Errorf("decode global trust list trust_list: %d items exceeds limit %d", len(items), GlobalTrustListMaxEntries)
	}
	entries := make([]GlobalTrustListEntry, 0, len(items))
	seenIdx := make(map[int]struct{}, len(items))
	for _, item := range items {
		entry, err := DecodeGlobalTrustListEntry(item)
		if err != nil {
			return nil, err
		}
		if entry.IDX < 1 {
			return nil, fmt.Errorf("decode global trust list trust_list: idx %d is not positive", entry.IDX)
		}
		if _, dup := seenIdx[entry.IDX]; dup {
			return nil, fmt.Errorf("decode global trust list trust_list: duplicate idx %d", entry.IDX)
		}
		seenIdx[entry.IDX] = struct{}{}
		entries = append(entries, entry)
	}
	// Sort by idx so imported/owned reads are canonical.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].IDX < entries[j].IDX })
	return entries, nil
}

// DecodeGlobalTrustListEntry strictly decodes one owned/imported trust_list
// item. Explicit-null item fields are rejected (not nullable in OpenAPI);
// unknown keys fail closed; name is required and non-empty; name/url bounds use
// UTF-8 rune counts.
func DecodeGlobalTrustListEntry(item json.RawMessage) (GlobalTrustListEntry, error) {
	if isJSONNull(item) {
		return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list: null item")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(item, &object); err != nil {
		return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item: %w", err)
	}
	for key := range object {
		if _, ok := globalTrustListKnownItemKeys[key]; !ok {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item: unknown key %q (fail closed)", key)
		}
	}
	entry := GlobalTrustListEntry{IDX: 1}
	if raw, ok := object["idx"]; ok {
		if isJSONNull(raw) {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item idx: explicit null is not accepted (field is not nullable)")
		}
		if err := json.Unmarshal(raw, &entry.IDX); err != nil {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item idx: %w", err)
		}
	}
	nameRaw, hasName := object["name"]
	if !hasName || isJSONNull(nameRaw) {
		return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item name: missing or null (name is a reviewed required non-empty field)")
	}
	if err := json.Unmarshal(nameRaw, &entry.Name); err != nil {
		return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item name: %w", err)
	}
	if entry.Name == "" {
		return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item name: must be non-empty")
	}
	if utf8.RuneCountInString(entry.Name) > GlobalTrustListNameMaxLen {
		return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item name: %d UTF-8 characters exceeds limit %d", utf8.RuneCountInString(entry.Name), GlobalTrustListNameMaxLen)
	}
	if raw, ok := object["status"]; ok {
		if isJSONNull(raw) {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item status: explicit null is not accepted (field is not nullable)")
		}
		var status bool
		if err := json.Unmarshal(raw, &status); err != nil {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item status: %w", err)
		}
		entry.Status = &status
	}
	if raw, ok := object["url"]; ok {
		if isJSONNull(raw) {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item url: explicit null is not accepted (field is not nullable)")
		}
		var url string
		if err := json.Unmarshal(raw, &url); err != nil {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item url: %w", err)
		}
		if utf8.RuneCountInString(url) > GlobalTrustListURLMaxLen {
			return GlobalTrustListEntry{}, fmt.Errorf("decode global trust list trust_list item url: %d UTF-8 characters exceeds limit %d", utf8.RuneCountInString(url), GlobalTrustListURLMaxLen)
		}
		entry.URL = &url
	}
	return entry, nil
}

// GetGlobalTrustList returns the complete global trust-list parameter document.
func (c *Client) GetGlobalTrustList(ctx context.Context, epID string) (GlobalTrustListDocument, error) {
	if epID == "" {
		return GlobalTrustListDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response GlobalTrustListDocument
	err := c.doJSON(ctx, Operation{Name: "get global trust list parameter", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/global_trust_list_parameter", nil, nil, &response, true)
	return response, err
}

// PutGlobalTrustList replaces the complete global trust-list parameter envelope.
func (c *Client) PutGlobalTrustList(ctx context.Context, epID string, result GlobalTrustListResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put global trust list parameter", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/global_trust_list_parameter", nil, result, nil, true)
}
