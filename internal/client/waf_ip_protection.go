package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

// IPProtectionConfig is the typed known projection of the ip-protection config.
// Required: status, ip_reputation. Optional: geo_ip_mode, block_country_list,
// ip_list. ip_list is the raw item array (lenient) preserved opaquely when the
// Terraform wrapper is omitted; strict decoding is exported as
// DecodeIPProtectionIPList and applied by the resource only when it owns/imports.
type IPProtectionConfig struct {
	Status           *bool
	IPReputation     *bool
	GeoIPMode        *string
	BlockCountryList []string
	IPList           []json.RawMessage
}

// IPProtectionDocument retains the complete raw module envelope (via the shared
// WAFModuleResult template/configs envelope) and typed known config.
type IPProtectionDocument struct {
	Result WAFModuleResult
	Config IPProtectionConfig
}

func (d *IPProtectionDocument) UnmarshalJSON(data []byte) error {
	var module WAFModuleDocument
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	config, err := decodeIPProtectionConfig(module.Result.Configs)
	if err != nil {
		return err
	}
	d.Result = module.Result
	d.Config = config
	return nil
}

// IPProtection review constants pinned from OpenAPI 26.3.a.
// ip_list maxItems is 256.
// IPRule.ip carries NO maxLength, so no ip length bound is enforced (only
// non-empty, since OpenAPI marks ip required).
const (
	IPProtectionIPListMaxEntries = 256
)

// ipProtectionKnownItemKeys are the only keys an ip_list item may carry. GET
// items include idx; PUT items omit idx (regenerated one-based on write).
var ipProtectionKnownItemKeys = map[string]struct{}{
	"idx":  {},
	"type": {},
	"ip":   {},
}

func decodeIPProtectionConfig(configs map[string]json.RawMessage) (IPProtectionConfig, error) {
	config := IPProtectionConfig{}
	status, err := requireBool(configs, "status", "ip protection")
	if err != nil {
		return IPProtectionConfig{}, err
	}
	config.Status = &status

	ipReputation, err := requireBool(configs, "ip_reputation", "ip protection")
	if err != nil {
		return IPProtectionConfig{}, err
	}
	config.IPReputation = &ipReputation

	config.GeoIPMode, err = optionalStringRejectingNull(configs, "geo_ip_mode", "ip protection")
	if err != nil {
		return IPProtectionConfig{}, err
	}
	if config.GeoIPMode != nil {
		if err := validateReviewedEnum("ip protection config geo_ip_mode", *config.GeoIPMode, "block", "allow"); err != nil {
			return IPProtectionConfig{}, err
		}
	}
	config.BlockCountryList, err = optionalStringArrayRejectingNull(configs, "block_country_list", "ip protection")
	if err != nil {
		return IPProtectionConfig{}, err
	}

	ipList, ok := configs["ip_list"]
	if !ok {
		return config, nil
	}
	if isJSONNull(ipList) {
		return IPProtectionConfig{}, fmt.Errorf("decode ip protection config ip_list: explicit null is not accepted (field is not nullable)")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(ipList, &items); err != nil {
		return IPProtectionConfig{}, fmt.Errorf("decode ip protection config ip_list: %w", err)
	}
	config.IPList = items
	return config, nil
}

// IPProtectionIPListEntry is one active reviewed GET/read ip_list item. The
// wire-only idx is decoded from GET for validation and one-based ordering,
// sorted by idx, and never exposed in Terraform state. Production also returns
// fixed GET-only placeholder slots with explicit idx/type and ip:null for
// inactive rule types. DecodeIPProtectionIPList validates those placeholders
// but filters them from the active entries returned to Terraform.
type IPProtectionIPListEntry struct {
	IDX  int    `json:"idx"`
	Type string `json:"type,omitempty"`
	IP   string `json:"ip"`
}

// IPProtectionIPListPutEntry is the reviewed PUT/write shape of one ip_list
// item. The pinned PutIPProtection schema omits idx (idx is GET-only and
// regenerated one-based on the read side), so the PUT body must carry only
// type and ip. type is the reviewed enum (trust-ip/block-ip/allow-only-ip,
// default trust-ip); ip is required non-empty.
type IPProtectionIPListPutEntry struct {
	Type string `json:"type,omitempty"`
	IP   string `json:"ip"`
}

// EncodeIPProtectionIPListForPut converts the ordered owned GET/read entries
// (already idx-validated and sorted on decode, or freshly built in Terraform
// order) into the reviewed PUT/write shape that omits wire-only idx.
func EncodeIPProtectionIPListForPut(entries []IPProtectionIPListEntry) []IPProtectionIPListPutEntry {
	put := make([]IPProtectionIPListPutEntry, 0, len(entries))
	for _, entry := range entries {
		put = append(put, IPProtectionIPListPutEntry{Type: entry.Type, IP: entry.IP})
	}
	return put
}

// PrepareIPProtectionIPListForPut converts a fresh raw GET array into a safe
// carried-forward PUT array. It removes GET-only idx from active items while
// preserving their other fields opaquely, and drops only the exact production
// placeholder form: an item with known keys, explicit positive idx, explicit
// reviewed type, and ip:null. Missing-ip items, malformed placeholders, null
// items, duplicate or malformed explicit indices, and placeholders with unknown
// fields fail closed instead of being forwarded or silently discarded.
func PrepareIPProtectionIPListForPut(rawItems []json.RawMessage) ([]json.RawMessage, error) {
	if len(rawItems) == 0 {
		return rawItems, nil
	}
	if len(rawItems) > IPProtectionIPListMaxEntries {
		return nil, fmt.Errorf("prepare ip protection ip_list for PUT: %d items exceeds limit %d", len(rawItems), IPProtectionIPListMaxEntries)
	}
	prepared := make([]json.RawMessage, 0, len(rawItems))
	seenIdx := make(map[int]struct{}, len(rawItems))
	for _, item := range rawItems {
		if isJSONNull(item) {
			return nil, fmt.Errorf("prepare ip protection ip_list for PUT: null item")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(item, &object); err != nil {
			return nil, fmt.Errorf("prepare ip protection ip_list item for PUT: %w", err)
		}
		if idxRaw, hasIDX := object["idx"]; hasIDX {
			if isJSONNull(idxRaw) {
				return nil, fmt.Errorf("prepare ip protection ip_list item for PUT: idx is explicit null")
			}
			var idx int
			if err := json.Unmarshal(idxRaw, &idx); err != nil {
				return nil, fmt.Errorf("prepare ip protection ip_list item idx for PUT: %w", err)
			}
			if idx < 1 {
				return nil, fmt.Errorf("prepare ip protection ip_list item for PUT: idx %d is not positive", idx)
			}
			if _, duplicate := seenIdx[idx]; duplicate {
				return nil, fmt.Errorf("prepare ip protection ip_list item for PUT: duplicate idx %d", idx)
			}
			seenIdx[idx] = struct{}{}
		}
		ipRaw, hasIP := object["ip"]
		if !hasIP {
			return nil, fmt.Errorf("prepare ip protection ip_list item for PUT: missing ip")
		}
		if isJSONNull(ipRaw) {
			_, placeholder, err := decodeIPProtectionIPListEntry(item)
			if err != nil {
				return nil, fmt.Errorf("prepare ip protection placeholder for PUT: %w", err)
			}
			if !placeholder {
				return nil, fmt.Errorf("prepare ip protection placeholder for PUT: internal placeholder classification mismatch")
			}
			continue
		}
		delete(object, "idx")
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, fmt.Errorf("encode prepared ip protection ip_list item: %w", err)
		}
		prepared = append(prepared, encoded)
	}
	return prepared, nil
}

// NormalizeIPProtectionResultForPut converts the GET representation of an IP
// protection result into its PUT representation. The 26.3.a contract defines
// distinct IPRuleGet and IPRulePut schemas: GET supplies idx and may include
// reviewed inactive placeholders, while PUT accepts active rules without idx.
// All unrelated envelope and config fields are preserved opaquely.
func NormalizeIPProtectionResultForPut(result WAFModuleResult) (WAFModuleResult, error) {
	normalized := result.Clone()
	raw, ok := normalized.Configs["ip_list"]
	if !ok {
		return normalized, nil
	}
	if isJSONNull(raw) {
		return WAFModuleResult{}, fmt.Errorf("normalize ip protection result for PUT: configs.ip_list is explicit null")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return WAFModuleResult{}, fmt.Errorf("normalize ip protection result for PUT: decode configs.ip_list: %w", err)
	}
	prepared, err := PrepareIPProtectionIPListForPut(items)
	if err != nil {
		return WAFModuleResult{}, fmt.Errorf("normalize ip protection result for PUT: %w", err)
	}
	if err := normalized.SetConfig("ip_list", prepared); err != nil {
		return WAFModuleResult{}, fmt.Errorf("normalize ip protection result for PUT: encode configs.ip_list: %w", err)
	}
	return normalized, nil
}

// DecodeIPProtectionIPList applies STRICT decoding to the raw ip_list items:
// fail-closed unknown item keys, require non-empty strings for active items,
// validate and filter the live-observed explicit-null placeholder form,
// positive-unique idx validation across active and placeholder slots, idx sort,
// and the reviewed 256-item wire bound. The OpenAPI IPRule.ip schema has no
// maxLength, so no active-ip length bound is enforced (only non-empty).
func DecodeIPProtectionIPList(items []json.RawMessage) ([]IPProtectionIPListEntry, error) {
	if len(items) > IPProtectionIPListMaxEntries {
		return nil, fmt.Errorf("decode ip protection ip_list: %d items exceeds limit %d", len(items), IPProtectionIPListMaxEntries)
	}
	entries := make([]IPProtectionIPListEntry, 0, len(items))
	seenIdx := make(map[int]struct{}, len(items))
	for _, item := range items {
		entry, placeholder, err := decodeIPProtectionIPListEntry(item)
		if err != nil {
			return nil, err
		}
		if entry.IDX < 1 {
			return nil, fmt.Errorf("decode ip protection ip_list: idx %d is not positive", entry.IDX)
		}
		if _, dup := seenIdx[entry.IDX]; dup {
			return nil, fmt.Errorf("decode ip protection ip_list: duplicate idx %d", entry.IDX)
		}
		seenIdx[entry.IDX] = struct{}{}
		if placeholder {
			continue
		}
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].IDX < entries[j].IDX })
	return entries, nil
}

func decodeIPProtectionIPListEntry(item json.RawMessage) (IPProtectionIPListEntry, bool, error) {
	if isJSONNull(item) {
		return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list: null item")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(item, &object); err != nil {
		return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item: %w", err)
	}
	for key := range object {
		if _, ok := ipProtectionKnownItemKeys[key]; !ok {
			return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item: unknown key %q (fail closed)", key)
		}
	}
	entry := IPProtectionIPListEntry{IDX: 1, Type: "trust-ip"}
	idxRaw, hasIDX := object["idx"]
	if hasIDX {
		raw := idxRaw
		if isJSONNull(raw) {
			return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item idx: explicit null is not accepted (field is not nullable)")
		}
		if err := json.Unmarshal(raw, &entry.IDX); err != nil {
			return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item idx: %w", err)
		}
	}
	typeRaw, hasType := object["type"]
	if hasType {
		raw := typeRaw
		if isJSONNull(raw) {
			return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item type: explicit null is not accepted (field is not nullable)")
		}
		if err := json.Unmarshal(raw, &entry.Type); err != nil {
			return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item type: %w", err)
		}
	}
	if err := validateReviewedEnum("ip protection ip_list item type", entry.Type, "trust-ip", "block-ip", "allow-only-ip"); err != nil {
		return IPProtectionIPListEntry{}, false, err
	}
	ipRaw, hasIP := object["ip"]
	if !hasIP {
		return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item ip: missing (active ip is required; production placeholders must use explicit null)")
	}
	if isJSONNull(ipRaw) {
		if !hasIDX || !hasType {
			return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item ip: explicit null is accepted only for a production placeholder with explicit idx and type")
		}
		return entry, true, nil
	}
	if err := json.Unmarshal(ipRaw, &entry.IP); err != nil {
		return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item ip: %w", err)
	}
	if entry.IP == "" {
		return IPProtectionIPListEntry{}, false, fmt.Errorf("decode ip protection ip_list item ip: must be non-empty")
	}
	return entry, false, nil
}

// GetIPProtection returns the complete ip-protection module document.
func (c *Client) GetIPProtection(ctx context.Context, epID string) (IPProtectionDocument, error) {
	if epID == "" {
		return IPProtectionDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response IPProtectionDocument
	err := c.doJSON(ctx, Operation{Name: "get ip protection", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/ip_protection", nil, nil, &response, true)
	return response, err
}

// PutIPProtection replaces the complete ip-protection module envelope.
func (c *Client) PutIPProtection(ctx context.Context, epID string, result WAFModuleResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put ip protection", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/ip_protection", nil, result, nil, true)
}
