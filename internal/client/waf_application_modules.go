package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ApplicationModuleStatus is one entry returned by the app-scoped bulk module
// status endpoint. Inherited is nil only when the optional wire field is absent.
type ApplicationModuleStatus struct {
	ID        string
	Status    string
	Inherited *string
}

// ApplicationModuleStatuses is the complete typed response from
// GET /waf/apps/{ep_id}/modules.
type ApplicationModuleStatuses []ApplicationModuleStatus

var applicationModuleIDs = stringSet(
	"known_attacks",
	"anomaly_detection",
	"information_leakage",
	"cookie_security",
	"file_protection",
	"parameter_validation",
	"http_header_security",
	"csrf_protection",
	"mitb_protection",
	"request_limits",
	"url_access",
	"ip_protection",
	"known_bots",
	"threshold_detection",
	"ml_bot_detection",
	"biometrics_based_detection",
	"bot_deception",
	"ddos_prevention",
	"custom_rule",
	"web_socket_security",
	"api_protection",
	"api_gateway",
	"mobile_api_protection",
	"json_protection",
	"xml_protection_policy",
	"ml_api_protection",
	"graphql_protection",
	"account_takeover",
	"rewriting_requests",
	"caching_compression",
	"global_trust_list_parameter",
	"content_routing",
	"cors_protection",
	"waiting_room",
	"advanced_bot_protection",
)

var applicationModuleStatusKeys = stringSet("id", "status", "inherited")

func (statuses *ApplicationModuleStatuses) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("decode application modules: response must be an array, not null")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("decode application modules: %w", err)
	}

	decoded := make(ApplicationModuleStatuses, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		status, err := decodeApplicationModuleStatus(item)
		if err != nil {
			return fmt.Errorf("decode application modules item %d: %w", index, err)
		}
		if _, duplicate := seen[status.ID]; duplicate {
			return fmt.Errorf("decode application modules item %d: duplicate module id %q", index, status.ID)
		}
		seen[status.ID] = struct{}{}
		decoded = append(decoded, status)
	}
	sort.Slice(decoded, func(i, j int) bool { return decoded[i].ID < decoded[j].ID })
	*statuses = decoded
	return nil
}

func decodeApplicationModuleStatus(data json.RawMessage) (ApplicationModuleStatus, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return ApplicationModuleStatus{}, fmt.Errorf("item must be an object, not null")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return ApplicationModuleStatus{}, fmt.Errorf("item must be an object: %w", err)
	}
	for key := range object {
		if _, known := applicationModuleStatusKeys[key]; !known {
			return ApplicationModuleStatus{}, fmt.Errorf("unknown field %q (fail closed)", key)
		}
	}

	id, err := requiredApplicationModuleString(object, "id")
	if err != nil {
		return ApplicationModuleStatus{}, err
	}
	if _, known := applicationModuleIDs[id]; !known {
		return ApplicationModuleStatus{}, fmt.Errorf("unsupported module id %q", id)
	}
	status, err := requiredApplicationModuleString(object, "status")
	if err != nil {
		return ApplicationModuleStatus{}, err
	}
	if err := validateReviewedEnum("application module status", status, "enable", "disable"); err != nil {
		return ApplicationModuleStatus{}, err
	}

	decoded := ApplicationModuleStatus{ID: id, Status: status}
	if raw, present := object["inherited"]; present {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ApplicationModuleStatus{}, fmt.Errorf("field %q must not be null", "inherited")
		}
		var inherited string
		if err := json.Unmarshal(raw, &inherited); err != nil {
			return ApplicationModuleStatus{}, fmt.Errorf("field %q: %w", "inherited", err)
		}
		if err := validateReviewedEnum("application module inherited", inherited, "enable", "disable"); err != nil {
			return ApplicationModuleStatus{}, err
		}
		decoded.Inherited = &inherited
	}
	return decoded, nil
}

func requiredApplicationModuleString(object map[string]json.RawMessage, field string) (string, error) {
	raw, present := object[field]
	if !present {
		return "", fmt.Errorf("missing required field %q", field)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("field %q must not be null", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("field %q: %w", field, err)
	}
	if value == "" {
		return "", fmt.Errorf("field %q must not be empty", field)
	}
	return value, nil
}

// GetApplicationModules returns the complete, canonicalized module status
// inventory for an application.
func (c *Client) GetApplicationModules(ctx context.Context, epID string) (ApplicationModuleStatuses, error) {
	epID = strings.TrimSpace(epID)
	if epID == "" {
		return nil, fmt.Errorf("application ID must not be empty")
	}
	var response ApplicationModuleStatuses
	err := c.doJSON(
		ctx,
		Operation{Name: "get application modules", Retry: RetrySafe},
		http.MethodGet,
		"waf/apps/"+url.PathEscape(epID)+"/modules",
		nil,
		nil,
		&response,
		true,
	)
	return response, err
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
