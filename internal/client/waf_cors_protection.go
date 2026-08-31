package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// CorsAllowedOrigins is the typed projection of the one owned allowed origin.
// The reviewed schema defines an object, while production GET may return that
// same object inside an array. An empty array means no remote origin is
// configured; a singleton maps to this one Terraform object; multi-item arrays
// fail closed because Terraform intentionally owns at most one origin.
type CorsAllowedOrigins struct {
	Protocol          *string
	OriginName        *string
	Port              *int
	IncludeSubDomains *bool
}

// CorsMethodPolicy is the typed projection of the allowed_methods object.
type CorsMethodPolicy struct {
	Status  *bool
	Methods []string
}

// CorsHeaderPolicy is the typed projection of allowed_headers/exposed_headers.
type CorsHeaderPolicy struct {
	Status  *bool
	Headers []string
}

// CorsProtectionConfig is the typed known projection of the cors-protection
// config. Required: status, block_cors_traffic, allowed_origins,
// allowed_methods, allowed_headers, exposed_headers. Optional: url_pattern,
// allowed_credentials, allowed_maximum_age.
type CorsProtectionConfig struct {
	Status             *bool
	BlockCorsTraffic   *bool
	AllowedOrigins     *CorsAllowedOrigins
	AllowedMethods     *CorsMethodPolicy
	AllowedHeaders     *CorsHeaderPolicy
	ExposedHeaders     *CorsHeaderPolicy
	URLPattern         *string
	AllowedCredentials *string
	AllowedMaximumAge  *int
}

// CorsProtectionDocument retains the complete raw module envelope (via the
// shared WAFModuleResult template/configs envelope) and typed known config.
type CorsProtectionDocument struct {
	Result WAFModuleResult
	Config CorsProtectionConfig
}

func (d *CorsProtectionDocument) UnmarshalJSON(data []byte) error {
	var module WAFModuleDocument
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	config, err := decodeCorsProtectionConfig(module.Result.Configs)
	if err != nil {
		return err
	}
	d.Result = module.Result
	d.Config = config
	return nil
}

// CorsProtection review constants pinned from OpenAPI 26.3.a.
const (
	CorsPortMin              = 0
	CorsPortMax              = 65535
	CorsAllowedMaximumAgeMin = 0
	CorsAllowedMaximumAgeMax = 86400
)

func decodeCorsProtectionConfig(configs map[string]json.RawMessage) (CorsProtectionConfig, error) {
	config := CorsProtectionConfig{}
	status, err := requireBool(configs, "status", "cors protection")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	config.Status = &status

	block, err := requireBool(configs, "block_cors_traffic", "cors protection")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	config.BlockCorsTraffic = &block

	origins, err := decodeCorsAllowedOrigins(configs, "allowed_origins")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	config.AllowedOrigins = origins

	methods, err := decodeCorsMethodPolicy(configs, "allowed_methods")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	config.AllowedMethods = methods

	allowedHeaders, err := decodeCorsHeaderPolicy(configs, "allowed_headers")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	config.AllowedHeaders = allowedHeaders

	exposedHeaders, err := decodeCorsHeaderPolicy(configs, "exposed_headers")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	config.ExposedHeaders = exposedHeaders

	config.URLPattern, err = optionalStringRejectingNull(configs, "url_pattern", "cors protection")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	config.AllowedCredentials, err = optionalStringRejectingNull(configs, "allowed_credentials", "cors protection")
	if err != nil {
		return CorsProtectionConfig{}, err
	}
	if config.AllowedCredentials != nil {
		if err := validateReviewedEnum("cors protection allowed_credentials", *config.AllowedCredentials, "None", "TRUE", "FALSE"); err != nil {
			return CorsProtectionConfig{}, err
		}
	}
	if raw, ok := configs["allowed_maximum_age"]; ok {
		if isJSONNull(raw) {
			return CorsProtectionConfig{}, fmt.Errorf("decode cors protection allowed_maximum_age: explicit null is not accepted (field is not nullable)")
		}
		var age int
		if err := json.Unmarshal(raw, &age); err != nil {
			return CorsProtectionConfig{}, fmt.Errorf("decode cors protection allowed_maximum_age: %w", err)
		}
		if age < CorsAllowedMaximumAgeMin || age > CorsAllowedMaximumAgeMax {
			return CorsProtectionConfig{}, fmt.Errorf("decode cors protection allowed_maximum_age: %d out of range [%d, %d]", age, CorsAllowedMaximumAgeMin, CorsAllowedMaximumAgeMax)
		}
		config.AllowedMaximumAge = &age
	}
	return config, nil
}

func decodeCorsAllowedOrigins(configs map[string]json.RawMessage, name string) (*CorsAllowedOrigins, error) {
	raw, ok := configs[name]
	if !ok || isJSONNull(raw) {
		return nil, fmt.Errorf("decode cors protection: missing %s object", name)
	}
	object, err := decodeCorsAllowedOriginsObject(raw, name)
	if err != nil {
		return nil, err
	}
	if object == nil {
		return nil, nil
	}
	protocol, err := requireString(object, "protocol", "cors protection allowed_origins")
	if err != nil {
		return nil, err
	}
	if err := validateReviewedEnum("cors protection allowed_origins protocol", protocol, "ANY", "HTTP", "HTTPS"); err != nil {
		return nil, err
	}
	originName, err := requireString(object, "origin_name", "cors protection allowed_origins")
	if err != nil {
		return nil, err
	}
	origins := &CorsAllowedOrigins{Protocol: &protocol, OriginName: &originName}
	port, err := optionalIntRejectingNull(object, "port", "cors protection allowed_origins")
	if err != nil {
		return nil, err
	}
	if port != nil {
		if *port < CorsPortMin || *port > CorsPortMax {
			return nil, fmt.Errorf("decode cors protection allowed_origins port: %d out of range [%d, %d]", *port, CorsPortMin, CorsPortMax)
		}
		origins.Port = port
	}
	include, err := optionalBoolRejectingNull(object, "include_sub_domains", "cors protection allowed_origins")
	if err != nil {
		return nil, err
	}
	origins.IncludeSubDomains = include
	return origins, nil
}

func decodeCorsAllowedOriginsObject(raw json.RawMessage, name string) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("decode cors protection %s: empty value", name)
	}
	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("decode cors protection %s singleton array: %w", name, err)
		}
		if len(items) == 0 {
			return nil, nil
		}
		if len(items) > 1 {
			return nil, fmt.Errorf("decode cors protection %s: array has %d items, want at most 1", name, len(items))
		}
		if isJSONNull(items[0]) {
			return nil, fmt.Errorf("decode cors protection %s: singleton array item is null", name)
		}
		raw = items[0]
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("decode cors protection %s: %w", name, err)
	}
	if object == nil {
		return nil, fmt.Errorf("decode cors protection %s: expected object", name)
	}
	return object, nil
}

func decodeCorsMethodPolicy(configs map[string]json.RawMessage, name string) (*CorsMethodPolicy, error) {
	raw, ok := configs[name]
	if !ok || isJSONNull(raw) {
		return nil, fmt.Errorf("decode cors protection: missing %s object", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("decode cors protection %s: %w", name, err)
	}
	status, err := requireBool(object, "status", "cors protection "+name)
	if err != nil {
		return nil, err
	}
	policy := &CorsMethodPolicy{Status: &status}
	policy.Methods, err = optionalStringArrayRejectingNull(object, "methods", "cors protection "+name)
	if err != nil {
		return nil, err
	}
	if err := validateReviewedStringListEnum("cors protection allowed_methods methods", policy.Methods,
		"GET", "POST", "HEAD", "TRACE", "CONNECT", "DELETE", "PUT", "PATCH"); err != nil {
		return nil, err
	}
	return policy, nil
}

func decodeCorsHeaderPolicy(configs map[string]json.RawMessage, name string) (*CorsHeaderPolicy, error) {
	raw, ok := configs[name]
	if !ok || isJSONNull(raw) {
		return nil, fmt.Errorf("decode cors protection: missing %s object", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("decode cors protection %s: %w", name, err)
	}
	status, err := requireBool(object, "status", "cors protection "+name)
	if err != nil {
		return nil, err
	}
	policy := &CorsHeaderPolicy{Status: &status}
	policy.Headers, err = optionalStringArrayRejectingNull(object, "headers", "cors protection "+name)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func requireBool(configs map[string]json.RawMessage, name, label string) (bool, error) {
	raw, ok := configs[name]
	if !ok || isJSONNull(raw) {
		return false, fmt.Errorf("decode %s: missing %s", label, name)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("decode %s %s: %w", label, name, err)
	}
	return value, nil
}

func requireString(configs map[string]json.RawMessage, name, label string) (string, error) {
	raw, ok := configs[name]
	if !ok || isJSONNull(raw) {
		return "", fmt.Errorf("decode %s: missing %s", label, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("decode %s %s: %w", label, name, err)
	}
	return value, nil
}

// optionalStringRejectingNull returns nil only when the key is absent. An
// explicit JSON null is rejected (the field is not nullable in OpenAPI). A
// malformed value is rejected.
func optionalStringRejectingNull(configs map[string]json.RawMessage, name, label string) (*string, error) {
	raw, ok := configs[name]
	if !ok {
		return nil, nil
	}
	if isJSONNull(raw) {
		return nil, fmt.Errorf("decode %s %s: explicit null is not accepted (field is not nullable)", label, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode %s %s: %w", label, name, err)
	}
	return &value, nil
}

// optionalIntRejectingNull returns nil only when the key is absent. An explicit
// JSON null is rejected.
func optionalIntRejectingNull(configs map[string]json.RawMessage, name, label string) (*int, error) {
	raw, ok := configs[name]
	if !ok {
		return nil, nil
	}
	if isJSONNull(raw) {
		return nil, fmt.Errorf("decode %s %s: explicit null is not accepted (field is not nullable)", label, name)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode %s %s: %w", label, name, err)
	}
	return &value, nil
}

// optionalBoolRejectingNull returns nil only when the key is absent. An explicit
// JSON null is rejected.
func optionalBoolRejectingNull(configs map[string]json.RawMessage, name, label string) (*bool, error) {
	raw, ok := configs[name]
	if !ok {
		return nil, nil
	}
	if isJSONNull(raw) {
		return nil, fmt.Errorf("decode %s %s: explicit null is not accepted (field is not nullable)", label, name)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode %s %s: %w", label, name, err)
	}
	return &value, nil
}

// optionalStringArrayRejectingNull returns nil only when the key is absent. An
// explicit JSON null is rejected.
func optionalStringArrayRejectingNull(configs map[string]json.RawMessage, name, label string) ([]string, error) {
	raw, ok := configs[name]
	if !ok {
		return nil, nil
	}
	if isJSONNull(raw) {
		return nil, fmt.Errorf("decode %s %s: explicit null is not accepted (field is not nullable)", label, name)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("decode %s %s: %w", label, name, err)
	}
	return values, nil
}

// GetCorsProtection returns the complete cors-protection module document.
func (c *Client) GetCorsProtection(ctx context.Context, epID string) (CorsProtectionDocument, error) {
	if epID == "" {
		return CorsProtectionDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response CorsProtectionDocument
	err := c.doJSON(ctx, Operation{Name: "get cors protection", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/cors_protection", nil, nil, &response, true)
	return response, err
}

// PutCorsProtection replaces the complete cors-protection module envelope.
func (c *Client) PutCorsProtection(ctx context.Context, epID string, result WAFModuleResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put cors protection", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/cors_protection", nil, result, nil, true)
}
