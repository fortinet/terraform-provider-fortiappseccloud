package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const redactedValue = "[REDACTED]"

var diagnosticSensitiveValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s,;]+`),
	regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`),
	regexp.MustCompile(`(?i)\b(?:[A-Z0-9-]+\.)+(?:app|cloud|co|com|dev|edu|gov|internal|io|local|net|org)\b(?::\d+)?`),
	regexp.MustCompile(`\b[A-Fa-f0-9]{24,}\b`),
	regexp.MustCompile(`\b[A-Za-z0-9_-]{32,}\b`),
	regexp.MustCompile(`(^|[\s(])/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]+`),
}

var diagnosticSensitiveLabels = []string{
	"authorization",
	"password",
	"passwd",
	"access token",
	"access-token",
	"access_token",
	"refresh token",
	"refresh-token",
	"refresh_token",
	"api token",
	"api-token",
	"api_token",
	"bearer token",
	"bearer-token",
	"private key",
	"private-key",
	"private_key",
	"client key",
	"client-key",
	"client_key",
	"account key",
	"account-key",
	"account_key",
	"api key",
	"api-key",
	"api_key",
	"secret",
	"token",
}

// APIError describes a non-successful API response without exposing secret-bearing bodies.
type APIError struct {
	Operation     string
	Method        string
	URL           string
	StatusCode    int
	Body          string
	RetryAfter    time.Duration
	retryAfterSet bool
}

func (e *APIError) Error() string {
	message := fmt.Sprintf("%s: %s %s returned HTTP %d", e.Operation, e.Method, e.URL, e.StatusCode)
	if e.Body != "" {
		message += ": " + e.Body
	}
	return message
}

// StatusCode extracts an HTTP status code from a wrapped API error.
func StatusCode(err error) (int, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return 0, false
	}
	return apiErr.StatusCode, true
}

// IsStatus reports whether an error is an API response with one of the given statuses.
func IsStatus(err error, statuses ...int) bool {
	statusCode, ok := StatusCode(err)
	if !ok {
		return false
	}
	for _, status := range statuses {
		if statusCode == status {
			return true
		}
	}
	return false
}

// IsNotFound reports whether an error is an API 404 response. Resource code must
// still decide whether 404 means drift for that specific endpoint.
func IsNotFound(err error) bool {
	return IsStatus(err, 404)
}

func redactURL(value *url.URL) string {
	redacted := *value
	redacted.User = nil
	segments := strings.Split(redacted.Path, "/")
	for index, segment := range segments {
		if segment == "apps" && index+1 < len(segments) && segments[index+1] != "" {
			segments[index+1] = redactedValue
		}
		if segment == "template" && index+1 < len(segments) && segments[index+1] != "" && segments[index+1] != "clone" {
			segments[index+1] = redactedValue
		}
	}
	redacted.Path = strings.Join(segments, "/")
	redacted.RawPath = ""
	query := redacted.Query()
	for key := range query {
		if isSensitiveKey(key) {
			query.Set(key, redactedValue)
		}
	}
	redacted.RawQuery = query.Encode()
	return redacted.String()
}

func redactBody(data []byte) string {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return ""
	}

	var value any
	if json.Unmarshal(data, &value) == nil {
		redactJSONValue(value)
		redacted, err := json.Marshal(value)
		if err == nil {
			return truncate(string(redacted), 2048)
		}
	}

	return "non-JSON response body redacted"
}

func redactJSONValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isDiagnosticKey(key) {
				typed[key] = redactDiagnosticValue(child)
				continue
			}
			if isSensitiveKey(key) {
				typed[key] = redactedValue
				continue
			}
			redactJSONValue(child)
		}
	case []any:
		for _, child := range typed {
			redactJSONValue(child)
		}
	}
}

// redactDiagnosticValue keeps validation reasons useful without treating a
// free-form API diagnostic as trusted output. Values commonly used to echo
// request data are fully redacted, while diagnostic strings are scrubbed of
// value-bearing suffixes, credentials, and obvious endpoint identifiers.
func redactDiagnosticValue(value any) any {
	switch typed := value.(type) {
	case string:
		return redactDiagnosticText(typed)
	case map[string]any:
		for key, child := range typed {
			if isDiagnosticKey(key) {
				typed[key] = redactDiagnosticValue(child)
				continue
			}
			if isDiagnosticInputKey(key) || isSensitiveKey(key) {
				typed[key] = redactedValue
				continue
			}
			typed[key] = redactDiagnosticValue(child)
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = redactDiagnosticValue(child)
		}
		return typed
	default:
		return value
	}
}

func redactDiagnosticText(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return ""
	}

	lowerValue := strings.ToLower(value)
	for _, label := range diagnosticSensitiveLabels {
		if containsDiagnosticLabel(lowerValue, label) {
			return label + " " + redactedValue
		}
	}

	for _, pattern := range diagnosticSensitiveValuePatterns {
		value = pattern.ReplaceAllStringFunc(value, func(match string) string {
			if len(match) > 0 && unicode.IsSpace(rune(match[0])) {
				return match[:1] + redactedValue
			}
			if strings.HasPrefix(match, "(/") {
				return "(" + redactedValue
			}
			return redactedValue
		})
	}

	// Backend validation commonly uses "reason: rejected value" or
	// "field=rejected value". The reason is useful; the echoed value is not.
	// Credential labels and recognizable sensitive values are scrubbed above
	// so a value placed before the separator cannot bypass those protections.
	if separator := strings.IndexAny(value, ":="); separator >= 0 {
		prefix := strings.TrimSpace(value[:separator+1])
		if prefix == ":" || prefix == "=" {
			return redactedValue
		}
		return truncate(prefix+" "+redactedValue, 512)
	}
	return truncate(value, 512)
}

func containsDiagnosticLabel(value, label string) bool {
	for searchStart := 0; searchStart < len(value); {
		match := strings.Index(value[searchStart:], label)
		if match < 0 {
			return false
		}
		match += searchStart
		matchEnd := match + len(label)
		startsAtBoundary := match == 0 || !isDiagnosticIdentifierByte(value[match-1])
		endsAtBoundary := matchEnd == len(value) || !isDiagnosticIdentifierByte(value[matchEnd])
		if startsAtBoundary && endsAtBoundary {
			return true
		}
		searchStart = match + 1
	}
	return false
}

func isDiagnosticIdentifierByte(value byte) bool {
	return value == '_' || value >= '0' && value <= '9' || value >= 'a' && value <= 'z'
}

func isDiagnosticKey(key string) bool {
	switch normalizeSensitiveKey(key) {
	case "detail", "details", "message", "messages", "msg", "error_detail", "error_message":
		return true
	default:
		return false
	}
}

func isDiagnosticInputKey(key string) bool {
	switch normalizeSensitiveKey(key) {
	case "actual", "body", "context", "ctx", "data", "given", "input", "payload", "received", "rejected", "request", "response", "value":
		return true
	default:
		return false
	}
}

func isSensitiveKey(key string) bool {
	normalized := normalizeSensitiveKey(key)
	for _, fragment := range []string{
		"authorization",
		"password",
		"passwd",
		"token",
		"secret",
		"private_key",
		"certificate",
		"client_key",
		"account_key",
		"api_key",
		"content",
		"detail",
		"message",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func normalizeSensitiveKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}
