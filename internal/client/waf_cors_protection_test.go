package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCorsProtectionGetMergePutPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	var putBody map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v2/waf/apps/app%2Fid/cors_protection" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if r.Header.Get("Authorization") != "Basic token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"result":{"configs":{"status":false,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"old.example","port":0,"include_sub_domains":false},"allowed_methods":{"status":false,"methods":["GET"]},"allowed_headers":{"status":false,"headers":["X-Old"]},"exposed_headers":{"status":false,"headers":[]},"url_pattern":"/old","allowed_credentials":"None","allowed_maximum_age":0,"future_config":{"keep":true}},"template":false,"future_envelope":"keep"}}`)
		case http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&putBody); err != nil {
				t.Errorf("decode PUT body: %v", err)
			}
			fmt.Fprint(w, `{"detail":"Module updated"}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	apiClient, err := New(context.Background(), Config{
		BaseURL:    server.URL,
		APIToken:   "token",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	document, err := apiClient.GetCorsProtection(context.Background(), "app/id")
	if err != nil {
		t.Fatalf("GetCorsProtection() error = %v", err)
	}
	if document.Config.Status == nil || *document.Config.Status {
		t.Fatalf("status = %#v", document.Config.Status)
	}
	if document.Config.AllowedOrigins == nil || document.Config.AllowedOrigins.OriginName == nil || *document.Config.AllowedOrigins.OriginName != "old.example" {
		t.Fatalf("allowed_origins = %#v", document.Config.AllowedOrigins)
	}
	if document.Config.AllowedMethods == nil || len(document.Config.AllowedMethods.Methods) != 1 || document.Config.AllowedMethods.Methods[0] != "GET" {
		t.Fatalf("allowed_methods = %#v", document.Config.AllowedMethods)
	}

	updated := document.Result.Clone()
	if err := updated.SetConfig("status", true); err != nil {
		t.Fatalf("SetConfig(status) error = %v", err)
	}
	if err := updated.SetConfig("allowed_origins", map[string]any{
		"protocol":    "HTTPS",
		"origin_name": "new.example",
		"port":        int(8443),
	}); err != nil {
		t.Fatalf("SetConfig(allowed_origins) error = %v", err)
	}
	if err := updated.SetConfig("allowed_methods", map[string]any{"status": true, "methods": []any{"GET", "POST"}}); err != nil {
		t.Fatalf("SetConfig(allowed_methods) error = %v", err)
	}
	if err := apiClient.PutCorsProtection(context.Background(), "app/id", updated); err != nil {
		t.Fatalf("PutCorsProtection() error = %v", err)
	}

	if _, ok := putBody["future_envelope"]; !ok {
		t.Fatalf("PUT body lost future_envelope: %s", mustJSON(putBody))
	}
	var configs map[string]json.RawMessage
	if err := json.Unmarshal(putBody["configs"], &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	if _, ok := configs["future_config"]; !ok {
		t.Fatalf("PUT configs lost future_config: %s", mustJSON(configs))
	}
	var status bool
	if err := json.Unmarshal(configs["status"], &status); err != nil || !status {
		t.Fatalf("PUT status = %s, error = %v", configs["status"], err)
	}
	var origins map[string]any
	if err := json.Unmarshal(configs["allowed_origins"], &origins); err != nil {
		t.Fatalf("decode allowed_origins: %v", err)
	}
	if origins["protocol"] != "HTTPS" || origins["origin_name"] != "new.example" {
		t.Fatalf("PUT allowed_origins = %#v", origins)
	}
}

func TestCorsProtectionDecodeMissingRequiredRejects(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"result":{"configs":{"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		`{"result":{"configs":{"status":true,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		`{"result":{"template":false}}`,
	} {
		if err := json.Unmarshal([]byte(body), &CorsProtectionDocument{}); err == nil {
			t.Fatalf("Unmarshal accepted a missing required field: %s", body)
		}
	}
}

func TestCorsProtectionDecodeAllowedOriginsMissingRequiredRejects(t *testing.T) {
	t.Parallel()

	// Missing origin_name inside allowed_origins.
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`), &CorsProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted a missing allowed_origins.origin_name")
	}
	// Null allowed_origins.
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":null,"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`), &CorsProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted a null allowed_origins")
	}
}

func TestCorsProtectionDecodeAllowedOriginsSingletonArrayCompatibility(t *testing.T) {
	t.Parallel()

	var document CorsProtectionDocument
	body := `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":[{"protocol":"HTTPS","origin_name":"array.example","port":443,"include_sub_domains":true,"future_origin_key":"keep"}],"allowed_methods":{"status":true,"methods":["GET"]},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("Unmarshal singleton-array response error = %v", err)
	}
	origins := document.Config.AllowedOrigins
	if origins == nil || origins.Protocol == nil || *origins.Protocol != "HTTPS" ||
		origins.OriginName == nil || *origins.OriginName != "array.example" ||
		origins.Port == nil || *origins.Port != 443 ||
		origins.IncludeSubDomains == nil || !*origins.IncludeSubDomains {
		t.Fatalf("decoded singleton-array allowed_origins = %#v", origins)
	}

	var rawItems []map[string]json.RawMessage
	if err := json.Unmarshal(document.Result.Configs["allowed_origins"], &rawItems); err != nil {
		t.Fatalf("raw allowed_origins did not retain array shape: %v", err)
	}
	if len(rawItems) != 1 {
		t.Fatalf("raw allowed_origins items = %d, want 1", len(rawItems))
	}
	if _, ok := rawItems[0]["future_origin_key"]; !ok {
		t.Fatal("raw allowed_origins lost unknown singleton-array item field")
	}
}

func TestCorsProtectionDecodeAllowedOriginsArrayCardinalityRejects(t *testing.T) {
	t.Parallel()

	for name, origins := range map[string]string{
		"multiple":  `[{"protocol":"ANY","origin_name":"one"},{"protocol":"HTTPS","origin_name":"two"}]`,
		"null item": `[null]`,
	} {
		name, origins := name, origins
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := fmt.Sprintf(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":%s,"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`, origins)
			if err := json.Unmarshal([]byte(body), &CorsProtectionDocument{}); err == nil {
				t.Fatalf("Unmarshal accepted %s allowed_origins array", name)
			}
		})
	}
}

func TestCorsProtectionDecodeAllowedOriginsEmptyArrayCompatibility(t *testing.T) {
	t.Parallel()

	var document CorsProtectionDocument
	body := `{"result":{"configs":{"status":false,"block_cors_traffic":false,"allowed_origins":[],"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("Unmarshal empty-array response error = %v", err)
	}
	if document.Config.AllowedOrigins != nil {
		t.Fatalf("empty-array allowed_origins = %#v, want nil", document.Config.AllowedOrigins)
	}
	var rawItems []json.RawMessage
	if err := json.Unmarshal(document.Result.Configs["allowed_origins"], &rawItems); err != nil {
		t.Fatalf("raw allowed_origins did not retain empty-array shape: %v", err)
	}
	if len(rawItems) != 0 {
		t.Fatalf("raw allowed_origins items = %d, want 0", len(rawItems))
	}
}

func TestCorsProtectionDecodeRejectsUnsupportedEnums(t *testing.T) {
	t.Parallel()

	valid := `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"HTTPS","origin_name":"x"},"allowed_methods":{"status":true,"methods":["GET","PATCH"]},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"allowed_credentials":"TRUE"},"template":false}}`
	if err := json.Unmarshal([]byte(valid), &CorsProtectionDocument{}); err != nil {
		t.Fatalf("valid control error = %v", err)
	}
	for name, body := range map[string]string{
		"protocol":            `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"FTP","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		"method":              `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":true,"methods":["OPTIONS"]},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		"allowed credentials": `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"allowed_credentials":"true"},"template":false}}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := json.Unmarshal([]byte(body), &CorsProtectionDocument{}); err == nil {
				t.Fatal("Unmarshal accepted an unsupported enum")
			}
		})
	}
}

func TestCorsProtectionDecodePortRangeRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x","port":65536},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`), &CorsProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted an out-of-range port")
	}
}

// TestCorsProtectionDecodePortRangeControl is the in-range companion to the
// out-of-range port rejection: port 65535 (the max) decodes cleanly.
func TestCorsProtectionDecodePortRangeControl(t *testing.T) {
	t.Parallel()

	var document CorsProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x","port":65535},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.AllowedOrigins == nil || document.Config.AllowedOrigins.Port == nil || *document.Config.AllowedOrigins.Port != 65535 {
		t.Fatalf("port = %#v", document.Config.AllowedOrigins)
	}
}

// TestCorsProtectionDecodeExplicitNullOptionalRejects guards that explicit
// JSON null for non-nullable optional fields (port, include_sub_domains,
// methods, headers, url_pattern, allowed_credentials, allowed_maximum_age) is
// rejected, not silently treated as absent.
func TestCorsProtectionDecodeExplicitNullOptionalRejects(t *testing.T) {
	t.Parallel()

	bodies := map[string]string{
		"port":                `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x","port":null},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		"include_sub_domains": `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x","include_sub_domains":null},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		"methods":             `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false,"methods":null},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`,
		"headers":             `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false,"headers":null},"exposed_headers":{"status":false}},"template":false}}`,
		"url_pattern":         `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"url_pattern":null},"template":false}}`,
		"allowed_credentials": `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"allowed_credentials":null},"template":false}}`,
		"allowed_maximum_age": `{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"allowed_maximum_age":null},"template":false}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := json.Unmarshal([]byte(body), &CorsProtectionDocument{}); err == nil {
				t.Fatalf("Unmarshal accepted an explicit null for %s", name)
			}
		})
	}
}

// TestCorsProtectionDecodeAbsentOptionalIsNil is the valid control proving
// absent optional fields decode to nil (presence-aware), distinct from the
// explicit-null rejection above.
func TestCorsProtectionDecodeAbsentOptionalIsNil(t *testing.T) {
	t.Parallel()

	var document CorsProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false}},"template":false}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.AllowedOrigins == nil {
		t.Fatal("allowed_origins = nil")
	}
	if document.Config.AllowedOrigins.Port != nil || document.Config.AllowedOrigins.IncludeSubDomains != nil {
		t.Fatalf("absent optionals = %#v, want nil", document.Config.AllowedOrigins)
	}
	if document.Config.AllowedMethods.Methods != nil {
		t.Fatalf("absent methods = %#v, want nil", document.Config.AllowedMethods.Methods)
	}
	if document.Config.AllowedHeaders.Headers != nil {
		t.Fatalf("absent headers = %#v, want nil", document.Config.AllowedHeaders.Headers)
	}
	if document.Config.URLPattern != nil || document.Config.AllowedCredentials != nil || document.Config.AllowedMaximumAge != nil {
		t.Fatal("absent top-level optionals are not nil")
	}
}

func TestCorsProtectionDecodeAllowedMaximumAgeRangeRejects(t *testing.T) {
	t.Parallel()

	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"allowed_maximum_age":86401},"template":false}}`), &CorsProtectionDocument{}); err == nil {
		t.Fatal("Unmarshal accepted an out-of-range allowed_maximum_age")
	}
}

func TestCorsProtectionDecodeAllowedMaximumAgeRangeControl(t *testing.T) {
	t.Parallel()

	// In-range control: 86400 (the max) decodes cleanly.
	var document CorsProtectionDocument
	if err := json.Unmarshal([]byte(`{"result":{"configs":{"status":true,"block_cors_traffic":false,"allowed_origins":{"protocol":"ANY","origin_name":"x"},"allowed_methods":{"status":false},"allowed_headers":{"status":false},"exposed_headers":{"status":false},"allowed_maximum_age":86400},"template":false}}`), &document); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if document.Config.AllowedMaximumAge == nil || *document.Config.AllowedMaximumAge != 86400 {
		t.Fatalf("allowed_maximum_age = %#v", document.Config.AllowedMaximumAge)
	}
}

func TestCorsProtectionEmptyEndpointErrors(t *testing.T) {
	t.Parallel()

	apiClient, err := New(context.Background(), Config{BaseURL: "https://example.test", APIToken: "token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := apiClient.GetCorsProtection(context.Background(), ""); err == nil {
		t.Fatal("GetCorsProtection() accepted an empty ep_id")
	}
	if err := apiClient.PutCorsProtection(context.Background(), "", WAFModuleResult{}); err == nil {
		t.Fatal("PutCorsProtection() accepted an empty ep_id")
	}
}
