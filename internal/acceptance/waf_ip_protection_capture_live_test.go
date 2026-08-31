package acceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"terraform-provider-fortiappseccloud/internal/client"
)

const ipProtectionCaptureGateVersion = "ip_protection_wire_capture_v1"

// ipProtectionCaptureEvent intentionally has no URL or header fields. The
// diagnostic artifact therefore cannot contain the hostname, application
// endpoint ID, Authorization header, cookie, or user-agent value.
type ipProtectionCaptureEvent struct {
	Sequence       int       `json:"sequence"`
	CapturedAtUTC  time.Time `json:"captured_at_utc"`
	Stage          string    `json:"stage"`
	Method         string    `json:"method"`
	RequestBody    any       `json:"request_body,omitempty"`
	StatusCode     int       `json:"status_code,omitempty"`
	ResponseBody   any       `json:"response_body,omitempty"`
	TransportError bool      `json:"transport_error,omitempty"`
}

type ipProtectionCaptureArtifact struct {
	Format          string                     `json:"format"`
	RedactionNotice string                     `json:"redaction_notice"`
	Events          []ipProtectionCaptureEvent `json:"events"`
}

type ipProtectionCaptureRoundTripper struct {
	base http.RoundTripper

	mu     sync.Mutex
	stage  string
	events []ipProtectionCaptureEvent
}

func newIPProtectionCaptureRoundTripper(base http.RoundTripper) *ipProtectionCaptureRoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &ipProtectionCaptureRoundTripper{base: base}
}

func (r *ipProtectionCaptureRoundTripper) setStage(stage string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stage = stage
}

func (r *ipProtectionCaptureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if !isIPProtectionCaptureRequest(request) {
		return r.base.RoundTrip(request)
	}

	event := ipProtectionCaptureEvent{
		CapturedAtUTC: time.Now().UTC(),
		Stage:         r.currentStage(),
		Method:        request.Method,
	}
	if request.Body != nil {
		requestData, err := io.ReadAll(request.Body)
		if err != nil {
			event.RequestBody = redactedCaptureFailure("request_body_read_failed", 0)
		} else {
			event.RequestBody = sanitizeIPProtectionCaptureBody(requestData)
			request.Body = io.NopCloser(bytes.NewReader(requestData))
		}
	}

	response, err := r.base.RoundTrip(request)
	if err != nil {
		event.TransportError = true
		r.appendEvent(event)
		return nil, err
	}

	event.StatusCode = response.StatusCode
	responseData, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(responseData))
	if readErr != nil {
		event.ResponseBody = redactedCaptureFailure("response_body_read_failed", len(responseData))
	} else {
		event.ResponseBody = sanitizeIPProtectionCaptureBody(responseData)
	}
	r.appendEvent(event)
	return response, nil
}

func (r *ipProtectionCaptureRoundTripper) currentStage() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stage == "" {
		return "unlabelled"
	}
	return r.stage
}

func (r *ipProtectionCaptureRoundTripper) appendEvent(event ipProtectionCaptureEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	event.Sequence = len(r.events) + 1
	r.events = append(r.events, event)
}

func (r *ipProtectionCaptureRoundTripper) artifact() ipProtectionCaptureArtifact {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := append([]ipProtectionCaptureEvent(nil), r.events...)
	return ipProtectionCaptureArtifact{
		Format:          "fortiappseccloud-ip-protection-sanitized-wire-capture-v1",
		RedactionNotice: "Authorization headers, URL/hostname, application name, ep_id, HTTP headers, and non-IP-Protection fields are not captured.",
		Events:          events,
	}
}

func isIPProtectionCaptureRequest(request *http.Request) bool {
	if request == nil || request.URL == nil {
		return false
	}
	return strings.Contains(request.URL.Path, "/waf/apps/") &&
		strings.HasSuffix(request.URL.Path, "/ip_protection") &&
		(request.Method == http.MethodGet || request.Method == http.MethodPut)
}

func sanitizeIPProtectionCaptureBody(data []byte) any {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return redactedCaptureFailure("non_json_body_redacted", len(data))
	}
	return sanitizeIPProtectionCaptureValue(value, captureValueTopLevel)
}

type captureValueContext uint8

const (
	captureValueTopLevel captureValueContext = iota
	captureValueResult
	captureValueConfigs
	captureValueIPList
	captureValueIPItem
)

func sanitizeIPProtectionCaptureValue(value any, valueContext captureValueContext) any {
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeIPProtectionCaptureObject(typed, valueContext)
	case []any:
		if valueContext != captureValueIPList {
			return map[string]any{
				"_redacted_json_type": "array",
				"_item_count":         len(typed),
			}
		}
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, sanitizeIPProtectionCaptureValue(item, captureValueIPItem))
		}
		return items
	default:
		if valueContext == captureValueIPItem {
			return map[string]any{"_redacted_json_type": jsonTypeName(value)}
		}
		return value
	}
}

func sanitizeIPProtectionCaptureObject(object map[string]any, valueContext captureValueContext) map[string]any {
	allowed := captureAllowedKeys(valueContext)
	sanitized := make(map[string]any, len(allowed)+1)
	omitted := 0
	for key, value := range object {
		childContext, ok := allowed[key]
		if !ok {
			omitted++
			continue
		}
		sanitized[key] = sanitizeIPProtectionCaptureValue(value, childContext)
	}
	if omitted > 0 {
		sanitized["_omitted_key_count"] = omitted
	}
	return sanitized
}

func captureAllowedKeys(valueContext captureValueContext) map[string]captureValueContext {
	switch valueContext {
	case captureValueTopLevel:
		return map[string]captureValueContext{
			"configs":  captureValueConfigs,
			"detail":   captureValueResult,
			"result":   captureValueResult,
			"template": captureValueResult,
		}
	case captureValueResult:
		return map[string]captureValueContext{
			"configs":  captureValueConfigs,
			"template": captureValueResult,
		}
	case captureValueConfigs:
		return map[string]captureValueContext{
			"block_country_list": captureValueResult,
			"geo_ip_mode":        captureValueResult,
			"ip_list":            captureValueIPList,
			"ip_reputation":      captureValueResult,
			"status":             captureValueResult,
		}
	case captureValueIPItem:
		return map[string]captureValueContext{
			"idx":  captureValueResult,
			"ip":   captureValueResult,
			"type": captureValueResult,
		}
	default:
		return map[string]captureValueContext{}
	}
}

func redactedCaptureFailure(reason string, byteLength int) map[string]any {
	return map[string]any{
		"_capture":     reason,
		"_byte_length": byteLength,
	}
}

func jsonTypeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

func writeIPProtectionCaptureArtifact(recorder *ipProtectionCaptureRoundTripper) (string, error) {
	file, err := os.CreateTemp("", "fortiappseccloud-ip-protection-wire-capture-*.json")
	if err != nil {
		return "", fmt.Errorf("create sanitized capture artifact: %w", err)
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("restrict sanitized capture artifact permissions: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(recorder.artifact()); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write sanitized capture artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close sanitized capture artifact: %w", err)
	}
	return path, nil
}

func liveClientWithIPProtectionCapture(t *testing.T, recorder *ipProtectionCaptureRoundTripper) *client.Client {
	t.Helper()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	transport.TLSClientConfig = tlsConfig
	recorder.base = transport

	httpClient := &http.Client{
		Transport: recorder,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	api, err := client.New(context.Background(), client.Config{
		BaseURL:    os.Getenv("FORTIAPPSECCLOUD_HOSTNAME"),
		APIToken:   os.Getenv("FORTIAPPSECCLOUD_API_TOKEN"),
		Username:   os.Getenv("FORTIAPPSECCLOUD_USERNAME"),
		Password:   os.Getenv("FORTIAPPSECCLOUD_PASSWORD"),
		Timeout:    2 * time.Minute,
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatalf("configure IP Protection capture client: %v", err)
	}
	return api
}

// TestAccIPProtectionWireCapture is a user-authorized diagnostic for the
// production IP Protection contract mismatch. It captures only allowlisted
// module JSON fields and never records a URL, header, app name, or ep_id.
func TestAccIPProtectionWireCapture(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_APP", "yes")

	appName := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_APP_NAME")
	skipUnlessExactEnvironment(
		t,
		"FORTIAPPSECCLOUD_ACC_IP_PROTECTION_CAPTURE_WRITE",
		ipProtectionCaptureGateVersion+":"+appName,
	)
	domain := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_DOMAIN")
	originAddress := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_ORIGIN_ADDRESS")
	platform := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLATFORM")
	region := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_REGION")

	recorder := newIPProtectionCaptureRoundTripper(nil)
	api := liveClientWithIPProtectionCapture(t, recorder)
	var artifactPath string
	persistArtifact := func() {
		if artifactPath != "" {
			return
		}
		path, err := writeIPProtectionCaptureArtifact(recorder)
		if err != nil {
			t.Errorf("persist sanitized IP Protection capture: %v", err)
			return
		}
		artifactPath = path
		t.Logf("sanitized IP Protection capture written to %s", path)
	}
	t.Cleanup(persistArtifact)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	refuseExistingApplicationName(t, ctx, api, appName)
	registerDisposableApplicationCleanup(t, api, appName)

	created, err := api.CreateApplication(ctx, client.ApplicationCreateRequest{
		AppName:        appName,
		CreationOrigin: client.ApplicationCreationOriginTerraform,
		DomainName:     domain,
		ExtraDomains:   []string{},
		BlockMode:      0,
		Service:        []string{"https"},
		ServerAddress:  originAddress,
		ServerType:     "https",
		ServerPort:     443,
		CDNStatus:      0,
		IsGlobalCDN:    0,
		Region:         region,
		Platform:       platform,
		CustomPort:     client.ApplicationCustomPort{HTTP: 80, HTTPS: 443},
	})
	if err != nil {
		t.Fatalf("create disposable application for IP Protection capture: %v", err)
	}
	epID, err := waitForCreatedApplication(ctx, api, appName, created.EPID)
	if err != nil {
		t.Fatal(err)
	}

	var original client.IPProtectionDocument
	for attempt := 0; attempt < 30; attempt++ {
		recorder.setStage("initial_snapshot_get")
		original, err = api.GetIPProtection(ctx, epID)
		if err == nil {
			break
		}
		if !client.IsStatus(err, 400, 403, 404, 409, 503) {
			t.Fatalf("snapshot IP Protection for wire capture: %v", err)
		}
		waitForLiveRetry(t, ctx)
	}
	if err != nil {
		t.Fatalf("IP Protection snapshot did not become available: %v", err)
	}
	if len(original.Config.IPList) != 0 {
		t.Fatal("refusing IP Protection capture because the new disposable application did not start with an empty ip_list")
	}

	updated := original.Result.Clone()
	updated.Template = false
	if err := updated.SetConfig("status", false); err != nil {
		t.Fatalf("build captured IP Protection status: %v", err)
	}
	if err := updated.SetConfig("ip_reputation", false); err != nil {
		t.Fatalf("build captured IP Protection reputation: %v", err)
	}
	if err := updated.SetConfig("ip_list", []client.IPProtectionIPListPutEntry{{
		Type: "trust-ip",
		IP:   "1.1.1.1",
	}}); err != nil {
		t.Fatalf("build captured IP Protection ip_list: %v", err)
	}

	recorder.setStage("test_put")
	putErr := api.PutIPProtection(ctx, epID, updated)

	recorder.setStage("post_put_get")
	postPut, getErr := api.GetIPProtection(ctx, epID)
	var ownedDecodeErr error
	if getErr == nil {
		_, ownedDecodeErr = client.DecodeIPProtectionIPList(postPut.Config.IPList)
	}

	restoreCase := customModuleLiveCase{
		snapshotLabel:     "ip protection capture",
		normalizeSnapshot: normalizeIPProtectionSnapshot,
		restore: func(ctx context.Context, api *client.Client, epID string, snapshot any) error {
			recorder.setStage("restore_put")
			result, ok := snapshot.(client.WAFModuleResult)
			if !ok {
				return fmt.Errorf("internal IP Protection capture snapshot type mismatch")
			}
			return api.PutIPProtection(ctx, epID, result)
		},
		snapshot: func(ctx context.Context, api *client.Client, epID string) (any, error) {
			recorder.setStage("restore_verification_get")
			document, err := api.GetIPProtection(ctx, epID)
			if err != nil {
				return nil, err
			}
			return document.Result, nil
		},
	}
	restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	restoreErr := restoreCustomModuleSnapshot(restoreCtx, api, epID, restoreCase, original.Result)
	restoreCancel()

	persistArtifact()
	if putErr != nil {
		t.Errorf("captured IP Protection PUT failed: %v", putErr)
	}
	if getErr != nil {
		t.Errorf("captured IP Protection GET failed: %v", getErr)
	} else if ownedDecodeErr != nil {
		t.Errorf("captured IP Protection GET does not satisfy the reviewed owned-item contract: %v", ownedDecodeErr)
	}
	if restoreErr != nil {
		t.Errorf("restore captured IP Protection snapshot: %v", restoreErr)
	}
}

func TestIPProtectionCaptureSanitizesIdentityHeadersAndUnknownFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "secret-token" {
			t.Error("test request did not carry its dummy authorization header")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"template":false,"configs":{"status":false,"ip_reputation":false,"ip_list":[{"idx":1,"type":"trust-ip","ip":null,"future_secret":"do-not-capture"}],"future_config":"do-not-capture"},"future_result":"do-not-capture"},"future_top":"do-not-capture"}`)
	}))
	defer server.Close()

	recorder := newIPProtectionCaptureRoundTripper(server.Client().Transport)
	recorder.setStage("unit_test")
	httpClient := server.Client()
	httpClient.Transport = recorder
	request, err := http.NewRequest(
		http.MethodPut,
		server.URL+"/v2/waf/apps/sensitive-endpoint-id/ip_protection",
		strings.NewReader(`{"template":false,"configs":{"status":false,"ip_reputation":false,"ip_list":[{"type":"trust-ip","ip":"1.1.1.1","request_secret":"do-not-capture"}]},"request_top_secret":"do-not-capture"}`),
	)
	if err != nil {
		t.Fatalf("build unit capture request: %v", err)
	}
	request.Header.Set("Authorization", "secret-token")
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("execute unit capture request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	encoded, err := json.Marshal(recorder.artifact())
	if err != nil {
		t.Fatalf("encode unit capture artifact: %v", err)
	}
	text := string(encoded)
	for _, forbidden := range []string{
		"secret-token",
		"sensitive-endpoint-id",
		"do-not-capture",
		"request_secret",
		"future_secret",
		"future_config",
		"future_result",
		"future_top",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("sanitized capture contains forbidden value %q: %s", forbidden, text)
		}
	}
	for _, required := range []string{
		`"stage":"unit_test"`,
		`"method":"PUT"`,
		`"ip":"1.1.1.1"`,
		`"ip":null`,
		`"_omitted_key_count":1`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("sanitized capture is missing %s: %s", required, text)
		}
	}
}

func TestIPProtectionCaptureIgnoresOtherEndpoints(t *testing.T) {
	t.Parallel()

	recorder := newIPProtectionCaptureRoundTripper(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"secret":"not captured"}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	}))
	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/v2/waf/apps/sensitive-id/cors_protection", nil)
	if err != nil {
		t.Fatalf("build ignored request: %v", err)
	}
	response, err := recorder.RoundTrip(request)
	if err != nil {
		t.Fatalf("execute ignored request: %v", err)
	}
	_ = response.Body.Close()
	if events := recorder.artifact().Events; len(events) != 0 {
		t.Fatalf("capture recorded %d non-IP-Protection events", len(events))
	}
}

func TestIPProtectionCaptureArtifactUsesRestrictedPermissions(t *testing.T) {
	t.Parallel()

	recorder := newIPProtectionCaptureRoundTripper(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"detail":"ok"}`)),
			Header:     make(http.Header),
			Request:    request,
		}, nil
	}))
	recorder.setStage("artifact_permissions")
	request, err := http.NewRequest(http.MethodPut, "https://example.invalid/v2/waf/apps/redacted/ip_protection", strings.NewReader(`{"configs":{"status":false,"ip_reputation":false,"ip_list":[]}}`))
	if err != nil {
		t.Fatalf("build artifact request: %v", err)
	}
	response, err := recorder.RoundTrip(request)
	if err != nil {
		t.Fatalf("capture artifact request: %v", err)
	}
	_ = response.Body.Close()

	path, err := writeIPProtectionCaptureArtifact(recorder)
	if err != nil {
		t.Fatalf("write capture artifact: %v", err)
	}
	defer os.Remove(path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat capture artifact: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("capture artifact permissions = %o, want 600", permissions)
	}
}

// roundTripFunc is kept local to acceptance tests so the diagnostic capture
// can prove endpoint scoping without exporting a transport helper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
