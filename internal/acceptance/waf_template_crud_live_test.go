package acceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"terraform-provider-fortiappseccloud/internal/client"
)

const (
	templateCRUDCaptureGateVersion = "template_crud_v1"
	templateCRUDDevHostname        = "https://api.dev1.fortiappsec.com"
)

// templateCRUDCaptureEvent intentionally records only the relative template
// path, selected non-secret contract headers, and request/response bodies.
// Authorization, cookies, the API hostname, and all other headers are excluded.
type templateCRUDCaptureEvent struct {
	Sequence              int       `json:"sequence"`
	CapturedAtUTC         time.Time `json:"captured_at_utc"`
	Stage                 string    `json:"stage"`
	Method                string    `json:"method"`
	Path                  string    `json:"path"`
	RequestContentType    string    `json:"request_content_type,omitempty"`
	IdempotencyKeyPresent bool      `json:"idempotency_key_present,omitempty"`
	RequestBody           any       `json:"request_body,omitempty"`
	StatusCode            int       `json:"status_code,omitempty"`
	ResponseContentType   string    `json:"response_content_type,omitempty"`
	Location              string    `json:"location,omitempty"`
	ResponseBody          any       `json:"response_body,omitempty"`
	TransportError        bool      `json:"transport_error,omitempty"`
}

type templateCRUDCaptureArtifact struct {
	Format          string                     `json:"format"`
	RedactionNotice string                     `json:"redaction_notice"`
	Events          []templateCRUDCaptureEvent `json:"events"`
}

type templateCRUDCaptureRoundTripper struct {
	base http.RoundTripper

	mu     sync.Mutex
	stage  string
	events []templateCRUDCaptureEvent
}

func newTemplateCRUDCaptureRoundTripper(base http.RoundTripper) *templateCRUDCaptureRoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &templateCRUDCaptureRoundTripper{base: base}
}

func (r *templateCRUDCaptureRoundTripper) setStage(stage string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stage = stage
}

func (r *templateCRUDCaptureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if !isTemplateCRUDCaptureRequest(request) {
		return r.base.RoundTrip(request)
	}

	event := templateCRUDCaptureEvent{
		CapturedAtUTC:         time.Now().UTC(),
		Stage:                 r.currentStage(),
		Method:                request.Method,
		Path:                  request.URL.EscapedPath(),
		RequestContentType:    request.Header.Get("Content-Type"),
		IdempotencyKeyPresent: request.Header.Get("Idempotency-Key") != "",
	}
	if request.Body != nil {
		requestData, err := io.ReadAll(request.Body)
		if err != nil {
			event.RequestBody = captureBodyReadFailure("request", 0)
		} else {
			event.RequestBody = decodeCapturedTemplateBody(requestData)
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
	event.ResponseContentType = response.Header.Get("Content-Type")
	event.Location = response.Header.Get("Location")
	responseData, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(responseData))
	if readErr != nil {
		event.ResponseBody = captureBodyReadFailure("response", len(responseData))
	} else {
		event.ResponseBody = decodeCapturedTemplateBody(responseData)
	}
	r.appendEvent(event)
	return response, nil
}

func isTemplateCRUDCaptureRequest(request *http.Request) bool {
	if request == nil || request.URL == nil {
		return false
	}
	path := request.URL.EscapedPath()
	if request.Method == http.MethodPost && path == "/v2/waf/template" {
		return true
	}
	return strings.HasPrefix(path, "/v2/waf/template/") &&
		(request.Method == http.MethodGet || request.Method == http.MethodDelete)
}

func decodeCapturedTemplateBody(data []byte) any {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(data, &value); err == nil {
		return value
	}
	return map[string]any{
		"_capture":     "non_json_body",
		"_byte_length": len(data),
		"value":        string(data),
	}
}

func captureBodyReadFailure(direction string, byteLength int) map[string]any {
	return map[string]any{
		"_capture":     direction + "_body_read_failed",
		"_byte_length": byteLength,
	}
}

func (r *templateCRUDCaptureRoundTripper) currentStage() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stage == "" {
		return "unlabelled"
	}
	return r.stage
}

func (r *templateCRUDCaptureRoundTripper) appendEvent(event templateCRUDCaptureEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	event.Sequence = len(r.events) + 1
	r.events = append(r.events, event)
}

func (r *templateCRUDCaptureRoundTripper) artifact() templateCRUDCaptureArtifact {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := append([]templateCRUDCaptureEvent(nil), r.events...)
	return templateCRUDCaptureArtifact{
		Format:          "fortiappseccloud-template-crud-wire-capture-v1",
		RedactionNotice: "Authorization, cookies, API hostname, and unapproved HTTP headers are not captured.",
		Events:          events,
	}
}

func writeTemplateCRUDCaptureArtifact(recorder *templateCRUDCaptureRoundTripper) (string, error) {
	file, err := os.CreateTemp("", "fortiappseccloud-template-crud-wire-capture-*.json")
	if err != nil {
		return "", fmt.Errorf("create template CRUD capture artifact: %w", err)
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("restrict template CRUD capture artifact permissions: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(recorder.artifact()); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write template CRUD capture artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close template CRUD capture artifact: %w", err)
	}
	return path, nil
}

func liveClientWithTemplateCRUDCapture(t *testing.T, recorder *templateCRUDCaptureRoundTripper) *client.Client {
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
		Timeout:    2 * time.Minute,
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatalf("configure template CRUD capture client: %v", err)
	}
	return api
}

func TestAccTemplateCRUDWireCapture(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run live acceptance tests")
	}
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED", "yes")
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_HOSTNAME", templateCRUDDevHostname)
	skipUnlessExactEnvironment(t, "FORTIAPPSECCLOUD_ACC_DISPOSABLE_TEMPLATE", "yes")

	templateName := requireEnvironment(t, "FORTIAPPSECCLOUD_ACC_TEMPLATE_NAME")
	skipUnlessExactEnvironment(
		t,
		"FORTIAPPSECCLOUD_ACC_TEMPLATE_LIFECYCLE_WRITE",
		templateCRUDCaptureGateVersion+":"+templateName,
	)
	requireEnvironment(t, "FORTIAPPSECCLOUD_API_TOKEN")

	recorder := newTemplateCRUDCaptureRoundTripper(nil)
	api := liveClientWithTemplateCRUDCapture(t, recorder)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	refuseExistingTemplateName(t, ctx, api, templateName)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cleanupCancel()
		recorder.setStage("cleanup")
		cleanupTemplatesByExactName(t, cleanupCtx, api, templateName)
		path, err := writeTemplateCRUDCaptureArtifact(recorder)
		if err != nil {
			t.Errorf("persist template CRUD capture: %v", err)
			return
		}
		t.Logf("template CRUD capture written to %s", path)
	})

	recorder.setStage("create")
	created, err := api.CreateTemplate(ctx, client.TemplateCreateRequest{
		Name:      templateName,
		Endpoints: []string{},
	})
	if err != nil {
		t.Fatalf("create disposable template: %v", err)
	}
	if created.Result.Name != templateName {
		t.Fatalf("created template name = %q, want exact disposable name", created.Result.Name)
	}
	if created.Result.Predefined {
		t.Fatal("created disposable template was marked predefine=true")
	}
	if len(created.Result.Endpoints) != 0 {
		t.Fatalf("created disposable template endpoints count = %d, want 0", len(created.Result.Endpoints))
	}

	recorder.setStage("read")
	read, err := waitForTemplateRead(ctx, api, created.Result.TemplateID)
	if err != nil {
		t.Fatalf("read created disposable template: %v", err)
	}
	if read.TemplateID != created.Result.TemplateID || read.Name != templateName {
		t.Fatalf("read template identity did not match the create response")
	}
	if read.Predefined || len(read.Endpoints) != 0 {
		t.Fatalf("read template predefine/endpoints did not match the requested disposable template")
	}

	recorder.setStage("delete")
	if err := api.DeleteTemplate(ctx, created.Result.TemplateID); err != nil {
		t.Fatalf("delete disposable template: %v", err)
	}
	if err := waitForTemplateAbsence(ctx, api, templateName); err != nil {
		t.Fatalf("verify disposable template deletion: %v", err)
	}
}

func refuseExistingTemplateName(t *testing.T, ctx context.Context, api *client.Client, templateName string) {
	t.Helper()
	templates, err := api.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("verify disposable template name: %v", err)
	}
	for _, template := range templates.Templates {
		if template.Name == templateName {
			t.Fatal("refusing template CRUD acceptance: disposable template name already exists")
		}
	}
}

func waitForTemplateRead(ctx context.Context, api *client.Client, templateID string) (client.Template, error) {
	for attempt := 0; attempt < 30; attempt++ {
		template, err := api.GetTemplate(ctx, templateID)
		if err == nil {
			return template, nil
		}
		if !client.IsStatus(err, http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable) {
			return client.Template{}, err
		}
		if err := waitTemplateCRUDRetry(ctx); err != nil {
			return client.Template{}, err
		}
	}
	return client.Template{}, fmt.Errorf("template did not become readable")
}

func cleanupTemplatesByExactName(t *testing.T, ctx context.Context, api *client.Client, templateName string) {
	t.Helper()
	templates, err := api.ListTemplates(ctx)
	if err != nil {
		t.Errorf("inspect disposable template during cleanup: %v", err)
		return
	}
	for _, template := range templates.Templates {
		if template.Name != templateName {
			continue
		}
		if template.Predefined {
			t.Errorf("refusing cleanup: exact disposable template name resolved to a predefined template")
			return
		}
		if err := api.DeleteTemplate(ctx, template.TemplateID); err != nil && !client.IsNotFound(err) {
			t.Errorf("cleanup disposable template: %v", err)
			return
		}
	}
	if err := waitForTemplateAbsence(ctx, api, templateName); err != nil {
		t.Errorf("verify disposable template cleanup: %v", err)
	}
}

func waitForTemplateAbsence(ctx context.Context, api *client.Client, templateName string) error {
	for attempt := 0; attempt < 30; attempt++ {
		templates, err := api.ListTemplates(ctx)
		if err != nil {
			if client.IsStatus(err, http.StatusConflict, http.StatusServiceUnavailable) {
				if err := waitTemplateCRUDRetry(ctx); err != nil {
					return err
				}
				continue
			}
			return err
		}
		present := false
		for _, template := range templates.Templates {
			if template.Name == templateName {
				present = true
				break
			}
		}
		if !present {
			return nil
		}
		if err := waitTemplateCRUDRetry(ctx); err != nil {
			return err
		}
	}
	return fmt.Errorf("template %q remained present after delete", templateName)
}

func waitTemplateCRUDRetry(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
