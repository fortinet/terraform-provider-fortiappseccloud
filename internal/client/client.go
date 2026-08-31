package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL         = "https://api.appsec.fortinet.com"
	defaultTimeout         = 60 * time.Second
	defaultMaxAttempts     = 4
	defaultMinRetryDelay   = 500 * time.Millisecond
	defaultMaxRetryDelay   = 10 * time.Second
	defaultMaxResponseBody = 8 << 20
)

// Config configures a FortiAppSec Cloud API client.
type Config struct {
	BaseURL     string
	APIToken    string
	Username    string
	Password    string
	Insecure    bool
	CACertFile  string
	Timeout     time.Duration
	UserAgent   string
	HTTPClient  *http.Client
	Retry       RetryConfig
	MaxBodySize int64
}

// RetryConfig controls retry behavior for operations explicitly marked safe.
type RetryConfig struct {
	MaxAttempts   int
	MinDelay      time.Duration
	MaxDelay      time.Duration
	DisableJitter bool
}

// RetryMode declares whether an operation may be retried after an ambiguous failure.
type RetryMode int

const (
	RetryNever RetryMode = iota
	RetrySafe
)

// Operation describes request behavior that cannot be inferred from an HTTP method alone.
type Operation struct {
	Name                       string
	Retry                      RetryMode
	RetryConflict              bool
	DoNotRetrySuccessfulResult bool
}

// Client is a context-aware FortiAppSec Cloud API client.
type Client struct {
	baseURL     *url.URL
	httpClient  *http.Client
	authHeader  string
	userAgent   string
	timeout     time.Duration
	retry       RetryConfig
	maxBodySize int64
	sleep       func(context.Context, time.Duration) error
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

// New creates and authenticates a client. API tokens are preferred; username/password
// authentication is retained for compatibility with the existing provider.
func New(ctx context.Context, cfg Config) (*Client, error) {
	baseURL, err := normalizeBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}

	if err := validateAuthentication(cfg); err != nil {
		return nil, err
	}
	if cfg.Insecure && cfg.CACertFile != "" {
		return nil, errors.New("insecure and cacert_file cannot be configured together")
	}
	if cfg.HTTPClient != nil && (cfg.Insecure || cfg.CACertFile != "") {
		return nil, errors.New("a custom HTTP client cannot be combined with insecure or cacert_file")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 0 {
		return nil, errors.New("timeout must not be negative")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient, err = newHTTPClient(cfg, timeout)
		if err != nil {
			return nil, err
		}
	}

	retry := cfg.Retry
	if retry.MaxAttempts == 0 {
		retry.MaxAttempts = defaultMaxAttempts
	}
	if retry.MaxAttempts < 1 {
		return nil, errors.New("retry max attempts must be at least 1")
	}
	if retry.MinDelay == 0 {
		retry.MinDelay = defaultMinRetryDelay
	}
	if retry.MaxDelay == 0 {
		retry.MaxDelay = defaultMaxRetryDelay
	}
	if retry.MinDelay < 0 || retry.MaxDelay < 0 || retry.MaxDelay < retry.MinDelay {
		return nil, errors.New("invalid retry delay range")
	}

	maxBodySize := cfg.MaxBodySize
	if maxBodySize == 0 {
		maxBodySize = defaultMaxResponseBody
	}
	if maxBodySize < 1 {
		return nil, errors.New("maximum response body size must be positive")
	}

	c := &Client{
		baseURL:     baseURL,
		httpClient:  httpClient,
		userAgent:   cfg.UserAgent,
		timeout:     timeout,
		retry:       retry,
		maxBodySize: maxBodySize,
		sleep:       sleepContext,
	}

	if cfg.APIToken != "" {
		c.authHeader = basicToken(cfg.APIToken)
		return c, nil
	}

	var response loginResponse
	err = c.doJSON(ctx, Operation{Name: "login", Retry: RetryNever}, http.MethodPost, "token", nil, loginRequest{
		Username: cfg.Username,
		Password: cfg.Password,
	}, &response, false)
	if err != nil {
		return nil, fmt.Errorf("authenticate with username and password: %w", err)
	}
	if strings.TrimSpace(response.Token) == "" {
		return nil, errors.New("authenticate with username and password: response did not include a token")
	}
	c.authHeader = response.Token

	return c, nil
}

func validateAuthentication(cfg Config) error {
	hasToken := strings.TrimSpace(cfg.APIToken) != ""
	hasUsername := strings.TrimSpace(cfg.Username) != ""
	hasPassword := cfg.Password != ""

	if hasToken && (hasUsername || hasPassword) {
		return errors.New("configure either api_token or username and password, not both")
	}
	if hasToken {
		return nil
	}
	if hasUsername != hasPassword {
		return errors.New("username and password must be configured together")
	}
	if !hasUsername {
		return errors.New("configure api_token or username and password")
	}
	return nil
}

func normalizeBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultBaseURL
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse hostname: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("hostname scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("hostname must include a host")
	}
	if parsed.User != nil {
		return nil, errors.New("hostname must not include user information")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(parsed.Path, "/v2") {
		parsed.Path = path.Join(parsed.Path, "v2")
	}
	parsed.RawPath = ""
	return parsed, nil
}

func newHTTPClient(cfg Config, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.Insecure {
		// InsecureSkipVerify is an explicit provider opt-in for development environments.
		tlsConfig.InsecureSkipVerify = true //nolint:gosec
	}
	if cfg.CACertFile != "" {
		pemData, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read custom CA certificate: %w", err)
		}
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		if !rootCAs.AppendCertsFromPEM(pemData) {
			return nil, errors.New("custom CA certificate did not contain a valid PEM certificate")
		}
		tlsConfig.RootCAs = rootCAs
	}
	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func basicToken(token string) string {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "basic ") {
		return token
	}
	return "Basic " + token
}

func (c *Client) doJSON(
	ctx context.Context,
	op Operation,
	method string,
	endpoint string,
	query url.Values,
	requestBody any,
	responseBody any,
	authenticated bool,
) error {
	return c.doJSONWithHeaders(ctx, op, method, endpoint, query, requestBody, responseBody, authenticated, nil)
}

func (c *Client) doJSONWithHeaders(
	ctx context.Context,
	op Operation,
	method string,
	endpoint string,
	query url.Values,
	requestBody any,
	responseBody any,
	authenticated bool,
	headers http.Header,
) error {
	return c.doJSONWithHeadersAndMetadata(ctx, op, method, endpoint, query, requestBody, responseBody, authenticated, headers, nil)
}

type responseMetadata struct {
	StatusCode int
	Location   string
}

func (c *Client) doJSONWithHeadersAndMetadata(
	ctx context.Context,
	op Operation,
	method string,
	endpoint string,
	query url.Values,
	requestBody any,
	responseBody any,
	authenticated bool,
	headers http.Header,
	metadata *responseMetadata,
) error {
	var body []byte
	var err error
	if requestBody != nil {
		body, err = json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("%s: encode request body: %w", op.Name, err)
		}
	}
	contentType := ""
	if requestBody != nil {
		contentType = "application/json"
	}
	return c.doEncodedWithHeadersAndMetadata(ctx, op, method, endpoint, query, body, contentType, responseBody, authenticated, headers, metadata)
}

func (c *Client) doMultipart(
	ctx context.Context,
	op Operation,
	method string,
	endpoint string,
	fields map[string]string,
	uploads []OpenAPIUpload,
	responseBody any,
	authenticated bool,
) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fieldNames := make([]string, 0, len(fields))
	for fieldName := range fields {
		fieldNames = append(fieldNames, fieldName)
	}
	sort.Strings(fieldNames)
	for _, fieldName := range fieldNames {
		if err := writer.WriteField(fieldName, fields[fieldName]); err != nil {
			return fmt.Errorf("%s: encode multipart field %q: %w", op.Name, fieldName, err)
		}
	}
	for _, upload := range uploads {
		if strings.TrimSpace(upload.FieldName) == "" || strings.TrimSpace(upload.Path) == "" {
			return fmt.Errorf("%s: multipart upload field name and path must not be empty", op.Name)
		}
		contents, err := os.ReadFile(upload.Path)
		if err != nil {
			return fmt.Errorf("%s: read upload file %q: %w", op.Name, upload.Path, err)
		}
		part, err := writer.CreateFormFile(upload.FieldName, filepath.Base(upload.Path))
		if err != nil {
			return fmt.Errorf("%s: create multipart file field %q: %w", op.Name, upload.FieldName, err)
		}
		if _, err := part.Write(contents); err != nil {
			return fmt.Errorf("%s: encode multipart file %q: %w", op.Name, upload.Path, err)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("%s: finalize multipart request: %w", op.Name, err)
	}
	return c.doEncoded(ctx, op, method, endpoint, nil, body.Bytes(), writer.FormDataContentType(), responseBody, authenticated)
}

func (c *Client) doEncoded(
	ctx context.Context,
	op Operation,
	method string,
	endpoint string,
	query url.Values,
	body []byte,
	contentType string,
	responseBody any,
	authenticated bool,
) error {
	return c.doEncodedWithHeadersAndMetadata(ctx, op, method, endpoint, query, body, contentType, responseBody, authenticated, nil, nil)
}

func (c *Client) doEncodedWithHeadersAndMetadata(
	ctx context.Context,
	op Operation,
	method string,
	endpoint string,
	query url.Values,
	body []byte,
	contentType string,
	responseBody any,
	authenticated bool,
	headers http.Header,
	metadata *responseMetadata,
) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	attempts := 1
	if op.Retry == RetrySafe {
		attempts = c.retry.MaxAttempts
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		requestURL := c.buildURL(endpoint, query)
		request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("%s: create request: %w", op.Name, err)
		}
		request.Header.Set("Accept", "application/json")
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		if authenticated && c.authHeader != "" {
			request.Header.Set("Authorization", c.authHeader)
		}
		if c.userAgent != "" {
			request.Header.Set("User-Agent", c.userAgent)
		}
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}

		response, requestErr := c.httpClient.Do(request)
		if requestErr != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("%s: %w", op.Name, ctx.Err())
			}
			lastErr = fmt.Errorf("%s %s: %w", method, redactURL(requestURL), requestErr)
			if attempt == attempts {
				return lastErr
			}
			if err := c.waitForRetry(ctx, attempt, 0, false); err != nil {
				return fmt.Errorf("%s: %w", op.Name, err)
			}
			continue
		}

		responseData, readErr := readResponseBody(response.Body, c.maxBodySize)
		_ = response.Body.Close()
		success := response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices

		if !success {
			retryAfter, retryAfterSet := parseRetryAfter(response.Header.Get("Retry-After"))
			bodyDescription := redactBody(responseData)
			if readErr != nil && bodyDescription == "" {
				bodyDescription = "response body could not be read"
			}
			apiErr := &APIError{
				Operation:     op.Name,
				Method:        method,
				URL:           redactURL(requestURL),
				StatusCode:    response.StatusCode,
				Body:          bodyDescription,
				RetryAfter:    retryAfter,
				retryAfterSet: retryAfterSet,
			}
			lastErr = apiErr

			if attempt == attempts || !retryableStatus(op, response.StatusCode) {
				return apiErr
			}
			if err := c.waitForRetry(ctx, attempt, retryAfter, retryAfterSet); err != nil {
				return fmt.Errorf("%s: %w", op.Name, err)
			}
			continue
		}

		if readErr != nil {
			var tooLarge *responseTooLargeError
			if op.Retry == RetrySafe && !op.DoNotRetrySuccessfulResult && attempt < attempts && !errors.As(readErr, &tooLarge) {
				if err := c.waitForRetry(ctx, attempt, 0, false); err != nil {
					return fmt.Errorf("%s: %w", op.Name, err)
				}
				continue
			}
			return fmt.Errorf("%s: read response: %w", op.Name, readErr)
		}

		if metadata != nil {
			metadata.StatusCode = response.StatusCode
			metadata.Location = response.Header.Get("Location")
		}
		if responseBody == nil {
			return nil
		}
		if len(bytes.TrimSpace(responseData)) == 0 {
			if op.Retry == RetrySafe && !op.DoNotRetrySuccessfulResult && attempt < attempts {
				if err := c.waitForRetry(ctx, attempt, 0, false); err != nil {
					return fmt.Errorf("%s: %w", op.Name, err)
				}
				continue
			}
			return fmt.Errorf("%s: successful response did not include a JSON body", op.Name)
		}
		if err := json.Unmarshal(responseData, responseBody); err != nil {
			if op.Retry == RetrySafe && !op.DoNotRetrySuccessfulResult && attempt < attempts {
				if waitErr := c.waitForRetry(ctx, attempt, 0, false); waitErr != nil {
					return fmt.Errorf("%s: %w", op.Name, waitErr)
				}
				continue
			}
			return fmt.Errorf("%s: decode response: %w", op.Name, err)
		}
		return nil
	}

	return lastErr
}

func (c *Client) buildURL(endpoint string, query url.Values) *url.URL {
	requestURL := *c.baseURL
	basePath := strings.TrimRight(requestURL.EscapedPath(), "/")
	endpointPath := strings.TrimLeft(endpoint, "/")
	rawPath := basePath + "/" + endpointPath
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		decodedPath = rawPath
		rawPath = ""
	}
	requestURL.Path = decodedPath
	requestURL.RawPath = rawPath
	requestURL.RawQuery = query.Encode()
	return &requestURL
}

func retryableStatus(op Operation, statusCode int) bool {
	if op.Retry != RetrySafe {
		return false
	}
	if statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError {
		return true
	}
	return statusCode == http.StatusConflict && op.RetryConflict
}

func (c *Client) waitForRetry(ctx context.Context, attempt int, retryAfter time.Duration, retryAfterSet bool) error {
	delay := retryAfter
	if !retryAfterSet {
		multiplier := math.Pow(2, float64(attempt-1))
		delay = time.Duration(float64(c.retry.MinDelay) * multiplier)
		if !c.retry.DisableJitter && delay > 0 {
			delay = time.Duration(float64(delay) * (0.5 + rand.Float64()))
		}
	}
	if delay > c.retry.MaxDelay {
		delay = c.retry.MaxDelay
	}
	return c.sleep(ctx, delay)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type responseTooLargeError struct {
	limit int64
}

func (e *responseTooLargeError) Error() string {
	return fmt.Sprintf("response body exceeded %d bytes", e.limit)
}

func readResponseBody(body io.Reader, maxSize int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxSize+1))
	if err != nil {
		return data, err
	}
	if int64(len(data)) > maxSize {
		return data[:maxSize], &responseTooLargeError{limit: maxSize}
	}
	return data, nil
}

func parseRetryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}
	if retryTime, err := http.ParseTime(value); err == nil {
		delay := time.Until(retryTime)
		if delay < 0 {
			delay = 0
		}
		return delay, true
	}
	return 0, false
}
