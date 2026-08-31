package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Application contains stable application inventory fields used by Terraform resources and data sources.
type Application struct {
	EPID           string                  `json:"ep_id"`
	AppName        string                  `json:"app_name"`
	DomainName     string                  `json:"domain_name"`
	ExtraDomains   []string                `json:"extra_domains"`
	CNAME          string                  `json:"ep_cname"`
	BlockMode      int                     `json:"block_mode"`
	CDNStatus      int                     `json:"cdn_status"`
	Continent      string                  `json:"continent"`
	IsGlobalCDN    int                     `json:"is_global_cdn"`
	Platform       string                  `json:"platform"`
	PlatformRegion string                  `json:"platform_region"`
	Region         string                  `json:"region"`
	TemplateID     string                  `json:"template_id"`
	TemplateName   string                  `json:"template_name"`
	DNSStatus      int                     `json:"dns_status"`
	DomainStatus   map[string]any          `json:"domain_status"`
	WAFAddresses   map[string][]WAFAddress `json:"waf_addresses"`
}

// ApplicationCustomPort contains the public listener ports selected during onboarding.
type ApplicationCustomPort struct {
	HTTP  int64 `json:"http"`
	HTTPS int64 `json:"https"`
}

// ApplicationCreationOriginTerraform identifies application onboarding
// performed by this Terraform provider. The API uses this create-only marker
// to initialize switchable security modules in a disabled state.
const ApplicationCreationOriginTerraform = "fas_terraform"

// ApplicationCreateRequest is the reviewed public application onboarding payload.
// Initial origin fields are intentionally confined to create; ongoing origin ownership
// belongs to the origin-servers resource.
type ApplicationCreateRequest struct {
	AppName         string                `json:"app_name"`
	CreationOrigin  string                `json:"creation_origin,omitempty"`
	DomainName      string                `json:"domain_name"`
	ExtraDomains    []string              `json:"extra_domains"`
	BlockMode       int                   `json:"block_mode"`
	CertType        *int                  `json:"cert_type,omitempty"`
	Service         []string              `json:"service"`
	ServerAddress   string                `json:"server_address"`
	ServerType      string                `json:"server_type"`
	ServerPort      int64                 `json:"server_port"`
	CDNStatus       int                   `json:"cdn_status"`
	IsGlobalCDN     int                   `json:"is_global_cdn"`
	Continent       string                `json:"continent,omitempty"`
	Region          string                `json:"region,omitempty"`
	Platform        string                `json:"platform"`
	CustomPort      ApplicationCustomPort `json:"custom_port"`
	ServerCountry   string                `json:"server_country,omitempty"`
	BestMatchRegion string                `json:"best_match_region,omitempty"`
}

// ApplicationCreateResponse is returned after a successful onboarding request.
type ApplicationCreateResponse struct {
	EPID       string                  `json:"ep_id"`
	AppName    string                  `json:"app_name"`
	DomainInfo []ApplicationDomainInfo `json:"domain_info"`
}

// UnmarshalJSON accepts both the object-shaped response used by newer API
// deployments and the DNS-record array returned by the v1.0.5 integration.
// The application resource resolves ep_id by unique app_name when the array
// shape does not carry identity.
func (r *ApplicationCreateResponse) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var domains []ApplicationDomainInfo
		if err := json.Unmarshal(data, &domains); err != nil {
			return fmt.Errorf("decode application create DNS records: %w", err)
		}
		*r = ApplicationCreateResponse{DomainInfo: domains}
		return nil
	}
	type wire ApplicationCreateResponse
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("decode application create response: %w", err)
	}
	*r = ApplicationCreateResponse(decoded)
	return nil
}

// ApplicationDomainInfo describes one DNS record returned by onboarding.
type ApplicationDomainInfo struct {
	Domain string `json:"domain"`
	DNS    string `json:"dns"`
}

// ApplicationUpdateRequest owns placement/CDN configuration on the core app endpoint.
type ApplicationUpdateRequest struct {
	AppName     string `json:"app_name"`
	CDNStatus   int    `json:"cdn_status"`
	IsGlobalCDN int    `json:"is_global_cdn"`
	Continent   string `json:"continent,omitempty"`
	Region      string `json:"region,omitempty"`
}

// DNSLookupResult is the public DNS lookup response used by optional
// application onboarding prechecks.
type DNSLookupResult struct {
	Addresses []string `json:"A"`
}

// BackendConnectivityRequest identifies one origin address to test before
// application onboarding.
type BackendConnectivityRequest struct {
	DomainName string
	Address    string
	Protocol   string
	Port       int64
}

// DNSLookup resolves an origin hostname through the public WAF utility API.
func (c *Client) DNSLookup(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("DNS lookup domain must not be empty")
	}
	var response DNSLookupResult
	err := c.doJSON(ctx, Operation{Name: "resolve origin DNS", Retry: RetrySafe}, http.MethodPost, "waf/misc/dns-lookup", nil, map[string]string{"domain": domain}, &response, true)
	if err != nil {
		return nil, err
	}
	if len(response.Addresses) == 0 {
		return nil, fmt.Errorf("origin DNS lookup returned no addresses")
	}
	return response.Addresses, nil
}

// TestBackendConnectivity verifies one resolved origin through the public WAF
// connectivity utility. The diagnostic response is intentionally not exposed
// because it can contain request and origin details.
func (c *Client) TestBackendConnectivity(ctx context.Context, request BackendConnectivityRequest) error {
	if strings.TrimSpace(request.DomainName) == "" || strings.TrimSpace(request.Address) == "" {
		return fmt.Errorf("backend connectivity domain and address must not be empty")
	}
	if request.Port < 1 || request.Port > 65535 {
		return fmt.Errorf("backend connectivity port must be between 1 and 65535")
	}
	query := url.Values{
		"domain_name":  []string{request.DomainName},
		"backend_ip":   []string{request.Address},
		"backend_type": []string{strings.ToUpper(request.Protocol)},
		"backend_port": []string{strconv.FormatInt(request.Port, 10)},
	}
	var response struct {
		NetworkConnectivity int `json:"network_connectivity"`
	}
	if err := c.doJSON(ctx, Operation{Name: "test origin connectivity", Retry: RetrySafe}, http.MethodGet, "waf/misc/backend-ip-test", query, nil, &response, true); err != nil {
		return err
	}
	if response.NetworkConnectivity != 1 {
		return fmt.Errorf("origin connectivity precheck did not succeed")
	}
	return nil
}

// CreateApplication creates an application without using non-public placement APIs.
func (c *Client) CreateApplication(ctx context.Context, request ApplicationCreateRequest) (ApplicationCreateResponse, error) {
	var response ApplicationCreateResponse
	err := c.doJSON(ctx, Operation{Name: "create application", Retry: RetryNever}, http.MethodPost, "waf/apps", nil, request, &response, true)
	return response, err
}

// UpdateApplication updates the public placement/CDN configuration.
func (c *Client) UpdateApplication(ctx context.Context, epID string, request ApplicationUpdateRequest) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "update application", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID), nil, request, nil, true)
}

// UpdateApplicationBlockMode updates the independently routed block-mode setting.
func (c *Client) UpdateApplicationBlockMode(ctx context.Context, epID string, enabled bool) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	mode := 0
	if enabled {
		mode = 1
	}
	return c.doJSON(ctx, Operation{Name: "update application block mode", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/block", nil, map[string]int{"block_mode": mode}, nil, true)
}

// GetApplicationEndpoint returns the complete, intentionally untyped endpoint document.
// Its incomplete OpenAPI shape is used only for preserving GET-merge-PUT ownership of
// reviewed listener, extra-domain, and certificate-mode fields.
func (c *Client) GetApplicationEndpoint(ctx context.Context, epID string) (map[string]any, error) {
	if epID == "" {
		return nil, fmt.Errorf("application ID must not be empty")
	}
	var response map[string]any
	err := c.doJSON(ctx, Operation{Name: "get application endpoint", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/endpoint", nil, nil, &response, true)
	return response, err
}

// PutApplicationEndpoint writes a complete endpoint document after caller-side preservation.
func (c *Client) PutApplicationEndpoint(ctx context.Context, epID string, document map[string]any) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "update application endpoint", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/endpoint", nil, document, nil, true)
}

// DeleteApplication deletes an application by stable endpoint ID.
func (c *Client) DeleteApplication(ctx context.Context, epID string) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "delete application", Retry: RetryNever}, http.MethodDelete, "waf/apps/"+url.PathEscape(epID), nil, nil, nil, true)
}

// WAFAddress is an application edge address returned by the inventory API.
type WAFAddress struct {
	IP string `json:"ip"`
}

// ApplicationPage is the cursor-paginated full application inventory response.
type ApplicationPage struct {
	Applications []Application `json:"app_list"`
	CanAdd       int           `json:"can_add"`
	NextCursor   string        `json:"next_cursor"`
	PrevCursor   string        `json:"prev_cursor"`
	Total        int           `json:"total"`
}

// ApplicationSummary is returned by GET /waf/apps?partial=true.
type ApplicationSummary struct {
	EPID       string `json:"ep_id"`
	AppName    string `json:"app_name"`
	DomainName string `json:"domain_name"`
}

// ApplicationDetail is the brief, non-inventory shape returned by GET /waf/apps/{ep_id}.
type ApplicationDetail struct {
	AppName    string   `json:"app_name"`
	DomainName string   `json:"domain_name"`
	BlockMode  int      `json:"block_mode"`
	FSAStatus  int      `json:"fsa_status"`
	WAFRegions []string `json:"waf_regions"`
}

// ListApplicationsOptions controls cursor pagination and API-side filtering.
type ListApplicationsOptions struct {
	Size    int
	Filter  string
	Forward *bool
	Cursor  string
}

// ListApplications returns the full cursor-paginated application inventory.
func (c *Client) ListApplications(ctx context.Context, options ListApplicationsOptions) (ApplicationPage, error) {
	if options.Size != 0 && options.Size != 10 && options.Size != 20 && options.Size != 30 {
		return ApplicationPage{}, fmt.Errorf("application page size must be 10, 20, or 30")
	}

	query := make(url.Values)
	if options.Size != 0 {
		query.Set("size", strconv.Itoa(options.Size))
	}
	if options.Filter != "" {
		query.Set("filter", options.Filter)
	}
	if options.Forward != nil {
		query.Set("forward", strconv.FormatBool(*options.Forward))
	}
	if options.Cursor != "" {
		query.Set("cursor", options.Cursor)
	}

	var response ApplicationPage
	err := c.doJSON(ctx, Operation{Name: "list applications", Retry: RetrySafe}, http.MethodGet, "waf/apps", query, nil, &response, true)
	return response, err
}

// ListAllApplications follows forward cursors until every application has been read.
func (c *Client) ListAllApplications(ctx context.Context, options ListApplicationsOptions) ([]Application, error) {
	if options.Size == 0 {
		options.Size = 30
	}
	options.Forward = nil

	seenCursors := make(map[string]struct{})
	if options.Cursor != "" {
		seenCursors[options.Cursor] = struct{}{}
	}

	var applications []Application
	for {
		page, err := c.ListApplications(ctx, options)
		if err != nil {
			return nil, err
		}
		applications = append(applications, page.Applications...)
		if page.NextCursor == "" {
			return applications, nil
		}
		if _, exists := seenCursors[page.NextCursor]; exists {
			return nil, fmt.Errorf("application pagination repeated cursor %q", page.NextCursor)
		}
		seenCursors[page.NextCursor] = struct{}{}
		options.Cursor = page.NextCursor
		forward := true
		options.Forward = &forward
	}
}

// FindApplicationByName resolves a legacy application name only when exactly one match exists.
func (c *Client) FindApplicationByName(ctx context.Context, appName string) (Application, error) {
	if appName == "" {
		return Application{}, fmt.Errorf("application name must not be empty")
	}
	applications, err := c.ListAllApplications(ctx, ListApplicationsOptions{Size: 30})
	if err != nil {
		return Application{}, err
	}

	var match *Application
	for index := range applications {
		if applications[index].AppName != appName {
			continue
		}
		if match != nil {
			return Application{}, fmt.Errorf("multiple applications matched name %q", appName)
		}
		match = &applications[index]
	}
	if match == nil {
		return Application{}, fmt.Errorf("application named %q was not found", appName)
	}
	return *match, nil
}

// FindApplicationByEPID resolves one stable endpoint ID via the list endpoint's
// ep_id filter. The backend recognises an ep_id filter as a direct main-table
// EndPoint.get, so this resolves in a single API call without paginating the
// account inventory.
func (c *Client) FindApplicationByEPID(ctx context.Context, epID string) (Application, error) {
	if epID == "" {
		return Application{}, fmt.Errorf("application ID must not be empty")
	}
	filter, err := epIDFilter(epID)
	if err != nil {
		return Application{}, fmt.Errorf("build ep_id filter: %w", err)
	}
	page, err := c.ListApplications(ctx, ListApplicationsOptions{Size: 30, Filter: filter})
	if err != nil {
		return Application{}, err
	}
	for _, application := range page.Applications {
		if application.EPID == epID {
			return application, nil
		}
	}
	return Application{}, fmt.Errorf("application %q was not found", epID)
}

// epIDFilter builds the backend filter JSON string that narrows a list request
// to a single ep_id. The shape matches the documented filter contract:
// [{"id":"ep_id","logic":{},"value":["<epID>"]}].
func epIDFilter(epID string) (string, error) {
	encoded, err := json.Marshal(epID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`[{"id":"ep_id","logic":{},"value":[%s]}]`, encoded), nil
}

// ListApplicationSummaries returns the documented partial application response.
func (c *Client) ListApplicationSummaries(ctx context.Context) ([]ApplicationSummary, error) {
	query := url.Values{"partial": []string{"true"}}
	var response []ApplicationSummary
	err := c.doJSON(ctx, Operation{Name: "list application summaries", Retry: RetrySafe}, http.MethodGet, "waf/apps", query, nil, &response, true)
	return response, err
}

// GetApplication returns the brief application detail response.
func (c *Client) GetApplication(ctx context.Context, epID string) (ApplicationDetail, error) {
	if epID == "" {
		return ApplicationDetail{}, fmt.Errorf("application ID must not be empty")
	}
	var response ApplicationDetail
	err := c.doJSON(ctx, Operation{Name: "get application", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID), nil, nil, &response, true)
	return response, err
}

// ApplicationExists resolves ambiguous application-detail 400/403/404 responses
// by consulting the complete application inventory. The production API can
// return 403 invalid_app_operation after a successful asynchronous delete even
// though the caller remains authorized to list applications.
func (c *Client) ApplicationExists(ctx context.Context, epID string) (bool, error) {
	if epID == "" {
		return false, fmt.Errorf("application ID must not be empty")
	}
	if _, err := c.GetApplication(ctx, epID); err == nil {
		return true, nil
	} else if !IsStatus(err, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound) {
		return false, err
	}

	applications, err := c.ListAllApplications(ctx, ListApplicationsOptions{Size: 30})
	if err != nil {
		return false, fmt.Errorf("list applications while resolving %q: %w", epID, err)
	}
	for _, application := range applications {
		if application.EPID == epID {
			return true, nil
		}
	}
	return false, nil
}

// TemplateEndpoint accepts both the detailed string membership shape and the
// list API's [ep_id, app_name, domain_name] tuple shape.
type TemplateEndpoint struct {
	EPID       string `json:"ep_id"`
	AppName    string `json:"app_name,omitempty"`
	DomainName string `json:"domain_name,omitempty"`
}

func (e *TemplateEndpoint) UnmarshalJSON(data []byte) error {
	var epID string
	if err := json.Unmarshal(data, &epID); err == nil {
		if epID == "" {
			return fmt.Errorf("decode template endpoint: endpoint ID must not be empty")
		}
		e.EPID = epID
		return nil
	}

	var tuple []string
	if err := json.Unmarshal(data, &tuple); err != nil {
		return fmt.Errorf("decode template endpoint: %w", err)
	}
	if len(tuple) == 0 {
		return fmt.Errorf("decode template endpoint: empty tuple")
	}
	if tuple[0] == "" {
		return fmt.Errorf("decode template endpoint: endpoint ID must not be empty")
	}
	e.EPID = tuple[0]
	if len(tuple) > 1 {
		e.AppName = tuple[1]
	}
	if len(tuple) > 2 {
		e.DomainName = tuple[2]
	}
	return nil
}

// Template is a user or predefined WAF template.
type Template struct {
	TemplateID string             `json:"template_id"`
	Name       string             `json:"name"`
	Predefined bool               `json:"predefine"`
	Features   []string           `json:"features"`
	Endpoints  []TemplateEndpoint `json:"endpoints"`
}

// TemplateList is the template inventory envelope.
type TemplateList struct {
	Templates []Template `json:"result"`
	Total     int        `json:"total"`
	UserPerm  string     `json:"user_perm"`
}

// TemplateCreateRequest is the reviewed future POST /waf/template payload.
// Endpoints is intentionally sent as an empty list by the base Terraform
// resource because membership belongs to waf_template_attachment.
type TemplateCreateRequest struct {
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
}

// TemplateCreateResponse is the user-approved future 201 response contract.
type TemplateCreateResponse struct {
	Result Template `json:"result"`
	Detail string   `json:"detail"`
}

// UnmarshalJSON fails closed when a successful create response drifts from the
// approved future lifecycle contract. Presence matters for false and empty
// values, so ordinary struct unmarshalling is insufficient here.
func (r *TemplateCreateResponse) UnmarshalJSON(data []byte) error {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode template create response: %w", err)
	}
	resultRaw, ok := envelope["result"]
	if !ok || isJSONNull(resultRaw) {
		return fmt.Errorf("decode template create response: missing result object")
	}
	var resultFields map[string]json.RawMessage
	if err := json.Unmarshal(resultRaw, &resultFields); err != nil {
		return fmt.Errorf("decode template create response result: %w", err)
	}
	for _, name := range []string{"template_id", "name", "predefine", "features", "endpoints"} {
		value, present := resultFields[name]
		if !present || isJSONNull(value) {
			return fmt.Errorf("decode template create response result: missing %s", name)
		}
	}
	var result Template
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return fmt.Errorf("decode template create response result: %w", err)
	}
	detailRaw, ok := envelope["detail"]
	if !ok || isJSONNull(detailRaw) {
		return fmt.Errorf("decode template create response: missing detail")
	}
	var detail string
	if err := json.Unmarshal(detailRaw, &detail); err != nil {
		return fmt.Errorf("decode template create response detail: %w", err)
	}
	*r = TemplateCreateResponse{Result: result, Detail: detail}
	return nil
}

type templateDetail struct {
	Result Template `json:"result"`
}

// ListTemplates returns all public templates visible to the account.
func (c *Client) ListTemplates(ctx context.Context) (TemplateList, error) {
	var response TemplateList
	err := c.doJSON(ctx, Operation{Name: "list templates", Retry: RetrySafe}, http.MethodGet, "waf/template", nil, nil, &response, true)
	return response, err
}

// CreateTemplate creates a user template using the reviewed future API
// contract. The idempotency key makes transport retries safe once that
// contract is deployed.
func (c *Client) CreateTemplate(ctx context.Context, request TemplateCreateRequest) (TemplateCreateResponse, error) {
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" {
		return TemplateCreateResponse{}, fmt.Errorf("template name must not be empty")
	}
	if request.Endpoints == nil {
		request.Endpoints = []string{}
	}
	idempotencyKey, err := newIdempotencyKey()
	if err != nil {
		return TemplateCreateResponse{}, fmt.Errorf("create template: generate idempotency key: %w", err)
	}
	var response TemplateCreateResponse
	var metadata responseMetadata
	err = c.doJSONWithHeadersAndMetadata(
		ctx,
		Operation{Name: "create template", Retry: RetrySafe, DoNotRetrySuccessfulResult: true},
		http.MethodPost,
		"waf/template",
		nil,
		request,
		&response,
		true,
		http.Header{"Idempotency-Key": []string{idempotencyKey}},
		&metadata,
	)
	if err != nil {
		return TemplateCreateResponse{}, err
	}
	if metadata.StatusCode != http.StatusCreated {
		return TemplateCreateResponse{}, fmt.Errorf("create template: response status was %d, want %d", metadata.StatusCode, http.StatusCreated)
	}
	if strings.TrimSpace(response.Result.TemplateID) == "" {
		return TemplateCreateResponse{}, fmt.Errorf("create template: response result did not include template_id")
	}
	if strings.TrimSpace(response.Result.Name) == "" {
		return TemplateCreateResponse{}, fmt.Errorf("create template: response result did not include name")
	}
	if response.Result.Name != request.Name {
		return TemplateCreateResponse{}, fmt.Errorf("create template: response name %q did not match requested name %q", response.Result.Name, request.Name)
	}
	wantLocation := "/v2/waf/template/" + url.PathEscape(response.Result.TemplateID)
	if metadata.Location != wantLocation {
		return TemplateCreateResponse{}, fmt.Errorf("create template: response Location was %q, want %q", metadata.Location, wantLocation)
	}
	return response, nil
}

// GetTemplate returns one template by stable template ID.
func (c *Client) GetTemplate(ctx context.Context, templateID string) (Template, error) {
	if templateID == "" {
		return Template{}, fmt.Errorf("template ID must not be empty")
	}
	var response templateDetail
	err := c.doJSON(ctx, Operation{Name: "get template", Retry: RetrySafe}, http.MethodGet, "waf/template/"+url.PathEscape(templateID), nil, nil, &response, true)
	if err == nil && response.Result.TemplateID == "" {
		response.Result.TemplateID = templateID
	}
	return response.Result, err
}

// TemplateExists resolves ambiguous template-detail 400/403/404 responses by
// consulting the complete template inventory. The dev API returns 403 after a
// successful template delete even though the caller remains authorized to list
// templates.
func (c *Client) TemplateExists(ctx context.Context, templateID string) (bool, error) {
	templateID = strings.TrimSpace(templateID)
	if templateID == "" {
		return false, fmt.Errorf("template ID must not be empty")
	}
	templates, err := c.ListTemplates(ctx)
	if err != nil {
		return false, fmt.Errorf("list templates while resolving %q: %w", templateID, err)
	}
	for _, template := range templates.Templates {
		if template.TemplateID == templateID {
			return true, nil
		}
	}
	return false, nil
}

// PutTemplateEndpoints replaces template membership with a caller-preserved complete list.
func (c *Client) PutTemplateEndpoints(ctx context.Context, templateID string, endpointIDs []string) error {
	if templateID == "" {
		return fmt.Errorf("template ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "update template endpoints", Retry: RetrySafe, RetryConflict: true}, http.MethodPut, "waf/template/"+url.PathEscape(templateID), nil, map[string][]string{"endpoints": endpointIDs}, nil, true)
}

// DeleteTemplate deletes a user template by stable template ID.
func (c *Client) DeleteTemplate(ctx context.Context, templateID string) error {
	templateID = strings.TrimSpace(templateID)
	if templateID == "" {
		return fmt.Errorf("template ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "delete template", Retry: RetrySafe}, http.MethodDelete, "waf/template/"+url.PathEscape(templateID), nil, nil, nil, true)
}

func newIdempotencyKey() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	// RFC 4122 variant/version bits make logs recognizable while uniqueness,
	// not UUID semantics, is what the API relies on.
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}

// OriginServersDocument is the public origin-server response envelope.
type OriginServersDocument struct {
	Result OriginServersResult `json:"result"`
}

// OriginServersResult contains the complete mutable server-pool collection.
type OriginServersResult struct {
	ServerPools []OriginServerPool `json:"server_pools"`
}

// OriginServerPool is one load-balancing pool.
type OriginServerPool struct {
	Health        OriginServerHealth      `json:"health"`
	LBAlgorithm   string                  `json:"lb_algo"`
	Name          string                  `json:"name"`
	Persistence   OriginServerPersistence `json:"persistence"`
	ServerBalance bool                    `json:"server_balance"`
	Servers       []OriginServer          `json:"server_list"`
	rawUnknown    map[string]json.RawMessage
}

// OriginServerHealth is one pool's health-check policy.
type OriginServerHealth struct {
	Code       *int64  `json:"code,omitempty"`
	Enabled    bool    `json:"health_check"`
	Interval   *int64  `json:"interval,omitempty"`
	Matched    *string `json:"matched,omitempty"`
	Method     *string `json:"method,omitempty"`
	Retry      *int64  `json:"retry,omitempty"`
	Timeout    *int64  `json:"timeout,omitempty"`
	URL        *string `json:"url,omitempty"`
	rawUnknown map[string]json.RawMessage
}

// OriginServerPersistence is one pool's session persistence policy.
type OriginServerPersistence struct {
	Domain     *string `json:"domain,omitempty"`
	Name       *string `json:"name,omitempty"`
	Path       *string `json:"path,omitempty"`
	Timeout    *int64  `json:"timeout,omitempty"`
	Type       string  `json:"type"`
	rawUnknown map[string]json.RawMessage
}

// OriginServer is one backend server. Known production fields omitted from the
// pinned schema are included so a normal read/write cycle does not discard them.
type OriginServer struct {
	Address           *string              `json:"addr,omitempty"`
	Backup            *bool                `json:"backup,omitempty"`
	CertificateVerify *bool                `json:"cert_verify,omitempty"`
	ConnectionFilters []OriginServerFilter `json:"conn_filter,omitempty"`
	ConnectionName    *string              `json:"conn_name,omitempty"`
	EncryptionLevel   *string              `json:"enc_level,omitempty"`
	HTTP2             *bool                `json:"http2,omitempty"`
	HTTPPort          *int64               `json:"http_port,omitempty"`
	HTTPSPort         *int64               `json:"https_port,omitempty"`
	Index             *int64               `json:"idx,omitempty"`
	Port              *int64               `json:"port,omitempty"`
	SSL               *bool                `json:"ssl,omitempty"`
	Status            *string              `json:"status,omitempty"`
	TLS10             *bool                `json:"tls_1_0,omitempty"`
	TLS11             *bool                `json:"tls_1_1,omitempty"`
	TLS12             *bool                `json:"tls_1_2,omitempty"`
	TLS13             *bool                `json:"tls_1_3,omitempty"`
	Type              *string              `json:"type,omitempty"`
	Weight            *int64               `json:"weight,omitempty"`
	HealthCheckStatus *string              `json:"health_check_status,omitempty"`
	Locked            *bool                `json:"locked,omitempty"`
	rawUnknown        map[string]json.RawMessage
}

// OriginServerFilter is a dynamic cloud-connector selector.
type OriginServerFilter struct {
	Name       string   `json:"Name"`
	Values     []string `json:"Values"`
	rawUnknown map[string]json.RawMessage
}

var originServerKnownFields = map[string]struct{}{
	"addr": {}, "backup": {}, "cert_verify": {}, "conn_filter": {}, "conn_name": {}, "enc_level": {},
	"http2": {}, "http_port": {}, "https_port": {}, "idx": {}, "port": {}, "ssl": {}, "status": {},
	"tls_1_0": {}, "tls_1_1": {}, "tls_1_2": {}, "tls_1_3": {}, "type": {}, "weight": {},
	"health_check_status": {}, "locked": {},
}

var originServerPoolKnownFields = map[string]struct{}{
	"health": {}, "lb_algo": {}, "name": {}, "persistence": {}, "server_balance": {}, "server_list": {},
}

var originServerHealthKnownFields = map[string]struct{}{
	"code": {}, "health_check": {}, "interval": {}, "matched": {}, "method": {}, "retry": {}, "timeout": {}, "url": {},
}

var originServerPersistenceKnownFields = map[string]struct{}{
	"domain": {}, "name": {}, "path": {}, "timeout": {}, "type": {},
}

func (p *OriginServerPool) UnmarshalJSON(data []byte) error {
	type wire OriginServerPool
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	unknown, err := unknownJSONFields(data, originServerPoolKnownFields)
	if err != nil {
		return err
	}
	*p = OriginServerPool(decoded)
	p.rawUnknown = unknown
	return nil
}

func (p OriginServerPool) MarshalJSON() ([]byte, error) {
	type wire OriginServerPool
	return marshalWithUnknownJSON(wire(p), p.rawUnknown)
}

func (h *OriginServerHealth) UnmarshalJSON(data []byte) error {
	type wire OriginServerHealth
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	unknown, err := unknownJSONFields(data, originServerHealthKnownFields)
	if err != nil {
		return err
	}
	*h = OriginServerHealth(decoded)
	h.rawUnknown = unknown
	return nil
}

func (h OriginServerHealth) MarshalJSON() ([]byte, error) {
	type wire OriginServerHealth
	return marshalWithUnknownJSON(wire(h), h.rawUnknown)
}

func (p *OriginServerPersistence) UnmarshalJSON(data []byte) error {
	type wire OriginServerPersistence
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	unknown, err := unknownJSONFields(data, originServerPersistenceKnownFields)
	if err != nil {
		return err
	}
	*p = OriginServerPersistence(decoded)
	p.rawUnknown = unknown
	return nil
}

func (p OriginServerPersistence) MarshalJSON() ([]byte, error) {
	type wire OriginServerPersistence
	return marshalWithUnknownJSON(wire(p), p.rawUnknown)
}

func (s *OriginServer) UnmarshalJSON(data []byte) error {
	type wire OriginServer
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	lockedJSON, hasLocked := object["locked"]
	delete(object, "locked")
	withoutLocked, err := json.Marshal(object)
	if err != nil {
		return err
	}
	var decoded wire
	if err := json.Unmarshal(withoutLocked, &decoded); err != nil {
		return err
	}
	if hasLocked {
		locked, err := decodeFlexibleBool(lockedJSON)
		if err == nil {
			decoded.Locked = locked
		}
	}
	unknown, err := unknownJSONFields(data, originServerKnownFields)
	if err != nil {
		return err
	}
	*s = OriginServer(decoded)
	s.rawUnknown = unknown
	return nil
}

func decodeFlexibleBool(data json.RawMessage) (*bool, error) {
	if string(data) == "null" {
		return nil, nil
	}
	var boolean bool
	if err := json.Unmarshal(data, &boolean); err == nil {
		return &boolean, nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return nil, fmt.Errorf("expected boolean, boolean string, or null")
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "true", "1", "yes", "on", "enable", "enabled", "lock", "locked":
		boolean = true
	case "", "false", "0", "no", "off", "disable", "disabled", "none", "unlock", "unlocked":
		boolean = false
	default:
		return nil, fmt.Errorf("unsupported boolean string")
	}
	return &boolean, nil
}

func (s OriginServer) MarshalJSON() ([]byte, error) {
	type wire OriginServer
	return marshalWithUnknownJSON(wire(s), s.rawUnknown)
}

func (f *OriginServerFilter) UnmarshalJSON(data []byte) error {
	type wire OriginServerFilter
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	delete(object, "Name")
	delete(object, "Values")
	*f = OriginServerFilter(decoded)
	f.rawUnknown = cloneRawMap(object)
	return nil
}

func (f OriginServerFilter) MarshalJSON() ([]byte, error) {
	type wire OriginServerFilter
	return marshalWithUnknownJSON(wire(f), f.rawUnknown)
}

func unknownJSONFields(data []byte, knownFields map[string]struct{}) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	for name := range knownFields {
		delete(object, name)
	}
	return cloneRawMap(object), nil
}

func marshalWithUnknownJSON(knownValue any, unknown map[string]json.RawMessage) ([]byte, error) {
	knownJSON, err := json.Marshal(knownValue)
	if err != nil {
		return nil, err
	}
	var known map[string]json.RawMessage
	if err := json.Unmarshal(knownJSON, &known); err != nil {
		return nil, err
	}
	object := cloneRawMap(unknown)
	if object == nil {
		object = make(map[string]json.RawMessage)
	}
	for name, value := range known {
		object[name] = value
	}
	return json.Marshal(object)
}

// MergeOriginServerOmittedFields carries omitted optional/computed values and
// server extensions across a full origin PUT. Servers are matched by their
// stable configured identity; fields are not copied onto replacement servers.
func MergeOriginServerOmittedFields(planned, current []OriginServerPool) {
	currentPools := make(map[string]OriginServerPool, len(current))
	for _, pool := range current {
		currentPools[pool.Name] = pool
	}
	for poolIndex := range planned {
		currentPool, ok := currentPools[planned[poolIndex].Name]
		if !ok {
			continue
		}
		planned[poolIndex].rawUnknown = cloneRawMap(currentPool.rawUnknown)
		planned[poolIndex].Health.rawUnknown = cloneRawMap(currentPool.Health.rawUnknown)
		planned[poolIndex].Persistence.rawUnknown = cloneRawMap(currentPool.Persistence.rawUnknown)
		preserveInt64Pointer(&planned[poolIndex].Health.Code, currentPool.Health.Code)
		preserveInt64Pointer(&planned[poolIndex].Health.Interval, currentPool.Health.Interval)
		preserveStringPointer(&planned[poolIndex].Health.Matched, currentPool.Health.Matched)
		preserveStringPointer(&planned[poolIndex].Health.Method, currentPool.Health.Method)
		preserveInt64Pointer(&planned[poolIndex].Health.Retry, currentPool.Health.Retry)
		preserveInt64Pointer(&planned[poolIndex].Health.Timeout, currentPool.Health.Timeout)
		preserveStringPointer(&planned[poolIndex].Health.URL, currentPool.Health.URL)
		preserveStringPointer(&planned[poolIndex].Persistence.Domain, currentPool.Persistence.Domain)
		preserveStringPointer(&planned[poolIndex].Persistence.Name, currentPool.Persistence.Name)
		preserveStringPointer(&planned[poolIndex].Persistence.Path, currentPool.Persistence.Path)
		preserveInt64Pointer(&planned[poolIndex].Persistence.Timeout, currentPool.Persistence.Timeout)
		currentServers := make(map[string][]OriginServer)
		for _, server := range currentPool.Servers {
			key := originServerPreservationKey(server)
			currentServers[key] = append(currentServers[key], server)
		}
		for serverIndex := range planned[poolIndex].Servers {
			server := &planned[poolIndex].Servers[serverIndex]
			key := originServerPreservationKey(*server)
			matches := currentServers[key]
			if len(matches) == 0 {
				continue
			}
			matched := matches[0]
			currentServers[key] = matches[1:]
			server.rawUnknown = cloneRawMap(matched.rawUnknown)
			preserveStringPointer(&server.Address, matched.Address)
			preserveBoolPointer(&server.Backup, matched.Backup)
			preserveBoolPointer(&server.CertificateVerify, matched.CertificateVerify)
			preserveStringPointer(&server.ConnectionName, matched.ConnectionName)
			preserveStringPointer(&server.EncryptionLevel, matched.EncryptionLevel)
			preserveBoolPointer(&server.HTTP2, matched.HTTP2)
			preserveInt64Pointer(&server.HTTPPort, matched.HTTPPort)
			preserveInt64Pointer(&server.HTTPSPort, matched.HTTPSPort)
			preserveInt64Pointer(&server.Port, matched.Port)
			preserveBoolPointer(&server.SSL, matched.SSL)
			preserveStringPointer(&server.Status, matched.Status)
			preserveBoolPointer(&server.TLS10, matched.TLS10)
			preserveBoolPointer(&server.TLS11, matched.TLS11)
			preserveBoolPointer(&server.TLS12, matched.TLS12)
			preserveBoolPointer(&server.TLS13, matched.TLS13)
			preserveStringPointer(&server.Type, matched.Type)
			preserveInt64Pointer(&server.Weight, matched.Weight)
			currentFilters := make(map[string][]OriginServerFilter)
			for _, filter := range matched.ConnectionFilters {
				currentFilters[filter.Name] = append(currentFilters[filter.Name], filter)
			}
			for filterIndex := range server.ConnectionFilters {
				filter := &server.ConnectionFilters[filterIndex]
				matches := currentFilters[filter.Name]
				if len(matches) == 0 {
					continue
				}
				filter.rawUnknown = cloneRawMap(matches[0].rawUnknown)
				currentFilters[filter.Name] = matches[1:]
			}
		}
	}
}

func preserveStringPointer(destination **string, source *string) {
	if *destination == nil && source != nil {
		value := *source
		*destination = &value
	}
}

func preserveInt64Pointer(destination **int64, source *int64) {
	if *destination == nil && source != nil {
		value := *source
		*destination = &value
	}
}

func preserveBoolPointer(destination **bool, source *bool) {
	if *destination == nil && source != nil {
		value := *source
		*destination = &value
	}
}

func originServerPreservationKey(server OriginServer) string {
	return strings.Join([]string{pointerString(server.Type), pointerString(server.Address), pointerString(server.ConnectionName)}, "\x00")
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// GetOriginServers returns the complete origin server pool configuration.
func (c *Client) GetOriginServers(ctx context.Context, epID string) (OriginServersDocument, error) {
	if epID == "" {
		return OriginServersDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response OriginServersDocument
	err := c.doJSON(ctx, Operation{Name: "get origin servers", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/servers", nil, nil, &response, true)
	return response, err
}

// PutOriginServers replaces the complete origin server pool configuration.
func (c *Client) PutOriginServers(ctx context.Context, epID string, pools []OriginServerPool) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "update origin servers", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/servers", nil, map[string]any{"server_pools": pools}, nil, true)
}

// OpenAPIValidationDocument is the typed portion of API-protection GET.
type OpenAPIValidationDocument struct {
	Result OpenAPIValidationResult `json:"result"`
}

// OpenAPIValidationResult contains configuration and template inheritance.
type OpenAPIValidationResult struct {
	Configs  OpenAPIValidationConfig `json:"configs"`
	Template bool                    `json:"template"`
}

// OpenAPIValidationConfig is the managed OpenAPI validation configuration.
type OpenAPIValidationConfig struct {
	Action   string                  `json:"action"`
	Status   bool                    `json:"status"`
	FileList []OpenAPIValidationFile `json:"file_list"`
}

// OpenAPIValidationFile is server metadata for one uploaded document.
type OpenAPIValidationFile struct {
	Description string `json:"desc"`
	Index       int64  `json:"idx"`
	MD5         string `json:"md5"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	URL         string `json:"url"`
}

// OpenAPIUpload describes one local file and multipart field name.
type OpenAPIUpload struct {
	FieldName string
	Path      string
}

// GetOpenAPIValidation returns the current validation configuration.
func (c *Client) GetOpenAPIValidation(ctx context.Context, epID string) (OpenAPIValidationDocument, error) {
	if epID == "" {
		return OpenAPIValidationDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response OpenAPIValidationDocument
	err := c.doJSON(ctx, Operation{Name: "get OpenAPI validation", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/api_protection", nil, nil, &response, true)
	return response, err
}

// PutOpenAPIValidation updates validation using the endpoint's multipart contract.
func (c *Client) PutOpenAPIValidation(ctx context.Context, epID string, config OpenAPIValidationConfig, uploads []OpenAPIUpload) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode OpenAPI validation config: %w", err)
	}
	fields := map[string]string{"template": "false", "configs": string(configJSON)}
	return c.doMultipart(ctx, Operation{Name: "update OpenAPI validation", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/api_protection", fields, uploads, nil, true)
}

// WAFSettings contains the typed, stable portion of GET /waf/settings.
type WAFSettings struct {
	CertificateRenewalRecipients string            `json:"cr_recipients"`
	CertificateRenewalStatus     string            `json:"cr_status"`
	PlatformOption               string            `json:"platform_option"`
	PreferredPlatform            string            `json:"preferred_platform"`
	PreferredRegion              string            `json:"preferred_region"`
	SupportedPlatforms           []PlatformRegions `json:"support_platform_regions"`
}

// PlatformRegions groups the supported regions for one cloud platform.
type PlatformRegions struct {
	Platform string   `json:"platform"`
	Provider string   `json:"provider"`
	Regions  []Region `json:"regions"`
}

// Region is a public FortiAppSec Cloud placement option.
type Region struct {
	Continent      string `json:"continent"`
	LogicalRegion  string `json:"logical_region"`
	PhysicalRegion string `json:"physical_region"`
}

// GetWAFSettings returns typed global settings and public region reference data.
func (c *Client) GetWAFSettings(ctx context.Context) (WAFSettings, error) {
	var response WAFSettings
	err := c.doJSON(ctx, Operation{Name: "get WAF settings", Retry: RetrySafe}, http.MethodGet, "waf/settings", nil, nil, &response, true)
	return response, err
}
