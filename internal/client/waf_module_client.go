package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	wafModuleEPIDPlaceholder       = "{ep_id}"
	wafModuleTemplateIDPlaceholder = "{template_id}"
)

var (
	wafModulePathPattern         = regexp.MustCompile(`^/waf/apps/\{ep_id\}/[a-z0-9][a-z0-9_-]*$`)
	wafTemplateModulePathPattern = regexp.MustCompile(`^/waf/template/\{template_id\}/[a-z0-9][a-z0-9_-]*$`)
)

// WAFModuleEndpoint is static descriptor metadata for one app-scoped WAF
// module. Path must use the exact /waf/apps/{ep_id}/<static-segment> form.
type WAFModuleEndpoint struct {
	Path      string
	Operation string
}

// WAFTemplateModuleEndpoint is static descriptor metadata for one
// template-scoped WAF module.
type WAFTemplateModuleEndpoint struct {
	Path      string
	Operation string
}

// Validate rejects endpoint metadata that could address anything except one
// reviewed app-scoped WAF module path.
func (e WAFModuleEndpoint) Validate() error {
	if strings.Count(e.Path, wafModuleEPIDPlaceholder) != 1 || !wafModulePathPattern.MatchString(e.Path) {
		return fmt.Errorf("WAF module endpoint path must match /waf/apps/{ep_id}/<static-segment>")
	}
	operation := strings.TrimSpace(e.Operation)
	if operation == "" {
		return fmt.Errorf("WAF module endpoint operation must not be empty")
	}
	for _, character := range operation {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("WAF module endpoint operation must not contain control characters")
		}
	}
	return nil
}

// Validate rejects endpoint metadata that could address anything except one
// reviewed template-scoped WAF module path.
func (e WAFTemplateModuleEndpoint) Validate() error {
	if strings.Count(e.Path, wafModuleTemplateIDPlaceholder) != 1 || !wafTemplateModulePathPattern.MatchString(e.Path) {
		return fmt.Errorf("WAF template module endpoint path must match /waf/template/{template_id}/<static-segment>")
	}
	return validateWAFModuleOperation(e.Operation)
}

// GetWAFModule returns the complete document for a statically described WAF
// module endpoint.
func (c *Client) GetWAFModule(ctx context.Context, endpoint WAFModuleEndpoint, epID string) (WAFModuleDocument, error) {
	resolvedPath, err := endpoint.resolve(epID)
	if err != nil {
		return WAFModuleDocument{}, err
	}
	var response WAFModuleDocument
	err = c.doJSON(
		ctx,
		Operation{Name: "get " + strings.TrimSpace(endpoint.Operation), Retry: RetrySafe},
		http.MethodGet,
		resolvedPath,
		nil,
		nil,
		&response,
		true,
	)
	return response, err
}

// PutWAFModule replaces the complete result for a statically described WAF
// module endpoint. Conflict responses are returned without transport retry so
// the resource layer can perform a fresh GET and merge.
func (c *Client) PutWAFModule(ctx context.Context, endpoint WAFModuleEndpoint, epID string, result WAFModuleResult) error {
	resolvedPath, err := endpoint.resolve(epID)
	if err != nil {
		return err
	}
	return c.doJSON(
		ctx,
		Operation{Name: "put " + strings.TrimSpace(endpoint.Operation), Retry: RetrySafe},
		http.MethodPut,
		resolvedPath,
		nil,
		result,
		nil,
		true,
	)
}

func (e WAFModuleEndpoint) resolve(epID string) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	epID = strings.TrimSpace(epID)
	if epID == "" {
		return "", fmt.Errorf("application ID must not be empty")
	}
	resolved := strings.Replace(e.Path, wafModuleEPIDPlaceholder, url.PathEscape(epID), 1)
	return strings.TrimPrefix(resolved, "/"), nil
}

// GetWAFTemplateModule returns the complete document for a statically
// described template module endpoint. The template flag may be omitted by the
// API; configs remains mandatory.
func (c *Client) GetWAFTemplateModule(ctx context.Context, endpoint WAFTemplateModuleEndpoint, templateID string) (WAFTemplateModuleDocument, error) {
	resolvedPath, err := endpoint.resolve(templateID)
	if err != nil {
		return WAFTemplateModuleDocument{}, err
	}
	var response WAFTemplateModuleDocument
	err = c.doJSON(
		ctx,
		Operation{Name: "get template " + strings.TrimSpace(endpoint.Operation), Retry: RetrySafe},
		http.MethodGet,
		resolvedPath,
		nil,
		nil,
		&response,
		true,
	)
	return response, err
}

// PutWAFTemplateModule replaces the complete result for a statically
// described template module endpoint.
func (c *Client) PutWAFTemplateModule(ctx context.Context, endpoint WAFTemplateModuleEndpoint, templateID string, result WAFModuleResult) error {
	resolvedPath, err := endpoint.resolve(templateID)
	if err != nil {
		return err
	}
	result.Template = false
	return c.doJSON(
		ctx,
		Operation{Name: "put template " + strings.TrimSpace(endpoint.Operation), Retry: RetrySafe},
		http.MethodPut,
		resolvedPath,
		nil,
		result,
		nil,
		true,
	)
}

func (e WAFTemplateModuleEndpoint) resolve(templateID string) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	templateID = strings.TrimSpace(templateID)
	if templateID == "" {
		return "", fmt.Errorf("template ID must not be empty")
	}
	resolved := strings.Replace(e.Path, wafModuleTemplateIDPlaceholder, url.PathEscape(templateID), 1)
	return strings.TrimPrefix(resolved, "/"), nil
}

func validateWAFModuleOperation(operation string) error {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return fmt.Errorf("WAF module endpoint operation must not be empty")
	}
	for _, character := range operation {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("WAF module endpoint operation must not contain control characters")
		}
	}
	return nil
}
