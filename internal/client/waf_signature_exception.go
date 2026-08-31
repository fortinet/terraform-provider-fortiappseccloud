package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SignatureExceptionView is the complete public GET projection for one
// signature exception. The public contract exposes only the optional template
// identifier; it does not return the exception-rule object accepted by PUT.
type SignatureExceptionView struct {
	TemplateID *string
}

func (view *SignatureExceptionView) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("decode signature exception: response must be an object, not null")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("decode signature exception: %w", err)
	}
	result, present := object["result"]
	if !present {
		*view = SignatureExceptionView{}
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(result), []byte("null")) {
		return fmt.Errorf("decode signature exception result: explicit null is not accepted")
	}
	var resultObject map[string]json.RawMessage
	if err := json.Unmarshal(result, &resultObject); err != nil {
		return fmt.Errorf("decode signature exception result: %w", err)
	}
	template, present := resultObject["template"]
	if !present {
		*view = SignatureExceptionView{}
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(template), []byte("null")) {
		return fmt.Errorf("decode signature exception template: explicit null is not accepted")
	}
	var templateID string
	if err := json.Unmarshal(template, &templateID); err != nil {
		return fmt.Errorf("decode signature exception template: %w", err)
	}
	*view = SignatureExceptionView{TemplateID: &templateID}
	return nil
}

// GetSignatureException returns the limited public read-only view for one
// signature ID. It does not return or reconstruct exception rules.
func (c *Client) GetSignatureException(ctx context.Context, epID, signatureID string) (SignatureExceptionView, error) {
	epID = strings.TrimSpace(epID)
	if epID == "" {
		return SignatureExceptionView{}, fmt.Errorf("application ID must not be empty")
	}
	signatureID = strings.TrimSpace(signatureID)
	if signatureID == "" {
		return SignatureExceptionView{}, fmt.Errorf("signature ID must not be empty")
	}
	query := url.Values{"signatureid": []string{signatureID}}
	var response SignatureExceptionView
	err := c.doJSON(
		ctx,
		Operation{Name: "get signature exception", Retry: RetrySafe},
		http.MethodGet,
		"waf/apps/"+url.PathEscape(epID)+"/signature_exception",
		query,
		nil,
		&response,
		true,
	)
	return response, err
}
