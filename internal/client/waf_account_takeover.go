package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Optional records whether a Terraform configuration value should be overlaid.
type Optional[T any] struct {
	Value T
	Set   bool
}

// AccountTakeoverConfig is the typed known projection of the account-takeover config.
type AccountTakeoverConfig struct {
	Action                 *string
	AuthURL                *string
	CredentialStuffing     *bool
	LogoffURL              *string
	Password               *string
	RedirectURL            *string
	ResponseBody           *string
	ReturnCode             *string
	SessionFixationProtect *bool
	SessionIDName          *string
	Status                 *bool
	Username               *string
}

// AccountTakeoverPatch overlays only fields explicitly present in Terraform configuration.
type AccountTakeoverPatch struct {
	Action                 Optional[string]
	AuthURL                Optional[string]
	CredentialStuffing     Optional[bool]
	LogoffURL              Optional[string]
	Password               Optional[string]
	RedirectURL            Optional[string]
	ResponseBody           Optional[string]
	ReturnCode             Optional[string]
	SessionFixationProtect Optional[bool]
	SessionIDName          Optional[string]
	Status                 Optional[bool]
	Username               Optional[string]
}

// AccountTakeoverDocument retains the complete raw module envelope and typed known fields.
type AccountTakeoverDocument struct {
	Result WAFModuleResult
	Config AccountTakeoverConfig
}

func (d *AccountTakeoverDocument) UnmarshalJSON(data []byte) error {
	var module WAFModuleDocument
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	config, err := decodeAccountTakeoverConfig(module.Result.Configs)
	if err != nil {
		return err
	}
	d.Result = module.Result
	d.Config = config
	return nil
}

// Clone returns a deep copy that can be safely modified for a PUT request.
func (d AccountTakeoverDocument) Clone() AccountTakeoverDocument {
	clone := AccountTakeoverDocument{Result: d.Result.Clone()}
	clone.Config, _ = decodeAccountTakeoverConfig(clone.Result.Configs)
	return clone
}

// Merge overlays explicitly configured fields while preserving current and unknown values.
func (d *AccountTakeoverDocument) Merge(patch AccountTakeoverPatch) error {
	fields := []struct {
		name  string
		set   bool
		value any
	}{
		{name: "action", set: patch.Action.Set, value: patch.Action.Value},
		{name: "auth_url", set: patch.AuthURL.Set, value: patch.AuthURL.Value},
		{name: "cred_stuffing_protect", set: patch.CredentialStuffing.Set, value: patch.CredentialStuffing.Value},
		{name: "logoff_url", set: patch.LogoffURL.Set, value: patch.LogoffURL.Value},
		{name: "password", set: patch.Password.Set, value: patch.Password.Value},
		{name: "redirect_url", set: patch.RedirectURL.Set, value: patch.RedirectURL.Value},
		{name: "response_body", set: patch.ResponseBody.Set, value: patch.ResponseBody.Value},
		{name: "return_code", set: patch.ReturnCode.Set, value: patch.ReturnCode.Value},
		{name: "sess_fixation_protect", set: patch.SessionFixationProtect.Set, value: patch.SessionFixationProtect.Value},
		{name: "sess_id_name", set: patch.SessionIDName.Set, value: patch.SessionIDName.Value},
		{name: "status", set: patch.Status.Set, value: patch.Status.Value},
		{name: "username", set: patch.Username.Set, value: patch.Username.Value},
	}
	for _, field := range fields {
		if !field.set {
			continue
		}
		if err := d.Result.SetConfig(field.name, field.value); err != nil {
			return err
		}
	}
	config, err := decodeAccountTakeoverConfig(d.Result.Configs)
	if err != nil {
		return err
	}
	d.Config = config
	return nil
}

// GetAccountTakeover returns the complete account-takeover module document.
func (c *Client) GetAccountTakeover(ctx context.Context, epID string) (AccountTakeoverDocument, error) {
	if epID == "" {
		return AccountTakeoverDocument{}, fmt.Errorf("application ID must not be empty")
	}
	var response AccountTakeoverDocument
	err := c.doJSON(ctx, Operation{Name: "get account takeover", Retry: RetrySafe}, http.MethodGet, "waf/apps/"+url.PathEscape(epID)+"/account_takeover", nil, nil, &response, true)
	return response, err
}

// PutAccountTakeover replaces the complete account-takeover module envelope.
func (c *Client) PutAccountTakeover(ctx context.Context, epID string, result WAFModuleResult) error {
	if epID == "" {
		return fmt.Errorf("application ID must not be empty")
	}
	return c.doJSON(ctx, Operation{Name: "put account takeover", Retry: RetrySafe}, http.MethodPut, "waf/apps/"+url.PathEscape(epID)+"/account_takeover", nil, result, nil, true)
}

func decodeAccountTakeoverConfig(configs map[string]json.RawMessage) (AccountTakeoverConfig, error) {
	action, err := decodeRequiredString(configs, "action")
	if err != nil {
		return AccountTakeoverConfig{}, err
	}
	status, err := decodeRequiredBool(configs, "status")
	if err != nil {
		return AccountTakeoverConfig{}, err
	}

	config := AccountTakeoverConfig{Action: &action, Status: &status}
	if config.AuthURL, err = decodeOptionalString(configs, "auth_url"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.CredentialStuffing, err = decodeOptionalBool(configs, "cred_stuffing_protect"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.LogoffURL, err = decodeOptionalString(configs, "logoff_url"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.Password, err = decodeOptionalString(configs, "password"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.RedirectURL, err = decodeOptionalString(configs, "redirect_url"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.ResponseBody, err = decodeOptionalString(configs, "response_body"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.ReturnCode, err = decodeOptionalString(configs, "return_code"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.SessionFixationProtect, err = decodeOptionalBool(configs, "sess_fixation_protect"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.SessionIDName, err = decodeOptionalString(configs, "sess_id_name"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	if config.Username, err = decodeOptionalString(configs, "username"); err != nil {
		return AccountTakeoverConfig{}, err
	}
	return config, nil
}

func decodeRequiredString(configs map[string]json.RawMessage, name string) (string, error) {
	value, ok := configs[name]
	if !ok || isJSONNull(value) {
		return "", fmt.Errorf("decode account takeover config: missing %s", name)
	}
	var decoded string
	if err := json.Unmarshal(value, &decoded); err != nil {
		return "", fmt.Errorf("decode account takeover config %s: %w", name, err)
	}
	return decoded, nil
}

func decodeRequiredBool(configs map[string]json.RawMessage, name string) (bool, error) {
	value, ok := configs[name]
	if !ok || isJSONNull(value) {
		return false, fmt.Errorf("decode account takeover config: missing %s", name)
	}
	var decoded bool
	if err := json.Unmarshal(value, &decoded); err != nil {
		return false, fmt.Errorf("decode account takeover config %s: %w", name, err)
	}
	return decoded, nil
}

func decodeOptionalString(configs map[string]json.RawMessage, name string) (*string, error) {
	value, ok := configs[name]
	if !ok {
		return nil, nil
	}
	if isJSONNull(value) {
		return nil, nil
	}
	var decoded string
	if err := json.Unmarshal(value, &decoded); err != nil {
		return nil, fmt.Errorf("decode account takeover config %s: %w", name, err)
	}
	return &decoded, nil
}

func decodeOptionalBool(configs map[string]json.RawMessage, name string) (*bool, error) {
	value, ok := configs[name]
	if !ok {
		return nil, nil
	}
	if isJSONNull(value) {
		return nil, nil
	}
	var decoded bool
	if err := json.Unmarshal(value, &decoded); err != nil {
		return nil, fmt.Errorf("decode account takeover config %s: %w", name, err)
	}
	return &decoded, nil
}
