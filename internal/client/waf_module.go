package client

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// WAFModuleDocument is the strict GET wrapper shared by app-scoped WAF modules.
type WAFModuleDocument struct {
	Result WAFModuleResult
}

// WAFTemplateModuleDocument is the GET wrapper used by template-scoped WAF
// module endpoints. The pinned OpenAPI reuses the app module schemas, while
// reviewed template examples are inconsistent about including template=false.
// Template module reads therefore accept an omitted template flag, but still
// require the complete configs object. App module reads remain strict.
type WAFTemplateModuleDocument struct {
	Result WAFModuleResult
}

// WAFModuleResult is the complete PUT envelope. Raw fields are retained so
// future API properties survive GET-merge-PUT updates.
type WAFModuleResult struct {
	Configs  map[string]json.RawMessage
	Template bool
	raw      map[string]json.RawMessage
}

func (d *WAFModuleDocument) UnmarshalJSON(data []byte) error {
	return d.unmarshalJSON(data, true)
}

func (d *WAFModuleDocument) unmarshalJSON(data []byte, requireTemplate bool) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("decode WAF module response: %w", err)
	}
	result, ok := object["result"]
	if !ok || isJSONNull(result) {
		return fmt.Errorf("decode WAF module response: missing result object")
	}
	if err := d.Result.unmarshalJSON(result, requireTemplate); err != nil {
		return fmt.Errorf("decode WAF module response result: %w", err)
	}
	return nil
}

func (d *WAFTemplateModuleDocument) UnmarshalJSON(data []byte) error {
	var document WAFModuleDocument
	if err := document.unmarshalJSON(data, false); err != nil {
		return err
	}
	if document.Result.Template {
		return fmt.Errorf("decode WAF template module response result: template flag must be false when present")
	}
	d.Result = document.Result
	return nil
}

func (r *WAFModuleResult) UnmarshalJSON(data []byte) error {
	return r.unmarshalJSON(data, true)
}

func (r *WAFModuleResult) unmarshalJSON(data []byte, requireTemplate bool) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return fmt.Errorf("decode WAF module result: %w", err)
	}

	configs, ok := object["configs"]
	if !ok || isJSONNull(configs) {
		return fmt.Errorf("decode WAF module result: missing configs object")
	}
	var configObject map[string]json.RawMessage
	if err := json.Unmarshal(configs, &configObject); err != nil {
		return fmt.Errorf("decode WAF module configs: %w", err)
	}

	template, ok := object["template"]
	if requireTemplate && (!ok || isJSONNull(template)) {
		return fmt.Errorf("decode WAF module result: missing template flag")
	}
	var templateValue bool
	if ok && !isJSONNull(template) {
		if err := json.Unmarshal(template, &templateValue); err != nil {
			return fmt.Errorf("decode WAF module template flag: %w", err)
		}
	} else if ok {
		return fmt.Errorf("decode WAF module result: null template flag")
	}

	r.Configs = cloneRawMap(configObject)
	r.Template = templateValue
	r.raw = cloneRawMap(object)
	return nil
}

func (r WAFModuleResult) MarshalJSON() ([]byte, error) {
	object := cloneRawMap(r.raw)
	if object == nil {
		object = make(map[string]json.RawMessage)
	}
	configs, err := json.Marshal(r.Configs)
	if err != nil {
		return nil, fmt.Errorf("encode WAF module configs: %w", err)
	}
	template, err := json.Marshal(r.Template)
	if err != nil {
		return nil, fmt.Errorf("encode WAF module template flag: %w", err)
	}
	object["configs"] = configs
	object["template"] = template
	return json.Marshal(object)
}

// Clone returns a deep copy suitable for a presence-aware merge.
func (r WAFModuleResult) Clone() WAFModuleResult {
	return WAFModuleResult{
		Configs:  cloneRawMap(r.Configs),
		Template: r.Template,
		raw:      cloneRawMap(r.raw),
	}
}

// SetConfig replaces one known config field without disturbing unknown fields.
func (r *WAFModuleResult) SetConfig(name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode WAF module config %q: %w", name, err)
	}
	if r.Configs == nil {
		r.Configs = make(map[string]json.RawMessage)
	}
	r.Configs[name] = encoded
	return nil
}

func cloneRawMap(source map[string]json.RawMessage) map[string]json.RawMessage {
	if source == nil {
		return nil
	}
	clone := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		clone[key] = append(json.RawMessage(nil), value...)
	}
	return clone
}

func isJSONNull(value json.RawMessage) bool {
	return len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}
