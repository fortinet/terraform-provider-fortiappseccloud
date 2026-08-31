package generator

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"go/format"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var templateFiles embed.FS

func renderOutputs(manifest Manifest) (map[string][]byte, error) {
	if len(manifest.Resources) == 0 {
		return nil, fmt.Errorf("renderer requires at least one reviewed resource")
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render generated manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	model, err := buildRenderModel(manifest)
	if err != nil {
		return nil, err
	}

	outputs := map[string][]byte{manifestOutputPath: manifestBytes}

	// One register file ranges all resources.
	registerRendered, err := executeTemplate("templates/register.go.tmpl", model)
	if err != nil {
		return nil, err
	}
	registerFormatted, err := format.Source(registerRendered)
	if err != nil {
		return nil, fmt.Errorf("gofmt generated %s: %w", registerOutputPath, err)
	}
	outputs[registerOutputPath] = registerFormatted

	// One shared app/template codec and two docs pages per resource.
	for _, resource := range model.Resources {
		data := struct {
			Marker   string
			Manifest Manifest
			Resource ResourceRender
		}{
			Marker:   generatedMarker,
			Manifest: manifest,
			Resource: resource,
		}
		goPath := resourceOutputPath(resource.TypeNameSuffix)
		goRendered, err := executeTemplate("templates/resource.go.tmpl", data)
		if err != nil {
			return nil, err
		}
		goFormatted, err := format.Source(goRendered)
		if err != nil {
			return nil, fmt.Errorf("gofmt generated %s: %w", goPath, err)
		}
		outputs[goPath] = goFormatted

		docsPath := docsOutputPath(resource.TypeNameSuffix)
		docsRendered, err := executeTemplate("templates/resource.md.tmpl", data)
		if err != nil {
			return nil, err
		}
		outputs[docsPath] = docsRendered

		templateDocsPath := templateDocsOutputPath(resource.TypeNameSuffix)
		templateDocsRendered, err := executeTemplate("templates/template_resource.md.tmpl", data)
		if err != nil {
			return nil, err
		}
		outputs[templateDocsPath] = templateDocsRendered
	}

	want := 2 + 3*len(manifest.Resources)
	if len(outputs) != want {
		return nil, fmt.Errorf("renderer produced %d outputs, want %d", len(outputs), want)
	}
	return outputs, nil
}

func executeTemplate(name string, data any) ([]byte, error) {
	source, err := templateFiles.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read embedded template %s: %w", name, err)
	}
	tmpl, err := template.New(name).Funcs(templateFuncs()).Option("missingkey=error").Parse(string(source))
	if err != nil {
		return nil, fmt.Errorf("parse embedded template %s: %w", name, err)
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("execute embedded template %s: %w", name, err)
	}
	return output.Bytes(), nil
}

// templateFuncs provides the helpers shared by all templates.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"join":                      strings.Join,
		"quote":                     func(s string) string { return `"` + s + `"` },
		"sortedResources":           sortedResources,
		"enumOneOfArgs":             enumOneOfArgs,
		"enumProse":                 enumProse,
		"providerIntDefault":        providerIntDefault,
		"providerBoolDefault":       providerBoolDefault,
		"providerStringDefault":     providerStringDefault,
		"providerStringDefaultJSON": providerStringDefaultJSON,
		"hasSubItemArray":           hasSubItemArray,
		"hasItemStringArray":        hasItemStringArray,
		"boundCheck":                boundCheck,
		"trimWAFPrefix":             func(value string) string { return strings.TrimPrefix(value, "waf_") },
	}
}

// boundCheck renders the Go boolean expression that tests an integer value
// (valueExpr) against the reviewed bound(s). A two-sided range produces
// "valueExpr < min || valueExpr > max"; a min-only bound produces
// "valueExpr < min"; a max-only bound produces "valueExpr > max". A missing
// endpoint is never treated as zero. It returns "" when neither bound is
// present, so the template can guard the whole check with {{if boundCheck ...}}.
func boundCheck(hasMin, hasMax bool, min, max int64, valueExpr string) string {
	switch {
	case hasMin && hasMax:
		return fmt.Sprintf("%s < %d || %s > %d", valueExpr, min, valueExpr, max)
	case hasMin:
		return fmt.Sprintf("%s < %d", valueExpr, min)
	case hasMax:
		return fmt.Sprintf("%s > %d", valueExpr, max)
	}
	return ""
}

// hasSubItemArray reports whether any item field in the collection is a nested
// array-of-objects (Kind == "array" with SubItemArray).
func hasSubItemArray(fields []ItemFieldRender) bool {
	for _, f := range fields {
		if f.Kind == "array" && f.SubItemArray != nil {
			return true
		}
	}
	return false
}

// hasItemStringArray reports whether any item field in the collection is an
// item-level scalar-string-array (Kind == "string_array" with
// ItemScalarStringArray).
func hasItemStringArray(fields []ItemFieldRender) bool {
	for _, f := range fields {
		if f.Kind == "string_array" && f.ItemScalarStringArray != nil {
			return true
		}
	}
	return false
}

// providerIntDefault renders a reviewed integer provider default as a Go
// integer literal, or 0 when no default is pinned. Used for optional item
// integer fields so omission sends the reviewed default instead of 0.
func providerIntDefault(value *int64) string {
	if value == nil {
		return "0"
	}
	return strconv.FormatInt(*value, 10)
}

// providerBoolDefault renders a reviewed boolean provider default as a Go
// boolean literal, or false when no default is pinned. Used for optional item
// boolean fields so omission sends the reviewed default (false for filter-like
// fields, true for known_bots item status) instead of the zero value.
func providerBoolDefault(value *bool) string {
	if value == nil {
		return "false"
	}
	if *value {
		return "true"
	}
	return "false"
}

// providerStringDefault renders a reviewed string provider default as a Go
// double-quoted string literal, or "" when no default is pinned. Used for
// optional nested string fields so omission sends the reviewed default.
func providerStringDefault(value *string) string {
	if value == nil {
		return `""`
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(*value, `\`, `\\`), `"`, `\"`) + `"`
}

// providerStringDefaultJSON renders a reviewed string provider default as a Go
// double-quoted string literal whose VALUE is the JSON encoding of the default
// (including the surrounding JSON quotes), e.g. for default HTTP the literal's
// value is the 6 bytes `"HTTP"`. Used by the unchanged-projection
// canonicalization, which compares raw JSON bytes (a JSON string is encoded
// with surrounding quotes) against the reviewed default, so an absent string
// and an explicit-default string compare equal. Returns `""` when no default
// is pinned (empty/absent equivalence).
func providerStringDefaultJSON(value *string) string {
	if value == nil {
		return `""`
	}
	escaped := strings.ReplaceAll(strings.ReplaceAll(*value, `\`, `\\`), `"`, `\"`)
	// The Go literal's value must be the JSON form: "escaped" with surrounding
	// quotes as part of the value, so the Go source is "\"escaped\"".
	return `"` + `\"` + escaped + `\"` + `"`
}

// enumProse renders the comma-separated enum values for use inside a Go
// string literal (error messages): alert, alert_deny, deny_no_log.
func enumProse(values []string) string {
	return strings.Join(values, ", ")
}

func sortedResources(model RenderModel) []ResourceRender {
	resources := append([]ResourceRender(nil), model.Resources...)
	sort.SliceStable(resources, func(i, j int) bool { return resources[i].TerraformName < resources[j].TerraformName })
	return resources
}

// OutputPaths returns the deterministic generated output path set.
func OutputPaths(outputs map[string][]byte) []string {
	paths := make([]string, 0, len(outputs))
	for path := range outputs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
