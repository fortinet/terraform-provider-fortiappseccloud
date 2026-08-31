package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	// BaselineVersion is the FortiAppSec Cloud contract version reviewed by the v2 design.
	BaselineVersion = "26.3.a"
	// BaselineSHA256 pins the exact OpenAPI input used for contract extraction.
	BaselineSHA256 = "463015364e7d4d7cbd8f346a2e238928d1c7c741271656fec06bd8ed87e58e63"
)

var httpMethods = map[string]struct{}{
	"delete":  {},
	"get":     {},
	"head":    {},
	"options": {},
	"patch":   {},
	"post":    {},
	"put":     {},
	"trace":   {},
}

// Document is the normalized WAF operation inventory extracted from OpenAPI.
type Document struct {
	Version    string
	SHA256     string
	PathCount  int
	Operations []Operation
}

// Operation contains the contract metadata needed by the endpoint-classification phase.
type Operation struct {
	Path        string
	Method      string
	Summary     string
	Description string
	Tags        []string
	Public      bool
}

type openAPIDocument struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

type openAPIOperation struct {
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

// ParseOpenAPI extracts and deterministically sorts every /waf operation.
func ParseOpenAPI(data []byte) (Document, error) {
	var source openAPIDocument
	if err := json.Unmarshal(data, &source); err != nil {
		return Document{}, fmt.Errorf("decode OpenAPI document: %w", err)
	}

	digest := sha256.Sum256(data)
	document := Document{
		Version: source.Info.Version,
		SHA256:  hex.EncodeToString(digest[:]),
	}

	for path, pathItem := range source.Paths {
		if !strings.HasPrefix(path, "/waf/") && path != "/waf" {
			continue
		}
		document.PathCount++

		for method, rawOperation := range pathItem {
			method = strings.ToLower(method)
			if _, ok := httpMethods[method]; !ok {
				continue
			}

			var sourceOperation openAPIOperation
			if err := json.Unmarshal(rawOperation, &sourceOperation); err != nil {
				return Document{}, fmt.Errorf("decode %s %s: %w", strings.ToUpper(method), path, err)
			}
			document.Operations = append(document.Operations, Operation{
				Path:        path,
				Method:      strings.ToUpper(method),
				Summary:     sourceOperation.Summary,
				Description: sourceOperation.Description,
				Tags:        append([]string(nil), sourceOperation.Tags...),
				Public:      !contains(sourceOperation.Tags, "Non Public"),
			})
		}
	}

	sort.Slice(document.Operations, func(i, j int) bool {
		if document.Operations[i].Path == document.Operations[j].Path {
			return document.Operations[i].Method < document.Operations[j].Method
		}
		return document.Operations[i].Path < document.Operations[j].Path
	})

	return document, nil
}

// Find returns one operation by method and exact OpenAPI path.
func (d Document) Find(method, path string) (Operation, bool) {
	method = strings.ToUpper(method)
	for _, operation := range d.Operations {
		if operation.Method == method && operation.Path == path {
			return operation, true
		}
	}
	return Operation{}, false
}
