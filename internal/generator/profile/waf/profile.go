package waf

import _ "embed"

// DefaultOverridesJSON is the reviewed policy bundled with the generator.
//
//go:embed overrides.json
var DefaultOverridesJSON []byte
