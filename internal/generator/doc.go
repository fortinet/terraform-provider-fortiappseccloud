// Package generator builds the reviewed app-scoped WAF OpenAPI vertical slice
// and renders deterministic Framework resource codecs, a register file, and
// docs pages for each reviewed generated resource.
//
//go:generate go run ../../cmd/wafdocgen -root ../..
//go:generate go run ../../cmd/wafgen -root ../..
package generator
