package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"terraform-provider-fortiappseccloud/internal/generator"
)

func main() {
	root := flag.String("root", ".", "repository root containing the pinned OpenAPI input")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("unexpected positional arguments: %v", flag.Args())
	}

	openAPI, err := os.ReadFile(filepath.Join(*root, "openapi_spec", "openapi.json"))
	if err != nil {
		fatalf("read pinned OpenAPI input: %v", err)
	}
	overrides, err := os.ReadFile(filepath.Join(*root, "internal", "generator", "profile", "waf", "overrides.json"))
	if err != nil {
		fatalf("read reviewed WAF overrides: %v", err)
	}
	outputs, err := generator.Generate(openAPI, overrides)
	if err != nil {
		fatalf("generate WAF resources: %v", err)
	}
	for _, path := range generator.OutputPaths(outputs) {
		target := filepath.Join(*root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			fatalf("create output directory for %s: %v", path, err)
		}
		if err := os.WriteFile(target, outputs[path], 0o644); err != nil {
			fatalf("write %s: %v", path, err)
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wafgen: "+format+"\n", args...)
	os.Exit(1)
}
