package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"

	"terraform-provider-fortiappseccloud/internal/contract"
	frameworkprovider "terraform-provider-fortiappseccloud/internal/provider"
)

func TestGeneratedManifestCoversRegisteredModules(t *testing.T) {
	t.Parallel()

	type manifestResource struct {
		TerraformName string `json:"terraform_name"`
		GoName        string `json:"go_name"`
		Source        struct {
			GetMethod       string `json:"get_method"`
			GetPath         string `json:"get_path"`
			PutMethod       string `json:"put_method"`
			PutPath         string `json:"put_path"`
			TemplateGetPath string `json:"template_get_path"`
			TemplatePutPath string `json:"template_put_path"`
		} `json:"source"`
		ReviewedPolicy struct {
			TerraformName string `json:"terraform_name"`
			GoName        string `json:"go_name"`
			TypeName      string `json:"type_name_suffix"`
			GetPath       string `json:"get_path"`
			PutPath       string `json:"put_path"`
		} `json:"reviewed_policy"`
	}
	var manifest struct {
		Scope struct {
			SelectedResourceCount int `json:"selected_resource_count"`
		} `json:"scope"`
		Resources []manifestResource `json:"resources"`
	}
	manifestData, err := os.ReadFile(filepath.Join("internal", "generator", "manifest", "waf_modules.generated.json"))
	if err != nil {
		t.Fatalf("read generated manifest: %v", err)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode generated manifest: %v", err)
	}
	if manifest.Scope.SelectedResourceCount != 26 || len(manifest.Resources) != 26 {
		t.Fatalf("manifest generated resource counts = %d/%d, want 26/26", manifest.Scope.SelectedResourceCount, len(manifest.Resources))
	}

	server := providerserver.NewProtocol5(frameworkprovider.New("test", "test")())()
	schemas, err := server.GetProviderSchema(context.Background(), &tfprotov5.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("get provider schema: %v", err)
	}
	if len(schemas.ResourceSchemas) != 71 || len(schemas.DataSourceSchemas) != 2 {
		t.Fatalf("served schema counts = %d resources/%d data sources, want 71/2", len(schemas.ResourceSchemas), len(schemas.DataSourceSchemas))
	}

	indexData, err := os.ReadFile(filepath.Join("website", "docs", "index.html.markdown"))
	if err != nil {
		t.Fatalf("read public documentation index: %v", err)
	}
	index := string(indexData)
	for typeName := range schemas.ResourceSchemas {
		if !strings.Contains(index, typeName) {
			t.Errorf("public documentation index is missing served resource %q", typeName)
		}
	}
	for typeName := range schemas.DataSourceSchemas {
		if !strings.Contains(index, typeName) {
			t.Errorf("public documentation index is missing served data source %q", typeName)
		}
	}

	templateExampleData, err := os.ReadFile(filepath.Join("examples", "waf-template", "main.tf"))
	if err != nil {
		t.Fatalf("read template examples: %v", err)
	}
	templateExamples := string(templateExampleData)
	if !strings.Contains(templateExamples, `resource "fortiappseccloud_waf_template"`) ||
		!strings.Contains(templateExamples, `resource "fortiappseccloud_waf_template_csrf_protection"`) {
		t.Fatal("shared template example must cover template CRUD and one typed template module")
	}

	reviewed := contract.ImplementedGeneratedResources()
	reviewedByName := make(map[string]contract.ReviewedCandidate, len(reviewed))
	for _, candidate := range reviewed {
		reviewedByName[candidate.TerraformName] = candidate
	}
	if len(reviewedByName) != 26 {
		t.Fatalf("reviewed generated resources = %d, want 26", len(reviewedByName))
	}

	manifestNames := make([]string, 0, len(manifest.Resources))
	for _, generated := range manifest.Resources {
		generated := generated
		module := strings.TrimPrefix(generated.TerraformName, "fortiappseccloud_waf_")
		t.Run(module, func(t *testing.T) {
			t.Parallel()
			candidate, ok := reviewedByName[generated.TerraformName]
			if !ok {
				t.Fatalf("manifest resource %q has no reviewed generated contract", generated.TerraformName)
			}
			if generated.GoName != candidate.GoName || generated.Source.GetMethod != "GET" || generated.Source.PutMethod != "PUT" ||
				generated.Source.GetPath != candidate.Path || generated.Source.PutPath != candidate.Path {
				t.Fatalf("manifest source does not match reviewed contract: manifest=%#v candidate=%#v", generated, candidate)
			}
			if generated.ReviewedPolicy.TerraformName != candidate.TerraformName || generated.ReviewedPolicy.GoName != candidate.GoName ||
				generated.ReviewedPolicy.TypeName != candidate.TypeNameSuffix || generated.ReviewedPolicy.GetPath != candidate.Path ||
				generated.ReviewedPolicy.PutPath != candidate.Path {
				t.Fatalf("reviewed manifest policy does not match %q", candidate.TerraformName)
			}
			templateType := "fortiappseccloud_waf_template_" + module
			wantTemplatePath := "/waf/template/{template_id}/" + module
			if generated.Source.TemplateGetPath != wantTemplatePath || generated.Source.TemplatePutPath != wantTemplatePath {
				t.Fatalf("template paths = %q/%q, want %q", generated.Source.TemplateGetPath, generated.Source.TemplatePutPath, wantTemplatePath)
			}
			if schemas.ResourceSchemas[generated.TerraformName] == nil || schemas.ResourceSchemas[templateType] == nil {
				t.Fatalf("provider does not serve app/template resource pair %q/%q", generated.TerraformName, templateType)
			}

			for _, requiredFile := range []string{
				filepath.Join("internal", "resources", "generated", "waf", "resource_"+module+".go"),
				filepath.Join("examples", "waf", module+".tf"),
				filepath.Join("website", "docs", "r", "waf_"+module+".html.markdown"),
				filepath.Join("website", "docs", "r", "waf_template_"+module+".html.markdown"),
			} {
				if info, statErr := os.Stat(requiredFile); statErr != nil || info.IsDir() {
					t.Errorf("required generated artifact %q is missing: %v", requiredFile, statErr)
				}
			}
			if !strings.Contains(index, generated.TerraformName) || !strings.Contains(index, templateType) {
				t.Errorf("public documentation index does not contain generated resource pair %q/%q", generated.TerraformName, templateType)
			}
		})
		manifestNames = append(manifestNames, generated.TerraformName)
	}

	reviewedNames := make([]string, 0, len(reviewedByName))
	for name := range reviewedByName {
		reviewedNames = append(reviewedNames, name)
	}
	sort.Strings(manifestNames)
	sort.Strings(reviewedNames)
	if !reflect.DeepEqual(manifestNames, reviewedNames) {
		t.Fatalf("manifest resources = %#v, want reviewed resources %#v", manifestNames, reviewedNames)
	}
}

func TestTerraformDocumentationInventoryMatchesProviderSchema(t *testing.T) {
	t.Parallel()

	server := providerserver.NewProtocol5(frameworkprovider.New("test", "test")())()
	schemas, err := server.GetProviderSchema(context.Background(), &tfprotov5.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("get provider schema: %v", err)
	}
	if schemas.Provider == nil || schemas.Provider.Block == nil {
		t.Fatal("served provider schema is missing")
	}

	indexData, err := os.ReadFile(filepath.Join("website", "docs", "index.html.markdown"))
	if err != nil {
		t.Fatalf("read provider documentation index: %v", err)
	}
	index := string(indexData)
	for _, attribute := range schemas.Provider.Block.Attributes {
		if !strings.Contains(index, "* `"+attribute.Name+"` -") {
			t.Errorf("provider documentation is missing argument %q", attribute.Name)
		}
	}

	checkInventory := func(kind, directory, linkDirectory string, served map[string]*tfprotov5.Schema) {
		t.Helper()

		wantFiles := make([]string, 0, len(served))
		for typeName := range served {
			fileName := strings.TrimPrefix(typeName, "fortiappseccloud_") + ".html.markdown"
			wantFiles = append(wantFiles, fileName)
			// The Terraform Registry serves documentation without a .html
			// suffix, so registry-relative links must be extension-less.
			link := "[`" + typeName + "`](" + linkDirectory + "/" + strings.TrimSuffix(strings.TrimSuffix(fileName, ".markdown"), ".html") + ")"
			if !strings.Contains(index, link) {
				t.Errorf("provider index is missing %s link %q", kind, link)
			}
		}
		sort.Strings(wantFiles)

		entries, readErr := os.ReadDir(directory)
		if readErr != nil {
			t.Fatalf("read %s documentation directory: %v", kind, readErr)
		}
		gotFiles := make([]string, 0, len(entries))
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".html.markdown") {
				gotFiles = append(gotFiles, entry.Name())
			}
		}
		sort.Strings(gotFiles)
		if !reflect.DeepEqual(gotFiles, wantFiles) {
			t.Errorf("%s documentation files = %#v, want exact served schema inventory %#v", kind, gotFiles, wantFiles)
		}
	}

	checkInventory("resource", filepath.Join("website", "docs", "r"), "r", schemas.ResourceSchemas)
	checkInventory("data source", filepath.Join("website", "docs", "d"), "d", schemas.DataSourceSchemas)
}
