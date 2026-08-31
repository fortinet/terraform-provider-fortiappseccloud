package waf

import (
	"reflect"
	"testing"

	"terraform-provider-fortiappseccloud/internal/resources/wafmodule"
)

func TestCachingCompressionTemplateDestroyPolicyUsesCoupledStatuses(t *testing.T) {
	t.Parallel()

	appDescriptor := cachingCompressionDescriptor()
	if appDescriptor.Destroy.Mode != wafmodule.DestroyForget || appDescriptor.Destroy.Verified {
		t.Fatalf("app destroy policy = %#v, want forget", appDescriptor.Destroy)
	}

	templateDescriptor := cachingCompressionTemplateDescriptor()
	if templateDescriptor.Destroy.Mode != wafmodule.DestroyDisable || !templateDescriptor.Destroy.Verified ||
		templateDescriptor.Destroy.Field != "status" ||
		!reflect.DeepEqual(templateDescriptor.Destroy.CoupledFields, []string{"cache.status", "compress.status"}) {
		t.Fatalf("template destroy policy = %#v, want reviewed coupled disable", templateDescriptor.Destroy)
	}
	if err := templateDescriptor.Validate(); err != nil {
		t.Fatalf("template descriptor validation failed: %v", err)
	}
}
