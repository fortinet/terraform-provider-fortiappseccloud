package wafmodule

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-fortiappseccloud/internal/client"
)

var typeNameSuffixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// DestroyMode identifies a reviewed module-specific destroy behavior.
type DestroyMode string

const (
	// DestroyForget removes the Terraform object without changing a remote
	// module that has no verified delete or disable operation.
	DestroyForget DestroyMode = "forget"
	// DestroyDisable writes a reviewed top-level boolean config field to false,
	// verifies the normalized response, and then allows Terraform to forget state.
	DestroyDisable DestroyMode = "disable"

	// VerifiedTemplateStatusDisableReason records the template-specific
	// evidence used by the hand-written template-module descriptors.
	VerifiedTemplateStatusDisableReason = "Template module configs.status=false disable behavior was verified in the accepted complete dev1 template matrix and confirmed as the module disable API behavior"
)

// DestroyPolicy records the reviewed behavior and evidence attached to a
// static module descriptor. Additional modes require their own verified
// implementation before the runtime accepts them.
type DestroyPolicy struct {
	Mode          DestroyMode
	Verified      bool
	Reason        string
	CoupledFields []string
	// Field records the reviewed top-level boolean configs field used by an
	// active disable policy or proposed for an individually gated promotion.
	// A forget policy may carry the candidate field without changing remote
	// state; a disable policy must carry exact live-verification provenance.
	Field string
}

// Descriptor binds static API metadata to a generated schema-specific codec.
type Descriptor struct {
	TypeNameSuffix string
	Endpoint       client.WAFModuleEndpoint
	Codec          Codec
	Destroy        DestroyPolicy
}

// Validate checks static descriptor metadata before a resource operation can
// address the API.
func (d Descriptor) Validate() error {
	if !typeNameSuffixPattern.MatchString(d.TypeNameSuffix) {
		return fmt.Errorf("WAF module type name suffix must contain only lowercase letters, digits, and underscores and start with a letter")
	}
	if err := d.Endpoint.Validate(); err != nil {
		return fmt.Errorf("invalid WAF module endpoint: %w", err)
	}
	if d.Codec == nil {
		return fmt.Errorf("WAF module codec must not be nil")
	}
	switch d.Destroy.Mode {
	case DestroyForget:
		if len(d.Destroy.CoupledFields) != 0 {
			return fmt.Errorf("app forget destroy policy must not declare coupled disable fields")
		}
		if d.Destroy.Verified {
			return fmt.Errorf("forget destroy policy must not be marked verified")
		}
		if strings.TrimSpace(d.Destroy.Reason) == "" {
			return fmt.Errorf("forget destroy policy must include a reason")
		}
		if strings.TrimSpace(d.Destroy.Field) != "" {
			if err := d.validateDestroyField(); err != nil {
				return fmt.Errorf("invalid candidate disable field: %w", err)
			}
		}
	case DestroyDisable:
		if len(d.Destroy.CoupledFields) != 0 {
			return fmt.Errorf("app disable destroy policy does not support coupled disable fields")
		}
		if !d.Destroy.Verified {
			return fmt.Errorf("disable destroy policy must be live verified")
		}
		if strings.TrimSpace(d.Destroy.Field) == "" {
			return fmt.Errorf("disable destroy policy must declare its top-level boolean config field")
		}
		if strings.TrimSpace(d.Destroy.Reason) == "" {
			return fmt.Errorf("disable destroy policy must include verification provenance")
		}
		if err := d.validateDestroyField(); err != nil {
			return fmt.Errorf("invalid disable field: %w", err)
		}
	default:
		return fmt.Errorf("unsupported WAF module destroy mode %q", d.Destroy.Mode)
	}
	return nil
}

func (d Descriptor) validateDestroyField() error {
	return validateDestroyField(d.Codec.Schema(context.Background()), d.Destroy.Field)
}

// Codec is the generated boundary between the shared lifecycle and a module's
// nested Terraform model. Implementations must not retain request state across
// calls.
type Codec interface {
	Schema(context.Context) schema.Schema
	ValidateConfig(context.Context, tfsdk.Config) diag.Diagnostics
	BuildPatch(context.Context, tfsdk.Config, tfsdk.Plan, tfsdk.State) (Patch, diag.Diagnostics)
	ValidateResult(context.Context, client.WAFModuleResult, OwnershipContext) diag.Diagnostics
	Flatten(context.Context, string, client.WAFModuleResult, OwnershipContext) (any, diag.Diagnostics)
}

// TemplateCodec adapts one typed app-module codec to the corresponding
// template-scoped GET/PUT pair. It intentionally has its own build and flatten
// entry points because template resources expose template_id + configs rather
// than ep_id + template + configs.
type TemplateCodec interface {
	Schema(context.Context) schema.Schema
	ValidateTemplateConfig(context.Context, tfsdk.Config) diag.Diagnostics
	BuildTemplatePatch(context.Context, tfsdk.Config, tfsdk.Plan, tfsdk.State) (Patch, diag.Diagnostics)
	ValidateResult(context.Context, client.WAFModuleResult, OwnershipContext) diag.Diagnostics
	FlattenTemplate(context.Context, string, client.WAFModuleResult, OwnershipContext) (any, diag.Diagnostics)
}

// TemplateDescriptor binds one typed codec to one reviewed template module
// endpoint.
type TemplateDescriptor struct {
	TypeNameSuffix  string
	Endpoint        client.WAFTemplateModuleEndpoint
	Codec           TemplateCodec
	Destroy         DestroyPolicy
	NormalizeForPut func(client.WAFModuleResult) (client.WAFModuleResult, error)
}

// Validate checks template module descriptor metadata before it can address
// the API.
func (d TemplateDescriptor) Validate() error {
	if !typeNameSuffixPattern.MatchString(d.TypeNameSuffix) {
		return fmt.Errorf("WAF template module type name suffix must contain only lowercase letters, digits, and underscores and start with a letter")
	}
	if !strings.HasPrefix(d.TypeNameSuffix, "waf_template_") {
		return fmt.Errorf("WAF template module type name suffix must start with waf_template_")
	}
	if err := d.Endpoint.Validate(); err != nil {
		return fmt.Errorf("invalid WAF template module endpoint: %w", err)
	}
	if d.Codec == nil {
		return fmt.Errorf("WAF template module codec must not be nil")
	}
	switch d.Destroy.Mode {
	case DestroyForget:
		if len(d.Destroy.CoupledFields) != 0 {
			return fmt.Errorf("template forget destroy policy must not declare coupled disable fields")
		}
		if d.Destroy.Verified {
			return fmt.Errorf("template forget destroy policy must not be marked verified")
		}
		if strings.TrimSpace(d.Destroy.Reason) == "" {
			return fmt.Errorf("template forget destroy policy must include a reason")
		}
		if strings.TrimSpace(d.Destroy.Field) != "" {
			if err := validateDestroyField(d.Codec.Schema(context.Background()), d.Destroy.Field); err != nil {
				return fmt.Errorf("invalid template candidate disable field: %w", err)
			}
		}
	case DestroyDisable:
		if !d.Destroy.Verified {
			return fmt.Errorf("template disable destroy policy must be verified")
		}
		if strings.TrimSpace(d.Destroy.Reason) == "" {
			return fmt.Errorf("template disable destroy policy must include verification provenance")
		}
		if err := validateDestroyField(d.Codec.Schema(context.Background()), d.Destroy.Field); err != nil {
			return fmt.Errorf("invalid template disable field: %w", err)
		}
		if err := validateTemplateCoupledDestroyFields(d.Codec.Schema(context.Background()), d.Destroy.CoupledFields); err != nil {
			return fmt.Errorf("invalid template coupled disable fields: %w", err)
		}
	default:
		return fmt.Errorf("unsupported WAF template module destroy mode %q", d.Destroy.Mode)
	}
	return nil
}

func validateTemplateCoupledDestroyFields(resourceSchema schema.Schema, fields []string) error {
	if len(fields) == 0 {
		return nil
	}
	if len(fields) != 2 || fields[0] != "cache.status" || fields[1] != "compress.status" {
		return fmt.Errorf("the only reviewed coupled disable fields are cache.status and compress.status")
	}
	for _, field := range fields {
		if err := validateNestedDestroyField(resourceSchema, field); err != nil {
			return err
		}
	}
	return nil
}

func validateNestedDestroyField(resourceSchema schema.Schema, candidate string) error {
	parts := strings.Split(candidate, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("coupled disable field %q must be one nested path below configs", candidate)
	}
	configs, ok := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	if !ok {
		return fmt.Errorf("codec schema must expose configs as a single nested block")
	}
	nested, ok := configs.Blocks[parts[0]].(schema.SingleNestedBlock)
	if !ok {
		return fmt.Errorf("codec schema configs.%s must be a single nested block", parts[0])
	}
	attribute, ok := nested.Attributes[parts[1]].(schema.BoolAttribute)
	if !ok {
		return fmt.Errorf("codec schema configs.%s must be a boolean attribute", candidate)
	}
	if !attribute.Required && !attribute.Optional {
		return fmt.Errorf("codec schema configs.%s must be writable", candidate)
	}
	return nil
}

func validateDestroyField(resourceSchema schema.Schema, candidate string) error {
	field := strings.TrimSpace(candidate)
	if field != "status" {
		return fmt.Errorf("top-level disable field must be %q", "status")
	}
	configs, ok := resourceSchema.Blocks["configs"].(schema.SingleNestedBlock)
	if !ok {
		return fmt.Errorf("codec schema must expose configs as a single nested block")
	}
	attribute, ok := configs.Attributes[field].(schema.BoolAttribute)
	if !ok {
		return fmt.Errorf("codec schema configs.%s must be a boolean attribute", field)
	}
	if !attribute.Required && !attribute.Optional {
		return fmt.Errorf("codec schema configs.%s must be writable", field)
	}
	return nil
}

// TemplateModel is the common top-level Terraform model for typed template
// module resources.
type TemplateModel struct {
	TemplateID types.String `tfsdk:"template_id"`
	Configs    types.Object `tfsdk:"configs"`
}

// Patch applies explicitly owned Terraform values to a cloned remote result.
type Patch interface {
	Apply(context.Context, *client.WAFModuleResult) diag.Diagnostics
}

// PatchFunc adapts a function into a Patch.
type PatchFunc func(context.Context, *client.WAFModuleResult) diag.Diagnostics

// Apply implements Patch.
func (f PatchFunc) Apply(ctx context.Context, result *client.WAFModuleResult) diag.Diagnostics {
	return f(ctx, result)
}
