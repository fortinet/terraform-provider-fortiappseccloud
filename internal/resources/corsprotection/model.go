package corsprotection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"terraform-provider-fortiappseccloud/internal/client"
)

type resourceModel struct {
	EPID     types.String `tfsdk:"ep_id"`
	Template types.Bool   `tfsdk:"template"`
	Configs  types.Object `tfsdk:"configs"`
}

type configsModel struct {
	Status             types.Bool   `tfsdk:"status"`
	BlockCorsTraffic   types.Bool   `tfsdk:"block_cors_traffic"`
	AllowedOrigins     types.Object `tfsdk:"allowed_origins"`
	AllowedMethods     types.Object `tfsdk:"allowed_methods"`
	AllowedHeaders     types.Object `tfsdk:"allowed_headers"`
	ExposedHeaders     types.Object `tfsdk:"exposed_headers"`
	URLPattern         types.String `tfsdk:"url_pattern"`
	AllowedCredentials types.String `tfsdk:"allowed_credentials"`
	AllowedMaximumAge  types.Int64  `tfsdk:"allowed_maximum_age"`
}

type allowedOriginsModel struct {
	Protocol          types.String `tfsdk:"protocol"`
	OriginName        types.String `tfsdk:"origin_name"`
	Port              types.Int64  `tfsdk:"port"`
	IncludeSubDomains types.Bool   `tfsdk:"include_sub_domains"`
}

type methodPolicyModel struct {
	Status  types.Bool `tfsdk:"status"`
	Methods types.List `tfsdk:"methods"`
}

type headerPolicyModel struct {
	Status  types.Bool `tfsdk:"status"`
	Headers types.List `tfsdk:"headers"`
}

var configsAttributeTypes = map[string]attr.Type{
	"status":              types.BoolType,
	"block_cors_traffic":  types.BoolType,
	"allowed_origins":     allowedOriginsObjectTypes(),
	"allowed_methods":     methodPolicyObjectTypes(),
	"allowed_headers":     headerPolicyObjectTypes(),
	"exposed_headers":     headerPolicyObjectTypes(),
	"url_pattern":         types.StringType,
	"allowed_credentials": types.StringType,
	"allowed_maximum_age": types.Int64Type,
}

func allowedOriginsObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"protocol":            types.StringType,
		"origin_name":         types.StringType,
		"port":                types.Int64Type,
		"include_sub_domains": types.BoolType,
	}}
}

func methodPolicyObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"status":  types.BoolType,
		"methods": types.ListType{ElemType: types.StringType},
	}}
}

func headerPolicyObjectTypes() basetypes.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"status":  types.BoolType,
		"headers": types.ListType{ElemType: types.StringType},
	}}
}

// validateTemplateConfigs enforces the template/configs mutual exclusion.
func validateTemplateConfigs(model resourceModel) error {
	if model.Template.IsUnknown() || model.Configs.IsUnknown() {
		return nil
	}
	if model.Template.IsNull() {
		return fmt.Errorf("template must be configured")
	}
	if model.Template.ValueBool() && !model.Configs.IsNull() {
		return fmt.Errorf("configs must be omitted when template is true")
	}
	if !model.Template.ValueBool() && model.Configs.IsNull() {
		return fmt.Errorf("configs must be configured when template is false")
	}
	return nil
}

// validateRequiredConfigs enforces CorsProtection's required request fields.
// These fields are Terraform-optional at the schema layer so the complete
// configs block can be omitted when an app switches to template=true.
func validateRequiredConfigs(ctx context.Context, configs types.Object) error {
	if configs.IsNull() || configs.IsUnknown() {
		return nil
	}
	var values configsModel
	if diagnostics := configs.As(ctx, &values, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode configs for validation: %s", diagnostics)
	}
	switch {
	case values.Status.IsNull():
		return fmt.Errorf("configs.status must be configured")
	case values.BlockCorsTraffic.IsNull():
		return fmt.Errorf("configs.block_cors_traffic must be configured")
	}
	if err := validateAllowedOriginsRequired(ctx, values.AllowedOrigins); err != nil {
		return err
	}
	if err := validatePolicyStatusRequired("allowed_methods", values.AllowedMethods); err != nil {
		return err
	}
	if err := validatePolicyStatusRequired("allowed_headers", values.AllowedHeaders); err != nil {
		return err
	}
	if err := validatePolicyStatusRequired("exposed_headers", values.ExposedHeaders); err != nil {
		return err
	}
	return nil
}

func validateAllowedOriginsRequired(ctx context.Context, value types.Object) error {
	if value.IsUnknown() {
		return nil
	}
	if value.IsNull() {
		return fmt.Errorf("configs.allowed_origins must be configured")
	}
	var origin allowedOriginsModel
	if diagnostics := value.As(ctx, &origin, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode configs.allowed_origins for validation: %s", diagnostics)
	}
	switch {
	case origin.Protocol.IsNull():
		return fmt.Errorf("configs.allowed_origins.protocol must be configured")
	case origin.OriginName.IsNull():
		return fmt.Errorf("configs.allowed_origins.origin_name must be configured")
	}
	return nil
}

func validatePolicyStatusRequired(name string, value types.Object) error {
	if value.IsUnknown() {
		return nil
	}
	if value.IsNull() {
		return fmt.Errorf("configs.%s must be configured", name)
	}
	status, ok := value.Attributes()["status"].(types.Bool)
	if !ok {
		return fmt.Errorf("decode configs.%s.status for validation", name)
	}
	if status.IsNull() {
		return fmt.Errorf("configs.%s.status must be configured", name)
	}
	return nil
}

// mergeCorsProtection overlays the Terraform-owned config scalars and nested
// policy objects onto a fresh GET result, preserving unknown envelope/config
// fields. Optional fields are overlaid only when the user declared them in
// config (configConfigs presence); omitted optionals preserve the fresh-GET
// value. planConfigs supplies resolved values for configured-unknown fields.
func mergeCorsProtection(ctx context.Context, document client.CorsProtectionDocument, template bool, configConfigs, planConfigs types.Object) (client.WAFModuleResult, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	updated := document.Result.Clone()
	updated.Template = template
	if template {
		return updated, diagnostics
	}
	if planConfigs.IsNull() || planConfigs.IsUnknown() {
		diagnostics.AddError("Invalid cors protection configuration", "configs must be configured when template is false.")
		return updated, diagnostics
	}
	var planValues configsModel
	diagnostics.Append(planConfigs.As(ctx, &planValues, basetypes.ObjectAsOptions{})...)
	if diagnostics.HasError() {
		return updated, diagnostics
	}
	// config presence drives optional overlays. For Create, config == plan; for
	// Update, config carries the user-declared (possibly null) optionals.
	var configValues configsModel
	if !configConfigs.IsNull() && !configConfigs.IsUnknown() {
		diagnostics.Append(configConfigs.As(ctx, &configValues, basetypes.ObjectAsOptions{})...)
		if diagnostics.HasError() {
			return updated, diagnostics
		}
	} else {
		configValues = planValues
	}

	if err := setBool(&updated, "status", planValues.Status); err != nil {
		diagnostics.AddError("Unable to merge cors protection status", err.Error())
		return updated, diagnostics
	}
	if err := setBool(&updated, "block_cors_traffic", planValues.BlockCorsTraffic); err != nil {
		diagnostics.AddError("Unable to merge cors protection block_cors_traffic", err.Error())
		return updated, diagnostics
	}
	if err := mergeAllowedOrigins(ctx, &updated, planValues.AllowedOrigins, configValues.AllowedOrigins); err != nil {
		diagnostics.AddError("Unable to merge cors protection allowed_origins", err.Error())
		return updated, diagnostics
	}
	if err := mergeMethodPolicy(ctx, &updated, "allowed_methods", planValues.AllowedMethods, configValues.AllowedMethods, methodPolicyObjectTypes()); err != nil {
		diagnostics.AddError("Unable to merge cors protection allowed_methods", err.Error())
		return updated, diagnostics
	}
	if err := mergeHeaderPolicy(ctx, &updated, "allowed_headers", planValues.AllowedHeaders, configValues.AllowedHeaders); err != nil {
		diagnostics.AddError("Unable to merge cors protection allowed_headers", err.Error())
		return updated, diagnostics
	}
	if err := mergeHeaderPolicy(ctx, &updated, "exposed_headers", planValues.ExposedHeaders, configValues.ExposedHeaders); err != nil {
		diagnostics.AddError("Unable to merge cors protection exposed_headers", err.Error())
		return updated, diagnostics
	}
	if !configValues.URLPattern.IsNull() && !configValues.URLPattern.IsUnknown() {
		if err := updated.SetConfig("url_pattern", planValues.URLPattern.ValueString()); err != nil {
			diagnostics.AddError("Unable to merge cors protection url_pattern", err.Error())
			return updated, diagnostics
		}
	}
	if !configValues.AllowedCredentials.IsNull() && !configValues.AllowedCredentials.IsUnknown() {
		if err := updated.SetConfig("allowed_credentials", planValues.AllowedCredentials.ValueString()); err != nil {
			diagnostics.AddError("Unable to merge cors protection allowed_credentials", err.Error())
			return updated, diagnostics
		}
	}
	if !configValues.AllowedMaximumAge.IsNull() && !configValues.AllowedMaximumAge.IsUnknown() {
		if err := updated.SetConfig("allowed_maximum_age", planValues.AllowedMaximumAge.ValueInt64()); err != nil {
			diagnostics.AddError("Unable to merge cors protection allowed_maximum_age", err.Error())
			return updated, diagnostics
		}
	}
	return updated, diagnostics
}

func setBool(updated *client.WAFModuleResult, name string, value types.Bool) error {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	return updated.SetConfig(name, value.ValueBool())
}

// mustRawJSON encodes a value to json.RawMessage; it panics only on values that
// json.Marshal cannot fail on (strings/bools/int64/slices thereof).
func mustRawJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("mustRawJSON: %v", err))
	}
	return encoded
}

// rawNestedObject returns the fresh-GET raw object for a nested config field
// as a mutable map, so configured fields can be overlaid while unknown nested
// keys are preserved. Returns an empty map if the field is absent or null.
func rawNestedObject(updated *client.WAFModuleResult, name string) (map[string]json.RawMessage, error) {
	raw, ok := updated.Configs[name]
	if !ok || len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return map[string]json.RawMessage{}, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("decode nested object %s: %w", name, err)
	}
	if object == nil {
		return map[string]json.RawMessage{}, nil
	}
	return object, nil
}

// setNestedObject re-encodes and stores a merged nested object.
func setNestedObject(updated *client.WAFModuleResult, name string, object map[string]json.RawMessage) error {
	return updated.SetConfig(name, object)
}

func mergeAllowedOrigins(ctx context.Context, updated *client.WAFModuleResult, planObject, configObject types.Object) error {
	if planObject.IsNull() || planObject.IsUnknown() {
		return nil
	}
	var planOrigins, configOrigins allowedOriginsModel
	if diagnostics := planObject.As(ctx, &planOrigins, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode allowed_origins: %v", diagnostics.Errors())
	}
	if !configObject.IsNull() && !configObject.IsUnknown() {
		if diagnostics := configObject.As(ctx, &configOrigins, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
			return fmt.Errorf("decode allowed_origins config: %v", diagnostics.Errors())
		}
	} else {
		configOrigins = planOrigins
	}
	merged, singletonArray, err := rawAllowedOriginsObject(updated)
	if err != nil {
		return err
	}
	// protocol and origin_name are required; always overlay the plan value.
	merged["protocol"] = mustRawJSON(planOrigins.Protocol.ValueString())
	merged["origin_name"] = mustRawJSON(planOrigins.OriginName.ValueString())
	// port and include_sub_domains are optional; overlay only when configured.
	if !configOrigins.Port.IsNull() && !configOrigins.Port.IsUnknown() {
		merged["port"] = mustRawJSON(planOrigins.Port.ValueInt64())
	}
	if !configOrigins.IncludeSubDomains.IsNull() && !configOrigins.IncludeSubDomains.IsUnknown() {
		merged["include_sub_domains"] = mustRawJSON(planOrigins.IncludeSubDomains.ValueBool())
	}
	if singletonArray {
		return updated.SetConfig("allowed_origins", []map[string]json.RawMessage{merged})
	}
	return setNestedObject(updated, "allowed_origins", merged)
}

// rawAllowedOriginsObject retains the fresh-GET representation while exposing
// the one owned origin as a mutable object. The reviewed schema uses an object,
// but production GET may return an empty or singleton array. Empty means there
// is no remote origin yet and becomes a singleton when Terraform configures
// one. Multi-item arrays fail closed because Terraform owns at most one origin.
func rawAllowedOriginsObject(updated *client.WAFModuleResult) (map[string]json.RawMessage, bool, error) {
	raw, ok := updated.Configs["allowed_origins"]
	if !ok || len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return map[string]json.RawMessage{}, false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if trimmed[0] != '[' {
		object, err := rawNestedObject(updated, "allowed_origins")
		return object, false, err
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, true, fmt.Errorf("decode allowed_origins singleton array: %w", err)
	}
	if len(items) == 0 {
		return map[string]json.RawMessage{}, true, nil
	}
	if len(items) > 1 {
		return nil, true, fmt.Errorf("decode allowed_origins array: got %d items, want at most 1", len(items))
	}
	if len(items[0]) == 0 || bytes.Equal(bytes.TrimSpace(items[0]), []byte("null")) {
		return nil, true, fmt.Errorf("decode allowed_origins singleton array: item is null")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(items[0], &object); err != nil {
		return nil, true, fmt.Errorf("decode allowed_origins singleton array item: %w", err)
	}
	if object == nil {
		return nil, true, fmt.Errorf("decode allowed_origins singleton array: item is not an object")
	}
	return object, true, nil
}

func mergeMethodPolicy(ctx context.Context, updated *client.WAFModuleResult, name string, planObject, configObject types.Object, _ basetypes.ObjectType) error {
	if planObject.IsNull() || planObject.IsUnknown() {
		return nil
	}
	var planPolicy, configPolicy methodPolicyModel
	if diagnostics := planObject.As(ctx, &planPolicy, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode %s: %v", name, diagnostics.Errors())
	}
	if !configObject.IsNull() && !configObject.IsUnknown() {
		if diagnostics := configObject.As(ctx, &configPolicy, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
			return fmt.Errorf("decode %s config: %v", name, diagnostics.Errors())
		}
	} else {
		configPolicy = planPolicy
	}
	merged, err := rawNestedObject(updated, name)
	if err != nil {
		return err
	}
	merged["status"] = mustRawJSON(planPolicy.Status.ValueBool())
	if !configPolicy.Methods.IsNull() && !configPolicy.Methods.IsUnknown() {
		methods := make([]string, 0, len(planPolicy.Methods.Elements()))
		for _, element := range planPolicy.Methods.Elements() {
			if s, ok := element.(basetypes.StringValue); ok {
				methods = append(methods, s.ValueString())
			}
		}
		merged["methods"] = mustRawJSON(methods)
	}
	return setNestedObject(updated, name, merged)
}

func mergeHeaderPolicy(ctx context.Context, updated *client.WAFModuleResult, name string, planObject, configObject types.Object) error {
	if planObject.IsNull() || planObject.IsUnknown() {
		return nil
	}
	var planPolicy, configPolicy headerPolicyModel
	if diagnostics := planObject.As(ctx, &planPolicy, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
		return fmt.Errorf("decode %s: %v", name, diagnostics.Errors())
	}
	if !configObject.IsNull() && !configObject.IsUnknown() {
		if diagnostics := configObject.As(ctx, &configPolicy, basetypes.ObjectAsOptions{}); diagnostics.HasError() {
			return fmt.Errorf("decode %s config: %v", name, diagnostics.Errors())
		}
	} else {
		configPolicy = planPolicy
	}
	merged, err := rawNestedObject(updated, name)
	if err != nil {
		return err
	}
	merged["status"] = mustRawJSON(planPolicy.Status.ValueBool())
	if !configPolicy.Headers.IsNull() && !configPolicy.Headers.IsUnknown() {
		headers := make([]string, 0, len(planPolicy.Headers.Elements()))
		for _, element := range planPolicy.Headers.Elements() {
			if s, ok := element.(basetypes.StringValue); ok {
				headers = append(headers, s.ValueString())
			}
		}
		merged["headers"] = mustRawJSON(headers)
	}
	return setNestedObject(updated, name, merged)
}

func stateModel(epID string, document client.CorsProtectionDocument) (resourceModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	model := resourceModel{
		EPID:     types.StringValue(epID),
		Template: types.BoolValue(document.Result.Template),
		Configs:  types.ObjectNull(configsAttributeTypes),
	}
	if document.Result.Template {
		return model, nil
	}
	attributes := map[string]attr.Value{
		"status":              types.BoolPointerValue(document.Config.Status),
		"block_cors_traffic":  types.BoolPointerValue(document.Config.BlockCorsTraffic),
		"allowed_origins":     stateAllowedOrigins(document.Config.AllowedOrigins, &diagnostics),
		"allowed_methods":     stateMethodPolicy(document.Config.AllowedMethods, &diagnostics),
		"allowed_headers":     stateHeaderPolicy(document.Config.AllowedHeaders, &diagnostics),
		"exposed_headers":     stateHeaderPolicy(document.Config.ExposedHeaders, &diagnostics),
		"url_pattern":         types.StringPointerValue(document.Config.URLPattern),
		"allowed_credentials": types.StringPointerValue(document.Config.AllowedCredentials),
		"allowed_maximum_age": types.Int64PointerValue(int64PointerToInt64(document.Config.AllowedMaximumAge)),
	}
	configs, objectDiag := types.ObjectValue(configsAttributeTypes, attributes)
	diagnostics.Append(objectDiag...)
	model.Configs = configs
	return model, diagnostics
}

func int64PointerToInt64(p *int) *int64 {
	if p == nil {
		return nil
	}
	v := int64(*p)
	return &v
}

func stateAllowedOrigins(origins *client.CorsAllowedOrigins, diagnostics *diag.Diagnostics) types.Object {
	if origins == nil {
		return types.ObjectNull(allowedOriginsObjectTypes().AttrTypes)
	}
	attributes := map[string]attr.Value{
		"protocol":            types.StringPointerValue(origins.Protocol),
		"origin_name":         types.StringPointerValue(origins.OriginName),
		"port":                types.Int64PointerValue(int64PointerToInt64(origins.Port)),
		"include_sub_domains": types.BoolPointerValue(origins.IncludeSubDomains),
	}
	object, objectDiag := types.ObjectValue(allowedOriginsObjectTypes().AttrTypes, attributes)
	diagnostics.Append(objectDiag...)
	return object
}

func stateMethodPolicy(policy *client.CorsMethodPolicy, diagnostics *diag.Diagnostics) types.Object {
	if policy == nil {
		return types.ObjectNull(methodPolicyObjectTypes().AttrTypes)
	}
	attributes := map[string]attr.Value{
		"status": types.BoolPointerValue(policy.Status),
	}
	if policy.Methods == nil {
		attributes["methods"] = types.ListNull(types.StringType)
	} else {
		values := make([]attr.Value, 0, len(policy.Methods))
		for _, method := range policy.Methods {
			values = append(values, types.StringValue(method))
		}
		list, listDiag := types.ListValue(types.StringType, values)
		diagnostics.Append(listDiag...)
		attributes["methods"] = list
	}
	object, objectDiag := types.ObjectValue(methodPolicyObjectTypes().AttrTypes, attributes)
	diagnostics.Append(objectDiag...)
	return object
}

func stateHeaderPolicy(policy *client.CorsHeaderPolicy, diagnostics *diag.Diagnostics) types.Object {
	if policy == nil {
		return types.ObjectNull(headerPolicyObjectTypes().AttrTypes)
	}
	attributes := map[string]attr.Value{
		"status": types.BoolPointerValue(policy.Status),
	}
	if policy.Headers == nil {
		attributes["headers"] = types.ListNull(types.StringType)
	} else {
		values := make([]attr.Value, 0, len(policy.Headers))
		for _, header := range policy.Headers {
			values = append(values, types.StringValue(header))
		}
		list, listDiag := types.ListValue(types.StringType, values)
		diagnostics.Append(listDiag...)
		attributes["headers"] = list
	}
	object, objectDiag := types.ObjectValue(headerPolicyObjectTypes().AttrTypes, attributes)
	diagnostics.Append(objectDiag...)
	return object
}
