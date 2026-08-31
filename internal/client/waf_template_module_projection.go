package client

// The helpers in this file build the reviewed typed projection used by each
// hand-written module resource from a template module's shared raw result.
// They keep template transport generic while preserving the stricter
// module-specific decoders and validation.

func ProjectAccountTakeoverResult(result WAFModuleResult) (AccountTakeoverDocument, error) {
	config, err := decodeAccountTakeoverConfig(result.Configs)
	return AccountTakeoverDocument{Result: result, Config: config}, err
}

func ProjectAnomalyDetectionResult(result WAFModuleResult) (AnomalyDetectionDocument, error) {
	config, err := decodeAnomalyDetectionConfig(result.Configs)
	return AnomalyDetectionDocument{Result: result, Config: config}, err
}

func ProjectCorsProtectionResult(result WAFModuleResult) (CorsProtectionDocument, error) {
	config, err := decodeCorsProtectionConfig(result.Configs)
	return CorsProtectionDocument{Result: result, Config: config}, err
}

func ProjectIPProtectionResult(result WAFModuleResult) (IPProtectionDocument, error) {
	config, err := decodeIPProtectionConfig(result.Configs)
	return IPProtectionDocument{Result: result, Config: config}, err
}

func ProjectCustomRuleResult(result WAFModuleResult) (CustomRuleDocument, error) {
	config, err := decodeCustomRuleConfig(result.Configs)
	return CustomRuleDocument{Result: result, Config: config}, err
}

func ProjectMlApiProtectionResult(result WAFModuleResult) (MlApiProtectionDocument, error) {
	config, err := decodeMlApiProtectionConfig(result.Configs)
	return MlApiProtectionDocument{Result: result, Config: config}, err
}
