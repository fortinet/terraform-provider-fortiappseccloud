package contract

// TemplateCreateFutureContract retains the historical name of the
// user-approved template-create response contract. OpenAPI 26.3.a now pins the
// same shape; production verification remains a separate evidence question.
var TemplateCreateFutureContract = struct {
	Method             string
	Path               string
	Status             int
	LocationPattern    string
	RequestFields      []string
	ResultFields       []string
	DetailAtTopLevel   bool
	IdempotencyHeader  string
	ProductionVerified bool
	Provenance         string
}{
	Method:             "POST",
	Path:               "/waf/template",
	Status:             201,
	LocationPattern:    "/v2/waf/template/{template_id}",
	RequestFields:      []string{"endpoints", "name"},
	ResultFields:       []string{"endpoints", "features", "name", "predefine", "template_id"},
	DetailAtTopLevel:   true,
	IdempotencyHeader:  "Idempotency-Key",
	ProductionVerified: false,
	Provenance:         "User-approved future create response contract on 2026-07-28; local implementation and deterministic tests only until the production API deploys it.",
}
