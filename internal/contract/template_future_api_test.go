package contract

import (
	"reflect"
	"strings"
	"testing"
)

func TestTemplateCreateFutureContract(t *testing.T) {
	t.Parallel()

	contract := TemplateCreateFutureContract
	if contract.Method != "POST" || contract.Path != "/waf/template" || contract.Status != 201 {
		t.Fatalf("method/path/status = %s %s %d", contract.Method, contract.Path, contract.Status)
	}
	if contract.LocationPattern != "/v2/waf/template/{template_id}" ||
		contract.IdempotencyHeader != "Idempotency-Key" ||
		!contract.DetailAtTopLevel ||
		contract.ProductionVerified {
		t.Fatalf("future contract = %#v", contract)
	}
	if !reflect.DeepEqual(contract.RequestFields, []string{"endpoints", "name"}) {
		t.Fatalf("request fields = %#v", contract.RequestFields)
	}
	if !reflect.DeepEqual(contract.ResultFields, []string{"endpoints", "features", "name", "predefine", "template_id"}) {
		t.Fatalf("result fields = %#v", contract.ResultFields)
	}
	if !strings.Contains(contract.Provenance, "local") || !strings.Contains(contract.Provenance, "production") {
		t.Fatalf("provenance = %q", contract.Provenance)
	}
}
