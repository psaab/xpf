package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16569: a tolerant-loaded term with `to neighbor` must render as deny,
// not as the widened permit the dropped `to` used to produce.
func TestGeneratePolicyOptionsUnknownToRendersDeny16569(t *testing.T) {
	tree, errs := config.NewParser(`policy-options {
 policy-statement only-from-a {
  term t1 {
   from { route-filter 10.10.0.0/16 exact; }
   to neighbor 192.0.2.1;
   then accept;
  }
 }
}`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["only-from-a"].Terms[0]
	if term.Action != "reject" {
		t.Fatalf("tolerant term Action=%q, want reject", term.Action)
	}
	got := New().generatePolicyOptions(&cfg.PolicyOptions, nil)
	if !strings.Contains(got, "route-map only-from-a deny 10") {
		t.Fatalf("rendered route-map is not deny:\n%s", got)
	}
	if strings.Contains(got, "route-map only-from-a permit") {
		t.Fatalf("rendered widened permit:\n%s", got)
	}
}
