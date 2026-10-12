package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// FAIL-ON-REVERT (#12517 R7-F2): a quoted/bracketed `then` inside the prepend
// run must not turn the authored reject into a permit in tolerant rendering.
func TestQuotedThenNextHopRejectRendersDeny12517(t *testing.T) {
	for _, tc := range []struct {
		name, text string
	}{
		{
			name: "issue term-line reproducer",
			text: `policy-options { policy-statement P { term t from protocol static then accept as-path-prepend 65001 "then" next-hop reject; term u then accept; } }`,
		},
		{
			name: "compact leading accept",
			text: `policy-options { policy-statement P { term t then accept as-path-prepend 65001 "then" next-hop reject; term u then accept; } }`,
		},
		{
			name: "bracketed then",
			text: `policy-options { policy-statement P { term t from protocol static then accept as-path-prepend [ 65001 "then" ] next-hop reject; term u then accept; } }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrs := config.NewParser(tc.text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse: %v", parseErrs)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile rejected persisted config: %v", err)
			}
			rendered := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&cfg.PolicyOptions)
			if !strings.Contains(rendered, "route-map P deny 10") {
				t.Fatalf("R7-F2 must preserve deny in sequence 10:\n%s", rendered)
			}
			if strings.Contains(rendered, "route-map P permit 10") {
				t.Fatalf("R7-F2 flipped deny to permit in sequence 10:\n%s", rendered)
			}
			if !strings.Contains(rendered, "route-map P permit 20") {
				t.Fatalf("control term must still permit in sequence 20:\n%s", rendered)
			}
		})
	}
}
