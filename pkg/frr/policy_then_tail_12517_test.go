package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// FAIL-ON-REVERT (#12517 R7-F2): a quoted/bracketed `then` inside the prepend
// run must not turn the authored reject into a permit in tolerant rendering.
// The split-term row adds a `then { accept; }` block for the same term; it
// renders `permit 10` without the override at the end of
// parsePolicyTermChildren.
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
		{
			name: "term-line then accept block for the same term",
			text: `policy-options { policy-statement P { term t then accept as-path-prepend 65001 "then" next-hop reject; term t { then { accept; } } term u then accept; } }`,
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

// FAIL-ON-REVERT (#12517 B5): the five from-match words #12517 detects as
// then tails stay out of the #12070/#12513 map. A community defined with one
// of those names keeps rendering its term-line action, and an AS-path-prepend
// run still absorbs them as invalid operands so tolerant rendering omits the
// whole prepend instead of emitting a truncated `set as-path prepend 65001`.
// RED when the words are merged into policyTermFromMatchInlineKeywords12070:
// the community rows lose their `set community`/`set comm-list` line and the
// prepend rows render `set as-path prepend 65001`.
func TestThenFromWordsKeepCommunityAndPrependRendering12517(t *testing.T) {
	for _, tc := range []struct {
		name, text, want, forbid string
	}{
		{
			name: "term-line community add neighbor",
			text: `policy-options { community neighbor members 65001:7; policy-statement P { term t then community add neighbor accept; term u then accept; } }`,
			want: "route-map P permit 10\n set community 65001:7 additive\n",
		},
		{
			name: "term-line community set rib",
			text: `policy-options { community rib members 65001:7; policy-statement P { term t then community set rib accept; term u then accept; } }`,
			want: "route-map P permit 10\n set community 65001:7\n",
		},
		{
			name: "term-line community delete instance",
			text: `policy-options { community instance members 65001:7; policy-statement P { term t then community delete instance accept; term u then accept; } }`,
			want: "route-map P permit 10\n set comm-list instance delete\n",
		},
		{
			name: "term-line bare community family",
			text: `policy-options { community family members 65001:7; policy-statement P { term t then community family accept; term u then accept; } }`,
			want: "route-map P permit 10\n set community 65001:7\n",
		},
		{
			name:   "prepend absorbs neighbor",
			text:   `policy-options { policy-statement P { term t from protocol static then as-path-prepend 65001 neighbor 192.0.2.1 accept; term u then accept; } }`,
			want:   "route-map P permit 10\n match source-protocol static\nexit\n",
			forbid: "set as-path prepend",
		},
		{
			name:   "prepend absorbs rib",
			text:   `policy-options { policy-statement P { term t then accept as-path-prepend 65001 rib inet.0; term u then accept; } }`,
			want:   "route-map P permit 10\nexit\n",
			forbid: "set as-path prepend",
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
			if !strings.Contains(rendered, tc.want) {
				t.Fatalf("render missing %q:\n%s", tc.want, rendered)
			}
			if tc.forbid != "" && strings.Contains(rendered, tc.forbid) {
				t.Fatalf("render contains %q:\n%s", tc.forbid, rendered)
			}
		})
	}
}
