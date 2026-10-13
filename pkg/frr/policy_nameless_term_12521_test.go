package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPackedNamelessPolicyTermsRenderDenyFallback12521(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name: "packed-policy-statement-name",
			input: `policy-options policy-statement EXPORT-STATIC term { ` +
				`from { protocol static; } then { accept; } }`,
		},
		{
			name: "packed-term-head",
			input: `policy-options { policy-statement EXPORT-STATIC term { ` +
				`from { protocol static; } then { accept; } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrs := config.NewParser(tc.input).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse packed policy: %v", parseErrs)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(warnings, "#12521") {
				t.Fatalf("tolerant compile warnings = %q, want #12521", cfg.Warnings)
			}
			ps := cfg.PolicyOptions.PolicyStatements["EXPORT-STATIC"]
			if ps == nil || len(ps.Terms) != 1 {
				t.Fatalf("compiled EXPORT-STATIC = %#v, want one neutral placeholder", ps)
			}
			term := ps.Terms[0]
			if term.Action != "" || len(term.FromProtocols) != 0 || len(term.RouteFilters) != 0 {
				t.Fatalf("compiled term = %#v, want untrusted matches/actions removed", term)
			}
			render := New().generatePolicyOptions(&cfg.PolicyOptions, nil)
			if !strings.Contains(render, "route-map EXPORT-STATIC deny 20\n") {
				t.Fatalf("nameless body did not retain the policy's deny fallback:\n%s", render)
			}
			if strings.Contains(render, "match source-protocol static") ||
				strings.Contains(render, "route-map EXPORT-STATIC permit 20") {
				t.Fatalf("nameless match/action escaped into FRR:\n%s", render)
			}
		})
	}
}
