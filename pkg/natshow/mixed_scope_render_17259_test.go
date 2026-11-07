package natshow

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Kimi delta-2: real producer + renderers over a compiled config whose
// rule-set carries BOTH a zone and an interface scope expansion sharing
// one rule (compileNATStatic shares rule pointers across expansions).
func TestNPTv6MixedScopeRendersPerExpansion17259(t *testing.T) {
	text := `security {
		zones { security-zone untrust; }
		nat { static { rule-set nrs {
			from zone untrust;
			from interface ge-0/0/1;
			rule n1 { match { destination-address 2602:fd41:70::/48; } then { static-nat { nptv6-prefix fd35:1940:27::/48; } } }
		} } }
	}`
	tree, parseErr := config.NewParser(text).Parse()
	if len(parseErr) != 0 {
		t.Fatalf("parse: %v", parseErr)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.Security.NAT.Static) < 2 {
		t.Fatalf("static rule-sets = %d, want 2 scope expansions", len(cfg.Security.NAT.Static))
	}
	var buf strings.Builder
	RenderNPTv6(&buf, cfg)
	out := buf.String()
	// One expansion (zone) arms the rule; the interface expansion must be
	// annotated NOT INSTALLED on its own row.
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Fatalf("render lacks the interface-expansion NOT INSTALLED:\n%s", out)
	}
	// Producer-level: the pair-keyed set must hold both verdicts.
	set := nptv6InstalledSet(cfg)
	verdicts := map[bool]bool{}
	for _, v := range set {
		verdicts[v] = true
	}
	if !verdicts[true] || !verdicts[false] {
		t.Fatalf("installed set verdicts = %v, want both true and false", set)
	}
}
