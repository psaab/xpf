package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15137 (A88-01) render leg: a neighbor whose import/export policy is
// NAMED after a neighbor keyword (passive, ...) must render its
// `route-map <name> in|out` and NO flag line for that name. Before the
// fix the policy compiled away, the neighbor carried the keyword's
// flag instead, and — with `no bgp ebgp-requires-policy` (#14584) in
// every stanza — the eBGP peer was unfiltered in that direction.
func TestBGPKeywordNamedPolicyRendersRouteMap15137(t *testing.T) {
	tree, perrs := config.NewParser(`protocols { bgp { local-as 65000; group G1 { peer-as 65001;
		neighbor 192.0.2.1 { import passive; export remove-private; } } } }
		policy-options { policy-statement passive { term t1 { then accept; } }
			policy-statement remove-private { term t1 { then accept; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Compiler leg (anti-vacuity): the policies survived compilation.
	if len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("neighbors = %d, want 1", len(cfg.Protocols.BGP.Neighbors))
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if len(n.Import) != 1 || n.Import[0] != "passive" || len(n.Export) != 1 || n.Export[0] != "remove-private" {
		t.Fatalf("compiled Import=%v Export=%v, want [passive]/[remove-private]", n.Import, n.Export)
	}
	if n.Passive || n.RemovePrivateAS {
		t.Fatalf("compiled Passive=%v RemovePrivateAS=%v, want both false (names are policies)", n.Passive, n.RemovePrivateAS)
	}

	section := New().buildManagedSection(&FullConfig{BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions})
	for _, want := range []string{
		"neighbor 192.0.2.1 route-map passive in",
		"neighbor 192.0.2.1 route-map remove-private out",
		"no bgp ebgp-requires-policy",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("rendered section missing %q:\n%s", want, section)
		}
	}
	for _, unwanted := range []string{
		"neighbor 192.0.2.1 passive",
		"neighbor 192.0.2.1 remove-private-AS",
	} {
		if strings.Contains(section, unwanted) {
			t.Errorf("rendered section must not contain flag line %q (the policy name is not a flag):\n%s", unwanted, section)
		}
	}
}
