package config

import (
	"strings"
	"testing"
)

// #13117 (D1-13 residual of #9246/#9913): a valid 4-key combined header
// `from-zone trust to-zone untrust` whose body instead carries the rule
// inside a non-policy absorbed child --
//
//	from-zone trust to-zone untrust {
//	    dmz extra { policy p1 { ... } }
//	}
//
// The policy compiler reads only direct `policy` children of the context
// node, so the rule under `dmz extra` is never compiled and the pair is
// built with zero rules. malformedZonePairShape9246's absorbed-list scan
// recognized a rule only when `policy` was packed into the child's keys;
// with the rule as a real child node the scan missed it, so strict commit
// accepted the config and tolerant loads built a no-rule pair -- fail-open
// under a global/default permit. The detector must name the shape so the
// context is skipped, recorded, and poisoned like every malformed pair.

func TestAbsorbedPolicyChildIsRefused13117(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	fromZone := `from-zone trust to-zone untrust { dmz extra { ` + deny + ` } }`
	n := &Node{
		Keys: []string{"from-zone", "trust", "to-zone", "untrust"},
		Children: []*Node{
			{
				Keys: []string{"dmz", "extra"},
				Children: []*Node{
					{Keys: []string{"policy", "p1"}},
				},
			},
		},
	}
	if got := malformedZonePairShape9246(n); got == "" {
		t.Fatal("absorbed child carrying its rule as a `policy` child node recorded NOTHING — the #9246 detector missed it and the deny would be silently dropped")
	}

	tree := zonePairShape12633(t, fromZone)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig accepted the absorbed-policy-child zone-pair shape")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must remain bootable: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) == 0 {
		t.Fatalf("absorbed-policy-child shape recorded nothing in MalformedZonePairs; dropped deny would fail open (pairs=%v)", cfg.Security.Policies)
	}
	joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
	if !strings.Contains(joined, "dmz") {
		t.Fatalf("MalformedZonePairs %q does not name the absorbed token `dmz`", joined)
	}
	if got := LenientDroppedPolicyLocator(cfg); got == "" {
		t.Fatal("tolerant compile did not add the snapshot poison carrier")
	}
	if len(cfg.Security.Policies) != 0 {
		t.Fatalf("malformed absorbed shape compiled zone pairs: %+v", cfg.Security.Policies)
	}
	for _, zp := range cfg.Security.Policies {
		if len(zp.Policies) == 0 {
			t.Fatalf("compiled pair %s->%s carries no rules — the authored deny was dropped", zp.FromZone, zp.ToZone)
		}
	}
}

func TestAbsorbedNonPolicyChildControlCompiles13117(t *testing.T) {
	// Control: an intermediate child without any policy intent (e.g. an
	// unrecognised token block) must not be treated as the absorbed-list
	// shape; only rule-bearing children are rejected. The real policy
	// compiles normally.
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	n := &Node{
		Keys: []string{"from-zone", "trust", "to-zone", "untrust"},
		Children: []*Node{
			{Keys: []string{"dmz", "extra"}},
			{Keys: []string{"policy", "p1"}},
		},
	}
	if got := malformedZonePairShape9246(n); got != "" {
		t.Fatalf("child without policy intent flagged malformed: %q", got)
	}

	tree := zonePairShape12633(t, `from-zone A to-zone B { `+deny+` }`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("valid combined pair must compile on tolerant loads: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 0 {
		t.Fatalf("valid combined pair poisoned: %q", cfg.Security.MalformedZonePairs)
	}
	if len(cfg.Security.Policies) != 1 ||
		cfg.Security.Policies[0].FromZone != "A" ||
		cfg.Security.Policies[0].ToZone != "B" ||
		len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("valid combined pair did not compile its policy: %+v", cfg.Security.Policies)
	}
}
