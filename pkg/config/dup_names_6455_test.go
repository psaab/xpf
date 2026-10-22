package config

import (
	"strings"
	"testing"
)

// #6455 (SPLIT: quoted-empty half shipped; group-authored half deferred).
//
// The pre-expansion duplicate-name gate family (validateDuplicateNamedBlockAST
// #5180, validateDuplicateNATRuleNamesAST #5649, validateDuplicateNATRuleSetNamesAST
// #6454) shared two limitations. This change closes ONLY Finding 2 (quoted-empty
// names). Finding 1 (group-authored duplicates) is DEFERRED: a pre-expansion
// per-group-body scan false-rejects legitimate apply-groups FRAGMENT configs that
// COALESCE post-expansion (see TestDup6455GroupFragmentCoalescingAccepted), so the
// correct detection must run post-ExpandGroups + union both node views — a design
// pass tracked separately.
//
// All tests drive the PUBLIC compile entry points (CompileConfig /
// CompileConfigLenient), not the private validators.

// TestDup6455QuotedEmptyNameRejected is the Finding 2 RED-on-revert proof: a
// single quoted-empty name for each of the family's containers is hard-rejected at
// strict commit as an authoring error (an empty name is not a valid operational
// identity), regardless of duplication. Each error carries the #6455 tag and the
// container kind.
func TestDup6455QuotedEmptyNameRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		kind string
	}{
		{
			name: "nat rule-set",
			cfg:  `security { nat { source { rule-set "" { rule R1 { then { source-nat { interface; } } } } } } }`,
			kind: "NAT source rule-set",
		},
		{
			name: "nat rule",
			cfg:  `security { nat { source { rule-set RS { rule "" { then { source-nat { interface; } } } } } } }`,
			kind: "NAT source rule",
		},
		{
			name: "group",
			cfg:  `groups { "" { system { host-name foo; } } }`,
			kind: "group",
		},
		{
			name: "interface",
			cfg:  `interfaces { "" { unit 0 { family inet { address 10.0.0.1/24; } } } }`,
			kind: "interface",
		},
		{
			name: "screen ids-option",
			cfg:  `security { screen { ids-option "" { icmp { ping-death; } } } }`,
			kind: "screen ids-option",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHierText(t, tc.cfg))
			if err == nil {
				t.Fatalf("CompileConfig must reject an empty %s name", tc.kind)
			}
			for _, want := range []string{"empty", tc.kind, "6455"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("empty-%s error should mention %q, got: %v", tc.name, want, err)
				}
			}
		})
	}
}

// TestDup6455QuotedEmptyLenientWarnsOnce proves (a) the tolerant path (Load /
// peer-sync, #1960) downgrades the empty-name reject to a warning so an
// already-persisted config still boots, and (b) the empty rule-set warning fires
// EXACTLY ONCE — the #5649 rule-name gate skips an empty rule-set so it is not
// double-reported alongside the #6454 rule-set gate (the Codex MINOR de-dup).
func TestDup6455QuotedEmptyLenientWarnsOnce(t *testing.T) {
	const cfg = `security { nat { source { rule-set "" { rule R1 { then { source-nat { interface; } } } } } } }`

	if _, err := CompileConfig(parseHierText(t, cfg)); err == nil {
		t.Fatal("strict CompileConfig must reject the empty rule-set name")
	}

	lenientCfg, err := CompileConfigLenient(parseHierText(t, cfg))
	if err != nil {
		t.Fatalf("CompileConfigLenient must not hard-fail on an empty name, got: %v", err)
	}
	n := 0
	for _, w := range lenientCfg.Warnings {
		if strings.Contains(w, "empty") && strings.Contains(w, "NAT source rule-set") && strings.Contains(w, "6455") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("empty NAT source rule-set must warn EXACTLY once (not double-reported), got %d in %v", n, lenientCfg.Warnings)
	}
}

// TestDup6455GroupFragmentCoalescingAccepted is the load-bearing no-false-positive
// guard for the deferred Finding 1: a legitimate apply-groups FRAGMENT config —
// fragments of ONE named object authored across repeated group roots that COALESCE
// into a single object under mergeNodes during ExpandGroups — MUST commit cleanly.
// These are exactly the cases the withdrawn per-group-body scan false-rejected;
// this test locks them ACCEPT so a future group-authored detector cannot
// reintroduce the false-reject.
func TestDup6455GroupFragmentCoalescingAccepted(t *testing.T) {
	// C1: an interface split across two group `interfaces` roots coalesces to ONE
	// ge-0/0/0 carrying both units.
	t.Run("interface fragments across two group roots", func(t *testing.T) {
		cfg, err := CompileConfig(parseHierText(t, `groups { G {
    interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
    interfaces { ge-0/0/0 { unit 1 { family inet { address 10.0.1.1/24; } } } }
} }
apply-groups G;`))
		if err != nil {
			t.Fatalf("interface fragments across group roots must coalesce and commit, got: %v", err)
		}
		ge := cfg.Interfaces.Interfaces["ge-0/0/0"]
		if ge == nil || len(ge.Units) != 2 {
			t.Fatalf("want one coalesced ge-0/0/0 with 2 units, got %+v", ge)
		}
	})

	// C2: a screen profile split into an ICMP fragment + a TCP fragment across two
	// group `security` roots coalesces to ONE profile carrying both checks.
	t.Run("screen profile fragments across two group roots", func(t *testing.T) {
		cfg, err := CompileConfig(parseHierText(t, `groups { G {
    security { screen { ids-option P { icmp { ping-death; } } } }
    security { screen { ids-option P { tcp { syn-fin; } } } }
} }
apply-groups G;`))
		if err != nil {
			t.Fatalf("screen profile fragments across group roots must coalesce and commit, got: %v", err)
		}
		p := cfg.Security.Screen["P"]
		if p == nil || !p.ICMP.PingDeath || !p.TCP.SynFin {
			t.Fatalf("want one coalesced profile P with icmp+tcp, got %+v", p)
		}
	})

	// C3: one NAT rule split into complementary match/then fragments across
	// repeated group roots coalesces to ONE rule.
	t.Run("nat rule match/then fragments across two group roots", func(t *testing.T) {
		cfg, err := CompileConfig(parseHierText(t, `groups { G {
    security { nat { source { rule-set RS { rule R { match { source-address 10.0.0.0/24; } } } } } }
    security { nat { source { rule-set RS { rule R { then { source-nat { interface; } } } } } } }
} }
apply-groups G;`))
		if err != nil {
			t.Fatalf("nat rule match/then fragments across group roots must coalesce and commit, got: %v", err)
		}
		got := 0
		rules := 0
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				got++
				rules = len(rs.Rules)
			}
		}
		if got != 1 || rules != 1 {
			t.Fatalf("want one coalesced rule-set RS with 1 rule, got rs=%d rules=%d", got, rules)
		}
	})

	// C4: two group-local same-name rule siblings + an inline same-name rule-set
	// peer — expansion coalesces the group siblings into the inline rule-set.
	t.Run("group rule siblings + inline peer coalesce", func(t *testing.T) {
		cfg, err := CompileConfig(parseHierText(t, `security { nat { source { rule-set RS { rule Ri { then { source-nat { off; } } } } } } }
groups { G {
    security { nat { source { rule-set RS { rule R { match { source-address 10.0.0.0/24; } } rule R { then { source-nat { interface; } } } } } } }
} }
apply-groups G;`))
		if err != nil {
			t.Fatalf("group rule siblings + inline peer must coalesce and commit, got: %v", err)
		}
		got := 0
		names := map[string]int{}
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				got++
				for _, r := range rs.Rules {
					names[r.Name]++
				}
			}
		}
		if got != 1 || names["R"] != 1 || names["Ri"] != 1 {
			t.Fatalf("want one coalesced rule-set RS with rules {R:1, Ri:1}, got rs=%d names=%v", got, names)
		}
	})
}

// TestDup6455NoFalsePositive guards the top-level gate scope through the PUBLIC
// compile path: an apply-groups deep-merge into a same-named inline object, a
// cross-group coalescing, and a group-authored #3096 bracket-list scope expansion
// all commit cleanly.
func TestDup6455NoFalsePositive(t *testing.T) {
	// apply-groups deep-merge: inline `rule-set RS { rule R1 }` + group-authored
	// `rule-set RS { rule R2 }` coalesce into ONE rule-set carrying BOTH rules.
	t.Run("apply-groups deep-merge carries both rules", func(t *testing.T) {
		cfg, err := CompileConfig(parseHierText(t, `security {
    nat { source { rule-set RS { rule R1 { then { source-nat { interface; } } } } } }
}
groups { G {
    security { nat { source { rule-set RS { rule R2 { then { source-nat { off; } } } } } } }
} }
apply-groups G;`))
		if err != nil {
			t.Fatalf("apply-groups deep-merge must commit, got: %v", err)
		}
		got := 0
		rules := 0
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				got++
				rules = len(rs.Rules)
			}
		}
		if got != 1 || rules != 2 {
			t.Fatalf("deep-merge must yield 1 rule-set RS with 2 rules, got rs=%d rules=%d", got, rules)
		}
	})

	// Two different groups authoring the SAME rule (identical action) coalesce.
	t.Run("cross-group same name coalesces", func(t *testing.T) {
		cfg, err := CompileConfig(parseHierText(t, `groups {
    G1 { security { nat { source { rule-set RS { rule R { then { source-nat { off; } } } } } } } }
    G2 { security { nat { source { rule-set RS { rule R { then { source-nat { off; } } } } } } } }
}
apply-groups [ G1 G2 ];`))
		if err != nil {
			t.Fatalf("cross-group same rule must coalesce and commit, got: %v", err)
		}
		got := 0
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				got++
			}
		}
		if got != 1 {
			t.Fatalf("cross-group same rule-set must coalesce to 1, got %d", got)
		}
	})

	// #3096: one authored `rule-set RS` with a bracket list of from-zones
	// Cartesian-expands into TWO same-named NATRuleSet objects at compile time —
	// one AST instance, not a duplicate.
	t.Run("bracket-list from-scope expansion (#3096)", func(t *testing.T) {
		cfg, err := CompileConfig(parseHierText(t, `security {
    nat { source { rule-set RS {
        from zone [ trust dmz ];
        to zone untrust;
        rule R1 { then { source-nat { interface; } } }
    } } }
}`))
		if err != nil {
			t.Fatalf("a single bracket-list-scoped rule-set must commit, got: %v", err)
		}
		fromZones := map[string]bool{}
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				fromZones[rs.FromZone] = true
			}
		}
		if !fromZones["trust"] || !fromZones["dmz"] {
			t.Fatalf("expanded rule-sets must cover from-zones {trust, dmz}, got: %v", fromZones)
		}
	})
}
