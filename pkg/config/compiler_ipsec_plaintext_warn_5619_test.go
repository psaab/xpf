package config

import (
	"fmt"
	"strings"
	"testing"
)

func compileWarn5619(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v (a #5619 plaintext advisory must NEVER reject)", err)
	}
	return cfg
}

func plaintextWarnings5619(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5619") {
			out = append(out, w)
		}
	}
	return out
}

// TestPlaintextWarningFiresForRouteBasedVPN is the core #5619 assertion: an
// operator committing a route-based IPsec VPN is told, at commit, that the
// decrypted plaintext is not evaluated against xpf security policies.
func TestPlaintextWarningFiresForRouteBasedVPN(t *testing.T) {
	cfg := compileWarn5619(t,
		"set security ipsec vpn myvpn bind-interface st0.0",
	)
	got := plaintextWarnings5619(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 #5619 advisory, got %d: %v", len(got), cfg.Warnings)
	}
	for _, want := range []string{"myvpn", "st0.0", "NOT evaluated against xpf security policies"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("advisory missing %q; got: %s", want, got[0])
		}
	}
}

// TestPlaintextWarningNamesTheContradictedZone covers the sharpest case: the
// operator put the tunnel in a security zone and the commit ACCEPTED it, so
// they have been told something specific and untrue. The advisory must say the
// zone does not govern the decrypted traffic.
func TestPlaintextWarningNamesTheContradictedZone(t *testing.T) {
	cfg := compileWarn5619(t,
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
	)
	got := plaintextWarnings5619(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 #5619 advisory, got %d: %v", len(got), cfg.Warnings)
	}
	if !strings.Contains(got[0], `security-zone "vpn"`) {
		t.Errorf("advisory must name the contradicted zone; got: %s", got[0])
	}
	if !strings.Contains(got[0], "does NOT govern its decrypted traffic") {
		t.Errorf("advisory must state the zone does not govern the plaintext; got: %s", got[0])
	}
	if !strings.Contains(got[0], "reads as protected and is not") {
		t.Errorf("the ZONED case must ESCALATE — the operator has been told something "+
			"specific and untrue, and the wording must say so; got: %s", got[0])
	}
}

// TestPlaintextWarningNeverRejects is the no-brick property (#1960), and it is
// the one this file exists to defend. An operator with a working VPN must be
// able to commit an UNRELATED change. Compiles must succeed in every shape.
func TestPlaintextWarningNeverRejects(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"bare bind-interface", []string{
			"set security ipsec vpn v bind-interface st0",
		}},
		{"zoned tunnel plus unrelated change", []string{
			"set security ipsec vpn v bind-interface st0.0",
			"set security zones security-zone vpn interfaces st0.0",
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set system host-name fw-unrelated-change",
		}},
		{"several tunnels", []string{
			"set security ipsec vpn a bind-interface st0.0",
			"set security ipsec vpn b bind-interface st0.1",
			"set security ipsec vpn c bind-interface st1.0",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileWarn5619(t, tc.lines...)
			if len(plaintextWarnings5619(cfg)) == 0 {
				t.Error("expected at least one #5619 advisory")
			}
		})
	}
}

// TestPlaintextWarningIsQuietWithoutIPsec is the negative control: a config
// with no route-based IPsec must produce no advisory at all. It is true in both
// worlds by construction, so it stays green under every #5619 mutation and a red
// here means the walk over-fires rather than that the fix regressed.
func TestPlaintextWarningIsQuietWithoutIPsec(t *testing.T) {
	cfg := compileWarn5619(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.1.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.2.1",
	)
	if got := plaintextWarnings5619(cfg); len(got) != 0 {
		t.Errorf("advisory fired with no route-based IPsec configured: %v", got)
	}
}

// TestPlaintextWarningSkipsInvalidBindInterface: a bind-interface that
// materializes NO xfrm device is already reported by the #5297 arm (silent
// tunnel down). Adding a plaintext advisory on top would be noise about a
// plaintext path that does not exist.
//
// ONE reachable rejection site, and the inputs separate the two ways to reach
// it. The advisory tests `ifID == 0` FIRST and only then the
// IsSecureTunnelIfName predicate, so every input that fails the predicate has
// already been discarded by the if_id test — the predicate line is not
// reachable with any input (tracked separately; it is a dead branch, not a
// behaviour difference). An earlier revision of this test asserted the
// opposite: it labelled `ge-0/0/0.0` as "rejected by the predicate" and drove
// `st-1` / `st65536` as the rows that "pass the predicate", which stopped being
// true when #6691 gave secureTunnelIndex a `0 <= idx < 65536` range and made
// IsSecureTunnelIfName reject both. That premise check caught itself on the
// merge rather than going quietly green, which is why these rows changed.
//
// What still varies, and is worth pinning, is WHICH HALF of the bind-interface
// is invalid. A BASE-side rejection is visible to a base-name predicate; a
// UNIT-side rejection is NOT — `st0.65535` and `st0.abc` have a perfectly valid
// base and are refused only because XFRMIfNameAndID cannot build an if_id for
// the unit. A guard written against the base name alone would let those two
// through and emit an advisory about a device the routing layer never creates.
//
// Measured on this tree (see XFRMIfNameAndID / secureTunnelIndex, xfrmi.go):
//
//	name         invalid half   IsSecureTunnelIfName(base)   XFRMIfNameAndID -> ifID
//	ge-0/0/0.0   base           false                        0
//	st0.65535    unit           TRUE                         0   (unit >= 0xffff)
//	st0.abc      unit           TRUE                         0   (unit unparseable)
func TestPlaintextWarningSkipsInvalidBindInterface(t *testing.T) {
	for _, tc := range []struct {
		name, bindIface, invalidHalf string
		basePredicate                bool
	}{
		{"invalid_base_name", "ge-0/0/0.0", "base", false},
		{"unit_out_of_range", "st0.65535", "unit", true},
		{"unit_unparseable", "st0.abc", "unit", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			line := "set security ipsec vpn bad bind-interface " + tc.bindIface
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("setpath %q: %v", line, err)
			}
			// Premise check: assert this input really is invalid in the half it
			// is here to exercise, so a future change to either predicate cannot
			// quietly turn this subtest into a duplicate of its sibling.
			base, _, _ := strings.Cut(tc.bindIface, ".")
			if got := IsSecureTunnelIfName(base); got != tc.basePredicate {
				t.Fatalf("premise broken: IsSecureTunnelIfName(%q) = %v, want %v — "+
					"%q no longer has an invalid %s half", base, got, tc.basePredicate,
					tc.bindIface, tc.invalidHalf)
			}
			if _, ifID := XFRMIfNameAndID(tc.bindIface); ifID != 0 {
				t.Fatalf("premise broken: %q now yields if_id %d, so it no longer "+
					"exercises a bind-interface that materializes no device", tc.bindIface, ifID)
			}
			// The strict path REJECTS an invalid bind-interface (#5297), so drive
			// the advisory directly against the AST rather than through
			// CompileConfig.
			if got := warnSecureTunnelPlaintextUnadjudicatedAST(tree.Children); len(got) != 0 {
				t.Errorf("advisory fired for a bind-interface with an invalid %s half, "+
					"which creates no xfrm device: %v", tc.invalidHalf, got)
			}
		})
	}
}

// TestPlaintextWarningFiresOnEveryCompilePath pins the coverage this advisory's
// own argument leans on, which nothing else in this file exercised.
//
// The operator who most needs telling is the one who does NOT re-commit after
// an upgrade: their config arrives by RESTART (Store.Load) or PEER-SYNC
// (Store.SyncApply), and both use the LENIENT entry point, not the strict one
// an operator drives by hand. An advisory that fired only on strict commit
// would systematically miss exactly the population it was written for, and
// every test here would still be green.
//
// The node-aware variants are included because `apply-groups "${node}"` makes
// the two nodes compile different trees — an advisory that survived on node 0
// and vanished on node 1 would be worse than none, since the operator would
// see it, fix nothing, and reasonably conclude the peer is clean.
func TestPlaintextWarningFiresOnEveryCompilePath(t *testing.T) {
	build := func(t *testing.T) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, line := range []string{
			"set security ipsec vpn v1 bind-interface st0.0",
			"set security zones security-zone vpn interfaces st0.0",
		} {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		return tree
	}

	for _, tc := range []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
	}{
		{"strict_operator_commit", CompileConfig},
		{"lenient_restart_and_peer_sync", CompileConfigLenient},
		{"node0", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNode(tr, 0) }},
		{"node1", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNode(tr, 1) }},
		{"node0_lenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
		{"node1_lenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.compile(build(t))
			if err != nil {
				t.Fatalf("compile: %v (a #5619 plaintext advisory must NEVER reject)", err)
			}
			got := plaintextWarnings5619(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 #5619 advisory on the %s path, got %d: %v",
					tc.name, len(got), got)
			}
		})
	}
}

// TestPlaintextWarningCoversDuplicateSecurityBlocks: parseStatements APPENDS a
// repeated top-level block rather than merging it, and the compiler compiles
// every one — so a VPN living in a duplicate `security {}` must not be missed.
func TestPlaintextWarningCoversDuplicateSecurityBlocks(t *testing.T) {
	tree, err := NewParser(`
security {
    ipsec {
        vpn first {
            bind-interface st0.0;
        }
    }
}
security {
    ipsec {
        vpn second {
            bind-interface st1.0;
        }
    }
}
`).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := warnSecureTunnelPlaintextUnadjudicatedAST(tree.Children)
	if len(got) != 1 {
		t.Fatalf("want ONE aggregated advisory, got %d: %v", len(got), got)
	}
	joined := got[0]
	for _, want := range []string{"first", "second", "st0.0", "st1.0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in: %s", want, joined)
		}
	}
}

// TestPlaintextWarningReadsBracketedZoneList: a bracketed membership list
// arrives bracket-stripped and NESTED under the first member (#5248/#2419), so
// reading only the first would drop the rest and silently omit the zone clause
// for every tunnel after the first.
func TestPlaintextWarningReadsBracketedZoneList(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set security ipsec vpn a bind-interface st0.0",
		"set security ipsec vpn b bind-interface st0.1",
		"set security zones security-zone vpn interfaces [ st0.0 st0.1 ]",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("setpath %q: %v", line, err)
		}
	}
	got := warnSecureTunnelPlaintextUnadjudicatedAST(tree.Children)
	if len(got) != 1 {
		t.Fatalf("want ONE aggregated advisory, got %d: %v", len(got), got)
	}
	// BOTH members must appear in the ZONED group. If the bracketed tail were
	// dropped, st0.1 would fall into the unzoned group instead.
	for _, ref := range []string{"st0.0", "st0.1"} {
		if !strings.Contains(got[0], ref+" (security ipsec vpn") {
			t.Errorf("advisory does not name %s: %s", ref, got[0])
		}
	}
	if strings.Count(got[0], `security-zone "vpn"`) != 2 {
		t.Errorf("a bracketed zone member lost its zone clause — the tail of "+
			"`interfaces [ st0.0 st0.1 ]` was dropped, so it was reported as unzoned: %s",
			got[0])
	}
}

// TestPlaintextWarningIsAggregatedToOne pins the aggregation contract: ONE
// advisory per commit however many tunnels are configured. An advisory that
// fires N times on every commit is filtered out, and then it protects nobody.
func TestPlaintextWarningIsAggregatedToOne(t *testing.T) {
	for _, n := range []int{1, 2, 5} {
		t.Run(fmt.Sprintf("%d_tunnels", n), func(t *testing.T) {
			lines := make([]string, 0, n)
			for i := 0; i < n; i++ {
				lines = append(lines,
					fmt.Sprintf("set security ipsec vpn v%d bind-interface st0.%d", i, i))
			}
			cfg := compileWarn5619(t, lines...)
			got := plaintextWarnings5619(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 aggregated advisory for %d tunnels, got %d: %v",
					n, len(got), got)
			}
			for i := 0; i < n; i++ {
				ref := fmt.Sprintf("st0.%d", i)
				if !strings.Contains(got[0], ref) {
					t.Errorf("the single advisory must name every affected tunnel; %s missing "+
						"from: %s", ref, got[0])
				}
			}
		})
	}
}

// TestPlaintextWarningSeparatesZonedFromUnzoned pins the escalation the zoned
// case earns, and the #6682 note the unzoned case earns.
//
// Leaving a tunnel out of a zone is NOT a mitigation: IPsec plaintext never
// reaches zone policy at all, so zoning the interface or not changes nothing. An
// operator reading only the zoned paragraph could otherwise conclude that
// unzoning is the safe option.
//
// #6682 / #9251: this comment used to give the mechanism as "an interface in no
// zone resolves to zone id 0 and a `from-zone any to-zone any permit` rule
// matches zone-pair (0,0)". That was never true — #3110 fenced every rule tier
// against zone 0, and #6682 made an unzoned ingress an explicit deny. The
// advisory's caveat was corrected by #6682; this cell's comment and message were
// not, and #9251 corrected them. The assertion is unchanged.
func TestPlaintextWarningSeparatesZonedFromUnzoned(t *testing.T) {
	cfg := compileWarn5619(t,
		"set security ipsec vpn zoned bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
		"set security ipsec vpn bare bind-interface st1.0",
	)
	got := plaintextWarnings5619(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 aggregated advisory, got %d: %v", len(got), got)
	}
	adv := got[0]

	zoneIdx := strings.Index(adv, "ASSIGNED A ZONE THAT IS NOT ENFORCED")
	plainIdx := strings.Index(adv, "NOT ZONE-ADJUDICATED")
	if zoneIdx < 0 || plainIdx < 0 {
		t.Fatalf("advisory must carry BOTH groups; got: %s", adv)
	}
	zonedSection := adv[zoneIdx:plainIdx]
	if !strings.Contains(zonedSection, "st0.0") {
		t.Errorf("the zoned tunnel must be in the escalated group: %s", adv)
	}
	if strings.Contains(zonedSection, "st1.0") {
		t.Errorf("the UNZONED tunnel must not be reported as zoned: %s", adv)
	}
	if !strings.Contains(adv[plainIdx:], "st1.0") {
		t.Errorf("the unzoned tunnel must be named: %s", adv)
	}
	if !strings.Contains(adv, "#6682") {
		t.Errorf("with an unzoned tunnel present the advisory must say that unzoning is "+
			"NOT a mitigation (#6682): %s", adv)
	}
}

// TestPlaintextWarningOmitsTheUnzonedCaveatWhenAllZoned keeps the #6682 note
// from becoming noise on a config where it does not apply.
func TestPlaintextWarningOmitsTheUnzonedCaveatWhenAllZoned(t *testing.T) {
	cfg := compileWarn5619(t,
		"set security ipsec vpn zoned bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
	)
	got := plaintextWarnings5619(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 advisory, got %d: %v", len(got), got)
	}
	if strings.Contains(got[0], "#6682") {
		t.Errorf("the unzoned caveat must not fire when every tunnel is zoned: %s", got[0])
	}
	if strings.Contains(got[0], "NOT ZONE-ADJUDICATED") {
		t.Errorf("the unzoned group must be omitted entirely when empty: %s", got[0])
	}
}

// TestPlaintextWarningMatchesZoneAcrossSpellings is the bare-`st0` check.
//
// `bind-interface st0` and a zone on `st0.0` describe the SAME xfrmi — both
// if_id 1 (pkg/routing/xfrm.go) — but they are different strings. Matching the
// zone literally would report a ZONED tunnel as unzoned, dropping the
// escalation in exactly the case that earns it: where the operator HAS been
// told something specific and untrue. Same spelling-mismatch class as the
// #5619 netdev-name bug, so it is joined the same way: on if_id.
func TestPlaintextWarningMatchesZoneAcrossSpellings(t *testing.T) {
	for _, tc := range []struct{ bind, zoneRef string }{
		{"st0.0", "st0.0"},
		{"st0", "st0.0"},   // bare bind, dotted zone ref
		{"st0.0", "st0"},   // dotted bind, bare zone ref
		{"st0", "st0"},     // both bare
		{"st1.7", "st1.7"}, // non-zero unit
	} {
		t.Run(tc.bind+"_zone_"+tc.zoneRef, func(t *testing.T) {
			cfg := compileWarn5619(t,
				"set security ipsec vpn v bind-interface "+tc.bind,
				"set security zones security-zone vpn interfaces "+tc.zoneRef,
			)
			got := plaintextWarnings5619(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 advisory, got %d: %v", len(got), got)
			}
			if !strings.Contains(got[0], "ASSIGNED A ZONE THAT IS NOT ENFORCED") {
				t.Errorf("bind-interface %q with a zone on %q must land in the ESCALATED "+
					"group — they are the same xfrmi (same if_id), and reporting it as "+
					"unzoned drops the escalation exactly where the operator has been told "+
					"something untrue. Got: %s", tc.bind, tc.zoneRef, got[0])
			}
			if strings.Contains(got[0], "#6682") {
				t.Errorf("the unzoned caveat fired for a tunnel that IS zoned: %s", got[0])
			}
		})
	}
}
