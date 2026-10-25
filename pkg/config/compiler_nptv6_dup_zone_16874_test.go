package config

import (
	"strings"
	"testing"
)

// #16874: a repeated `from zone` value on an NPTv6 static rule-set committed
// clean but every dataplane apply then failed the NPTv6 overlap pre-pass.
//
// Mechanism: `from zone [ untrust untrust ]` reached compileNATStatic as two
// identical scopes, producing two identical StaticNATRuleSets
// {R, untrust}. Strict validateNPTv6Strict's #4339 self-skip is keyed on
// (rule-set, rule) names only, so the self-pair was never compared and the
// commit was persisted. The apply pre-pass NPTv6OverlapConflict (and the
// Rust helper) has no name-identity skip, so it returned
// `rule-set "R" rule "r1" ... overlaps rule-set "R" rule "r1"` and every
// later apply wedged on the previous snapshot.
//
// Fix: dedupe (kind, value) scope values in collectNATScopes — a repeated
// list value carries no meaning in Junos — so one logical scope yields
// exactly one expansion for every NAT kind.
//
// FAIL-ON-REVERT: drop the dedupe in collectNATScopes and
// TestNPTv6DuplicateFromZoneCommits16874 goes RED (two expansions and a
// non-empty NPTv6OverlapConflict pre-pass verdict despite a clean commit).

func nptv6DupZoneCommit16874(name, fromClause string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security zones security-zone trust",
		fromClause,
		"set security nat static rule-set " + name + " rule r1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set " + name + " rule r1 then static-nat nptv6-prefix fd00:1::/48",
	}
}

func TestNPTv6DuplicateFromZoneCommits16874(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{
			name: "bracket duplicate",
			lines: nptv6DupZoneCommit16874("R",
				"set security nat static rule-set R from zone [ untrust untrust ]"),
		},
		{
			name: "repeated clauses",
			lines: []string{
				"set security zones security-zone untrust",
				"set security nat static rule-set R from zone untrust",
				"set security nat static rule-set R from zone untrust",
				"set security nat static rule-set R rule r1 match destination-address 2001:db8:1::/48",
				"set security nat static rule-set R rule r1 then static-nat nptv6-prefix fd00:1::/48",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("duplicate from-zone must commit (Junos treats a repeated list value as one), got: %v", err)
			}
			if got := len(cfg.Security.NAT.Static); got != 1 {
				t.Fatalf("duplicate from-zone must expand to exactly one rule-set, got %d expansions", got)
			}
			rs := cfg.Security.NAT.Static[0]
			if rs.Name != "R" || rs.FromZone != "untrust" {
				t.Fatalf("expansion = {%q %q}, want {R untrust}", rs.Name, rs.FromZone)
			}
			if conflict := NPTv6OverlapConflict(cfg); conflict != "" {
				t.Fatalf("dataplane pre-pass must accept the committed config, got conflict %q", conflict)
			}
		})
	}
}

// The deduplicated shape must be indistinguishable from the single-spelling
// shape: one expansion, same zone, pre-pass clean.
func TestNPTv6DuplicateFromZoneMatchesSingle16874(t *testing.T) {
	single, err := CompileConfig(buildTree(t, nptv6DupZoneCommit16874("R",
		"set security nat static rule-set R from zone untrust")))
	if err != nil {
		t.Fatalf("single from-zone must commit: %v", err)
	}
	dup, err := CompileConfig(buildTree(t, nptv6DupZoneCommit16874("R",
		"set security nat static rule-set R from zone [ untrust untrust ]")))
	if err != nil {
		t.Fatalf("duplicate from-zone must commit: %v", err)
	}
	if len(single.Security.NAT.Static) != len(dup.Security.NAT.Static) {
		t.Fatalf("single=%d expansions, duplicate=%d; must match",
			len(single.Security.NAT.Static), len(dup.Security.NAT.Static))
	}
	if got := NPTv6OverlapConflict(dup); got != "" {
		t.Fatalf("duplicate shape pre-pass = %q, want clean", got)
	}
	if got := NPTv6OverlapConflict(single); got != "" {
		t.Fatalf("single shape pre-pass = %q, want clean", got)
	}
}

// Distinct scopes must NOT be collapsed: `from zone [ untrust trust ]`
// still expands once per distinct zone (the #4339 legitimate multi-scope
// shape), and the commit stays clean via the self-skip + zone partition.
func TestNPTv6DistinctFromZonesNotCollapsed16874(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, nptv6DupZoneCommit16874("R",
		"set security nat static rule-set R from zone [ untrust trust ]")))
	if err != nil {
		t.Fatalf("distinct from-zones must commit: %v", err)
	}
	if got := len(cfg.Security.NAT.Static); got != 2 {
		t.Fatalf("distinct from-zones must expand to 2 rule-sets, got %d", got)
	}
	zones := map[string]bool{}
	for _, rs := range cfg.Security.NAT.Static {
		zones[rs.FromZone] = true
	}
	if !zones["untrust"] || !zones["trust"] {
		t.Fatalf("expansions cover zones %v, want untrust+trust", zones)
	}
	if conflict := NPTv6OverlapConflict(cfg); conflict != "" {
		t.Fatalf("distinct-zone multi-scope must pass pre-pass, got %q", conflict)
	}
}

// TWIN control: two differently-named rule-sets in the SAME zone with the
// same prefixes are a genuine overlap and still reject at strict commit —
// the dedupe must not blunt the live gate.
func TestNPTv6TwinRuleSetsStillReject16874(t *testing.T) {
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set R from zone untrust",
		"set security nat static rule-set R rule r1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set R rule r1 then static-nat nptv6-prefix fd00:1::/48",
		"set security nat static rule-set S from zone untrust",
		"set security nat static rule-set S rule r1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set S rule r1 then static-nat nptv6-prefix fd00:1::/48",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("two distinct rule-sets in one zone with identical prefixes must reject")
	} else if !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("twin rejection must report the overlap, got: %v", err)
	}
}

// Non-NPTv6 static NAT: the dedupe lives in collectNATScopes, so a repeated
// from-zone on an ordinary static rule-set also collapses to one expansion.
func TestStaticNATDuplicateFromZoneCollapses16874(t *testing.T) {
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set R from zone [ untrust untrust ]",
		"set security nat static rule-set R rule r1 match destination-address 192.0.2.1/32",
		"set security nat static rule-set R rule r1 then static-nat prefix 10.0.0.1/32",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("ordinary static NAT with duplicate from-zone must commit: %v", err)
	}
	if got := len(cfg.Security.NAT.Static); got != 1 {
		t.Fatalf("duplicate from-zone must expand once, got %d rule-sets", got)
	}
	if cfg.Security.NAT.Static[0].FromZone != "untrust" {
		t.Fatalf("FromZone = %q, want untrust", cfg.Security.NAT.Static[0].FromZone)
	}
}

// Source NAT: repeated from/to zone values collapse on both sides of the
// Cartesian product (one pair, not four).
func TestSourceNATDuplicateScopesCollapse16874(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set RS from zone [ trust trust ]",
		"set security nat source rule-set RS to zone [ untrust untrust ]",
		"set security nat source rule-set RS rule R1 then source-nat interface",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("source NAT with duplicate scopes must commit: %v", err)
	}
	if got := len(cfg.Security.NAT.Source); got != 1 {
		t.Fatalf("duplicate from/to scopes must expand to 1 rule-set, got %d", got)
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromZone != "trust" || rs.ToZone != "untrust" {
		t.Fatalf("expansion = from %q to %q, want trust->untrust", rs.FromZone, rs.ToZone)
	}
}

// Hierarchical twin: repeated `from zone untrust;` statements inside a
// braced rule-set behave the same (issue probe shape).
func TestNPTv6DuplicateFromZoneHierarchical16874(t *testing.T) {
	text := "security { zones { security-zone untrust; } " +
		"nat { static { rule-set R { from zone untrust; from zone untrust; " +
		"rule r1 { match { destination-address 2001:db8:1::/48; } " +
		"then { static-nat { nptv6-prefix fd00:1::/48; } } } } } } }"
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical duplicate from-zone must commit: %v", err)
	}
	if got := len(cfg.Security.NAT.Static); got != 1 {
		t.Fatalf("hierarchical duplicate must expand once, got %d", got)
	}
	if conflict := NPTv6OverlapConflict(cfg); conflict != "" {
		t.Fatalf("pre-pass must be clean, got %q", conflict)
	}
}
