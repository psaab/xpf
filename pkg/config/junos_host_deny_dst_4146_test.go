package config

import "testing"

// junos_host_deny_dst_4146_test.go pins the projection SSOT for the #4146
// destination slice: an explicit `match destination-address` on a `to-zone
// junos-host` DENY is projected into the kernel rule (Dst / DstExcluded /
// DstAny) instead of forcing the whole ingress-zone program un-representable.
//
// Before this slice `junosHostProjectTerm` marked ANY destination-scoped term
// un-representable, so the whole-program gate emitted NOTHING for the zone and
// the configured deny was silently unenforced on the direct host-bound path
// (the kernel delivers those packets; userspace-dp never sees them).
//
// The daemon-side VERDICT gate lives in
// pkg/daemon/host_inbound_junos_host_dst_4146_test.go.

// jh4146DstProjection compiles a flat-set config and returns the whole
// projection (some cases legitimately produce an un-representable program).
func jh4146DstProjection(t *testing.T, policyCmds ...string) JunosHostDenyProjection {
	t.Helper()
	base := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:2::10/64",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security zones security-zone untrust host-inbound-traffic system-services ssh",
		"set security address-book global address wan-ip 10.0.2.10/32",
		"set security address-book global address wan-ip6 2001:db8:2::10/128",
		"set security address-book global address bad-host 10.0.0.5/32",
	}
	tree := &ConfigTree{}
	for _, cmd := range append(base, policyCmds...) {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return BuildJunosHostDenyProjection(cfg)
}

func jh4146OneProgram(t *testing.T, proj JunosHostDenyProjection) JunosHostDenyProgram {
	t.Helper()
	if len(proj.Programs) != 1 {
		t.Fatalf("want exactly 1 junos-host program, got %d: %+v", len(proj.Programs), proj.Programs)
	}
	return proj.Programs[0]
}

// TestJunosHostDstScopedDenyProjectsDaddr is the #4146 destination-slice
// fail-on-revert guard: a DENY with `match destination-address wan-ip` is
// REPRESENTABLE and carries the destination set onto the rule.
//
// RED on revert: restoring the "a non-`any` destination is un-representable"
// gate makes Representable false and RulesV4 empty.
func TestJunosHostDstScopedDenyProjectsDaddr(t *testing.T) {
	proj := jh4146DstProjection(t,
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address wan-ip",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	p := jh4146OneProgram(t, proj)
	if !p.Representable {
		t.Fatalf("a destination-scoped DENY must be representable: %+v", p)
	}
	if len(p.RulesV4) != 1 {
		t.Fatalf("want one IPv4 drop rule, got %+v", p.RulesV4)
	}
	r := p.RulesV4[0]
	if r.DstAny || r.DstExcluded || len(r.Dst) != 1 || r.Dst[0] != "10.0.2.10/32" {
		t.Errorf("rule destination = {any:%v excluded:%v set:%v}, want the positive set [10.0.2.10/32]",
			r.DstAny, r.DstExcluded, r.Dst)
	}
	// The v4-only destination emits no v6 rule (Junos empty-positive-set).
	if len(p.RulesV6) != 0 {
		t.Errorf("a v4-only destination must emit no IPv6 rule, got %+v", p.RulesV6)
	}
	// The policy renders, so its #4168 warning is suppressed.
	if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "blk")] {
		t.Errorf("a rendered destination-scoped deny must land in RenderedPolicyKeys: %+v", proj.RenderedPolicyKeys)
	}
}

// TestJunosHostDstAnyStillRendersNoDaddr is the no-op regression guard: the
// overwhelmingly common `destination-address any` must still render DstAny with
// an empty set, i.e. no daddr predicate at all — byte-identical to pre-slice
// output.
func TestJunosHostDstAnyStillRendersNoDaddr(t *testing.T) {
	proj := jh4146DstProjection(t,
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	p := jh4146OneProgram(t, proj)
	if len(p.RulesV4) != 1 {
		t.Fatalf("want one IPv4 rule, got %+v", p.RulesV4)
	}
	r := p.RulesV4[0]
	if !r.DstAny || r.DstExcluded || len(r.Dst) != 0 {
		t.Errorf("destination-address any must project DstAny with no set, got {any:%v excluded:%v set:%v}",
			r.DstAny, r.DstExcluded, r.Dst)
	}
}

// TestJunosHostDstAnyExcludedProjectsNoRule is the #5828 degenerate case on the
// DESTINATION dimension. `destination-address any` + `destination-address-
// excluded` is "every destination EXCEPT every destination" = the empty set:
// the term matches NOTHING and must project NO rule for either family.
// Classifying the empty concrete set as the "any" arm would emit an
// UNCONDITIONAL drop — the #5828 over-deny shape, which can lock out all direct
// host-bound traffic on the ingress zone.
func TestJunosHostDstAnyExcludedProjectsNoRule(t *testing.T) {
	proj := jh4146DstProjection(t,
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address-excluded",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	p := jh4146OneProgram(t, proj)
	if len(p.RulesV4) != 0 || len(p.RulesV6) != 0 {
		t.Fatalf("destination any+excluded is inert and must project no rule, got v4=%+v v6=%+v",
			p.RulesV4, p.RulesV6)
	}
}

// TestJunosHostDstExcludedProjectsNegatedSet covers the constrained exclusion
// arm: `destination-address wan-ip` + excluded drops to every destination EXCEPT
// the WAN address on IPv4 and — because the excluded set carries no IPv6 prefix
// — to ALL IPv6 destinations (the documented match-all-of-opposite-family
// semantic, identical to the source dimension).
func TestJunosHostDstExcludedProjectsNegatedSet(t *testing.T) {
	proj := jh4146DstProjection(t,
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address wan-ip",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address-excluded",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	p := jh4146OneProgram(t, proj)
	if len(p.RulesV4) != 1 {
		t.Fatalf("want one IPv4 rule, got %+v", p.RulesV4)
	}
	if r := p.RulesV4[0]; !r.DstExcluded || r.DstAny || len(r.Dst) != 1 || r.Dst[0] != "10.0.2.10/32" {
		t.Errorf("IPv4 rule destination = {any:%v excluded:%v set:%v}, want the negated set [10.0.2.10/32]",
			r.DstAny, r.DstExcluded, r.Dst)
	}
	if len(p.RulesV6) != 1 || !p.RulesV6[0].DstAny {
		t.Errorf("an excluded destination set with no v6 prefix must match ALL v6 destinations, got %+v", p.RulesV6)
	}
}

// TestJunosHostDstScopedPermitStaysUnrepresentable is the over-reach guard: a
// permit is projected ONLY as a `saddr !=` subtraction of later denies, which
// cannot express a destination-scoped carve. A destination-scoped PERMIT must
// therefore keep the WHOLE program un-representable — rendering the following
// deny while silently dropping the permit's destination dimension would deny
// traffic the operator explicitly permitted.
func TestJunosHostDstScopedPermitRendersAReturn9504(t *testing.T) {
	proj := jh4146DstProjection(t,
		"set security policies from-zone untrust to-zone junos-host policy ok match source-address any",
		"set security policies from-zone untrust to-zone junos-host policy ok match destination-address wan-ip",
		"set security policies from-zone untrust to-zone junos-host policy ok match application any",
		"set security policies from-zone untrust to-zone junos-host policy ok then permit",
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address any",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	p := jh4146OneProgram(t, proj)
	if !p.Representable {
		t.Fatalf("#9504: a destination-scoped permit renders as a return carrying its own "+
			"daddr, so the program is representable: %+v", p)
	}
	if len(p.RulesV4) != 2 {
		t.Fatalf("want the permit's return then the deny's drop in v4, got %+v", p.RulesV4)
	}
	if r := p.RulesV4[0]; r.Verdict != JunosHostReturn || r.DstAny || len(r.Dst) != 1 {
		t.Errorf("first v4 rule = %+v, want a return scoped to the permit's destination — "+
			"a return that dropped its daddr would carve the later deny wider than authored", r)
	}
	if r := p.RulesV4[1]; r.Verdict != JunosHostDrop || !r.DstAny {
		t.Errorf("second v4 rule = %+v, want the deny's drop for every destination", r)
	}
	// The deny is enforced; the permit is NEVER suppressed, because the half that
	// would refuse what it does not match is enforced on no path (#9504).
	if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "blk")] {
		t.Errorf("the deny renders a rule yet is not marked rendered: %+v", proj.RenderedPolicyKeys)
	}
	if proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "ok")] {
		t.Errorf("a permit must never be marked rendered: %+v", proj.RenderedPolicyKeys)
	}
}

// TestJunosHostFeedTaintedDstUnrepresentable proves the destination dimension
// carries the SAME feed-taint gate as the source: a dynamic-feed-bound address
// is not commit-stable, so it can never become a static nft rule. The policy
// keeps the #4168 warning instead.
func TestJunosHostFeedTaintedDstUnrepresentable(t *testing.T) {
	proj := jh4146DstProjection(t,
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name feedy profile feed-name malware",
		"set security policies from-zone untrust to-zone junos-host policy blk match source-address bad-host",
		"set security policies from-zone untrust to-zone junos-host policy blk match destination-address feedy",
		"set security policies from-zone untrust to-zone junos-host policy blk match application any",
		"set security policies from-zone untrust to-zone junos-host policy blk then deny",
	)
	p := jh4146OneProgram(t, proj)
	if p.Representable {
		t.Fatalf("a feed-tainted destination must keep the program un-representable: %+v", p)
	}
	if len(proj.RenderedPolicyKeys) != 0 {
		t.Errorf("a feed-tainted deny must keep its #4168 warning: %+v", proj.RenderedPolicyKeys)
	}
}

// TestJunosHostProjectAddrMatchIsOneFormula pins the shared source/destination
// address-match formula (junosHostProjectAddrMatch). Both dimensions MUST route
// through it so the #5828 degenerate `any`+excluded case can never be fixed on
// one dimension and regress on the other.
func TestJunosHostProjectAddrMatchIsOneFormula(t *testing.T) {
	cases := []struct {
		name              string
		set               []string
		anyFam, excluded  bool
		emptyBoth         bool
		wantAny, wantExcl bool
		wantSet           []string
		wantOK            bool
	}{
		{name: "wildcard", anyFam: true, wantAny: true, wantOK: true},
		// The #5828 degenerate case: "every address EXCEPT every address" is the
		// empty set, so the caller must project NO rule (ok=false), never the
		// unconditional "any" arm.
		{name: "wildcard+excluded is the empty set", anyFam: true, excluded: true},
		{name: "positive set", set: []string{"10.0.0.0/8"}, wantSet: []string{"10.0.0.0/8"}, wantOK: true},
		{name: "positive set with no family prefix"},
		{name: "excluded constrained set", set: []string{"10.0.0.0/8"}, excluded: true,
			wantExcl: true, wantSet: []string{"10.0.0.0/8"}, wantOK: true},
		{name: "excluded set with no family prefix matches all", excluded: true, wantAny: true, wantOK: true},
		// #6613: "everything except nothing" resolved in BOTH families is the
		// degenerate form Rust fails CLOSED on (rule_l3_matches requires
		// !(v4_empty && v6_empty)). Projecting the match-all arm would widen the
		// authored scope to every firewall address while the dataplane denies
		// nothing. Reachable on the LENIENT load / peer-sync path only.
		{name: "excluded empty in BOTH families fails closed", excluded: true, emptyBoth: true, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAny, gotExcl, gotSet, ok := junosHostProjectAddrMatch(tc.set, tc.anyFam, tc.excluded, tc.emptyBoth)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if gotAny != tc.wantAny || gotExcl != tc.wantExcl {
				t.Errorf("any=%v excluded=%v, want any=%v excluded=%v", gotAny, gotExcl, tc.wantAny, tc.wantExcl)
			}
			if len(gotSet) != len(tc.wantSet) {
				t.Fatalf("set = %v, want %v", gotSet, tc.wantSet)
			}
			for i := range gotSet {
				if gotSet[i] != tc.wantSet[i] {
					t.Errorf("set[%d] = %q, want %q", i, gotSet[i], tc.wantSet[i])
				}
			}
		})
	}
}
