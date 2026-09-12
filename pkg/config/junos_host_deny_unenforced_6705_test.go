package config

import (
	"strings"
	"testing"
)

// #6705: a `to-zone junos-host` DENY that projects NO rule must keep its #4168
// advisory. The suppression claims the kernel host-inbound gate enforces the
// deny; a deny the projection handed the kernel nothing for is not enforced,
// however representable it was.
//
// The reachable vector is an application-any permit for EVERY source ahead of
// the deny. It commits cleanly through the STRICT path — the #3044 missing-
// dimension gate and the #6526 valueless-leaf gate both reject their spellings
// before the projection ever runs, so neither is the way in. `source-address
// any` is a legitimate, fully-authored value, which is exactly why it reached
// the projection unflagged: junosHostBuildRule's permitAll arm then shadowed
// every later deny and the program came out empty while the deny still counted
// as rendered. The operator got neither the DROP rules nor the warning.
//
// The assertions read the projected rule CONTENT and the warning text, never
// "a program exists" — an existence assertion is what let this hide, since the
// zone kept emitting a Program struct with empty rule lists throughout.
func buildJunosHost6705(t *testing.T, cmds ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
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
		t.Fatalf("STRICT CompileConfig: %v", err)
	}
	return cfg
}

func junosHost6705Base() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security address-book global address NET9 10.0.9.0/24",
		"set security address-book global address HOST50 10.0.1.50/32",
	}
}

func junosHost6705Deny() []string {
	return []string{
		"set security policies from-zone trust to-zone junos-host policy p2 match source-address NET9",
		"set security policies from-zone trust to-zone junos-host policy p2 match destination-address any",
		"set security policies from-zone trust to-zone junos-host policy p2 match application any",
		"set security policies from-zone trust to-zone junos-host policy p2 then deny",
	}
}

func junosHost6705Permit(src string) []string {
	return []string{
		"set security policies from-zone trust to-zone junos-host policy p1 match source-address " + src,
		"set security policies from-zone trust to-zone junos-host policy p1 match destination-address any",
		"set security policies from-zone trust to-zone junos-host policy p1 match application any",
		"set security policies from-zone trust to-zone junos-host policy p1 then permit",
	}
}

// junosHost6705Warned reports whether the junos-host enforcement advisory was
// emitted for this policy. It keys on the policy name plus the advisory's
// SUBJECT ("cannot enforce on the direct host-bound path"), not on an issue
// number: the projection's suppression bookkeeping is described as the "#4168
// warning" throughout junos_host_deny.go, but the emitted string cites #4146.
// Matching the number from the code comments would have made this predicate
// permanently false and the assertion vacuous.
func junosHost6705Warned(cfg *Config, policy string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `"`+policy+`"`) &&
			strings.Contains(w, "cannot enforce on the direct host-bound path") {
			return true
		}
	}
	return false
}

// TestJunosHostShadowedDenyKeepsItsAdvisory6705 is the defect proper: the deny
// projects nothing and must therefore stay warned.
func TestJunosHostShadowedDenyKeepsItsAdvisory6705(t *testing.T) {
	cmds := append(junosHost6705Base(), junosHost6705Permit("any")...)
	cmds = append(cmds, junosHost6705Deny()...)
	cfg := buildJunosHost6705(t, cmds...)

	proj := BuildJunosHostDenyProjection(cfg)
	key := JunosHostZonePairPolicyKey("trust", "p2")

	// CONTENT, not existence: the permit-all genuinely shadows the deny, so the
	// correct projection really is zero rules in BOTH families. That is not the
	// bug — the bug is calling that outcome "rendered".
	for _, prog := range proj.Programs {
		if prog.Zone != "trust" {
			continue
		}
		if len(prog.RulesV4) != 0 || len(prog.RulesV6) != 0 {
			t.Fatalf("premise broken: expected the permit-all to shadow the deny, got RulesV4=%+v RulesV6=%+v",
				prog.RulesV4, prog.RulesV6)
		}
	}
	if proj.RenderedPolicyKeys[key] {
		t.Errorf("deny p2 projected NO rule yet is marked rendered — its #4168 advisory is suppressed, "+
			"so the operator gets neither the kernel DROP program nor the diagnostic (renderedKeys=%v)",
			proj.RenderedPolicyKeys)
	}
	if !junosHost6705Warned(cfg, "p2") {
		t.Errorf("deny p2 emitted no rule and no enforcement advisory: a config that commits with zero warnings "+
			"left the host-inbound DROP program empty; warnings=%v", cfg.Warnings)
	}
}

// TestJunosHostRenderedDenyStaysSuppressed6705 is the TIGHTENING control. A fix
// that simply stopped suppressing — or that keyed suppression off something
// always false — would satisfy the test above while destroying the #4168
// mechanism. This pins the other side: a deny that DOES project a rule keeps
// its suppression, and the rule content is the authored one.
func TestJunosHostRenderedDenyStaysSuppressed6705(t *testing.T) {
	cmds := append(junosHost6705Base(), junosHost6705Permit("HOST50")...)
	cmds = append(cmds, junosHost6705Deny()...)
	cfg := buildJunosHost6705(t, cmds...)

	proj := BuildJunosHostDenyProjection(cfg)
	key := JunosHostZonePairPolicyKey("trust", "p2")

	var got *JunosHostDenyProgram
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "trust" {
			got = &proj.Programs[i]
		}
	}
	if got == nil {
		t.Fatal("no program projected for zone trust")
	}
	if len(got.RulesV4) != 2 {
		t.Fatalf("expected the permit's return then the p2 drop in v4, got %+v", got.RulesV4)
	}
	if r := got.RulesV4[0]; r.Verdict != JunosHostReturn || len(r.Src) != 1 || r.Src[0] != "10.0.1.50/32" {
		t.Errorf("first v4 rule = %+v, want the permit's return for [10.0.1.50/32]", r)
	}
	if r := got.RulesV4[1]; r.Verdict != JunosHostDrop || len(r.Src) != 1 || r.Src[0] != "10.0.9.0/24" {
		t.Errorf("deny rule = %+v, want a drop for [10.0.9.0/24]", r)
	}
	if !proj.RenderedPolicyKeys[key] {
		t.Errorf("deny p2 projected a real DROP rule but is NOT marked rendered — the #4168 suppression "+
			"has been broken for genuinely enforced denies (renderedKeys=%v)", proj.RenderedPolicyKeys)
	}
	if junosHost6705Warned(cfg, "p2") {
		t.Errorf("deny p2 is enforced by the kernel gate yet still carries its #4168 advisory; warnings=%v",
			cfg.Warnings)
	}
}

// TestJunosHostEmptyMatchSpellingsAreRejectedStrict6705 pins the premise the
// issue got wrong, so a future change that relaxes either gate cannot silently
// re-open this path. The omitted and valueless spellings do NOT reach the
// projection on the strict path — they are rejected at commit — which is why
// the fix above is aimed at emission rather than at the match dimension.
func TestJunosHostEmptyMatchSpellingsAreRejectedStrict6705(t *testing.T) {
	for _, tc := range []struct {
		name    string
		permit  []string
		wantRef string
	}{
		{
			name: "source-address omitted entirely",
			permit: []string{
				"set security policies from-zone trust to-zone junos-host policy p1 match destination-address any",
				"set security policies from-zone trust to-zone junos-host policy p1 match application any",
				"set security policies from-zone trust to-zone junos-host policy p1 then permit",
			},
			wantRef: "#3044",
		},
		{
			name: "source-address present but valueless",
			permit: []string{
				"set security policies from-zone trust to-zone junos-host policy p1 match source-address",
				"set security policies from-zone trust to-zone junos-host policy p1 match destination-address any",
				"set security policies from-zone trust to-zone junos-host policy p1 match application any",
				"set security policies from-zone trust to-zone junos-host policy p1 then permit",
			},
			wantRef: "#6526",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(junosHost6705Base(), tc.permit...)
			cmds = append(cmds, junosHost6705Deny()...)
			tree := &ConfigTree{}
			for _, cmd := range cmds {
				path, err := ParseSetCommand(cmd)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict commit ACCEPTED an empty %s match dimension — the projection "+
					"would then treat it as match-ANY and a permit would shadow every later deny", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantRef) {
				t.Errorf("rejected by the wrong gate: want a %s rejection, got %v", tc.wantRef, err)
			}
		})
	}
}

// TestJunosHostV6OnlyDenyIsRendered6705 binds the IPv6 half of the emission
// record. junosHostProjectProgram notes emission separately per family, and the
// two arms are symmetric — which is exactly why a matrix must mutate them
// SEPARATELY: dropping the v4 record alone reddens four pre-existing tests, so
// a combined cell would have redded on the v4 half and masked that nothing at
// all covered v6. An IPv6-only deny (no v4 rule to carry it) is the only shape
// that can tell them apart, and without this test the v6 arm could be deleted
// silently, spuriously warning that a correctly-enforced v6 deny is unenforced.
func TestJunosHostV6OnlyDenyIsRendered6705(t *testing.T) {
	cfg := buildJunosHost6705(t,
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8:1::1/64",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security address-book global address NET6 2001:db8:9::/64",
		"set security policies from-zone trust to-zone junos-host policy p2 match source-address NET6",
		"set security policies from-zone trust to-zone junos-host policy p2 match destination-address any",
		"set security policies from-zone trust to-zone junos-host policy p2 match application any",
		"set security policies from-zone trust to-zone junos-host policy p2 then deny",
	)

	proj := BuildJunosHostDenyProjection(cfg)
	var got *JunosHostDenyProgram
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "trust" {
			got = &proj.Programs[i]
		}
	}
	if got == nil {
		t.Fatal("no program projected for zone trust")
	}
	// The premise: this deny lives ONLY in the v6 rule list.
	if len(got.RulesV4) != 0 {
		t.Fatalf("premise broken: expected no v4 rule for a v6-only deny, got %+v", got.RulesV4)
	}
	if len(got.RulesV6) != 1 {
		t.Fatalf("expected exactly one v6 DROP rule, got %+v", got.RulesV6)
	}
	if src := got.RulesV6[0].Src; len(src) != 1 || src[0] != "2001:db8:9::/64" {
		t.Errorf("v6 deny source content = %v, want [2001:db8:9::/64]", src)
	}
	if key := JunosHostZonePairPolicyKey("trust", "p2"); !proj.RenderedPolicyKeys[key] {
		t.Errorf("a v6-only deny projected a real DROP rule but is not marked rendered — the v6 emission "+
			"record is not wired, so an enforced IPv6 deny would be reported as unenforced (renderedKeys=%v)",
			proj.RenderedPolicyKeys)
	}
	if junosHost6705Warned(cfg, "p2") {
		t.Errorf("v6-only deny is enforced yet still carries its advisory; warnings=%v", cfg.Warnings)
	}
}
