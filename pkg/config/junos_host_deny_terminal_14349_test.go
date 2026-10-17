package config

import (
	"strings"
	"testing"
)

// #14349: a permit-only junos-host program whose sole permit emits no
// concrete return in either family must still retain the #11065 terminal
// deny in both families. Two authored shapes reach that empty intersection:
//
//   - cross-family-empty: a v4-only source with a v6-only application
//     (`admin-v4` + `junos-pingv6`) builds ok=false in both families —
//     v4 loses the app, v6 loses the source.
//   - skipped (#12040): a permit skipped on tolerant load because its
//     content was dropped (LenientContentDropped) or a referenced
//     application carries match drops (ApplicationReferenceMatchDrops)
//     `continue`s before any return can set hasPermit.
//
// Before the fix both left hasPermitProgram=false, so
// BuildJunosHostDenyProjection returned Representable=true with
// RulesV4==nil and RulesV6==nil; the userspace wrapper then dropped the
// empty program entirely and coarse host-inbound alone decided —
// failing open for 100% of both families despite an authored
// permit-only (deny-by-default) program.

func jh14349AssertTerminalDenyBothFamilies(t *testing.T, prog *JunosHostDenyProgram) {
	t.Helper()
	if prog == nil {
		t.Fatal("no junos-host program projected")
	}
	if !prog.Representable {
		t.Fatalf("program must stay representable: %+v", *prog)
	}
	for _, tc := range []struct {
		family string
		rules  []JunosHostDenyRule
	}{
		{"ip", prog.RulesV4},
		{"ip6", prog.RulesV6},
	} {
		if len(tc.rules) != 1 {
			t.Fatalf("%s: want exactly the unconditional terminal deny, got %+v", tc.family, tc.rules)
		}
		r := tc.rules[0]
		if r.Family != tc.family || r.Verdict != JunosHostDrop || !r.SrcAny || !r.DstAny ||
			r.SrcExcluded || r.DstExcluded || len(r.Src) != 0 || len(r.Dst) != 0 || len(r.L4) != 0 {
			t.Errorf("%s: terminal rule = %+v, want unconditional JunosHostDrop (SrcAny+DstAny, no L4/predicates)", tc.family, r)
		}
	}
}

func jh14349OneProgram(t *testing.T, proj JunosHostDenyProjection, zone string) *JunosHostDenyProgram {
	t.Helper()
	for i := range proj.Programs {
		if proj.Programs[i].Zone == zone {
			return &proj.Programs[i]
		}
	}
	t.Fatalf("no %s program in projection: %+v", zone, proj.Programs)
	return nil
}

func TestJunosHostPermitOnlySkippedOrCrossFamilyEmptyRetainsTerminalDeny(t *testing.T) {
	t.Run("cross-family empty permit", func(t *testing.T) {
		cfg := jhTestConfig()
		cfg.Security.AddressBook.Addresses["admin-v4"] = &Address{Name: "admin-v4", Value: "10.0.0.9/32"}
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{
				jhPermit("only-pingv6", []string{"admin-v4"}, []string{"junos-pingv6"}),
			}},
		}
		prog := jh14349OneProgram(t, BuildJunosHostDenyProjection(cfg), "untrust")
		jh14349AssertTerminalDenyBothFamilies(t, prog)
	})

	t.Run("skipped permit via LenientContentDropped", func(t *testing.T) {
		// Mirror the production tolerant-load shape: the lenient compiler
		// flags the incomplete permit, and junosHostProjectTerm turns that
		// into skipPermit. Setting the compiled flag directly is the same
		// input the projection consumes (cf. #9572 middle row).
		cfg := jhTestConfig()
		p := jhPermit("only-skipped", []string{"good-host"}, []string{"any"})
		p.LenientContentDropped = true
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{p}},
		}
		prog := jh14349OneProgram(t, BuildJunosHostDenyProjection(cfg), "untrust")
		jh14349AssertTerminalDenyBothFamilies(t, prog)
	})

	t.Run("skipped permit via ApplicationReferenceMatchDrops", func(t *testing.T) {
		cmds := append(append([]string{}, junosHostBaseZones...),
			"set applications application badType protocol icmp",
			"set applications application badType icmp-type bogus",
			"set security policies from-zone untrust to-zone junos-host policy only-bad match source-address any",
			"set security policies from-zone untrust to-zone junos-host policy only-bad match destination-address any",
			"set security policies from-zone untrust to-zone junos-host policy only-bad match application badType",
			"set security policies from-zone untrust to-zone junos-host policy only-bad then permit",
		)
		if _, err := CompileConfig(buildJunosHostWarnTree(t, cmds)); err == nil {
			t.Fatal("fixture is not a member of the tolerant downgrade: strict CompileConfig accepted an invalid icmp-type")
		}
		cfg, err := CompileConfigLenient(buildJunosHostWarnTree(t, cmds))
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		if drops := ApplicationReferenceMatchDrops("badType", &cfg.Applications); len(drops) == 0 {
			t.Fatal("badType must carry match drops, so the projection assertion below is vacuous")
		} else if !strings.Contains(strings.Join(drops, "\n"), "bogus") {
			t.Fatalf("badType drops = %q, want the malformed icmp-type token named", drops)
		}
		prog := jh14349OneProgram(t, BuildJunosHostDenyProjection(cfg), "untrust")
		jh14349AssertTerminalDenyBothFamilies(t, prog)
	})

	// Control: a match-all permit already returns every packet in both
	// families, so no terminal deny is appended and the trailing returns
	// are trimmed to an empty program (coarse gate decides, as authored).
	t.Run("match-all permit needs no terminal deny", func(t *testing.T) {
		cfg := jhTestConfig()
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{
				jhPermit("allow-all", []string{"any"}, []string{"any"}),
			}},
		}
		prog := jh14349OneProgram(t, BuildJunosHostDenyProjection(cfg), "untrust")
		if len(prog.RulesV4) != 0 || len(prog.RulesV6) != 0 {
			t.Fatalf("match-all permit must trim to no rules (no redundant terminal deny), got v4=%+v v6=%+v", prog.RulesV4, prog.RulesV6)
		}
	})

	// Control: a permit-free deny-only program must NOT gain a terminal
	// deny — hasAuthoredPermit is permit-gated, not program-gated.
	t.Run("deny-only program gains no terminal deny", func(t *testing.T) {
		cfg := jhTestConfig()
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{
				jhDeny("block-net", []string{"bad-net"}, []string{"any"}),
			}},
		}
		prog := jh14349OneProgram(t, BuildJunosHostDenyProjection(cfg), "untrust")
		if len(prog.RulesV4) != 1 || prog.RulesV4[0].Verdict != JunosHostDrop || len(prog.RulesV4[0].Src) != 1 {
			t.Fatalf("deny-only v4 = %+v, want exactly the authored scoped drop", prog.RulesV4)
		}
		if len(prog.RulesV6) != 0 {
			t.Fatalf("deny-only v6 = %+v, want no rules (v4-only source matches nothing in v6, and no terminal deny)", prog.RulesV6)
		}
	})
}
