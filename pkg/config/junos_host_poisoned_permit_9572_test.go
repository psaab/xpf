package config

import (
	"testing"
)

// #9572: on the TOLERANT compile channel (persisted load, HA peer sync), a
// `to-zone junos-host` PERMIT with a missing or valueless match dimension
// compiles with that dimension EMPTY and the #5575 LenientContentDropped flag
// set. The userspace snapshot builder refuses such a policy. The kernel
// projection read the empty dimension as `any` instead, so the permit became a
// permit-all (or a narrow-application poison) and erased the following deny
// from the host-inbound DROP program. The daemon installs that program from the
// config the helper refused, and on the direct host-bound path it is the
// enforcement.
//
// #6705 / #7477 measured the strict commit only, where the #3044 and #6526
// gates reject both spellings, and so called this vector unreachable. Every
// row below first proves it is tolerant-only: strict rejects the config and
// the lenient compile flags p0. Only then does it read the projected rule
// CONTENT. A "program exists" assertion is what hid #6705.

func compileJunosHost9572(t *testing.T, strict bool, cmds ...string) (*Config, error) {
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
	if strict {
		return CompileConfig(tree)
	}
	return CompileConfigLenient(tree)
}

const junosHost9572Pol = "set security policies from-zone trust to-zone junos-host policy "

// junosHost9572Config is the #6705 base (zone trust coarse-admits ssh) with a
// p0 permit carrying exactly the given match lines, followed by the issue's p1
// deny: every source, application junos-ssh.
func junosHost9572Config(p0Match ...string) []string {
	cmds := junosHost6705Base()
	for _, m := range p0Match {
		cmds = append(cmds, junosHost9572Pol+"p0 match "+m)
	}
	return append(cmds,
		junosHost9572Pol+"p0 then permit",
		junosHost9572Pol+"p1 match source-address any",
		junosHost9572Pol+"p1 match destination-address any",
		junosHost9572Pol+"p1 match application junos-ssh",
		junosHost9572Pol+"p1 then deny",
	)
}

func junosHost9572Policy(t *testing.T, cfg *Config, name string) *Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != "trust" || zpp.ToZone != "junos-host" {
			continue
		}
		for _, p := range zpp.Policies {
			if p != nil && p.Name == name {
				return p
			}
		}
	}
	t.Fatalf("policy %q not compiled into from-zone trust to-zone junos-host", name)
	return nil
}

func junosHost9572Program(proj JunosHostDenyProjection) *JunosHostDenyProgram {
	for i := range proj.Programs {
		if proj.Programs[i].Zone == "trust" {
			return &proj.Programs[i]
		}
	}
	return nil
}

// junosHost9572AssertSSHDrop asserts p1's authored content in ONE family: one
// rule, every source, nothing subtracted, and exactly TCP destination port 22.
func junosHost9572AssertSSHDrop(t *testing.T, family string, rules []JunosHostDenyRule) {
	t.Helper()
	if len(rules) != 1 {
		t.Fatalf("%s: want exactly the p1 DROP rule, got %d rules: %+v", family, len(rules), rules)
	}
	r := rules[0]
	if !r.SrcAny || len(r.Src) != 0 || len(r.PermitSubtract) != 0 {
		t.Errorf("%s: p1 source content = SrcAny:%v Src:%v PermitSubtract:%v, want every source with nothing subtracted",
			family, r.SrcAny, r.Src, r.PermitSubtract)
	}
	if len(r.L4) != 1 || r.L4[0].Proto != HostInboundProtoTCP ||
		len(r.L4[0].Ports) != 1 || r.L4[0].Ports[0] != (PortRange{Lo: 22, Hi: 22}) {
		t.Errorf("%s: p1 L4 content = %+v, want exactly tcp dport 22 (junos-ssh)", family, r.L4)
	}
}

// TestJunosHostPoisonedPermitKeepsFollowingDeny9572 is the acceptance: every
// poisoned spelling of p0 leaves p1's DROP in the program, as authored.
func TestJunosHostPoisonedPermitKeepsFollowingDeny9572(t *testing.T) {
	variants := []struct {
		name    string
		p0Match []string
	}{
		// application any: before the fix, the permitAll arm shadowed p1.
		{"source-address omitted, application any",
			[]string{"destination-address any", "application any"}},
		{"source-address valueless, application any",
			[]string{"source-address", "destination-address any", "application any"}},
		// narrow application: before the fix, the poison sentinel emptied the zone.
		{"source-address omitted, application junos-ssh",
			[]string{"destination-address any", "application junos-ssh"}},
		{"source-address valueless, application junos-ssh",
			[]string{"source-address", "destination-address any", "application junos-ssh"}},
		{"application omitted",
			[]string{"source-address any", "destination-address any"}},
		{"application valueless",
			[]string{"source-address any", "destination-address any", "application"}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			cmds := junosHost9572Config(v.p0Match...)
			if _, err := compileJunosHost9572(t, true, cmds...); err == nil {
				t.Fatalf("premise broken: the STRICT commit accepted this p0 spelling, so the row is not the tolerant channel")
			}
			cfg, err := compileJunosHost9572(t, false, cmds...)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			if !junosHost9572Policy(t, cfg, "p0").LenientContentDropped {
				t.Fatalf("premise broken: the lenient compile did not flag p0 LenientContentDropped")
			}
			if junosHost9572Policy(t, cfg, "p1").LenientContentDropped {
				t.Fatalf("premise broken: p1 is authored completely but is flagged LenientContentDropped")
			}

			proj := BuildJunosHostDenyProjection(cfg)
			prog := junosHost9572Program(proj)
			if prog == nil || !prog.Representable {
				t.Fatalf("zone trust projected no representable program (%+v): the poisoned permit emptied it", prog)
			}
			junosHost9572AssertSSHDrop(t, "ip", prog.RulesV4)
			junosHost9572AssertSSHDrop(t, "ip6", prog.RulesV6)
			if key := JunosHostZonePairPolicyKey("trust", "p1"); !proj.RenderedPolicyKeys[key] {
				t.Errorf("p1 emitted rules but is not marked rendered (renderedKeys=%v)", proj.RenderedPolicyKeys)
			}
		})
	}
}

// TestJunosHostAuthoredPermitStillSubtracts9572 holds the other side. A fix
// that stopped projecting every permit, or keyed the skip off an empty
// dimension instead of the flag, would satisfy the test above and break the
// #4146 set subtraction.
func TestJunosHostAuthoredPermitStillSubtracts9572(t *testing.T) {
	// S2-CTRL: a valid `application any` permit for every source legitimately
	// shadows p1 (#7477), strict and lenient alike.
	t.Run("S2-CTRL application any permit-all shadows p1", func(t *testing.T) {
		cmds := junosHost9572Config("source-address any", "destination-address any", "application any")
		for _, strict := range []bool{true, false} {
			cfg, err := compileJunosHost9572(t, strict, cmds...)
			if err != nil {
				t.Fatalf("strict=%v compile: %v", strict, err)
			}
			prog := junosHost9572Program(BuildJunosHostDenyProjection(cfg))
			if prog == nil {
				t.Fatalf("strict=%v: no program for zone trust", strict)
			}
			if len(prog.RulesV4) != 0 || len(prog.RulesV6) != 0 {
				t.Errorf("strict=%v: an authored permit-all must shadow p1, got RulesV4=%+v RulesV6=%+v",
					strict, prog.RulesV4, prog.RulesV6)
			}
		}
	})

	// An authored narrow-source permit still carves p1 with `saddr !=`.
	t.Run("authored source permit is subtracted from p1", func(t *testing.T) {
		cfg, err := compileJunosHost9572(t, true,
			junosHost9572Config("source-address NET9", "destination-address any", "application any")...)
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		prog := junosHost9572Program(BuildJunosHostDenyProjection(cfg))
		if prog == nil || len(prog.RulesV4) != 1 {
			t.Fatalf("want one v4 p1 rule, got %+v", prog)
		}
		if got := prog.RulesV4[0].PermitSubtract; len(got) != 1 || got[0] != "10.0.9.0/24" {
			t.Errorf("p1 PermitSubtract = %v, want [10.0.9.0/24] from the authored p0 permit", got)
		}
	})

	// The MIDDLE row: S2-CTRL's content, with only the flag differing. It shows
	// the flag drives the skip, not the resolved dimensions.
	t.Run("same permit-all content, flag set, stops shadowing", func(t *testing.T) {
		cfg, err := compileJunosHost9572(t, true,
			junosHost9572Config("source-address any", "destination-address any", "application any")...)
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		junosHost9572Policy(t, cfg, "p0").LenientContentDropped = true
		prog := junosHost9572Program(BuildJunosHostDenyProjection(cfg))
		if prog == nil {
			t.Fatal("no program for zone trust")
		}
		junosHost9572AssertSSHDrop(t, "ip", prog.RulesV4)
		junosHost9572AssertSSHDrop(t, "ip6", prog.RulesV6)
	})
}

// TestJunosHostPoisonedDenyStillDrops9572 pins the fix's SCOPE. Only a poisoned
// PERMIT is skipped. A poisoned DENY (here with source-address omitted) keeps
// projecting as a DROP for every source: that widens a DROP, the fail-closed
// direction, and skipping it would turn a refused config into an unenforced
// deny.
func TestJunosHostPoisonedDenyStillDrops9572(t *testing.T) {
	cmds := append(junosHost6705Base(),
		junosHost9572Pol+"p1 match destination-address any",
		junosHost9572Pol+"p1 match application junos-ssh",
		junosHost9572Pol+"p1 then deny",
	)
	if _, err := compileJunosHost9572(t, true, cmds...); err == nil {
		t.Fatal("premise broken: the STRICT commit accepted a deny with no source-address")
	}
	cfg, err := compileJunosHost9572(t, false, cmds...)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if !junosHost9572Policy(t, cfg, "p1").LenientContentDropped {
		t.Fatal("premise broken: the lenient compile did not flag the deny LenientContentDropped")
	}
	prog := junosHost9572Program(BuildJunosHostDenyProjection(cfg))
	if prog == nil {
		t.Fatal("no program for zone trust")
	}
	junosHost9572AssertSSHDrop(t, "ip", prog.RulesV4)
	junosHost9572AssertSSHDrop(t, "ip6", prog.RulesV6)
}

// TestJunosHostPoisonedPermitSkipsResolution9572 pins "skipped BEFORE
// resolution". A poisoned permit whose remaining content is un-representable
// here (a scheduler-gated permit) must not make the zone's whole program
// un-representable. Doing so would erase p1 through the representability gate
// instead of the permitAll arm.
func TestJunosHostPoisonedPermitSkipsResolution9572(t *testing.T) {
	cfg, err := compileJunosHost9572(t, true,
		junosHost9572Config("source-address NET9", "destination-address any", "application any")...)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	p0 := junosHost9572Policy(t, cfg, "p0")
	p0.SchedulerName = "office-hours"
	prog := junosHost9572Program(BuildJunosHostDenyProjection(cfg))
	if prog == nil || prog.Representable {
		t.Fatalf("premise broken: a scheduler-gated authored permit should make the program un-representable, got %+v", prog)
	}
	p0.LenientContentDropped = true
	prog = junosHost9572Program(BuildJunosHostDenyProjection(cfg))
	if prog == nil || !prog.Representable {
		t.Fatalf("a poisoned permit's leftover content emptied the zone's program: %+v", prog)
	}
	junosHost9572AssertSSHDrop(t, "ip", prog.RulesV4)
	junosHost9572AssertSSHDrop(t, "ip6", prog.RulesV6)
}
