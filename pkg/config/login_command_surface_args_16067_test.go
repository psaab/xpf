package config

import "testing"

// #16067: with argument samples registered, an argument-scoped pattern
// is enforceable and must not be reported on-box-only; without samples
// (a surface that has not proven it reconstructs arguments) the #8189
// advisory keeps speaking.


func loginClassCfgAllow(t *testing.T, allow string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range []string{
		"set system login class limited permissions view",
		`set system login class limited allow-commands "` + allow + `"`,
	} {
		path, quoted, err := ParseSetCommandQuoted(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		if err := tree.SetPathQuoted(path, quoted); err != nil {
			t.Fatalf("setpath %q: %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestArgumentSamplesSilenceAdvisory16067(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show route table", "show interfaces", "request system reboot"})
	RegisterCommandSurfaceArgumentSamples("the gRPC surface", func() []string {
		return []string{"show route table inet.0", "ping 192.0.2.1"}
	})
	t.Cleanup(func() { delete(registeredArgumentSamples, "the gRPC surface") })

	rules, ok, err := OperationalLoginRegexesFor(loginClassCfg(t, `^show route table secret-vrf$`), "limited")
	if err != nil || !ok {
		t.Fatalf("precondition: %v %v", ok, err)
	}
	if got := UnenforceableDenySurfaces(rules); len(got) != 0 {
		t.Errorf("argument-scoped deny with registered samples must not be reported unenforceable; got %v", got)
	}

	rules2, _, _ := OperationalLoginRegexesFor(loginClassCfg(t, `^qqq-not-a-command$`), "limited")
	if got := UnenforceableDenySurfaces(rules2); len(got) != 1 {
		t.Errorf("a pattern naming no command in any spelling must still be reported; got %v", got)
	}
}

func TestNoSamplesKeepsAdvisory16067(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show route table"})
	rules, _, _ := OperationalLoginRegexesFor(loginClassCfg(t, `^show route table secret-vrf$`), "limited")
	if got := UnenforceableDenySurfaces(rules); len(got) != 1 {
		t.Errorf("without registered samples the advisory must keep speaking; got %v", got)
	}
}

// #16378 fold (advisory false unenforceability): witnesses must exist
// for every pattern shape that can actually fire remotely — including
// non-literal argument words (character classes, alternations) and
// allow-side argument spellings — when a sample proves the slot.
func TestAdvisoryWitnessShapes16067(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show route table", "show interfaces", "ping"})
	RegisterCommandSurfaceArgumentSamples("the gRPC surface", func() []string {
		return []string{"show route table inet.0", "ping 192.0.2.1", "show log messages"}
	})
	t.Cleanup(func() { delete(registeredArgumentSamples, "the gRPC surface") })

	for _, pat := range []string{
		`^show route table secret-vrf$`,     // literal witness (existing)
		`secret-vrf`,                        // unanchored segment in a slot
		`^ping 10\.99\.`,                    // dotted literal segment
		`^show route table [a-z-]+$`,        // character-class argument word
		`^show (route table secret|log x)$`, // alternation naming a slot command
	} {
		rules, _, _ := OperationalLoginRegexesFor(loginClassCfg(t, pat), "limited")
		if got := UnenforceableDenySurfaces(rules); len(got) != 0 {
			t.Errorf("deny %q can fire remotely (a sample proves its slot) but was reported unenforceable: %v", pat, got)
		}
	}
	// Truly unenforceable shapes still speak.
	for _, pat := range []string{`^qqq-not-a-command$`, `^show qqq-zzz$`} {
		rules, _, _ := OperationalLoginRegexesFor(loginClassCfg(t, pat), "limited")
		if got := UnenforceableDenySurfaces(rules); len(got) != 1 {
			t.Errorf("deny %q names no producible command and must still be reported; got %v", pat, got)
		}
	}
}

// Allow-side witnesses: an allow written against an argument spelling
// permits that command remotely, so it must not be reported as
// permitting nothing (#16378 fold).
func TestAdvisoryAllowWitness16067(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show route table", "ping"})
	RegisterCommandSurfaceArgumentSamples("the gRPC surface", func() []string {
		return []string{"show route table inet.0", "ping 192.0.2.1"}
	})
	t.Cleanup(func() { delete(registeredArgumentSamples, "the gRPC surface") })

	cfg := loginClassCfgAllow(t, `^show route table secret-vrf$`)
	rules, ok, err := OperationalLoginRegexesFor(cfg, "limited")
	if err != nil || !ok {
		t.Fatalf("precondition: %v %v", ok, err)
	}
	if got := UnenforceableAllowSurfaces(rules); len(got) != 0 {
		t.Errorf("allow %q permits `show route table secret-vrf` remotely but was reported as permitting nothing: %v", `^show route table secret-vrf$`, got)
	}
	cfg2 := loginClassCfgAllow(t, `^qqq-zzz$`)
	rules2, _, _ := OperationalLoginRegexesFor(cfg2, "limited")
	if got := UnenforceableAllowSurfaces(rules2); len(got) != 1 {
		t.Errorf("allow naming no producible command must still be reported; got %v", got)
	}
}
