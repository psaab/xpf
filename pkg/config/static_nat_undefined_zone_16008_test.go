package config

import (
	"strings"
	"testing"
)

// #16008: a static-NAT rule-set whose `from zone` names no configured
// zone was warn-only (ValidateConfig) while the snapshot builder shipped
// the name verbatim and the Rust dataplane matched it by exact name
// equality — a typo'd from-zone silently never matched. Strict commit
// must reject naming rule-set and zone (like source/destination, #15001);
// the tolerant path must warn, record the rule-set in
// LenientNATUndefinedZoneRuleSets{Kind:"static"}, and retain it so the
// snapshot builders are the deciding drop layer.
//
// RED on revert: removing the static arm of natUndefinedZoneFindings
// makes strict CompileConfig accept the typo and every test below fail
// (strict accepts, no tolerant warning/record).

func staticZoneTree16008(t *testing.T, cmds ...string) *ConfigTree {
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
	return tree
}

func staticBadCmds16008() []string {
	return []string{
		"set security zones security-zone trust",
		"set security nat static rule-set static-bad from zone untrsut",
		"set security nat static rule-set static-bad rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set static-bad rule R1 then static-nat prefix 10.0.0.5/32",
	}
}

func TestStaticNATUndefinedZoneStrictRejected16008(t *testing.T) {
	_, err := CompileConfig(staticZoneTree16008(t, staticBadCmds16008()...))
	if err == nil {
		t.Fatal("strict CompileConfig accepted undefined static-NAT from-zone; want reject")
	}
	for _, want := range []string{"static-bad", "untrsut"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("strict error %q does not name %q", err.Error(), want)
		}
	}
	if want := `static-nat rule-set "static-bad": from-zone "untrsut" not defined`; err.Error() != want {
		t.Fatalf("strict error = %q, want exactly %q (unified-walk message)", err.Error(), want)
	}
}

func TestStaticNATUndefinedZoneLenientWarnsAndRecords16008(t *testing.T) {
	cfg, err := CompileConfigLenient(staticZoneTree16008(t, staticBadCmds16008()...))
	if err != nil {
		t.Fatalf("lenient CompileConfig rejected undefined static zone (#1960 no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "static-bad") && strings.Contains(w, "untrsut") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no warning naming static-bad/untrsut; warnings=%v", cfg.Warnings)
	}
	if !cfg.LenientNATUndefinedZoneRuleSets[NATRuleSetRef{Kind: "static", Name: "static-bad"}] {
		t.Fatalf("lenient record missing {static static-bad}; record=%v", cfg.LenientNATUndefinedZoneRuleSets)
	}
	if len(cfg.Security.NAT.Static) != 1 || cfg.Security.NAT.Static[0].Name != "static-bad" {
		t.Fatalf("tolerant compile must retain the rule-set for the snapshot-builder drop; static=%+v", cfg.Security.NAT.Static)
	}
}

func TestStaticNATDefinedAndUnscopedZonesCommit16008(t *testing.T) {
	for name, cmds := range map[string][]string{
		"defined": {
			"set security zones security-zone untrust",
			"set security nat static rule-set ok from zone untrust",
			"set security nat static rule-set ok rule R1 match destination-address 203.0.113.5/32",
			"set security nat static rule-set ok rule R1 then static-nat prefix 10.0.0.5/32",
		},
		"unscoped": {
			"set security zones security-zone trust",
			"set security nat static rule-set global rule R1 match destination-address 203.0.113.5/32",
			"set security nat static rule-set global rule R1 then static-nat prefix 10.0.0.5/32",
		},
		"interface-scoped": {
			"set security zones security-zone trust",
			"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
			"set security nat static rule-set scoped from interface ge-0/0/0.0",
			"set security nat static rule-set scoped rule R1 match destination-address 203.0.113.5/32",
			"set security nat static rule-set scoped rule R1 then static-nat prefix 10.0.0.5/32",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfig(staticZoneTree16008(t, cmds...))
			if err != nil {
				t.Fatalf("valid static NAT (%s) rejected: %v", name, err)
			}
			if cfg == nil {
				t.Fatal("nil cfg")
			}
		})
	}
}
