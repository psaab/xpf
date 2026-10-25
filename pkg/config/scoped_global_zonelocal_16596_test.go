package config

import (
	"strings"
	"testing"
)

// #16596: Junos requires global-policy addresses to be defined in the global
// address book. A single-zone scoped global must therefore NOT resolve its
// tokens against that zone's attached/inline book (the former #3287
// rewrite), even when the global book defines the same name.

func scopedGlobalBase16596() []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	}
}

func withGlobal16596(lines []string, name string, extra ...string) []string {
	out := append([]string(nil), lines...)
	out = append(out,
		"set security policies global policy "+name+" match source-address BLOCKED",
		"set security policies global policy "+name+" match destination-address any",
		"set security policies global policy "+name+" match application any",
		"set security policies global policy "+name+" then deny",
	)
	out = append(out, extra...)
	return out
}

func findGlobal16596(t *testing.T, cfg *Config, name string) *Policy {
	t.Helper()
	for _, p := range cfg.Security.GlobalPolicies {
		if p != nil && p.Name == name {
			return p
		}
	}
	t.Fatalf("global policy %q not found in %+v", name, cfg.Security.GlobalPolicies)
	return nil
}

// Same name in global and trust-attached books: the scoped global must keep
// the bare (global) token, strict-clean, and the trust zone-pair keeps the
// qualified zone-local token — zone-pair rows are unchanged.
func TestScopedGlobalSameNameResolvesGlobal16596(t *testing.T) {
	lines := scopedGlobalBase16596()
	lines = append(lines,
		"set security address-book global address BLOCKED 10.0.0.0/8",
		"set security address-book eng-book address BLOCKED 10.1.1.1/32",
		"set security address-book eng-book attach zone trust",
		"set security policies from-zone trust to-zone untrust policy zp match source-address BLOCKED",
		"set security policies from-zone trust to-zone untrust policy zp match destination-address any",
		"set security policies from-zone trust to-zone untrust policy zp match application any",
		"set security policies from-zone trust to-zone untrust policy zp then permit",
	)
	lines = withGlobal16596(lines, "gdeny",
		"set security policies global policy gdeny match from-zone trust")
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("strict compile must accept global-twin scoped global: %v", err)
	}
	gp := findGlobal16596(t, cfg, "gdeny")
	if len(gp.Match.SourceAddresses) != 1 || gp.Match.SourceAddresses[0] != "BLOCKED" {
		t.Fatalf("scoped global source = %v, want bare [BLOCKED] (global book)", gp.Match.SourceAddresses)
	}
	if gp.LenientContentDropped {
		t.Fatal("global-twin scoped global must not be poisoned")
	}
	if a := cfg.Security.AddressBook.Addresses["BLOCKED"]; a == nil || a.UsableValue() != "10.0.0.0/8" {
		t.Fatalf("global BLOCKED = %+v, want 10.0.0.0/8", a)
	}
	// Zone-pair control: trust policy still resolves zone-local first.
	found := false
	for _, pair := range cfg.Security.Policies {
		for _, p := range pair.Policies {
			for _, tok := range p.Match.SourceAddresses {
				if tok == "zone-local/trust/BLOCKED" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("zone-pair trust policy must keep zone-local token: %+v", cfg.Security.Policies)
	}
}

// The scoped row must agree with the unscoped and multi-zone rows: all keep
// the global token.
func TestScopedGlobalScopeVariantsAgree16596(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"unscoped", nil},
		{"single-zone", []string{"set security policies global policy g match from-zone trust"}},
		{"multi-zone", []string{
			"set security policies global policy g match from-zone trust",
			"set security policies global policy g match from-zone dmz",
		}},
		{"any-scope", []string{"set security policies global policy g match from-zone any"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := scopedGlobalBase16596()
			lines = append(lines,
				"set security address-book global address BLOCKED 10.0.0.0/8",
				"set security zones security-zone trust address-book address BLOCKED 10.1.1.1/32",
			)
			lines = withGlobal16596(lines, "g", tc.extra...)
			cfg, err := CompileConfig(buildTree(t, lines))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			gp := findGlobal16596(t, cfg, "g")
			if len(gp.Match.SourceAddresses) != 1 || gp.Match.SourceAddresses[0] != "BLOCKED" {
				t.Fatalf("%s: source = %v, want [BLOCKED]", tc.name, gp.Match.SourceAddresses)
			}
		})
	}
}

// Destination side: to-zone scope likewise must not rebind.
func TestScopedGlobalDestSameNameResolvesGlobal16596(t *testing.T) {
	lines := scopedGlobalBase16596()
	lines = append(lines,
		"set security address-book global address DST 192.0.2.0/24",
		"set security zones security-zone untrust address-book address DST 198.51.100.1/32",
		"set security policies global policy g match source-address any",
		"set security policies global policy g match destination-address DST",
		"set security policies global policy g match application any",
		"set security policies global policy g match to-zone untrust",
		"set security policies global policy g then deny",
	)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	gp := findGlobal16596(t, cfg, "g")
	if len(gp.Match.DestinationAddresses) != 1 || gp.Match.DestinationAddresses[0] != "DST" {
		t.Fatalf("dest = %v, want [DST]", gp.Match.DestinationAddresses)
	}
}

// Local-only token in a scoped global: strict rejects naming policy, field,
// token, and zone; tolerant warns and poisons so neither object enforces.
func TestScopedGlobalLocalOnlyRejected16596(t *testing.T) {

	lines := scopedGlobalBase16596()
	lines = append(lines,
		"set security zones security-zone trust address-book address LOCALNET 10.0.1.0/24",
		"set security policies global policy allow-local match source-address LOCALNET",
		"set security policies global policy allow-local match destination-address any",
		"set security policies global policy allow-local match application any",
		"set security policies global policy allow-local match from-zone trust",
		"set security policies global policy allow-local then permit",
	)
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("strict must reject local-only scoped global (#16596)")
	} else {
		for _, want := range []string{"allow-local", "source-address", "LOCALNET", "trust", "global address book", "#16596"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %q", err.Error(), want)
			}
		}
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if !warningsContaining15672(cfg, "LOCALNET", "#16596") {
		t.Fatalf("lenient must warn naming LOCALNET/#16596: %v", cfg.Warnings)
	}
	gp := findGlobal16596(t, cfg, "allow-local")
	if !gp.LenientContentDropped {
		t.Fatal("lenient local-only scoped global must be poisoned (LenientContentDropped)")
	}
	// The token must stay bare, never rewritten to the zone-local object.
	if len(gp.Match.SourceAddresses) != 1 || gp.Match.SourceAddresses[0] != "LOCALNET" {
		t.Fatalf("lenient source = %v, want bare [LOCALNET]", gp.Match.SourceAddresses)
	}
}

// Attached-book local-only token behaves identically to the inline book.
func TestScopedGlobalAttachedLocalOnlyRejected16596(t *testing.T) {
	lines := scopedGlobalBase16596()
	lines = append(lines,
		"set security address-book eng-book address ONLYHERE 10.1.1.1/32",
		"set security address-book eng-book attach zone trust",
		"set security policies global policy g match source-address ONLYHERE",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g match from-zone trust",
		"set security policies global policy g then deny",
	)
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("strict must reject attached-book local-only scoped global")
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if gp := findGlobal16596(t, cfg, "g"); !gp.LenientContentDropped {
		t.Fatal("lenient attached local-only must be poisoned")
	}
}

// A global address-set whose member exists only in the scoped zone's book
// must not smuggle that member into global scope.
func TestScopedGlobalSetMemberLocalOnlyRejected16596(t *testing.T) {
	lines := scopedGlobalBase16596()
	lines = append(lines,
		"set security address-book global address-set GRP address MEMB",
		"set security zones security-zone trust address-book address MEMB 10.1.1.1/32",
		"set security policies global policy g match source-address GRP",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g match from-zone trust",
		"set security policies global policy g then deny",
	)
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("strict must reject global set with zone-local-only member in scoped global")
	} else if !strings.Contains(err.Error(), "MEMB") {
		t.Errorf("error must name MEMB: %v", err)
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if gp := findGlobal16596(t, cfg, "g"); !gp.LenientContentDropped {
		t.Fatal("lenient set-member case must be poisoned")
	}
}

// Controls that must NOT be rejected: multi-zone scope (already global, and
// its local-only token is the #2008 undefined-reference gate's domain — this
// gate must not double-report it as a #16596 finding on the tolerant path),
// unscoped global with a global token, and a literal token.
func TestScopedGlobalControlsNotPoisoned16596(t *testing.T) {
	// Multi-zone: strict rejects via undefined reference (not necessarily
	// #16596), but the tolerant compile must not poison via #16596.
	lines := scopedGlobalBase16596()
	lines = append(lines,
		"set security zones security-zone trust address-book address LOCALNET 10.0.1.0/24",
		"set security policies global policy g match source-address LOCALNET",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g match from-zone trust",
		"set security policies global policy g match from-zone dmz",
		"set security policies global policy g then permit",
	)
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient multi-zone: %v", err)
	}
	if gp := findGlobal16596(t, cfg, "g"); gp.LenientContentDropped {
		t.Fatal("multi-zone scope must not be poisoned by #16596 gate")
	}
	if warningsContaining15672(cfg, "#16596") {
		t.Fatalf("multi-zone must not warn #16596: %v", cfg.Warnings)
	}

	// Literal token in a single-zone scope is not a book reference.
	lines2 := scopedGlobalBase16596()
	lines2 = append(lines2,
		"set security zones security-zone trust address-book address BLOCKED 10.1.1.1/32",
		"set security policies global policy g match source-address 10.9.0.0/24",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g match from-zone trust",
		"set security policies global policy g then deny",
	)
	if _, err := CompileConfig(buildTree(t, lines2)); err != nil {
		t.Fatalf("literal scoped global must commit: %v", err)
	}
}
