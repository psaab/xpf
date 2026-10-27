package config

import "testing"

// #17086: InterfaceRefRG is the single answer to "which redundancy
// group owns interface ref X". Before it, nine pkg/daemon resolvers
// hand-rolled the question with four unit-split rules and two
// member→parent rules, and one config got three different answers for
// the same member ref (SSOT 2, raw-field 0, RPM name-test 1).
//
// This table is the acceptance matrix from the issue: a plain reth
// unit, a structural bond0 unit, a physical member ref, and a stray-RG
// plain interface — plus the chain, cycle, RG-0 and unknown forms the
// member→parent walk must not guess on.
//
// FAIL-ON-REVERT: without InterfaceRefRG these cells do not compile;
// against any hand-rolled re-derivation (first-dot split + raw
// RedundancyGroup, or a `reth*` name test) the bond0, member and
// stray rows disagree with the SSOT, and a naive first-owner walk
// stops at the group-0 intermediate member on the chain rows.
func refRGTestConfig() *Config {
	mk := func(name string, rg int, parent string) *InterfaceConfig {
		return &InterfaceConfig{Name: name, RedundancyGroup: rg, RedundantParent: parent}
	}
	return &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"reth0":    mk("reth0", 1, ""),
		"bond0":    mk("bond0", 2, ""),
		"ge-0/0/1": mk("ge-0/0/1", 0, "bond0"),
		"ge-0/0/2": mk("ge-0/0/2", 0, "reth0"),
		"ge-0/0/5": mk("ge-0/0/5", 1, ""), // stray RG: neither structural nor nominal RETH
		"ge-0/0/7": mk("ge-0/0/7", 0, "ge-0/0/1"),
		"ge-0/0/8": mk("ge-0/0/8", 0, "ge-0/0/9"),
		"ge-0/0/9": mk("ge-0/0/9", 0, "ge-0/0/8"),
		"reth9":    mk("reth9", 0, ""), // nominal RETH carrying group 0
		"lo0":      mk("lo0", 0, ""),
	}}}
}

func TestInterfaceRefRG17086(t *testing.T) {
	cfg := refRGTestConfig()
	idx := cfg.RefRGIndexFor()
	for _, tc := range []struct {
		ref       string
		wantRG    int
		wantOwned bool
		wantPos   int // RefRG: positive-group convenience
		why       string
	}{
		{"reth0.0", 1, true, 1, "reth unit resolves to its base's group"},
		{"reth0", 1, true, 1, "bare reth base"},
		{"bond0.50", 2, true, 2, "structural RETH not spelled reth* owns its group — the RPM name-test dropped exactly this"},
		{"bond0", 2, true, 2, "bare structural base"},
		{"ge-0/0/1.0", 2, true, 2, "physical member ref resolves through redundant-parent to bond0"},
		{"ge-0/0/1", 2, true, 2, "bare member"},
		{"ge-0/0/2", 1, true, 1, "member of reth0"},
		{"ge-0/0/7.0", 2, true, 2, "member-of-member chain resolves to the RETH at its head"},
		{"ge-0/0/5", 0, false, 0, "stray redundancy-group on a plain interface owns nothing (SSOT excludes it; raw-field readers returned 1)"},
		{"ge-0/0/5.0", 0, false, 0, "stray-RG unit form also owns nothing"},
		{"ge-0/0/8", 0, true, 0, "redundant-parent cycle of group-0 structural owners terminates owned-at-0, never inventing a positive group"},
		{"ge-0/0/9.0", 0, true, 0, "cycle entered from the other member, same answer"},
		{"reth9.0", 0, true, 0, "a RETH carrying group 0 is owned at group 0; the >0 term is the caller's (RefRG reports 0)"},
		{"lo0", 0, false, 0, "plain interface owns nothing"},
		{"nonexistent.0", 0, false, 0, "unknown ref owns nothing"},
		{"", 0, false, 0, "empty ref owns nothing"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			rg, owned := cfg.InterfaceRefRG(tc.ref)
			if rg != tc.wantRG || owned != tc.wantOwned {
				t.Errorf("InterfaceRefRG(%q) = (%d,%v), want (%d,%v). %s",
					tc.ref, rg, owned, tc.wantRG, tc.wantOwned, tc.why)
			}
			// The precomputed per-packet index must agree on every cell.
			irg, iowned := idx.Lookup(tc.ref)
			if irg != tc.wantRG || iowned != tc.wantOwned {
				t.Errorf("RefRGIndex.Lookup(%q) = (%d,%v), want (%d,%v) — index and InterfaceRefRG diverged. %s",
					tc.ref, irg, iowned, tc.wantRG, tc.wantOwned, tc.why)
			}
			if got := cfg.RefRG(tc.ref); got != tc.wantPos {
				t.Errorf("RefRG(%q) = %d, want %d. %s", tc.ref, got, tc.wantPos, tc.why)
			}
		})
	}

	var nilCfg *Config
	if rg, owned := nilCfg.InterfaceRefRG("reth0.0"); owned || rg != 0 {
		t.Errorf("nil Config InterfaceRefRG = (%d,%v), want (0,false)", rg, owned)
	}
	if rg, owned := nilCfg.RefRGIndexFor().Lookup("reth0.0"); owned || rg != 0 {
		t.Errorf("nil Config RefRGIndex Lookup = (%d,%v), want (0,false)", rg, owned)
	}
	var nilIdx *RefRGIndex
	if rg, owned := nilIdx.Lookup("reth0.0"); owned || rg != 0 {
		t.Errorf("nil RefRGIndex Lookup = (%d,%v), want (0,false)", rg, owned)
	}
}
