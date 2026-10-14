package config

import (
	"fmt"
	"strings"
	"testing"
)

// #10308: data members of zones named `mgmt`/`control` stay on the
// policy-adjudicated path because the exemption is keyed on interface class,
// not zone name. The commit warning names the exact member and zone so an
// operator cannot mistake a data NIC for a vrf-mgmt lifeline.
func TestMgmtControlZoneDataMemberWarnsAtCommit10308(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone mgmt interfaces ge-0/0/0.0",
		"set security zones security-zone control interfaces ge-0/0/1.0",
	})
	for _, tc := range []struct{ zone, member string }{
		{"mgmt", "ge-0/0/0.0"},
		{"control", "ge-0/0/1.0"},
	} {
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "(#10308)") && strings.Contains(w, tc.zone) &&
				strings.Contains(w, tc.member) && strings.Contains(w, "interface class") &&
				strings.Contains(w, "not on the zone name") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no (#10308) advisory naming zone %q member %q and class-based exemption; warnings=%v",
				tc.zone, tc.member, cfg.Warnings)
		}
	}
}

// Canonical vrf-mgmt lifelines remain accepted and quiet in their traditional
// `mgmt`/`control` zones. The daemon's managementVRFIfaceSet still binds these
// interface classes to vrf-mgmt; only the data-NIC misuse is warned.
func TestMgmtControlZoneLifelinesStayQuiet10308(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set interfaces fxp0 unit 0 family inet address 10.0.9.1/24",
		"set interfaces em0 unit 0 family inet address 10.0.9.2/24",
		"set interfaces fab0 unit 0 family inet address 10.0.9.3/24",
		"set interfaces lo0 unit 0 family inet address 127.0.0.1/32",
		"set security zones security-zone mgmt interfaces fxp0.0",
		"set security zones security-zone mgmt interfaces fab0.0",
		"set security zones security-zone control interfaces em0.0",
		"set security zones security-zone mgmt interfaces lo0.0",
	})
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#10308)") {
			t.Fatalf("lifeline-only zones must not warn: %q (warnings=%v)", w, cfg.Warnings)
		}
	}
}

// Tolerant load/peer-sync paths do not repeat a commit-time advisory on every
// boot, matching the existing warning suppression contract.
func TestMgmtControlZoneAdvisorySuppressedOnLenientPath10308(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone mgmt interfaces ge-0/0/0.0",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#10308)") {
			t.Fatalf("lenient compile must suppress the commit-time advisory: %q", w)
		}
	}
}

// Other production exclusion classes do not receive a data-NIC warning merely
// because their zone happens to be named `mgmt` or `control`.
func TestMgmtControlZoneNonDataClassesStayQuiet10308(t *testing.T) {
	cfg := &Config{
		Security: SecurityConfig{
			Zones: map[string]*ZoneConfig{
				"mgmt":    {Interfaces: []string{"gr-0/0/0.0", "ge-0/0/1.0"}},
				"control": {Interfaces: []string{"st0.0"}},
			},
			IPsec: IPsecConfig{VPNs: map[string]*IPsecVPN{
				"vpn0": {BindInterface: "st0.0"},
			}},
		},
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{}},
			"ge-0/0/1": {Name: "ge-0/0/1", LocalFabricMember: "fab0"},
			"st0":      {Name: "st0"},
		}},
	}
	appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#10308)") {
			t.Fatalf("non-data exclusion classes must stay quiet: %q", w)
		}
	}
}

// Ownership is checked for the exact zone-member ref. A VPN binding bare `st5`
// must not make a distinct `st5.3` row silently inherit the tunnel exclusion.
func TestMgmtControlZoneSecureTunnelAliasStillWarns10308(t *testing.T) {
	cfg := &Config{
		Security: SecurityConfig{
			Zones: map[string]*ZoneConfig{
				"mgmt": {Interfaces: []string{"st5.3"}},
			},
			IPsec: IPsecConfig{VPNs: map[string]*IPsecVPN{
				"vpn0": {BindInterface: "st5"},
			}},
		},
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"st5": {Name: "st5"},
		}},
	}
	appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#10308)") {
			return
		}
	}
	t.Fatalf("distinct secure-tunnel alias must retain the zone-name advisory: %v", cfg.Warnings)
}

// #12830: bare references to unit-0 tunnels and bare secure-tunnel bindings
// are non-data, and quarantined claims must not produce an advisory.
func TestMgmtControlZoneBareUnit0TunnelsAndQuarantinedMembersStayQuiet12830(t *testing.T) {
	cfg := &Config{
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"mgmt":    {Interfaces: []string{"gr-0/0/0", "ge-0/0/1.0"}},
			"control": {Interfaces: []string{"ip-0/0/0", "st0", "st1"}},
			"trust":   {Interfaces: []string{"ge-0/0/1.0"}},
		}},
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"gr-0/0/0": {Name: "gr-0/0/0", Units: map[int]*InterfaceUnit{0: {Tunnel: &TunnelConfig{}}}},
			"ip-0/0/0": {Name: "ip-0/0/0", Units: map[int]*InterfaceUnit{0: {Tunnel: &TunnelConfig{}}}},
			"ge-0/0/1": {Name: "ge-0/0/1"},
		}},
	}
	cfg.Security.IPsec.VPNs = map[string]*IPsecVPN{
		"vpn0": {BindInterface: "st0"},
		"vpn1": {BindInterface: "st1.0"},
	}
	appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#10308)") {
			t.Fatalf("bare unit-0/secure-tunnel or quarantined members must stay quiet: %q (warnings=%v)", w, cfg.Warnings)
		}
	}
}

// #12830 mutants: an absent unknown interface and a bare non-zero or
// non-tunnel unit must still warn; interpreting every bare reference as unit
// 0 without tunnel evidence, or any st-looking name as secure tunnel, fails.
func TestMgmtControlZoneBareUnknownAndNonZeroUnitsStillWarn12830(t *testing.T) {
	cfg := &Config{
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"mgmt": {Interfaces: []string{"ge-9/0/0", "gr-0/0/0"}},
		}},
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"gr-0/0/0": {Name: "gr-0/0/0", Units: map[int]*InterfaceUnit{1: {Tunnel: &TunnelConfig{}}}},
		}},
	}
	appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
	for _, member := range []string{"ge-9/0/0", "gr-0/0/0"} {
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "(#10308)") && strings.Contains(w, member) {
				found = true
			}
		}
		if !found {
			t.Errorf("member %q must retain (#10308) advisory; warnings=%v", member, cfg.Warnings)
		}
	}
}

func TestMgmtControlZoneBindOnlySecureTunnelStaysQuiet12830(t *testing.T) {
	for _, bind := range []string{"st0", "st0.0"} {
		cfg := &Config{
			Security: SecurityConfig{
				Zones: map[string]*ZoneConfig{"mgmt": {Interfaces: []string{"st0"}}},
				IPsec: IPsecConfig{VPNs: map[string]*IPsecVPN{
					"vpn0": {BindInterface: bind},
				}},
			},
		}
		appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "(#10308)") {
				t.Errorf("bind-only st0 must stay quiet for bind %q: %q", bind, w)
			}
		}
	}
}

func TestMgmtControlZoneQuarantinedByIDCollisionStaysQuiet12830(t *testing.T) {
	collision := ""
	for i := range 1_000_000 {
		candidate := fmt.Sprintf("a-%d", i)
		if StableZoneID(candidate) == StableZoneID("mgmt") {
			collision = candidate
			break
		}
	}
	if collision == "" {
		t.Fatal("could not find deterministic zone-id collision fixture")
	}
	cfg := &Config{Security: SecurityConfig{Zones: map[string]*ZoneConfig{
		"mgmt":    {Interfaces: []string{"ge-0/0/0"}},
		collision: {},
	}}}
	appendUserspaceMgmtZoneAdvisoryLocked(cfg, compileOpts{})
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#10308)") {
			t.Fatalf("quarantined mgmt zone must not warn: %q", w)
		}
	}
}
