package config

import (
	"strings"
	"testing"
)

// #16572: Junos `disable` under routing protocols was unmodelled —
// `ospf area X interface Y disable` compiled to an ACTIVE OSPF
// interface, `protocols ospf disable` / `bgp disable` left the
// protocol running, and the #11571 gate then demanded host-inbound
// OSPF on the excluded segment's zone. These tests pin the modelled
// behaviour: the flag is recorded, no #10707 advisory is drawn, and
// the DEFECT row (disabled interface beside an active sibling, no
// host-inbound token) commits clean.

func has10707Disable16572(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "#10707") && strings.Contains(w, `"disable"`) {
			return true
		}
	}
	return false
}

func ospfIfaceNames16572(t *testing.T, cfg *Config) map[string]*OSPFInterface {
	t.Helper()
	out := map[string]*OSPFInterface{}
	if cfg == nil || cfg.Protocols.OSPF == nil {
		return out
	}
	for _, a := range cfg.Protocols.OSPF.Areas {
		for _, i := range a.Interfaces {
			out[i.Name] = i
		}
	}
	return out
}

// TestOSPFInterfaceDisableModelled16572 is the DEFECT row: the braced
// and flat spellings of `interface ge-0/0/1.0 disable` must record
// Disable on that interface only, leave the sibling active, and draw
// no #10707 advisory for `disable`.
func TestOSPFInterfaceDisableModelled16572(t *testing.T) {
	hier, err := CompileConfig(parseHierText(t,
		"protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; interface ge-0/0/1.0 { disable; } } } }"))
	if err != nil {
		t.Fatalf("hier compile: %v", err)
	}
	ifaces := ospfIfaceNames16572(t, hier)
	if len(ifaces) != 2 {
		t.Fatalf("hier interfaces = %v, want 2 entries", ifaces)
	}
	if ifaces["ge-0/0/1.0"] == nil || !ifaces["ge-0/0/1.0"].Disable {
		t.Fatalf("hier ge-0/0/1.0 must be Disable, got %+v", ifaces["ge-0/0/1.0"])
	}
	if ifaces["ge-0/0/0.0"] == nil || ifaces["ge-0/0/0.0"].Disable {
		t.Fatalf("hier ge-0/0/0.0 must stay enabled, got %+v", ifaces["ge-0/0/0.0"])
	}
	if has10707Disable16572(hier.Warnings) {
		t.Fatalf("hier disable must not draw #10707, warnings=%v", hier.Warnings)
	}

	flat, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 disable",
	}))
	if err != nil {
		t.Fatalf("flat compile: %v", err)
	}
	ifaces = ospfIfaceNames16572(t, flat)
	if ifaces["ge-0/0/1.0"] == nil || !ifaces["ge-0/0/1.0"].Disable {
		t.Fatalf("flat ge-0/0/1.0 must be Disable, got %+v", ifaces["ge-0/0/1.0"])
	}
	if ifaces["ge-0/0/0.0"] == nil || ifaces["ge-0/0/0.0"].Disable {
		t.Fatalf("flat ge-0/0/0.0 must stay enabled, got %+v", ifaces["ge-0/0/0.0"])
	}
	if has10707Disable16572(flat.Warnings) {
		t.Fatalf("flat disable must not draw #10707, warnings=%v", flat.Warnings)
	}

	// Packed braced tail: `interface ge-0/0/1.0 disable;`
	packed, err := CompileConfig(parseHierText(t,
		"protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0 disable; } } }"))
	if err != nil {
		t.Fatalf("packed compile: %v", err)
	}
	if got := ospfIfaceNames16572(t, packed)["ge-0/0/1.0"]; got == nil || !got.Disable {
		t.Fatalf("packed ge-0/0/1.0 must be Disable, got %+v", got)
	}

	// Merge: a second fragment disabling an already-modelled
	// interface wins (any-fragment disable).
	merged, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 cost 10",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 disable",
	}))
	if err != nil {
		t.Fatalf("merge compile: %v", err)
	}
	if got := ospfIfaceNames16572(t, merged)["ge-0/0/1.0"]; got == nil || !got.Disable || got.Cost != 10 {
		t.Fatalf("merged ge-0/0/1.0 must be Disable with cost kept, got %+v", got)
	}
}

// TestProtocolLevelDisableModelled16572 pins every whole-protocol
// shut named in the issue: ospf, ospf3, bgp, plus the isis/rip
// siblings compiled through the same switch.
func TestProtocolLevelDisableModelled16572(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf disable",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf3 disable",
		"set protocols bgp disable",
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 192.0.2.1",
		"set protocols isis disable",
		"set protocols rip disable",
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Protocols.OSPF == nil || !cfg.Protocols.OSPF.Disable {
		t.Fatalf("ospf Disable not set: %+v", cfg.Protocols.OSPF)
	}
	if cfg.Protocols.OSPFv3 == nil || !cfg.Protocols.OSPFv3.Disable {
		t.Fatalf("ospf3 Disable not set: %+v", cfg.Protocols.OSPFv3)
	}
	if cfg.Protocols.BGP == nil || !cfg.Protocols.BGP.Disable {
		t.Fatalf("bgp Disable not set: %+v", cfg.Protocols.BGP)
	}
	if cfg.Protocols.ISIS == nil || !cfg.Protocols.ISIS.Disable {
		t.Fatalf("isis Disable not set: %+v", cfg.Protocols.ISIS)
	}
	if cfg.Protocols.RIP == nil || !cfg.Protocols.RIP.Disable {
		t.Fatalf("rip Disable not set: %+v", cfg.Protocols.RIP)
	}
	if has10707Disable16572(cfg.Warnings) {
		t.Fatalf("protocol disable must not draw #10707, warnings=%v", cfg.Warnings)
	}

	// Hierarchical spellings.
	hier, err := CompileConfig(parseHierText(t,
		"protocols { ospf { disable; } bgp { disable; } ospf3 { disable; } isis { disable; } rip { disable; } }"))
	if err != nil {
		t.Fatalf("hier compile: %v", err)
	}
	if !hier.Protocols.OSPF.Disable || !hier.Protocols.BGP.Disable ||
		!hier.Protocols.OSPFv3.Disable || !hier.Protocols.ISIS.Disable || !hier.Protocols.RIP.Disable {
		t.Fatalf("hier disables not all set: ospf=%v bgp=%v ospf3=%v isis=%v rip=%v",
			hier.Protocols.OSPF.Disable, hier.Protocols.BGP.Disable,
			hier.Protocols.OSPFv3.Disable, hier.Protocols.ISIS.Disable, hier.Protocols.RIP.Disable)
	}
}

// TestOSPF3ISISInterfaceDisableModelled16572 pins the interface-level
// shut for the other two interface-bearing protocols in the issue.
func TestOSPF3ISISInterfaceDisableModelled16572(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf3 area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0 disable",
		"set protocols isis interface ge-0/0/0.0",
		"set protocols isis interface ge-0/0/1.0 disable",
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var v3Disabled, v3Enabled bool
	for _, a := range cfg.Protocols.OSPFv3.Areas {
		for _, i := range a.Interfaces {
			if i.Name == "ge-0/0/1.0" {
				v3Disabled = i.Disable
			}
			if i.Name == "ge-0/0/0.0" {
				v3Enabled = !i.Disable
			}
		}
	}
	if !v3Disabled || !v3Enabled {
		t.Fatalf("ospf3 disable modelling wrong: disabled=%v enabled=%v (%+v)", v3Disabled, v3Enabled, cfg.Protocols.OSPFv3)
	}
	var isisDisabled, isisEnabled bool
	for _, i := range cfg.Protocols.ISIS.Interfaces {
		if i.Name == "ge-0/0/1.0" {
			isisDisabled = i.Disable
		}
		if i.Name == "ge-0/0/0.0" {
			isisEnabled = !i.Disable
		}
	}
	if !isisDisabled || !isisEnabled {
		t.Fatalf("isis disable modelling wrong: disabled=%v enabled=%v (%+v)", isisDisabled, isisEnabled, cfg.Protocols.ISIS)
	}
	if has10707Disable16572(cfg.Warnings) {
		t.Fatalf("interface disable must not draw #10707, warnings=%v", cfg.Warnings)
	}
}

// TestBGPGroupNeighborDisableModelled16572 pins group inheritance and
// the neighbor-level shut.
func TestBGPGroupNeighborDisableModelled16572(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group OFF disable",
		"set protocols bgp group OFF peer-as 65002",
		"set protocols bgp group OFF neighbor 192.0.2.1",
		"set protocols bgp group ON peer-as 65002",
		"set protocols bgp group ON neighbor 192.0.2.2 disable",
		"set protocols bgp group ON neighbor 192.0.2.3",
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	byAddr := map[string]*BGPNeighbor{}
	for _, n := range cfg.Protocols.BGP.Neighbors {
		byAddr[n.Address] = n
	}
	if len(byAddr) != 3 {
		t.Fatalf("neighbors = %v, want 3", byAddr)
	}
	if !byAddr["192.0.2.1"].Disable {
		t.Fatalf("group-disable neighbor must inherit Disable: %+v", byAddr["192.0.2.1"])
	}
	if !byAddr["192.0.2.2"].Disable {
		t.Fatalf("neighbor-disable must set Disable: %+v", byAddr["192.0.2.2"])
	}
	if byAddr["192.0.2.3"].Disable {
		t.Fatalf("plain neighbor must stay enabled: %+v", byAddr["192.0.2.3"])
	}
	if has10707Disable16572(cfg.Warnings) {
		t.Fatalf("bgp disable must not draw #10707, warnings=%v", cfg.Warnings)
	}
}

// TestDisabledOSPFNoHostInboundDemand16572 is the acceptance row for
// the #11571 gate: with the excluded interface disabled, a strict
// commit without any host-inbound OSPF token must succeed, while the
// active sibling on another zoned interface still rejects. A
// whole-protocol disable likewise demands nothing.
func TestDisabledOSPFNoHostInboundDemand16572(t *testing.T) {
	base := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	}
	// Disabled interface only: commits with no token.
	if _, err := CompileConfig(buildTree(t, append(append([]string{}, base...),
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 disable"))); err != nil {
		t.Fatalf("disabled-only OSPF must commit without host-inbound ospf: %v", err)
	}
	// Whole-protocol disable with an active-looking interface: commits.
	if _, err := CompileConfig(buildTree(t, append(append([]string{}, base...),
		"set protocols ospf disable",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0"))); err != nil {
		t.Fatalf("protocol-disabled OSPF must commit without host-inbound ospf: %v", err)
	}
	// Control: the same interface ACTIVE still rejects (gate intact).
	if _, err := CompileConfig(buildTree(t, append(append([]string{}, base...),
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0"))); err == nil ||
		!strings.Contains(err.Error(), `omits "ospf"`) {
		t.Fatalf("active OSPF control must still reject, err=%v", err)
	}
	// Mixed: disabled on .1, active on .0 — rejection names only .0.
	_, err := CompileConfig(buildTree(t, append(append([]string{}, base...),
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 disable",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0")))
	if err == nil || !strings.Contains(err.Error(), `omits "ospf"`) ||
		!strings.Contains(err.Error(), `"ge-0/0/0.0"`) || strings.Contains(err.Error(), `"ge-0/0/1.0"`) {
		t.Fatalf("mixed config must reject naming only the active interface, err=%v", err)
	}
	// Tolerant load of the disabled row boots warning-free of the gate.
	cfg, err := CompileConfigLenient(buildTree(t, append(append([]string{}, base...),
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 disable")))
	if err != nil {
		t.Fatalf("lenient disabled OSPF: %v", err)
	}
	if containsManagedAdmissionDiagnostic11571(cfg.Warnings) {
		t.Fatalf("lenient disabled OSPF must not warn the gate: %v", cfg.Warnings)
	}
	// Routing-instance OSPF disable also demands nothing.
	ri := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set routing-instances vr1 instance-type virtual-router",
		"set routing-instances vr1 interface ge-0/0/1.0",
		"set routing-instances vr1 protocols ospf area 0.0.0.0 interface ge-0/0/1.0 disable",
	}
	if _, err := CompileConfig(buildTree(t, ri)); err != nil {
		t.Fatalf("RI disabled OSPF must commit: %v", err)
	}
}
