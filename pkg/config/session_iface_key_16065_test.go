package config

import (
	"fmt"
	"testing"
)

// session_iface_key_16065_test.go — #16065 (SI-6) regression tests for
// the shared session {ifindex, VID} -> unit-name derivation.
//
// The decisive fixture is the issue's two-unit WireGuard shape: wg0.0
// and wg0.1 share the single wg0 TUN (TunnelNameMap maps both refs to
// "wg0"), both VID 0. Pre-fix, every surface keyed both units on
// {wg0Ifindex, 0} and first-wins (or lowest-unit) named BOTH units'
// sessions after one sibling, so `clear ... interface wg0.1` deleted
// wg0.0's sessions. Post-fix the shared key is REFUSED: neither name
// is in the table, so no surface can select or display one sibling
// through the other.
//
// FAIL-ON-REVERT: restoring parent-keyed first-wins (or naming either
// wg unit) makes both wg assertions below fail; restoring the
// unit-number VID fallback makes the untagged/VLAN cells fail.

func wgTwoUnitCfg16065() *Config {
	return &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"wg0": {
					Name:   "wg0",
					Tunnel: &TunnelConfig{Mode: "wireguard", Name: "wg0"},
					Units: map[int]*InterfaceUnit{
						0: {Number: 0},
						1: {Number: 1},
					},
				},
				"ge-0/0/3": {
					Name: "ge-0/0/3",
					Units: map[int]*InterfaceUnit{
						50: {Number: 50, VlanID: 50},
						80: {Number: 80, VlanID: 80},
					},
				},
				"gr-0/0/0": {
					Name: "gr-0/0/0",
					Units: map[int]*InterfaceUnit{
						0: {Number: 0, Tunnel: &TunnelConfig{Name: "gr-0-0-0"}},
						1: {Number: 1, Tunnel: &TunnelConfig{Name: "gr-0-0-0u1"}},
					},
				},
			},
		},
	}
}

// lookup16065 is the fixed kernel table: wg0 (the shared TUN) = 20,
// the ge-0/0/3 PARENT/bind device = 14 with VLAN children 15 (.50) and
// 16 (.80), the GRE units own 30/31. Both key forms are looked up:
// the parent for the {parent, VID} ingress stamp, each child for the
// {child, VID} egress form.
func lookup16065(t *testing.T) func(string) (int, error) {
	t.Helper()
	return func(name string) (int, error) {
		switch name {
		case "wg0":
			return 20, nil
		case "ge-0-0-3":
			return 14, nil
		case "ge-0-0-3.50":
			return 15, nil
		case "ge-0-0-3.80":
			return 16, nil
		case "gr-0-0-0":
			return 30, nil
		case "gr-0-0-0u1":
			return 31, nil
		}
		t.Fatalf("unexpected kernel lookup %q", name)
		return 0, fmt.Errorf("no such device %q", name)
	}
}

func TestSessionIfaceNamesWireGuardSharedDeviceRefused16065(t *testing.T) {
	cfg := wgTwoUnitCfg16065()
	// Premise: both wg units really do resolve to the one TUN device.
	if got := cfg.ResolveKernelIfName("wg0.0"); got != "wg0" {
		t.Fatalf("premise: ResolveKernelIfName(wg0.0) = %q, want wg0", got)
	}
	if got := cfg.ResolveKernelIfName("wg0.1"); got != "wg0" {
		t.Fatalf("premise: ResolveKernelIfName(wg0.1) = %q, want wg0 (shared TUN)", got)
	}

	names := SessionIfaceNames(cfg, lookup16065(t))

	// The shared key {20, 0} is refused: neither sibling names it, so a
	// clear/display for wg0.0 or wg0.1 can never select the other's
	// sessions through this table.
	if name, ok := names[SessionIfaceKey{Ifindex: 20, VlanID: 0}]; ok {
		t.Fatalf("shared wg key {20,0} resolved to %q — one sibling is named for both; "+
			"clear wg0.1 would delete wg0.0 sessions (#16065)", name)
	}
	if !SharedSessionIfaceKey(cfg, lookup16065(t), SessionIfaceKey{Ifindex: 20, VlanID: 0}) {
		t.Fatal("SharedSessionIfaceKey({20,0}) = false, want true (wg0.0 and wg0.1 both claim it)")
	}
	// Deterministic across rebuilds (no map-order winner).
	for range 16 {
		again := SessionIfaceNames(cfg, lookup16065(t))
		if name, ok := again[SessionIfaceKey{Ifindex: 20, VlanID: 0}]; ok {
			t.Fatalf("rebuild named the shared key %q — refusal must be deterministic", name)
		}
	}
}

func TestSessionIfaceNamesChildAndPerUnitDevices16065(t *testing.T) {
	cfg := wgTwoUnitCfg16065()
	names := SessionIfaceNames(cfg, lookup16065(t))

	// VLAN units register BOTH key forms: {parent 14, VID} (the ingress
	// stamp AF_XDP records) and {child, VID} (own-device/FIB form).
	if name := names[SessionIfaceKey{Ifindex: 14, VlanID: 50}]; name != "ge-0/0/3.50" {
		t.Errorf("{14,50} = %q, want ge-0/0/3.50 (parent/bind ingress form)", name)
	}
	if name := names[SessionIfaceKey{Ifindex: 14, VlanID: 80}]; name != "ge-0/0/3.80" {
		t.Errorf("{14,80} = %q, want ge-0/0/3.80 (parent/bind ingress form)", name)
	}
	if name := names[SessionIfaceKey{Ifindex: 15, VlanID: 50}]; name != "ge-0/0/3.50" {
		t.Errorf("{15,50} = %q, want ge-0/0/3.50 (VLAN child ifindex)", name)
	}
	if name := names[SessionIfaceKey{Ifindex: 16, VlanID: 80}]; name != "ge-0/0/3.80" {
		t.Errorf("{16,80} = %q, want ge-0/0/3.80 (VLAN child ifindex)", name)
	}
	// Unit 1's own u1 device keys distinctly. Unit 0 is REFUSED here —
	// correctly: the bare-interface parent claim registers
	// "gr-0/0/0.0" (sessionParentDevice resolves the bare iface ref to
	// the same device, and the parent-form claim uses the unit display
	// for a unit ref... see the builder: the parent claim for unit 0
	// uses display "gr-0/0/0" while unit 1's parent claim at {30,0}
	// would be "gr-0/0/0.1" — no: both units' PARENT claims land on
	// {30,0} (parent device, VID 0) with different displays, so the
	// key is ambiguous and refused. That is the intended narrowing: an
	// ingress row stamped {30,0} cannot be attributed to unit 0 vs
	// unit 1 from the parent stamp alone; only child-stamped rows
	// (unit 1 at {31,0}) resolve precisely, and unit 0's child form
	// coincides with the refused parent key.
	if name := names[SessionIfaceKey{Ifindex: 31, VlanID: 0}]; name != "gr-0/0/0.1" {
		t.Errorf("{31,0} = %q, want gr-0/0/0.1 (its own u1 device)", name)
	}
	if !SharedSessionIfaceKey(cfg, lookup16065(t), SessionIfaceKey{Ifindex: 30, VlanID: 0}) {
		t.Error("SharedSessionIfaceKey({30,0}) = false, want true (gr units 0/1 share the parent stamp at VID 0)")
	}
	if SharedSessionIfaceKey(cfg, lookup16065(t), SessionIfaceKey{Ifindex: 31, VlanID: 0}) {
		t.Error("SharedSessionIfaceKey({31,0}) = true, want false (unit 1 alone claims its u1 device)")
	}
	if SharedSessionIfaceKey(cfg, lookup16065(t), SessionIfaceKey{Ifindex: 14, VlanID: 80}) {
		t.Error("SharedSessionIfaceKey({14,80}) = true, want false (one claimant)")
	}
	if SharedSessionIfaceKey(cfg, lookup16065(t), SessionIfaceKey{Ifindex: 16, VlanID: 80}) {
		t.Error("SharedSessionIfaceKey({16,80}) = true, want false (one claimant)")
	}
}

// F3: a TAGGED unit 0 keeps its ".0" identity (it owns a distinct VLAN
// child); only an untagged unit 0 renders bare.
func TestSessionIfaceNamesTaggedUnitZero16065(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, VlanID: 100},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0},
		}},
	}}}
	lookup := func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 40, nil
		case "ge-0-0-0.100":
			return 41, nil
		case "ge-0-0-1":
			return 42, nil
		}
		return 0, fmt.Errorf("no device %q", name)
	}
	names := SessionIfaceNames(cfg, lookup)
	if name := names[SessionIfaceKey{Ifindex: 41, VlanID: 100}]; name != "ge-0/0/0.0" {
		t.Errorf("tagged unit 0 child {41,100} = %q, want ge-0/0/0.0 (.0 identity kept)", name)
	}
	if name := names[SessionIfaceKey{Ifindex: 40, VlanID: 100}]; name != "ge-0/0/0.0" {
		t.Errorf("tagged unit 0 parent {40,100} = %q, want ge-0/0/0.0", name)
	}
	if name := names[SessionIfaceKey{Ifindex: 42, VlanID: 0}]; name != "ge-0/0/1" {
		t.Errorf("untagged unit 0 {42,0} = %q, want bare ge-0/0/1", name)
	}
}

func TestSessionIfNamesByIfindexRefusesShared16065(t *testing.T) {
	cfg := wgTwoUnitCfg16065()
	byIndex := SessionIfNamesByIfindex(cfg, lookup16065(t))

	// Flow-export projection: the shared TUN ifindex resolves to NO
	// name (pre-fix first-wins named it wg0 or wg0.0), so sampling
	// keeps zone semantics for both units' records.
	if name, ok := byIndex[20]; ok {
		t.Fatalf("byIndex[20] = %q — the shared TUN is named after a sibling; "+
			"flow-export sampling would judge both wg units by %q (#16065)", name, name)
	}
	// The parent ifindex carries two different unit names at different
	// VIDs (.50/.80) — the bare-ifindex projection cannot name it
	// without picking a sibling, so it is nameless too (C5).
	if name, ok := byIndex[14]; ok {
		t.Fatalf("byIndex[14] = %q — parent shared by .50/.80 at different VIDs must be nameless", name)
	}
	if name := byIndex[16]; name != "ge-0/0/3.80" {
		t.Errorf("byIndex[16] = %q, want ge-0/0/3.80 (child uniquely claims it)", name)
	}
	if name := byIndex[31]; name != "gr-0/0/0.1" {
		t.Errorf("byIndex[31] = %q, want gr-0/0/0.1", name)
	}
	// Deterministic across rebuilds despite Go map iteration.
	for range 16 {
		again := SessionIfNamesByIfindex(cfg, lookup16065(t))
		if _, ok := again[20]; ok {
			t.Fatal("rebuild named the shared TUN — projection refusal must be deterministic")
		}
		if _, ok := again[14]; ok {
			t.Fatal("rebuild named the multi-VID parent — projection refusal must be deterministic")
		}
	}
}

func TestSessionIfaceNamesNilAndUnresolvable16065(t *testing.T) {
	if got := SessionIfaceNames(nil, lookup16065(t)); len(got) != 0 {
		t.Errorf("nil cfg: got %v, want empty", got)
	}
	cfg := wgTwoUnitCfg16065()
	none := func(string) (int, error) { return 0, fmt.Errorf("no device") }
	if got := SessionIfaceNames(cfg, none); len(got) != 0 {
		t.Errorf("unresolvable devices: got %v, want empty (rows degrade to zone)", got)
	}
	// Nil slots from the tolerant load path are skipped, not panicked on.
	tolerant := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 7: nil}},
		"zz-nil":   nil,
	}}}
	got := SessionIfaceNames(tolerant, func(string) (int, error) { return 10, nil })
	if name := got[SessionIfaceKey{Ifindex: 10, VlanID: 0}]; name != "ge-0/0/0" || len(got) != 1 {
		t.Errorf("tolerant nil slots: got %v, want exactly {10,0}=ge-0/0/0", got)
	}
}
