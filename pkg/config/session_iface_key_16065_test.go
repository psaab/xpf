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
// the VLAN children own 15/14, the GRE units own 30/31. Any other
// device name is a fixture bug — in particular the PARENT "ge-0-0-3"
// must never be looked up for its VLAN units (#16065 child keying).
func lookup16065(t *testing.T) func(string) (int, error) {
	t.Helper()
	return func(name string) (int, error) {
		switch name {
		case "wg0":
			return 20, nil
		case "ge-0-0-3.50":
			return 15, nil
		case "ge-0-0-3.80":
			return 14, nil
		case "gr-0-0-0":
			return 30, nil
		case "gr-0-0-0u1":
			return 31, nil
		}
		t.Fatalf("unexpected kernel lookup %q (units must resolve to their OWN device)", name)
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

	// VLAN units key on the CHILD ifindex, not the parent's: the parent
	// "ge-0-0-3" is never looked up (lookup16065 fails the test if it
	// is), and no entry exists at a parent-derived key.
	if name := names[SessionIfaceKey{Ifindex: 15, VlanID: 50}]; name != "ge-0/0/3.50" {
		t.Errorf("{15,50} = %q, want ge-0/0/3.50 (VLAN child ifindex)", name)
	}
	if name := names[SessionIfaceKey{Ifindex: 14, VlanID: 80}]; name != "ge-0/0/3.80" {
		t.Errorf("{14,80} = %q, want ge-0/0/3.80 (VLAN child ifindex)", name)
	}
	// Per-unit tunnel devices key distinctly (no collision to refuse).
	if name := names[SessionIfaceKey{Ifindex: 30, VlanID: 0}]; name != "gr-0/0/0" {
		t.Errorf("{30,0} = %q, want gr-0/0/0 (unit 0 renders bare)", name)
	}
	if name := names[SessionIfaceKey{Ifindex: 31, VlanID: 0}]; name != "gr-0/0/0.1" {
		t.Errorf("{31,0} = %q, want gr-0/0/0.1 (its own u1 device)", name)
	}
	if SharedSessionIfaceKey(cfg, lookup16065(t), SessionIfaceKey{Ifindex: 14, VlanID: 80}) {
		t.Error("SharedSessionIfaceKey({14,80}) = true, want false (one claimant)")
	}
	// Exactly the four un-shared units produce entries.
	if len(names) != 4 {
		t.Errorf("SessionIfaceNames has %d entries, want 4 (wg pair refused): %v", len(names), names)
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
	if name := byIndex[14]; name != "ge-0/0/3.80" {
		t.Errorf("byIndex[14] = %q, want ge-0/0/3.80", name)
	}
	if name := byIndex[31]; name != "gr-0/0/0.1" {
		t.Errorf("byIndex[31] = %q, want gr-0/0/0.1", name)
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
