package devicemap

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14194: Resolve looked up `rethMembers[e.LogicalName]` with the entry's
// raw spelling, while RethMembersFromConfig keyed the set on the raw
// declared interface name. A slash RETH member (`ge-0/0/3`) with a dash
// device-map entry (`ge-0-0-3 key mac`) therefore skipped the resolver's
// PCI-only defense: allowMAC stayed true and the entry bound by MAC.
// When the member's MAC alternates physical<->virtual with the HA/RETH
// role, that MAC-only binding becomes unavailable or misbound.
//
// FAIL-ON-REVERT: revert the canonical (LinuxIfName) keying in
// RethMembersFromConfig and/or the canonical lookup in Resolve and the
// dash entry below binds by MAC again (BindBound) instead of going
// UNBOUND, and the virtual-MAC transition case misbinds.

const physMAC14194 = "00:11:22:33:44:55"
const virtMAC14194 = "02:bf:72:00:01:02"

func rethCfg14194(member string) *config.Config {
	return &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		member:  {Name: member, RedundantParent: "reth0"},
		"reth0": {Name: "reth0", RedundancyGroup: 1},
	}}}
}

// TestResolveRETHDashAliasSkipsMAC14194: slash member, dash entry,
// `key mac`. The NIC carries the PHYSICAL MAC. Pre-fix this binds by MAC;
// post-fix the MAC leg is skipped for a RETH member and, with no PCI key,
// the entry is UNBOUND.
func TestResolveRETHDashAliasSkipsMAC14194(t *testing.T) {
	for _, c := range []struct{ member, entry string }{
		{"ge-0/0/3", "ge-0-0-3"},
		{"ge-0-0-3", "ge-0/0/3"},
		{"ge-0/0/3", "ge-0/0/3"},
		{"ge-0-0-3", "ge-0-0-3"},
	} {
		entries := []config.DeviceMapEntry{
			{LogicalName: c.entry, MAC: physMAC14194, KeyOrder: config.DeviceMapKeyMAC},
		}
		nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", physMAC14194)}
		got := Resolve(entries, nics, RethMembersFromConfig(rethCfg14194(c.member)))
		if got[0].Status.Bound() {
			t.Errorf("member %q entry %q: RETH member bound by MAC (%v to %q); want UNBOUND (PCI-only defense)", c.member, c.entry, got[0].Status, got[0].CurrentNIC)
		}
		if got[0].Status != BindUnbound {
			t.Errorf("member %q entry %q: want BindUnbound, got %v", c.member, c.entry, got[0].Status)
		}
	}
}

// TestResolveRETHDashAliasVirtualMACTransition14194 models the decisive
// fixture from the issue: the entry pins the PHYSICAL MAC, then the
// member takes its VIRTUAL MAC in the active RETH role (PermMAC as
// enumerated still reports the factory MAC, but a MAC-keyed bind keyed
// on the running/virtual identity would miss or steal). More directly:
// with the physical card's perm MAC no longer matching because the
// operator pinned the virtual MAC, a MAC-leg bind must never happen for
// a RETH member — PCI is the only stable identity.
//
// Shape: entry pins the VIRTUAL MAC with `key mac`, NIC present with
// that virtual MAC as its perm MAC (synthesised transition state).
// A non-RETH entry would bind; a RETH member must not.
func TestResolveRETHDashAliasVirtualMACTransition14194(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0-0-3", MAC: virtMAC14194, KeyOrder: config.DeviceMapKeyMAC},
	}
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", virtMAC14194)}
	got := Resolve(entries, nics, RethMembersFromConfig(rethCfg14194("ge-0/0/3")))
	if got[0].Status.Bound() {
		t.Fatalf("RETH dash-alias entry bound by (virtual) MAC %v to %q; MAC alternates with RETH role so this bind is unstable/misbound", got[0].Status, got[0].CurrentNIC)
	}
	// Control: same entry/nics WITHOUT RETH membership binds by MAC,
	// proving the refusal above is the RETH gate, not a broken fixture.
	gotCtl := Resolve(entries, nics, nil)
	if gotCtl[0].Status != BindBound {
		t.Fatalf("control (non-RETH) should bind by MAC, got %v", gotCtl[0].Status)
	}
}

// TestResolveRETHDashAliasPCIStillBinds14194: a PCI-keyed dash entry for
// a slash RETH member must still bind by PCI — canonicalising the RETH
// lookup must not break the legitimate RETH bind.
func TestResolveRETHDashAliasPCIStillBinds14194(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0-0-3", PCIAddr: "0000:09:00.0", MAC: physMAC14194, KeyOrder: config.DeviceMapKeyPCIThenMAC},
	}
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", physMAC14194)}
	got := Resolve(entries, nics, RethMembersFromConfig(rethCfg14194("ge-0/0/3")))
	if !got[0].Status.Bound() {
		t.Fatalf("PCI-keyed RETH dash-alias entry should bind, got %v", got[0].Status)
	}
	if got[0].Logical != "ge-0-0-3" {
		t.Fatalf("bound logical = %q, want ge-0-0-3", got[0].Logical)
	}
}

// TestRethMembersFromConfigCanonicalKeys14194 pins the producer contract:
// the set is keyed by the canonical Linux name so ANY caller looking up
// by canonical name (or canonicalising an entry name) hits, regardless
// of the spelling the interface was declared with.
func TestRethMembersFromConfigCanonicalKeys14194(t *testing.T) {
	for _, member := range []string{"ge-0/0/3", "ge-0-0-3"} {
		m := RethMembersFromConfig(rethCfg14194(member))
		if !m["ge-0-0-3"] {
			t.Errorf("member declared %q: canonical key ge-0-0-3 missing from %v", member, m)
		}
		if len(m) != 1 {
			t.Errorf("member declared %q: want exactly 1 canonical key, got %v", member, m)
		}
	}
	if m := RethMembersFromConfig(nil); len(m) != 0 {
		t.Errorf("nil cfg should give empty set, got %v", m)
	}
}

// TestResolveRETHRawMapStillHonoured14194: callers that hand-build the
// rethMembers map in the Junos slash spelling (existing tests / callers)
// must still be honoured — Resolve canonicalises map keys on entry, so a
// raw slash-keyed map protects a dash entry and vice versa.
func TestResolveRETHRawMapStillHonoured14194(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0-0-3", MAC: physMAC14194, KeyOrder: config.DeviceMapKeyMAC},
	}
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", physMAC14194)}
	for _, reth := range []map[string]bool{
		{"ge-0/0/3": true},
		{"ge-0-0-3": true},
	} {
		got := Resolve(entries, nics, reth)
		if got[0].Status.Bound() {
			t.Errorf("raw reth map %v: RETH entry bound by MAC %v; want UNBOUND", reth, got[0].Status)
		}
	}
}
