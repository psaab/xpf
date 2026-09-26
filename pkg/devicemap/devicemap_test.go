package devicemap

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func nic(name, pci, perm string) PresentNIC {
	return PresentNIC{Name: name, PCIAddr: pci, PermMAC: perm}
}

func TestResolvePCIPrimaryWithMACCrossCheck(t *testing.T) {
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if len(got) != 1 || got[0].Status != BindBound {
		t.Fatalf("want bound, got %+v", got)
	}
	if got[0].CurrentNIC != "enp9s0" || got[0].Logical != "ge-0-0-3" {
		t.Fatalf("wrong binding: %+v", got[0])
	}
}

func TestResolvePCIMatchMACMismatchRefuses(t *testing.T) {
	// R-1/AGY HIGH-3: a card swapped into the pinned slot (PCI matches but
	// the permanent MAC differs) must REFUSE, never silently hijack.
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "de:ad:be:ef:00:01")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("want REFUSED on PCI-hit/MAC-mismatch, got %v", got[0].Status)
	}
	if got[0].CurrentNIC != "" || got[0].Logical != "" {
		t.Fatalf("refused binding must not bind a NIC: %+v", got[0])
	}
}

func TestResolvePCIOnlyWhenNoPermMAC(t *testing.T) {
	// V-5 / #4884: when the operator keys ONLY on PCI, no perm-MAC still
	// yields the intended PCI-only bind.
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindBoundPCIOnly {
		t.Fatalf("want PCI-only bind when entry does not pin a MAC, got %v", got[0].Status)
	}
}

func TestResolveMACFallbackWhenPCIMoved(t *testing.T) {
	// PCI miss but permanent MAC hit => fallback bind, flagged.
	nics := []PresentNIC{nic("enp10s0", "0000:0a:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindBoundViaMAC {
		t.Fatalf("want MAC-fallback bind, got %v", got[0].Status)
	}
	if got[0].CurrentNIC != "enp10s0" {
		t.Fatalf("fallback bound wrong NIC: %+v", got[0])
	}
}

func TestResolveUnboundWhenNoMatch(t *testing.T) {
	nics := []PresentNIC{nic("enp10s0", "0000:0a:00.0", "aa:bb:cc:dd:ee:ff")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindUnbound {
		t.Fatalf("want UNBOUND, got %v", got[0].Status)
	}
}

func TestResolveRETHMemberIgnoresMACFallback(t *testing.T) {
	// R-6: a RETH member is PCI-only. With PCI missing, it must NOT fall
	// back to MAC (its MAC alternates physical<->virtual) — it goes UNBOUND.
	nics := []PresentNIC{nic("enp10s0", "0000:0a:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/2", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	reth := map[string]bool{"ge-0/0/2": true}
	got := Resolve(entries, nics, reth)
	if got[0].Status != BindUnbound {
		t.Fatalf("RETH member must not MAC-fallback; want UNBOUND, got %v", got[0].Status)
	}
}

func TestResolveAmbiguousPCIRefuses(t *testing.T) {
	// AGY MEDIUM-4: two present NICs sharing one PCI address must refuse
	// (deterministic), not silently bind whichever the map iterated last.
	nics := []PresentNIC{
		nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55"),
		nic("enp9s0v1", "0000:09:00.0", "00:11:22:33:44:66"),
	}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", KeyOrder: config.DeviceMapKeyPCI},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("want REFUSED on ambiguous PCI, got %v", got[0].Status)
	}
}

func TestResolveAmbiguousPCIRefusesUnderMACKey(t *testing.T) {
	// Codex r2 HIGH-B: same-PCI ambiguity must refuse REGARDLESS of key order.
	// With key mac (PCI arm never runs), the order-independent pre-check must
	// still catch two NICs sharing the entry's PCI address.
	nics := []PresentNIC{
		nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55"),
		nic("enp9s0v1", "0000:09:00.0", "00:11:22:33:44:66"),
	}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55",
			KeyOrder: config.DeviceMapKeyMAC},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("ambiguous PCI must refuse even under key mac, got %v", got[0].Status)
	}
}

func TestResolveCrossKeySameNICRefusesBoth(t *testing.T) {
	// Codex r2 HIGH-C: two entries resolving to the SAME present NIC via
	// cross-key identities (one by PCI, one by that NIC's MAC) must REFUSE
	// both, not silently last-wins one logical name onto the NIC.
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", KeyOrder: config.DeviceMapKeyPCI},
		{LogicalName: "ge-0/0/4", MAC: "00:11:22:33:44:55", KeyOrder: config.DeviceMapKeyMAC},
	}
	got := Resolve(entries, nics, nil)
	for _, b := range got {
		if b.Status != BindRefusedAmbig {
			t.Fatalf("entry %s should REFUSE (two entries claim one NIC), got %v",
				b.Entry.LogicalName, b.Status)
		}
	}
}

func TestResolveAmbiguousMACRefuses(t *testing.T) {
	// Two NICs with the same permanent MAC (cloned/bonded) => refuse.
	nics := []PresentNIC{
		nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55"),
		nic("enp10s0", "0000:0a:00.0", "00:11:22:33:44:55"),
	}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", MAC: "00:11:22:33:44:55", KeyOrder: config.DeviceMapKeyMAC},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("want REFUSED on ambiguous MAC, got %v", got[0].Status)
	}
}

func TestResolveMACFirstStillRefusesSlotSwap(t *testing.T) {
	// Codex HIGH-1: with key mac-then-pci AND both pci+mac set, a card
	// swapped into the pinned PCI slot (PCI present, perm-MAC mismatch) must
	// REFUSE even though the MAC leg would run first — the topology-change
	// invariant is order-independent. Here the entry's MAC matches NO present
	// NIC (the original card is gone) but its PCI slot now holds a different
	// card; the order-independent pre-check must catch it.
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "de:ad:be:ef:00:01")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55",
			KeyOrder: config.DeviceMapKeyMACThenPCI},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindRefusedAmbig {
		t.Fatalf("mac-first slot swap must REFUSE (order-independent), got %v", got[0].Status)
	}
}

func TestResolveKeyOrderMACThenPCI(t *testing.T) {
	// mac-then-pci tries MAC first; a MAC hit binds as primary (not flagged
	// as "via MAC fallback" — MAC IS the primary key here).
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:bb:00.0", MAC: "00:11:22:33:44:55",
			KeyOrder: config.DeviceMapKeyMACThenPCI},
	}
	got := Resolve(entries, nics, nil)
	// MAC is the PRIMARY key here (mac-then-pci), so the bind must be a clean
	// BindBound, NOT the "via MAC fallback — PCI moved" status (Copilot).
	if got[0].Status != BindBound {
		t.Fatalf("mac-then-pci is MAC-primary, want BindBound, got %v", got[0].Status)
	}
	if got[0].CurrentNIC != "enp9s0" {
		t.Fatalf("mac-then-pci bound wrong NIC: %+v", got[0])
	}
}

// TestResolveMACPrimaryKeyIsNotFlagged covers the bug where any entry with a
// PCI address was (incorrectly) flagged BindBoundViaMAC even when MAC is the
// primary identity key (key=mac or key=mac-then-pci). Only pci-then-mac (the
// default) should report BindBoundViaMAC — for MAC-primary entries, a MAC hit
// is a clean BindBound.
func TestResolveMACPrimaryKeyIsNotFlagged(t *testing.T) {
	nics := []PresentNIC{nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55")}

	// key=mac: MAC is the ONLY key; PCI addr present but never tried.
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55",
			KeyOrder: config.DeviceMapKeyMAC},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindBound {
		t.Errorf("key=mac with PCI addr set must be BindBound (not via-MAC-fallback), got %v", got[0].Status)
	}

	// key=mac-then-pci: MAC is primary; PCI is fallback.
	entries[0].KeyOrder = config.DeviceMapKeyMACThenPCI
	got = Resolve(entries, nics, nil)
	if got[0].Status != BindBound {
		t.Errorf("key=mac-then-pci with MAC hit must be BindBound (MAC is primary), got %v", got[0].Status)
	}
}

// TestResolvePCIThenMACFallbackFlagged verifies that the pci-then-mac (default)
// key order DOES report BindBoundViaMAC when PCI misses and MAC matches — the
// "re-pin" signal is valid only on the fallback path.
func TestResolvePCIThenMACFallbackFlagged(t *testing.T) {
	// NIC is at a DIFFERENT PCI address than the entry pins, but MAC matches.
	nics := []PresentNIC{nic("enp10s0", "0000:0a:00.0", "00:11:22:33:44:55")}
	entries := []config.DeviceMapEntry{
		// default key order = pci-then-mac; PCI (0000:09:00.0) misses
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
	}
	got := Resolve(entries, nics, nil)
	if got[0].Status != BindBoundViaMAC {
		t.Fatalf("pci-then-mac with PCI miss + MAC hit must be BindBoundViaMAC, got %v", got[0].Status)
	}
}

// TestResolveDeterministicAcrossReorder is the boot-stability proof: the same
// identity resolves to the same logical name regardless of enumeration order
// (a hardware-event reorder or BIOS bus renumber that shuffles kernel names).
func TestResolveDeterministicAcrossReorder(t *testing.T) {
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
		{LogicalName: "ge-0/0/4", PCIAddr: "0000:0a:00.0", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	order1 := []PresentNIC{
		nic("enp9s0", "0000:09:00.0", "00:11:22:33:44:55"),
		nic("enp10s0", "0000:0a:00.0", "aa:bb:cc:dd:ee:ff"),
	}
	// Reordered + renamed kernel names, same identities.
	order2 := []PresentNIC{
		nic("eth5", "0000:0a:00.0", "aa:bb:cc:dd:ee:ff"),
		nic("eth0", "0000:09:00.0", "00:11:22:33:44:55"),
	}
	b1 := Resolve(entries, order1, nil)
	b2 := Resolve(entries, order2, nil)
	want := map[string]string{"ge-0/0/3": "ge-0-0-3", "ge-0/0/4": "ge-0-0-4"}
	for _, bs := range [][]Binding{b1, b2} {
		for _, b := range bs {
			if !b.Status.Bound() {
				t.Fatalf("entry %s should bind, got %v", b.Entry.LogicalName, b.Status)
			}
			if b.Logical != want[b.Entry.LogicalName] {
				t.Fatalf("entry %s bound to %q, want %q", b.Entry.LogicalName, b.Logical, want[b.Entry.LogicalName])
			}
		}
	}
	// The PCI 0000:09:00.0 NIC must map to ge-0-0-3 in BOTH orderings
	// despite its kernel name changing enp9s0 -> eth0.
	find := func(bs []Binding, logical string) string {
		for _, b := range bs {
			if b.Entry.LogicalName == logical {
				return b.CurrentNIC
			}
		}
		return ""
	}
	if find(b1, "ge-0/0/3") != "enp9s0" || find(b2, "ge-0/0/3") != "eth0" {
		t.Fatalf("identity did not track its NIC across rename")
	}
}
