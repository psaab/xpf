package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9009: the plan-key population diff #8901 left unrun, closed.
//
// These cells EXECUTE snapshotBindingPlanKey over constructed snapshots and
// assert whether the key MOVES. That is deliberately a different instrument
// from binding_plan_key_crossplane_8901_test.go, which regex-parsed field NAMES
// out of the two source files and, in its own words, "does not establish that
// the two keys move together, and should not be read as doing so".
//
// WHAT AGREEMENT MEANS. The two keys are never compared to each other — each
// side compares its own key across consecutive snapshots — so byte-equality is
// not the property. They must MOVE TOGETHER. Every cell below is therefore a
// pair: a baseline key and a perturbed key, asserting moved / did-not-move.
//
// The Rust side is authoritative for each of these: its filters and rx_queues
// resolution mirror `replan_queues`, the function that builds the layout, and
// the #2915 invariant is that the key moves whenever the layout would.

func planKeyIface9009(name, linux, parent string, ifindex, parentIfindex, vlan, rxq int) InterfaceSnapshot {
	return InterfaceSnapshot{
		Name: name, Zone: "trust", LinuxName: linux, ParentLinuxName: parent,
		Ifindex: ifindex, ParentIfindex: parentIfindex, VLANID: vlan, RXQueues: rxq,
	}
}

// ── D4: a reorder-only shared_umem edit must move NEITHER key ──

func TestSharedUMEMReorderDoesNotMoveThePlanKey9009(t *testing.T) {
	mk := func(ifaces ...string) *ConfigSnapshot {
		s := &ConfigSnapshot{}
		s.Userspace.SharedUMEM = &config.SharedUMEMConfig{
			Mode: "per-nic", Interfaces: ifaces, Phase0ArtifactFile: "/x.o",
		}
		return s
	}
	a := snapshotBindingPlanKey(mk("ge-0-0-1", "ge-0-0-2", "ge-0-0-3"))
	b := snapshotBindingPlanKey(mk("ge-0-0-3", "ge-0-0-1", "ge-0-0-2"))
	if a != b {
		t.Errorf("#9009 D4: reordering the shared_umem interface list moved Go's "+
			"plan key while Rust's canonical-JSON hash SORTS array items, so its "+
			"key is unchanged. compileSharedUMEMConfig appends in authored order "+
			"with no sort, so a bracketed-list reorder is a supported operator "+
			"edit — and this over-detect is a full AF_XDP teardown and rebind, "+
			"not wasted CPU.\n  a=%s\n  b=%s", a, b)
	}
	// The list must still be hashed at all: a fix that dropped shared_umem
	// entirely would satisfy the assertion above and re-open #8901.
	if c := snapshotBindingPlanKey(mk("ge-0-0-1", "ge-0-0-9")); c == a {
		t.Error("#9009 D4: changing shared_umem MEMBERSHIP did not move the key — " +
			"the sort must make the hash order-insensitive, not content-blind (#8901)")
	}
}

// ── D2: a refused fabric parent must move the key ──

func TestRefusedFabricParentMovesThePlanKey9009(t *testing.T) {
	// A fabric member with no InterfaceSnapshot of its own (a fabric member
	// needs no interface stanza), so ParentUnbindable is the only signal —
	// exactly the ownerless case the fabric fallback vote is written for.
	mk := func(unbindable bool) *ConfigSnapshot {
		return &ConfigSnapshot{
			Fabrics: []FabricSnapshot{{
				Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7,
				RXQueues: 4, ParentUnbindable: unbindable,
			}},
		}
	}
	before := snapshotBindingPlanKey(mk(false))
	after := snapshotBindingPlanKey(mk(true))
	if before == after {
		t.Errorf("#9009 D2: the fabric parent became unbindable and Go's plan key "+
			"did not move. Rust drops the row (snapshot_refuses_parent_netdev) so "+
			"ITS key moves — Go then calls a real plan change 'same plan' and "+
			"publishes straight through the pending-XSK-startup window while the "+
			"helper rebuilds its bindings. This is the under-detect direction.\n"+
			"  key=%s", before)
	}
	if !strings.Contains(before, "fabric=fab0") {
		t.Errorf("#9009 D2: the healthy fabric row is not hashed at all, so the "+
			"assertion above would be satisfied by a key that never mentions "+
			"fabrics: %s", before)
	}
	if strings.Contains(after, "fabric=fab0") {
		t.Errorf("#9009 D2: the refused fabric row is still hashed; Rust omits it "+
			"entirely: %s", after)
	}
}

// ── D3: a row whose BIND TARGET is refused must be dropped ──

func TestRefusedBindTargetRowIsNotHashed9009(t *testing.T) {
	// A VLAN child binds through its parent. When the snapshot refuses that
	// parent netdev, `replan_queues` produces no candidate, so Rust omits the
	// row from its hash.
	mk := func(parentUnbindable bool) *ConfigSnapshot {
		parent := InterfaceSnapshot{
			Name: "ge-0/0/0", Zone: "trust", LinuxName: "ge-0-0-0", Ifindex: 7,
		}
		if parentUnbindable {
			// The device-level verdict the vote tally reads.
			parent.Tunnel = true
		}
		child := planKeyIface9009("ge-0/0/0.100", "ge-0-0-0.100", "ge-0-0-0", 8, 7, 100, 4)
		return &ConfigSnapshot{Interfaces: []InterfaceSnapshot{parent, child}}
	}
	before := snapshotBindingPlanKey(mk(false))
	after := snapshotBindingPlanKey(mk(true))
	if before == after {
		t.Errorf("#9009 D3: the child's bind target became refused and Go's key did "+
			"not move. Rust's row set is a strict subset here — it filters on "+
			"binding_target_is_refused, a predicate this side already had "+
			"(buildUserspaceRefusedNetdevs) and did not apply.\n  key=%s", before)
	}
	if !strings.Contains(before, "iface=ge-0/0/0.100") {
		t.Errorf("#9009 D3: the child row is not hashed even when its parent is "+
			"bindable, so the move above is not attributable to the refusal: %s", before)
	}
	if strings.Contains(after, "iface=ge-0/0/0.100") {
		t.Errorf("#9009 D3: the child row is still hashed after its bind target was "+
			"refused: %s", after)
	}
}

// ── D1: an orphan VLAN child re-keys onto the PARENT's queue count ──

func TestOrphanVLANChildHashesTheParentsQueueCount9009(t *testing.T) {
	child := planKeyIface9009("ge-0/0/0.100", "ge-0-0-0.100", "ge-0-0-0", 8, 7, 100, 4)

	// ORPHAN: no row binds the physical parent (its own row is UNZONED, so it
	// is not a binding candidate). Management/control names no longer create
	// this shape: #10308 treats them as ordinary data-zone labels.
	orphan := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", Zone: "", LinuxName: "ge-0-0-0", Ifindex: 7},
		child,
	}}
	// NON-ORPHAN: the parent is a binding candidate.
	adopted := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", Zone: "trust", LinuxName: "ge-0-0-0", Ifindex: 7, RXQueues: 6},
		child,
	}}

	orphanKey := snapshotBindingPlanKey(orphan)
	adoptedKey := snapshotBindingPlanKey(adopted)

	// The child's OWN count (4) must not be what the orphan row hashes: for an
	// orphan the layout re-keys onto the parent's hardware queues (#3175), and
	// the parent netdev does not exist here so the resolved count is 0.
	orphanRow := planKeyRow9009(t, orphanKey, "iface=ge-0/0/0.100")
	adoptedRow := planKeyRow9009(t, adoptedKey, "iface=ge-0/0/0.100")
	if orphanRow == adoptedRow {
		t.Errorf("#9009 D1: the orphan and adopted child hash IDENTICALLY, so Go is "+
			"still hashing the child's own rx_queues in both cases. Rust hashes "+
			"rx_queue_count(parent) for the orphan — two sides tracking two "+
			"different numbers responding to different stimuli, which is why the "+
			"#8901 dismissal ('not a config commit') does not cover this case: the "+
			"divergence persists across commits.\n  orphan=%s\n  adopted=%s",
			orphanRow, adoptedRow)
	}
	if !strings.Contains(adoptedRow, "/4/") {
		t.Errorf("#9009 D1: with a real parent candidate the child's own rx_queues "+
			"(4) must still be hashed — the orphan rule must not leak into the "+
			"normal VLAN case: %s", adoptedRow)
	}
}

// planKeyRow9009 extracts one `key=...;` record so a cell can attribute a move
// to the row it is about rather than to the whole key.
func planKeyRow9009(t *testing.T, key, prefix string) string {
	t.Helper()
	for _, part := range strings.Split(key, ";") {
		if strings.HasPrefix(part, prefix) {
			return part
		}
	}
	t.Fatalf("row %q not present in key %q — the cell cannot attribute anything", prefix, key)
	return ""
}
