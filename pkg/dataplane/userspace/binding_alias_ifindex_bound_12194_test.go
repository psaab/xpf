package userspace

import (
	"strings"
	"testing"
)

// #12194: the VLAN-alias loop multiplied the child ifindex into the uint32
// composed userspace_bindings index BEFORE any ifindex bound, so a child of
// 2^28 or more wrapped back inside the dense cap and overwrote another
// interface's row. The primary loop has had the pre-multiply
// bindingIfindexInRange guard since #9698; the alias loop had only the
// post-multiply #814 cap, which a wrapped index passes. These cells run
// without BPF maps (same fake-map level as the #7497/#9698 cells).

const wrapChildIfindex12194 = 1<<28 + 17 // uint32(child)*16 + 0 == 17*16 + 0 == 272

// A wrapping alias child is refused: the error fails closed (naming the cap
// and #9698), and the low-ifindex primary row it would have aliased keeps
// its own slot — exactly one write, never overwritten by the parent's slot.
func TestAliasRefusesAWrappingChildIfindex12194(t *testing.T) {
	const parentIfindex = 8
	const victimIfindex = 17
	m := New()
	m.lastSnapshot = &ConfigSnapshot{
		Generation: 1,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0-0-1", Zone: "trust", Ifindex: parentIfindex},
			{Name: "ge-0-0-2", Zone: "trust", Ifindex: victimIfindex},
			{Name: "ge-0-0-1.50", Zone: "trust", Ifindex: wrapChildIfindex12194, ParentIfindex: parentIfindex},
		},
	}
	bindings := []BindingStatus{
		{Slot: 3, QueueID: 0, Ifindex: parentIfindex, Registered: true, Armed: true, Bound: true, Ready: true},
		{Slot: 7, QueueID: 0, Ifindex: victimIfindex, Registered: true, Armed: true, Bound: true, Ready: true},
	}
	status := &ProcessStatus{
		Enabled:      true,
		Workers:      1,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings:     bindings,
	}
	rec := &recordingBindingsMap7497{}
	set := map[uint32]struct{}{}

	// Primaries precede aliases, so the victim row is written before the
	// alias pass runs — the assertion is no-overwrite, not zero writes.
	idxs, err := m.applyPrimaryBindingRowsLocked(
		status, &fakeCtrlMap{}, rec, userspaceCtrlValue{}, map[uint32]bool{}, nil, set)
	if err != nil {
		t.Fatalf("primary pass rejected the fixture bindings: %v", err)
	}
	ctrlFake := &fakeCtrlMap{}
	_, err = m.applyAliasBindingRowsLocked(
		status, ctrlFake, rec, userspaceCtrlValue{Enabled: 1}, map[uint32]bool{}, idxs, set)
	if err == nil {
		t.Errorf("child=%d: alias pass accepted a wrapping child ifindex", wrapChildIfindex12194)
	} else {
		for _, want := range []string{"9698", "exceeds cap", "MAX_INTERFACES"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("child=%d: error does not carry %q: %v", wrapChildIfindex12194, want, err)
			}
		}
	}
	if !ctrlFake.haveStored || ctrlFake.stored.Enabled != 0 {
		t.Errorf("child=%d: fail-closed ctrl row not written with Enabled=0: haveStored=%v stored=%+v",
			wrapChildIfindex12194, ctrlFake.haveStored, ctrlFake.stored)
	}
	victimIdx := uint32(victimIfindex) * bindingQueuesPerIface
	writes := 0
	for _, w := range rec.writes {
		if w.Idx != victimIdx {
			continue
		}
		writes++
		if w.Val.Slot != 7 {
			t.Errorf("victim row idx=%d overwritten: slot=%d, want 7 (parent slot 3 leaked via wrapped child %d)",
				victimIdx, w.Val.Slot, wrapChildIfindex12194)
		}
	}
	if writes != 1 {
		t.Errorf("victim row idx=%d written %d times, want exactly 1 (primary only, no alias overwrite)", victimIdx, writes)
	}
}

// At exactly 2^28, the Go-side uint32 composition wraps to index zero. The
// shim's packet-side binding_slot uses checked_mul and returns None for this
// high ifindex, so this map-only control checks only that the alias row is
// refused; it does not claim packets from this child would steer to slot zero.
func TestAliasRefusesSlotZeroWrappingChild12194(t *testing.T) {
	const parentIfindex = 8
	const childIfindex = 1 << 28
	m := New()
	m.lastSnapshot = &ConfigSnapshot{
		Generation: 1,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0-0-1", Zone: "trust", Ifindex: parentIfindex},
			{Name: "ge-0-0-1.50", Zone: "trust", Ifindex: childIfindex, ParentIfindex: parentIfindex},
		},
	}
	status := &ProcessStatus{
		Enabled:      true,
		Workers:      1,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings: []BindingStatus{{
			Slot: 3, QueueID: 0, Ifindex: parentIfindex,
			Registered: true, Armed: true, Bound: true, Ready: true,
		}},
	}
	rec := &recordingBindingsMap7497{}
	idxs, err := m.applyPrimaryBindingRowsLocked(
		status, &fakeCtrlMap{}, rec, userspaceCtrlValue{}, map[uint32]bool{}, nil, map[uint32]struct{}{})
	if err != nil {
		t.Fatalf("primary pass rejected the parent binding: %v", err)
	}
	ctrlFake := &fakeCtrlMap{}
	if _, err = m.applyAliasBindingRowsLocked(
		status, ctrlFake, rec, userspaceCtrlValue{Enabled: 1}, map[uint32]bool{}, idxs, map[uint32]struct{}{}); err == nil {
		t.Fatalf("child=%d: alias pass accepted a slot-zero-wrapping ifindex", childIfindex)
	} else if !strings.Contains(err.Error(), "9698") || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("child=%d: unexpected fail-closed error: %v", childIfindex, err)
	}
	if !ctrlFake.haveStored || ctrlFake.stored.Enabled != 0 {
		t.Errorf("child=%d: fail-closed ctrl row not written with Enabled=0: haveStored=%v stored=%+v",
			childIfindex, ctrlFake.haveStored, ctrlFake.stored)
	}
	if val, ok := rec.wrote(0); ok {
		t.Errorf("child=%d: alias wrote wrapped slot-zero row %+v; packet-side checked multiplication is a separate bound",
			childIfindex, val)
	}
}

// Control: an ordinary alias child is still accepted, reusing its parent's
// slot, and the ctrl map is left alone (no fail-closed write). Without this
// the refusal above is equally satisfied by a guard that refuses everything.
func TestAliasAcceptsOrdinaryChildIfindex12194(t *testing.T) {
	const parentIfindex = 8
	const childIfindex = 9
	m := New()
	m.lastSnapshot = &ConfigSnapshot{
		Generation: 1,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0-0-1", Zone: "trust", Ifindex: parentIfindex},
			{Name: "ge-0-0-1.50", Zone: "trust", Ifindex: childIfindex, ParentIfindex: parentIfindex},
		},
	}
	status := &ProcessStatus{
		Enabled:      true,
		Workers:      1,
		Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		Bindings: []BindingStatus{{
			Slot: 3, QueueID: 0, Ifindex: parentIfindex,
			Registered: true, Armed: true, Bound: true, Ready: true,
		}},
	}
	rec := &recordingBindingsMap7497{}
	set := map[uint32]struct{}{}
	idxs, err := m.applyPrimaryBindingRowsLocked(
		status, &fakeCtrlMap{}, rec, userspaceCtrlValue{}, map[uint32]bool{}, nil, set)
	if err != nil {
		t.Fatalf("primary pass rejected the parent binding: %v", err)
	}
	ctrlFake := &fakeCtrlMap{}
	if _, err = m.applyAliasBindingRowsLocked(
		status, ctrlFake, rec, userspaceCtrlValue{Enabled: 1}, map[uint32]bool{}, idxs, set); err != nil {
		t.Fatalf("an ordinary alias child was rejected: %v", err)
	}
	if ctrlFake.haveStored {
		t.Errorf("valid alias wrote fail-closed ctrl row: %+v", ctrlFake.stored)
	}
	childIdx := uint32(childIfindex) * bindingQueuesPerIface
	cv, ok := rec.wrote(childIdx)
	if !ok {
		t.Fatalf("alias row idx=%d was not written", childIdx)
	}
	if cv.Slot != 3 {
		t.Fatalf("alias slot %d != parent slot 3; the child no longer steers into the parent's socket", cv.Slot)
	}
}
