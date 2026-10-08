package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #12307: the watchdog's VLAN-alias repair loop in verifyBindingsMapLocked
// (maps_sync.go) computed `idx := childIfindex*bindingQueuesPerIface + queue`
// and only then tested the #814 dense cap. The child ifindex is
// snapshot-supplied and unbounded above, so a child of 2^28 or more wraps the
// uint32 product back INSIDE the cap, and the #814 check after the multiply
// passes. The repair write is conditional on an all-zero lookup row, so when
// the wrapped low row is zero the watchdog repairs the WRONG row — another
// (ifindex, queue)'s slot — with the parent's slot. This is the same defect
// class #9698 fixed on the primary paths (apply + watchdog) and #12194 fixes
// on the apply alias path; this cell pins the watchdog alias path.
//
// These run without BPF maps, following the #9698 precedent of testing the
// extracted decision: the watchdog's own cell needs real maps and skips on an
// unprivileged `make test`.

// A wrapping child ifindex: uint32(child)*16 + 3 == 2*16 + 3 == 35, the
// (ifindex 2, queue 3) row. The true product exceeds the dense cap.
const wrapChildIfindex12307 = 1<<28 + 2

func liveBinding12307(ifindex int, queue uint32) BindingStatus {
	return BindingStatus{Slot: 5, QueueID: queue, Ifindex: ifindex, Registered: true, Armed: true, Bound: true, Ready: true}
}

func TestWatchdogAliasSkipsAWrappingChildIfindex12307(t *testing.T) {
	for _, child := range []uint32{wrapChildIfindex12307, dataplane.MaxInterfaces} {
		if idx, ok := watchdogAliasBindingIndex(child, 8, liveBinding12307(8, 3), nil); ok {
			t.Errorf("child=%d: watchdog alias would repair idx=%d, want skip", child, idx)
		}
	}
	// Ordinary child still yields its own index.
	want := uint32(9)*bindingQueuesPerIface + 3
	if idx, ok := watchdogAliasBindingIndex(9, 8, liveBinding12307(8, 3), nil); !ok || idx != want {
		t.Errorf("ordinary child 9 queue 3: got idx=%d ok=%v, want %d true", idx, ok, want)
	}
	// The highest child within the configured ifindex range remains valid.
	lastChild := dataplane.MaxInterfaces - 1
	lastIdx := lastChild*bindingQueuesPerIface + 3
	if idx, ok := watchdogAliasBindingIndex(lastChild, 8, liveBinding12307(8, 3), nil); !ok || idx != lastIdx {
		t.Errorf("last in-cap child %d queue 3: got idx=%d ok=%v, want %d true", lastChild, idx, ok, lastIdx)
	}
	// The existing guards still hold in the extracted decision.
	if _, ok := watchdogAliasBindingIndex(9, 8, liveBinding12307(8, bindingQueuesPerIface), nil); ok {
		t.Error("queue at the stride must still be skipped (#4894)")
	}
	notLive := liveBinding12307(8, 3)
	notLive.Ready = false
	if _, ok := watchdogAliasBindingIndex(9, 8, notLive, nil); ok {
		t.Error("a binding that is not forwarding-live must still be skipped (#1666)")
	}
}
