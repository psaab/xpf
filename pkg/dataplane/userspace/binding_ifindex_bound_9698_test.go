package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9698: the helper-supplied ifindex was multiplied into the uint32 composed
// userspace_bindings index BEFORE any bound, so an ifindex of 2^28 or more
// wrapped back inside the dense cap and wrote another (ifindex, queue)'s row.
// These cells run without BPF maps. The two #814 cells in
// maps_sync_cap_test.go need real maps and skip in an unprivileged run.

const wrapIfindex9698 = 1<<28 + 2 // uint32(ifindex)*16 + 3 == 2*16 + 3 == 35

func TestBindingIfindexInRange9698(t *testing.T) {
	for _, c := range []struct {
		ifindex int
		want    bool
	}{
		{1, true},
		{2, true},
		{int(dataplane.MaxInterfaces) - 1, true},
		{0, false},
		{-1, false},
		{int(dataplane.MaxInterfaces), false},
		{wrapIfindex9698, false},
		{1<<32 + 2, false}, // truncates to 2 in uint32(ifindex)
	} {
		if got := bindingIfindexInRange(c.ifindex); got != c.want {
			t.Errorf("bindingIfindexInRange(%d) = %v, want %v", c.ifindex, got, c.want)
		}
	}
}

// The apply site: a wrapping ifindex is refused and NO row is written at all.
// That includes row 35, which it would have aliased (ifindex 2, queue 3).
func TestApplyRefusesAWrappingIfindex9698(t *testing.T) {
	for _, ifindex := range []int{wrapIfindex9698, 1<<32 + 2} {
		rec, err := applyPrimary7497(t, New(), []BindingStatus{{
			Slot: 5, QueueID: 3, Ifindex: ifindex,
			Registered: true, Armed: true, Bound: true, Ready: true,
		}})
		if err == nil {
			t.Fatalf("ifindex=%d: apply accepted a wrapping ifindex", ifindex)
		}
		if len(rec.writes) != 0 {
			t.Fatalf("ifindex=%d: rows written before failing closed: %+v", ifindex, rec.writes)
		}
		for _, want := range []string{"9698", "exceeds cap", "MAX_INTERFACES"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ifindex=%d: error does not carry %q: %v", ifindex, want, err)
			}
		}
	}

	// Controls: the #814 over-cap value is still refused (with the text the
	// #814 cell asserts), and an ordinary ifindex is still accepted and
	// written at its own row.
	rec, err := applyPrimary7497(t, New(), []BindingStatus{{
		Slot: 5, QueueID: 3, Ifindex: int(dataplane.MaxInterfaces),
		Registered: true, Armed: true, Bound: true, Ready: true,
	}})
	if err == nil || len(rec.writes) != 0 || !strings.Contains(err.Error(), "exceeds cap") || !strings.Contains(err.Error(), "MAX_INTERFACES") {
		t.Errorf("ifindex=MaxInterfaces: want refusal naming the cap and MAX_INTERFACES with no write, got err=%v writes=%+v", err, rec.writes)
	}
	rec, err = applyPrimary7497(t, New(), []BindingStatus{{
		Slot: 5, QueueID: 3, Ifindex: 2,
		Registered: true, Armed: true, Bound: true, Ready: true,
	}})
	if err != nil {
		t.Fatalf("ordinary ifindex refused: %v", err)
	}
	if v, ok := rec.wrote(35); !ok || v.Slot != 5 {
		t.Fatalf("ordinary ifindex 2 queue 3 not written at idx 35 with slot 5: %+v", rec.writes)
	}
}

// The watchdog site: a wrapping ifindex is skipped, so nothing is looked up or
// repaired, while an ordinary one yields its own index.
func TestWatchdogSkipsAWrappingIfindex9698(t *testing.T) {
	live := func(ifindex int, queue uint32) BindingStatus {
		return BindingStatus{Slot: 5, QueueID: queue, Ifindex: ifindex, Registered: true, Armed: true, Bound: true, Ready: true}
	}
	for _, ifindex := range []int{wrapIfindex9698, 1<<32 + 2, int(dataplane.MaxInterfaces)} {
		if idx, ok := watchdogBindingIndex(live(ifindex, 3), nil); ok {
			t.Errorf("ifindex=%d: watchdog would repair idx=%d, want skip", ifindex, idx)
		}
	}
	if idx, ok := watchdogBindingIndex(live(2, 3), nil); !ok || idx != 35 {
		t.Errorf("ordinary ifindex 2 queue 3: got idx=%d ok=%v, want 35 true", idx, ok)
	}
	// The existing guards still hold in the extracted decision.
	if _, ok := watchdogBindingIndex(live(2, bindingQueuesPerIface), nil); ok {
		t.Error("queue at the stride must still be skipped (#4894)")
	}
	notLive := live(2, 3)
	notLive.Ready = false
	if _, ok := watchdogBindingIndex(notLive, nil); ok {
		t.Error("a binding that is not forwarding-live must still be skipped (#1666)")
	}
}
