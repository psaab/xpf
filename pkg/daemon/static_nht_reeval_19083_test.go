package daemon

import (
	"sync"
	"testing"
)

// TestVIPRemovalForcesStaticNHTReeval19083: a VIP removal forces one static-NHT
// re-evaluation (#19083: a static that registered since the last NHT event
// bypasses the blackhole filter until the next one). A promotion does not, and
// neither does a safety-net pass that removed nothing.
func TestVIPRemovalForcesStaticNHTReeval19083(t *testing.T) {
	d, _ := newDemotion18701(t, false, 0)
	d.directSendGARPsFn = func(int) {}
	var mu sync.Mutex
	var calls []int
	d.frrStaticNHTReevalFn = func(rg int) {
		mu.Lock()
		calls = append(calls, rg)
		mu.Unlock()
	}
	snapshot := func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), calls...)
	}

	d.applyDirectVIPOwnership(1, false, "demote") // owned -> not owned
	if got := snapshot(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("after the demotion: re-evaluations %v, want exactly one for RG1", got)
	}
	d.directRemoveVIPsFn = func(int) int { return 0 }
	d.applyDirectVIPOwnership(1, false, "safety-net") // nothing owned, nothing removed
	if got := snapshot(); len(got) != 1 {
		t.Fatalf("a safety-net pass that removed nothing re-evaluated: %v", got)
	}
	d.applyDirectVIPOwnership(1, true, "promote")
	if got := snapshot(); len(got) != 1 {
		t.Fatalf("a promotion re-evaluated: %v", got)
	}
}
