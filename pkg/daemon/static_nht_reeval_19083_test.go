package daemon

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/frr"
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

// TestStaticNHTReevalProductionLaunchIsAsyncAndCoalesced19083 drives the
// PRODUCTION launch (no seam) against a real frr.Manager whose section binds
// the #19083 map (Codex P2 lifecycle, R22 #2/#4):
//   - the VIP path never waits for the rebind (it is held in flight here);
//   - one demotion burst (two RGs) produces ONE rebind;
//   - a later demotion schedules the next one;
//   - with no FRR manager the trigger is a no-op.
func TestStaticNHTReevalProductionLaunchIsAsyncAndCoalesced19083(t *testing.T) {
	old := staticNHTReevalDebounce19083
	staticNHTReevalDebounce19083 = 50 * time.Millisecond
	t.Cleanup(func() { staticNHTReevalDebounce19083 = old })

	d, _ := newDemotion18701(t, false, 0)
	d.directSendGARPsFn = func(int) {}
	rec := &frr.RecordingExecutor{}
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rec)
	t.Cleanup(d.frr.Stop)
	if err := d.frr.ApplyFull(&frr.FullConfig{ClusterMode: true}); err != nil {
		t.Fatalf("apply the cluster section: %v", err)
	}
	gate := make(chan struct{})
	rec.ConfigBatchGate = gate
	own := func(rgs ...int) {
		d.directVIPMu.Lock()
		for _, rg := range rgs {
			d.directVIPOwned[rg] = true
		}
		d.directVIPMu.Unlock()
	}
	own(1, 2)
	waitBatches := func(n int) [][]string {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if b := rec.ConfigBatchesSnapshot(); len(b) >= n {
				return b
			}
			time.Sleep(10 * time.Millisecond)
		}
		return rec.ConfigBatchesSnapshot()
	}

	returned := make(chan struct{})
	go func() {
		d.applyDirectVIPOwnership(1, false, "demote")
		d.applyDirectVIPOwnership(2, false, "demote")
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		close(gate)
		t.Fatal("the VIP path waited for the static NHT re-evaluation; it must be asynchronous")
	}
	b := waitBatches(1)
	want := "ip nht static route-map xpf-static-nht-b-xpf-redist|ipv6 nht static route-map xpf-static-nht-b-xpf-redist|" +
		"ip nht static route-map xpf-static-nht-xpf-redist|ipv6 nht static route-map xpf-static-nht-xpf-redist"
	if len(b) != 1 || strings.Join(b[0], "|") != want {
		close(gate)
		t.Fatalf("after one demotion burst of two RGs: batches %q, want exactly one rebind %q", b, want)
	}
	close(gate)
	time.Sleep(4 * staticNHTReevalDebounce19083)
	if b := rec.ConfigBatchesSnapshot(); len(b) != 1 {
		t.Fatalf("one demotion burst ran %d rebinds, want ONE (coalesced): %q", len(b), b)
	}

	own(1)
	d.applyDirectVIPOwnership(1, false, "demote")
	if b := waitBatches(2); len(b) != 2 {
		t.Fatalf("a later demotion ran %d rebinds in total, want 2: %q", len(b), b)
	}

	d.frr = nil
	own(1)
	d.applyDirectVIPOwnership(1, false, "demote") // must not panic
}
