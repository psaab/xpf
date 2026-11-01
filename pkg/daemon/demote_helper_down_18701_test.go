package daemon

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18701: on a demotion edge, an UNRESPONSIVE local helper must not hold the
// VIPs hostage. On tcp the old primary kept the LAN VIP ~26 s after the peer
// took it, because the VIP release came after helper round trips that each
// burned their deadline, and the next ARP re-resolve landed on the dead node.

type order18701 struct {
	mu     sync.Mutex
	events []string
}

func (o *order18701) add(ev string) {
	o.mu.Lock()
	o.events = append(o.events, ev)
	o.mu.Unlock()
}

func (o *order18701) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.events...)
}

// slowHA18701 records the rg_active=false write and then blocks for hold,
// the way UpdateRGActive does against a helper that does not answer.
type slowHA18701 struct {
	log  *order18701
	hold time.Duration
}

func (h *slowHA18701) SetRGActive(_ context.Context, _ int, active bool) error {
	if !active {
		h.log.add("rg_active=false sent")
		time.Sleep(h.hold)
	}
	return nil
}

func (h *slowHA18701) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (h *slowHA18701) SyncFabricState(context.Context) error            { return nil }

// readinessDP18701 is the runtime the transit gate and the demotion read the
// #18697/#18685 verdict from.
type readinessDP18701 struct {
	dataplane.RuntimeDataPlane
	ha       *slowHA18701
	notReady atomic.Bool
}

func (d *readinessDP18701) HA() dataplane.HAController { return d.ha }
func (d *readinessDP18701) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}
func (d *readinessDP18701) HelperElectionNotReady() bool { return d.notReady.Load() }

func newDemotion18701(t *testing.T, notReady bool, hold time.Duration) (*Daemon, *order18701) {
	t.Helper()
	log := &order18701{}
	d := newActuationDaemon(t, &actuationHA{})
	dp := &readinessDP18701{ha: &slowHA18701{log: log, hold: hold}}
	dp.notReady.Store(notReady)
	d.setDataplane(dp)
	d.directRemoveVIPsFn = func(int) int { log.add("vips-removed"); return 1 }
	d.directAddVIPsFn = func(int) int { return 0 }
	d.directVIPMu.Lock()
	if d.directVIPOwned == nil {
		d.directVIPOwned = make(map[int]bool)
	}
	d.directVIPOwned[1] = true
	d.directVIPMu.Unlock()
	return d, log
}

// TestUnresponsiveHelperDemotionReleasesVIPsFirst18701: with the helper not
// answering, the VIPs go BEFORE the rg_active write, and the handler does not
// wait out a helper that never acknowledges.
func TestUnresponsiveHelperDemotionReleasesVIPsFirst18701(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, true, 5*time.Second)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	primeRG1Primary(t, d)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	ev := log.snapshot()
	vips, write := slices.Index(ev, "vips-removed"), slices.Index(ev, "rg_active=false sent")
	if vips < 0 || write < 0 || vips > write {
		t.Fatalf("events %v: with an unresponsive helper the VIPs must be released before the rg_active write", ev)
	}
	if took > 2*time.Second {
		t.Fatalf("the demotion waited %s on a helper that never acknowledges; the helper-side write must be bounded", took)
	}
}

// TestHealthyDemotionKeepsTheOrder18701: with a healthy helper the existing
// order stands (#18563/#18620): the rg_active write comes first and the VIPs
// after it, and the handler waits for the acknowledgement.
func TestHealthyDemotionKeepsTheOrder18701(t *testing.T) {
	d, log := newDemotion18701(t, false, 300*time.Millisecond)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	primeRG1Primary(t, d)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	ev := log.snapshot()
	vips, write := slices.Index(ev, "vips-removed"), slices.Index(ev, "rg_active=false sent")
	if vips < 0 || write < 0 || write > vips {
		t.Fatalf("events %v: a healthy demotion must write rg_active before releasing the VIPs", ev)
	}
	if took < 300*time.Millisecond {
		t.Fatalf("a healthy demotion returned after %s, before the helper acknowledged", took)
	}
}
