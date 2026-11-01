package daemon

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/frr"
	"golang.org/x/sync/semaphore"
)

// #18620: on a demotion edge the schedules that WITHDRAW the RG's routes must
// start only after the rg_active=false write. Before the fix the cluster-state
// connected-RG republish was launched at the top of handleClusterEvent. It
// raced UpdateRGActive for the manager lock, and on loss it won on about one
// demotion in ten. The helper then held a FIB without the RG's connected rows
// while still forwarding the RG. Live sessions were revoked as stale source NAT
// and re-created as transient seeds that blackholed the flow on failback.
//
// The recorder sees each action at the moment it takes effect:
//   - "rg_active=false": SetRGActive returned. Its return is the helper ack in
//     production.
//   - "publish": the routes-only snapshot reached the dataplane.
//   - "frr-armed" / "ipmon-armed": the debounced reconcile was armed.
//
// SetRGActive holds for 150 ms before returning. The pre-fix goroutine had
// applySem free and published inside that hold, so the order flips
// deterministically on revert.

type demotionOrderLog18620 struct {
	mu     sync.Mutex
	events []string
	pub    chan struct{}
}

func (l *demotionOrderLog18620) add(ev string) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
	if ev == "publish" {
		select {
		case l.pub <- struct{}{}:
		default:
		}
	}
}

func (l *demotionOrderLog18620) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type demotionOrderHA18620 struct {
	log  *demotionOrderLog18620
	hold time.Duration
	err  error // returned by the rg_active=false write
}

func (h *demotionOrderHA18620) SetRGActive(_ context.Context, _ int, active bool) error {
	if !active {
		time.Sleep(h.hold)
		h.log.add("rg_active=false")
		return h.err
	}
	h.log.add("rg_active=true")
	return nil
}

func (h *demotionOrderHA18620) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (h *demotionOrderHA18620) SyncFabricState(context.Context) error            { return nil }

// demotionOrderDP18620 is HA() plus the routes-only publish surface. The nil
// embed panics on anything else the demotion reaches for.
type demotionOrderDP18620 struct {
	dataplane.RuntimeDataPlane
	ha  *demotionOrderHA18620
	log *demotionOrderLog18620
}

func (d *demotionOrderDP18620) HA() dataplane.HAController { return d.ha }

// Mode keeps injectBlackholeRoutes on its userspace early return, the path the
// loss cluster runs.
func (d *demotionOrderDP18620) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}

func (d *demotionOrderDP18620) PublishRouteOverlaySnapshotWithLatch(*config.Config, []config.RouteOverlayEntry, map[string]bool, bool) (bool, error) {
	d.log.add("publish")
	return true, nil
}

func (d *demotionOrderDP18620) BumpFIBGeneration() (uint32, error) {
	d.log.add("bump")
	return 1, nil
}

func newDemotionOrderDaemon18620(t *testing.T, log *demotionOrderLog18620) *Daemon {
	t.Helper()
	d := newActuationDaemon(t, &actuationHA{})
	d.applySem = semaphore.NewWeighted(1)
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), &frr.RecordingExecutor{})
	d.frrHA.afterFunc = func(time.Duration, func()) { log.add("frr-armed") }
	d.ipmonGateHA.afterFunc = func(time.Duration, func()) { log.add("ipmon-armed") }
	d.setDataplane(&demotionOrderDP18620{
		ha:  &demotionOrderHA18620{log: log, hold: 150 * time.Millisecond},
		log: log,
	})
	return d
}

func TestDemotionWithdrawsRoutesOnlyAfterRGActiveClear18620(t *testing.T) {
	log := &demotionOrderLog18620{pub: make(chan struct{}, 1)}
	d := newDemotionOrderDaemon18620(t, log)
	primeRG1Primary(t, d)
	demoteRG1(t, d)

	select {
	case <-log.pub:
	case <-time.After(2 * time.Second):
		t.Fatalf("the demotion never published the connected-RG withdrawal; events = %v", log.snapshot())
	}
	events := log.snapshot()
	clear := slices.Index(events, "rg_active=false")
	if clear < 0 {
		t.Fatalf("the demotion never cleared rg_active; events = %v", events)
	}
	for _, ev := range []string{"publish", "frr-armed", "ipmon-armed"} {
		at := slices.Index(events, ev)
		if at < 0 {
			t.Fatalf("%s never happened on the demotion edge; events = %v", ev, events)
		}
		if at < clear {
			t.Fatalf("%s at %d preceded rg_active=false at %d; events = %v. "+
				"A routes-only snapshot published before the helper learns the RG is inactive "+
				"withdraws its connected rows under live forwarding (#18620)", ev, at, clear, events)
		}
	}
}

// A demotion whose rg_active=false write FAILS still schedules all three
// reconciles (review of #18638, seat T). The reconcile retry that later
// lands the write schedules none of them, so skipping them on error would
// leave FRR, ip-monitoring and the connected rows on the pre-demotion view.
// The rows themselves stay held until the helper acknowledges
// (helperActiveRGsLocked), so scheduling them here cannot withdraw anything
// early.
func TestDemotionSchedulesOnFailedRGActiveWrite18620(t *testing.T) {
	log := &demotionOrderLog18620{pub: make(chan struct{}, 1)}
	d := newDemotionOrderDaemon18620(t, log)
	d.setDataplane(&demotionOrderDP18620{
		ha:  &demotionOrderHA18620{log: log, hold: 0, err: errRGActiveRejected},
		log: log,
	})
	primeRG1Primary(t, d)
	demoteRG1(t, d)

	select {
	case <-log.pub:
	case <-time.After(2 * time.Second):
		t.Fatalf("a failed demotion write must still schedule the connected-RG republish; events = %v", log.snapshot())
	}
	events := log.snapshot()
	for _, ev := range []string{"rg_active=false", "publish", "frr-armed", "ipmon-armed"} {
		if !slices.Contains(events, ev) {
			t.Fatalf("%s missing after a failed rg_active write; events = %v", ev, events)
		}
	}
}
