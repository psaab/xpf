package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
	"golang.org/x/sync/semaphore"
)

// promotionOrderLog18927 records the effects whose order protects a newly
// active RG from forwarding through a stale helper FIB.
type promotionOrderLog18927 struct {
	mu      sync.Mutex
	events  []string
	changed chan struct{}
}

func (l *promotionOrderLog18927) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
	select {
	case l.changed <- struct{}{}:
	default:
	}
}

func (l *promotionOrderLog18927) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type promotionOrderHA18927 struct{ log *promotionOrderLog18927 }

func (h *promotionOrderHA18927) SetRGActive(_ context.Context, rgID int, active bool) error {
	h.log.add(fmt.Sprintf("rg_active[%d]=%t", rgID, active))
	return nil
}

func (h *promotionOrderHA18927) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (h *promotionOrderHA18927) SyncFabricState(context.Context) error            { return nil }

type promotionOrderDP18927 struct {
	dataplane.RuntimeDataPlane
	log       *promotionOrderLog18927
	ha        *promotionOrderHA18927
	publishErr error
	bumpErr    error
}

func (d *promotionOrderDP18927) HA() dataplane.HAController { return d.ha }
func (d *promotionOrderDP18927) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}
func (d *promotionOrderDP18927) PublishRouteOverlaySnapshotWithLatch(*config.Config, []config.RouteOverlayEntry, map[string]bool, bool) (bool, error) {
	d.log.add("publish")
	return true, d.publishErr
}
func (d *promotionOrderDP18927) BumpFIBGeneration() (uint32, error) {
	d.log.add("bump")
	return 1, d.bumpErr
}

func newPromotionOrderDaemon18927(t *testing.T) (*Daemon, *promotionOrderLog18927, *promotionOrderDP18927) {
	t.Helper()
	log := &promotionOrderLog18927{changed: make(chan struct{}, 32)}
	dp := &promotionOrderDP18927{log: log, ha: &promotionOrderHA18927{log: log}}
	d := newActuationDaemon(t, &actuationHA{})
	d.setDataplane(dp)
	d.applySem = semaphore.NewWeighted(1)
	return d, log, dp
}

func runPromotionPath18927(t *testing.T, d *Daemon, path string) {
	t.Helper()
	switch path {
	case "cluster-event":
		d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
		d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
			GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
		}, nil)
	case "vrrp-master":
		d.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
			GroupID: rethVRIDBase + 1, Interface: "reth1", State: vrrp.StateMaster,
		}, rgTransition{})
	case "reconcile":
		d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		d.reconcileRGState()
	default:
		t.Fatalf("unknown promotion path %q", path)
	}
}

func countPromotionEvent18927(events []string, event string) int {
	count := 0
	for _, got := range events {
		if got == event {
			count++
		}
	}
	return count
}

func waitPromotionRepublish18927(t *testing.T, log *promotionOrderLog18927, wantPublish, wantBump int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		events := log.snapshot()
		if countPromotionEvent18927(events, "publish") >= wantPublish && countPromotionEvent18927(events, "bump") >= wantBump {
			return
		}
		select {
		case <-log.changed:
		case <-timer.C:
			t.Fatalf("timed out waiting for connected-RG republish (%d publish, %d bump); events=%v",
				wantPublish, wantBump, log.snapshot())
		}
	}
}

// TestPromotionRepublishesConnectedRGBeforeRGActive18927 pins all three
// activation producers. Before #18927 the reconcile arm wrote rg_active=true
// before its async republish, while the event arms ignored synchronous
// publish/bump errors. Reverting the reconcile republish makes the ordering
// assertion RED; reverting result propagation makes each failed-publish row
// RED.
func TestPromotionRepublishesConnectedRGBeforeRGActive18927(t *testing.T) {
	paths := []string{"cluster-event", "vrrp-master", "reconcile"}
	for _, path := range paths {
		t.Run(path+"/ordering", func(t *testing.T) {
			d, log, _ := newPromotionOrderDaemon18927(t)
			runPromotionPath18927(t, d, path)
			events := log.snapshot()
			active := slices.Index(events, "rg_active[1]=true")
			if active < 2 || events[active-2] != "publish" || events[active-1] != "bump" {
				t.Fatalf("RG1 activation order = %v; want publish -> bump -> rg_active[1]=true (#18927)", events)
			}
			if path != "vrrp-master" {
				waitPromotionRepublish18927(t, log, 2, 2)
			}
		})
	}

	for _, failure := range []string{"publisher-error", "bump-error"} {
		for _, path := range paths {
			t.Run(path+"/"+failure, func(t *testing.T) {
				d, log, dp := newPromotionOrderDaemon18927(t)
				if failure == "publisher-error" {
					dp.publishErr = errors.New("connected-route publish failed")
				} else {
					dp.bumpErr = errors.New("FIB generation bump failed")
				}
				runPromotionPath18927(t, d, path)
				if path != "vrrp-master" {
					wantPublish, wantBump := 1, 0
					if path == "cluster-event" {
						wantPublish = 2
					}
					if failure == "bump-error" {
						wantBump = 1
						if path == "cluster-event" {
							wantBump = 2
						}
					}
					waitPromotionRepublish18927(t, log, wantPublish, wantBump)
				}
				events := log.snapshot()
				if slices.Contains(events, "rg_active[1]=true") {
					t.Fatalf("RG1 activation proceeded despite %s on %s: events=%v", failure, path, events)
				}
				if !slices.Contains(events, "publish") {
					t.Fatalf("connected-RG publish was not attempted: events=%v", events)
				}
				if failure == "bump-error" && !slices.Contains(events, "bump") {
					t.Fatalf("FIB generation bump was not attempted: events=%v", events)
				}
				if !d.getOrCreateRGState(1).NeedsApply() {
					t.Fatalf("failed republish cleared retry debt on %s; events=%v", path, events)
				}
			})
		}
	}
}

func TestTransferPreActivationSkipsHelperPublishAfterConnectedRouteFailure18927(t *testing.T) {
	for _, failure := range []string{"publisher-error", "bump-error"} {
		t.Run(failure, func(t *testing.T) {
			d, dp := newPreActivateDaemon18559(t)
			if failure == "publisher-error" {
				dp.fakeOverlayDP.publishErr = errors.New("connected-route publish failed")
			} else {
				dp.fakeOverlayDP.bumpErr = errors.New("FIB generation bump failed")
			}
			if err := d.beginTransferPreActivation([]int{1}); err == nil {
				t.Fatal("transfer pre-activation reported success after connected-route republish failure")
			}
			calls := dp.callsSnapshot()
			if slices.Contains(calls, "ha-publish") {
				t.Fatalf("helper forwarding publish proceeded after connected-route failure: calls=%v", calls)
			}
			want := []string{"mark", "publish"}
			if failure == "bump-error" {
				want = append(want, "bump")
			}
			if !slices.Equal(calls, want) {
				t.Fatalf("calls=%v, want %v after %s", calls, want, failure)
			}
		})
	}
}
