package userspace

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

// #18620: the connected-RG verdict the route builders use must keep an RG's
// connected rows while the helper still forwards that RG. The cluster verdict
// flips at the start of a demotion, but the helper learns it only when
// UpdateRGActive(false) is acknowledged. A snapshot built in between used to
// withdraw 2001:559:8585:80::/64 from the helper FIB under live forwarding.
// The first FIB-stale hit of each live SNAT session then re-resolved off
// reth0.80 and was revoked as stale source NAT (snat_revoked_sessions_total
// +12/+16 on loss, at the move before each trap hit).
//
// Fixture: RG1 owns reth0.80 (WAN), RG2 owns reth1.0 (LAN). The cluster
// verdict is a variable the cell flips, standing in for the cluster manager
// at the demotion edge.

type demotionHold18620 struct {
	m              *Manager
	clusterPrimary map[int]bool
}

func newDemotionHold18620(t *testing.T) *demotionHold18620 {
	t.Helper()
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	m, _ := newPreActivateManager18559(t)
	h := &demotionHold18620{m: m, clusterPrimary: map[int]bool{1: true, 2: true}}
	m.rgPrimaryProvider = func(rgID int) (bool, bool) {
		primary, known := h.clusterPrimary[rgID]
		return primary, known
	}
	// The node owns RG1 and the helper has acknowledged it. Unshimmed, the
	// post-send status apply errors after the ack (as in the #18559 cells);
	// the acknowledged inventory is what this fixture needs, so check that.
	_ = m.UpdateRGActive(1, true)
	if !h.helperHolds(1) {
		t.Fatal("setup: the helper inventory does not hold RG1 active after the promotion publish")
	}
	return h
}

func (h *demotionHold18620) helperHolds(rgID int) bool {
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	return h.m.helperActiveRGsLocked()[rgID]
}

// wanRowsPublished reports whether a route build NOW keeps RG1's connected
// rows: the WAN /64 is a connected route and reth0.80 is not marked
// peer-owned. Both outputs of the build are checked, because the Rust
// connected filter reads the mark and the Go rows are the FIB.
func (h *demotionHold18620) wanRowsPublished(t *testing.T) bool {
	t.Helper()
	cfg := clusteredConfig15742()
	interfaces := connectedRGInterfaces15742()
	h.m.mu.Lock()
	provider := h.m.rgPrimaryNowLocked()
	h.m.mu.Unlock()
	routes, _, err := buildRouteSnapshotsWithRGPrimary(cfg, interfaces, nil, provider)
	if err != nil {
		t.Fatalf("buildRouteSnapshotsWithRGPrimary: %v", err)
	}
	route := hasConnectedRoute15742(routes, "2001:559:8585:80::/64")
	marked := !markConnectedRGPeerOwned(cfg, interfaces, provider)[0].ConnectedRGPeerOwned
	if route != marked {
		t.Fatalf("route builder disagrees with the peer-owned mark: connected route %v, unmarked %v", route, marked)
	}
	return route
}

func TestDemotionKeepsConnectedRowsUntilHelperAck18620(t *testing.T) {
	h := newDemotionHold18620(t)
	if !h.wanRowsPublished(t) {
		t.Fatal("setup: RG1 is owned and its connected rows are not published")
	}

	// The demotion edge: the cluster verdict has flipped, the helper has not
	// been told. This is the window the loss journal shows (apply_snapshot
	// 50-80 ms before "RG state updated active=false").
	h.clusterPrimary[1] = false
	if !h.wanRowsPublished(t) {
		t.Fatal("a build in the demotion window withdrew RG1's connected rows while the helper " +
			"still forwards RG1; live SNAT sessions are revoked on their next hit (#18620)")
	}

	// The helper acknowledges the demotion: now the rows go.
	_ = h.m.UpdateRGActive(1, false)
	if h.helperHolds(1) {
		t.Fatal("setup: the acknowledged demotion left RG1 active in the helper inventory")
	}
	if h.wanRowsPublished(t) {
		t.Fatal("RG1's connected rows survived the acknowledged demotion; the standby would " +
			"publish a peer-owned prefix as transit connected (#15742)")
	}
}

// A demotion write the helper did not acknowledge leaves the helper
// forwarding: haGroups already says inactive, but the rows must stay.
// Keying the hold on haGroups instead of the acknowledged inventory fails
// here.
func TestFailedDemotionWriteKeepsConnectedRows18620(t *testing.T) {
	h := newDemotionHold18620(t)
	h.clusterPrimary[1] = false
	prior := h.m.controlRequestHook
	h.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "update_ha_state" {
			return errors.New("helper control socket closed")
		}
		return prior(req, status)
	}
	if err := h.m.UpdateRGActive(1, false); err == nil {
		t.Fatal("setup: the injected update_ha_state failure did not surface")
	}
	if !h.helperHolds(1) {
		t.Fatal("setup: a refused update_ha_state rewrote the acknowledged inventory")
	}
	h.m.mu.Lock()
	cluster := h.m.haGroups[1].Active
	h.m.mu.Unlock()
	if cluster {
		t.Fatal("setup: haGroups should already record the demotion intent")
	}
	if !h.wanRowsPublished(t) {
		t.Fatal("an unacknowledged demotion withdrew RG1's connected rows; the helper may still forward RG1")
	}
}

// The hold is the CURRENT helper's acknowledgement. A helper that went away
// holds nothing, so the cluster verdict alone decides again.
func TestHelperResetDropsConnectedHold18620(t *testing.T) {
	h := newDemotionHold18620(t)
	h.clusterPrimary[1] = false
	h.m.mu.Lock()
	h.m.resetAfterHelperGoneLocked()
	h.m.mu.Unlock()
	if h.wanRowsPublished(t) {
		t.Fatal("a reset helper's last inventory still held RG1's connected rows")
	}
}

// Promotion is unchanged (#16270): a cluster-primary RG is published before
// the helper is told, exactly as before. The hold only ever ADDS rows.
func TestPromotionPublishesBeforeHelperAck18620(t *testing.T) {
	h := newDemotionHold18620(t)
	h.clusterPrimary[2] = true
	h.m.mu.Lock()
	provider := h.m.rgPrimaryNowLocked()
	h.m.mu.Unlock()
	if primary, known := provider(2); !primary || !known {
		t.Fatalf("route provider(2) = (%v, %v) for a cluster-primary RG the helper has not been told about", primary, known)
	}
}

// releaseRecorder18620 records every call of the #18620 release hook.
type releaseRecorder18620 struct{ calls [][]int }

func (r *releaseRecorder18620) hook(rgIDs []int) {
	r.calls = append(r.calls, append([]int(nil), rgIDs...))
}

// Review of #18638 (seat T): a demotion whose rg_active write FAILED keeps
// the hold, and its cluster-state republish keeps the rows. The reconcile
// retry that later lands the write is not an ownership edge, so it schedules
// no republish. Without the release hook the connected rows then stay in the
// helper FIB after the helper went inactive, until some unrelated publish.
// The ack that drops the RG must itself ask for the withdrawal.
func TestFailedThenRetriedDemotionReleasesHold18620(t *testing.T) {
	h := newDemotionHold18620(t)
	rec := &releaseRecorder18620{}
	h.m.SetHeldRGReleaseFunc(rec.hook)
	h.clusterPrimary[1] = false

	prior := h.m.controlRequestHook
	h.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "update_ha_state" {
			return errors.New("helper control socket closed")
		}
		return prior(req, status)
	}
	_ = h.m.UpdateRGActive(1, false)
	if len(rec.calls) != 0 {
		t.Fatalf("release hook fired %v for an UNACKNOWLEDGED demotion; the helper may still forward RG1", rec.calls)
	}
	if !h.wanRowsPublished(t) {
		t.Fatal("setup: the failed demotion must keep RG1's rows")
	}

	// The reconcile retry lands the write.
	h.m.controlRequestHook = prior
	_ = h.m.UpdateRGActive(1, false)
	if len(rec.calls) != 1 || len(rec.calls[0]) != 1 || rec.calls[0][0] != 1 {
		t.Fatalf("release hook calls = %v, want exactly [[1]]: the retried ack must ask for "+
			"RG1's rows to be withdrawn (the retry schedules no republish of its own)", rec.calls)
	}
	if h.wanRowsPublished(t) {
		t.Fatal("RG1's rows survive the acknowledged retry")
	}
}

// The same release through the other full-inventory ack, the periodic
// syncHAStateLocked replay. An RG that stays active (RG2) is never released.
func TestInventoryReplayReleasesOnlyDroppedRG18620(t *testing.T) {
	h := newDemotionHold18620(t)
	rec := &releaseRecorder18620{}
	h.m.SetHeldRGReleaseFunc(rec.hook)
	h.m.mu.Lock()
	group := h.m.haGroups[1]
	group.Active = false
	h.m.haGroups[1] = group
	_ = h.m.syncHAStateLocked()
	h.m.mu.Unlock()
	if len(rec.calls) != 1 || len(rec.calls[0]) != 1 || rec.calls[0][0] != 1 {
		t.Fatalf("release hook calls = %v, want exactly [[1]] (RG2 stays active and held)", rec.calls)
	}
	// A repeat of the same inventory releases nothing more.
	h.m.mu.Lock()
	_ = h.m.syncHAStateLocked()
	h.m.mu.Unlock()
	if len(rec.calls) != 1 {
		t.Fatalf("release hook calls = %v after an identical replay, want no further call", rec.calls)
	}
}
