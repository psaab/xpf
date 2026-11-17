package userspace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #19103: a transfer pre-activation that ends only by its backstop deadline
// must stop counting for the helper on BOTH helper publishers: the degraded
// watchdog (which sends a snapshot published while the pre-activation was
// live, for as long as m.mu stays held) and the status poll (which skipped
// the all-inactive publish).

// degradedPreActiveManager19103 is a manager whose cluster truth has RG1
// inactive, with a live routes-ready pre-activation of RG1 published into the
// watchdog snapshot (the helper acknowledged RG1 active), ready for the
// degraded watchdog path. It returns the deadline.
func degradedPreActiveManager19103(t *testing.T, ttl time.Duration) (*Manager, time.Time) {
	t.Helper()
	m := sessionTestManager9629(t, map[int]HAGroupStatus{
		1: {Active: false, WatchdogTimestamp: 1},
	})
	until := time.Now().Add(ttl)
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 1, Active: true, WatchdogTimestamp: 1}}
	if m.transferPreActive == nil {
		m.transferPreActive = make(map[int]transferPreActivation)
	}
	m.publishedSnapshot = 1 // the live helper holds a published snapshot (#19167 fold 2)
	m.transferPreActive[1] = transferPreActivation{until: until, routesReady: true, readyEpoch: m.helperEpoch}
	m.publishHAWatchdogSnapshotLocked()
	snap := m.haWatchdogSnapshot.Load()
	m.mu.Unlock()
	if snap == nil || len(snap.groups) != 1 || !snap.groups[0].Active {
		t.Fatalf("setup: watchdog snapshot %+v, want RG1 active from the live pre-activation", snap)
	}
	return m, until
}

// Path 1: the snapshot was published while the pre-activation was live; m.mu
// is then held past the deadline. The degraded send must not carry RG1
// Active=true.
func TestDegradedWatchdogDropsAnExpiredPreActivation19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, 50*time.Millisecond)
	var sent []HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
		}
		return nil
	}
	m.mu.Lock() // a long apply_snapshot holds m.mu across the deadline
	time.Sleep(time.Until(until) + 20*time.Millisecond)
	err := m.UpdateHAWatchdog(1, 100)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("degraded refresh: %v", err)
	}
	if len(sent) != 1 || sent[0].RGID != 1 {
		t.Fatalf("setup: degraded send %+v, want one RG1 refresh", sent)
	}
	if sent[0].Active {
		t.Fatalf("degraded send %+v: RG1 still Active=true after its pre-activation deadline", sent)
	}
}

// Path 1, composed with the helper's lease rules (the #9629 Rust-mirror
// oracle). The helper's stored RG1 lease has already lapsed. A cached
// Active=true refresh matches the stored state and RESURRECTS it (#14943's
// matching-active arm); an inactive refresh is a stored-active mismatch, and
// an expired stored-active is never resurrected. #19103 acceptance 3: the
// helper rule is kept (an inactive refresh renews a stored-active lease only
// while it is still valid, #9629 MAJOR-4); the Go side must stop sending
// Active=true.
func TestDegradedRefreshCannotResurrectALapsedPreActivation19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, 50*time.Millisecond)
	oracle := newHARefreshOracle9629([]HAGroupStatus{{RGID: 1, Active: true, WatchdogTimestamp: 1}}, 10)
	oracle.leaseUntil[1] = 9 // lapsed before this receipt
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			oracle.apply(req.HAState.Groups)
		}
		return nil
	}
	m.mu.Lock()
	time.Sleep(time.Until(until) + 20*time.Millisecond)
	err := m.UpdateHAWatchdog(1, 100)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("degraded refresh: %v", err)
	}
	if oracle.forwardingActive(1) {
		t.Fatalf("helper lease for RG1 = active until %d: the degraded refresh resurrected a pre-activation past its deadline", oracle.leaseUntil[1])
	}
}

// pollTick19103 drives one status-poll HA backstop with the helper reporting
// helperActive as its active RGs.
func pollTick19103(m *Manager, helperActive ...int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	helper := make([]HAGroupStatus, 0, len(m.haGroups))
	for id := range m.haGroups {
		g := HAGroupStatus{RGID: id}
		for _, a := range helperActive {
			if a == id {
				g.Active = true
			}
		}
		helper = append(helper, g)
	}
	m.pollHABackstopLocked(helper, activeHAGroupSignature(m.haGroups), false)
}

// expiredOnlyPreActivation19103 leaves the manager with RG1 the only
// effective-active RG, through a routes-ready pre-activation that then
// expires. lastSync sets the poll's 5 s throttle baseline.
func expiredOnlyPreActivation19103(t *testing.T, lastSync time.Time) (*Manager, *haSendRecorder18559, int) {
	t.Helper()
	m, rec := newPreActivateManager18559(t)
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: false} // no other active RG
	epoch := m.BeginTransferPreActivation([]int{1}, time.Now().Add(60*time.Millisecond))
	_ = m.PublishTransferPreActivation([]int{1}, epoch)
	if got := rec.last(t); !got[1] {
		t.Fatalf("setup: helper inventory %v, want RG1 open", got)
	}
	time.Sleep(80 * time.Millisecond)
	m.mu.Lock()
	m.lastRGActivateTime = time.Time{}
	m.lastHASyncTime = lastSync
	m.mu.Unlock()
	return m, rec, rec.count()
}

// Path 2: the only effective-active RG was the pre-activation, and it expired.
// The next status tick must publish RG1 inactive.
func TestPollPublishesAnExpiredOnlyPreActivationInactive19103(t *testing.T) {
	m, rec, before := expiredOnlyPreActivation19103(t, time.Time{})
	pollTick19103(m, 1) // the helper still reports RG1 active
	if rec.count() == before {
		t.Fatal("the status poll published nothing: the helper was never told the expired pre-activation went inactive")
	}
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: RG1 still active after its pre-activation deadline", got)
	}
}

// Path 2, the bound: the expiry is owed even when the poll synced 1 s ago, so
// the 5 s sync throttle must not hold it for up to another 5 s.
func TestPollPublishesAnOwedExpiryInsideTheSyncThrottle19103(t *testing.T) {
	m, rec, before := expiredOnlyPreActivation19103(t, time.Now().Add(-time.Second))
	pollTick19103(m, 1)
	if rec.count() == before {
		t.Fatal("the expired pre-activation waited out the poll's 5 s sync throttle")
	}
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: RG1 still active after its pre-activation deadline", got)
	}
}

// Control: a LIVE pre-activation owes nothing, so the poll keeps its 5 s sync
// throttle (the exemption is for an owed expiry only).
func TestPollKeepsTheSyncThrottleForALivePreActivation19103(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: false}
	epoch := m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.PublishTransferPreActivation([]int{1}, epoch)
	m.mu.Lock()
	m.lastRGActivateTime = time.Time{}
	m.lastHASyncTime = time.Now().Add(-time.Second)
	m.mu.Unlock()
	before := rec.count()
	pollTick19103(m, 1)
	if rec.count() != before {
		t.Fatalf("the poll published inside its 5 s sync throttle with nothing owed (sends %d -> %d)", before, rec.count())
	}
}

// Control: an expiry the helper has ALREADY been told (it reports RG1
// inactive) owes nothing. An unrelated difference (RG2 active in the cluster
// truth, not yet in the helper's report) keeps the poll's change test true,
// so only the owed-expiry predicate could bypass the 5 s throttle here.
func TestPollKeepsTheSyncThrottleOnceAnExpiryIsDelivered19103(t *testing.T) {
	m, rec, _ := expiredOnlyPreActivation19103(t, time.Now().Add(-time.Second))
	m.mu.Lock()
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: true}
	m.mu.Unlock()
	before := rec.count()
	pollTick19103(m) // the helper reports no RG active
	if rec.count() != before {
		t.Fatalf("the poll bypassed its 5 s sync throttle for an expiry the helper already applied (sends %d -> %d)", before, rec.count())
	}
}

// The owed-expiry predicate on its own (the coordinator's ask): a future
// change to the poll's throttles cannot remove the exemption without this
// cell noticing. Owed only when ALL hold: the helper reports the RG active,
// a pre-activation entry exists for it, that entry no longer authorizes the
// helper, and the cluster truth has the RG inactive.
func TestPreActivationExpiryOwedPredicate19103(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name          string
		entry         *transferPreActivation
		clusterActive bool
		helperActive  bool
		want          bool
		staleEpoch    bool // the entry was made ready under a replaced helper
	}{
		// r24 P3-2: a LIVE deadline whose readiness belongs to a replaced
		// helper no longer authorizes this one, so its demotion is owed.
		{"live deadline, stale ready epoch", &transferPreActivation{until: now.Add(time.Minute), routesReady: true}, false, true, true, true},
		{"expired, helper still active, cluster inactive", &transferPreActivation{until: now.Add(-time.Second), routesReady: true}, false, true, true, false},
		{"live pre-activation", &transferPreActivation{until: now.Add(time.Minute), routesReady: true}, false, true, false, false},
		{"helper already inactive", &transferPreActivation{until: now.Add(-time.Second), routesReady: true}, false, false, false, false},
		{"cluster truth active", &transferPreActivation{until: now.Add(-time.Second), routesReady: true}, true, true, false, false},
		{"no pre-activation entry", nil, false, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newPreActivateManager18559(t)
			m.mu.Lock()
			defer m.mu.Unlock()
			m.haGroups[1] = HAGroupStatus{RGID: 1, Active: tc.clusterActive}
			// An unrelated RG2 entry keeps the map non-empty, so the "no entry
			// for RG1" case reaches the per-RG check instead of the
			// empty-map early return.
			m.transferPreActive = map[int]transferPreActivation{
				2: {until: now.Add(time.Minute), routesReady: true, readyEpoch: m.helperEpoch},
			}
			if tc.entry != nil {
				e := *tc.entry
				e.readyEpoch = m.helperEpoch
				if tc.staleEpoch {
					e.readyEpoch = m.helperEpoch + 1
				}
				m.transferPreActive[1] = e
			}
			helper := []HAGroupStatus{{RGID: 1, Active: tc.helperActive}}
			if got := m.preActivationExpiryOwedLocked(helper, now); got != tc.want {
				t.Fatalf("owed = %v, want %v", got, tc.want)
			}
		})
	}
}

// clock19103 is a settable pre-activation clock (the preActivateNowFn seam).
type clock19103 struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock19103) get() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock19103) set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

// codex-e P2-2: the snapshot's groups and deadlines come from ONE time sample.
// With two, a deadline falling between them gave an Active with no deadline.
// The clock reads before the deadline once and after it on every later read:
// the snapshot must still carry the deadline for the Active it publishes.
func TestSnapshotRecordsTheDeadlineAtTheClockBoundary19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, time.Minute)
	var reads atomic.Int32
	m.preActivateNowFn = func() time.Time {
		if reads.Add(1) == 1 {
			return until.Add(-time.Nanosecond)
		}
		return until.Add(time.Nanosecond)
	}
	m.mu.Lock()
	m.publishHAWatchdogSnapshotLocked()
	snap := m.haWatchdogSnapshot.Load()
	m.mu.Unlock()
	if len(snap.groups) != 1 || !snap.groups[0].Active {
		t.Fatalf("setup: snapshot groups %+v, want RG1 active (sampled before the deadline)", snap.groups)
	}
	if got, ok := snap.preActiveUntil[1]; !ok || !got.Equal(until) {
		t.Fatalf("snapshot deadline for RG1 = %v (present %v), want %v: an Active with no deadline", got, ok, until)
	}
}

// codex-e P2-3: a degraded refresh built while the pre-activation is live
// waits on sessionMu past its deadline. The sender re-checks the deadline
// after the queue; sent as built, the Active would resurrect a lapsed lease
// (the #9629 Rust-mirror oracle).
func TestQueuedDegradedRefreshExpiresAfterTheSessionQueue19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, time.Minute)
	clk := &clock19103{now: until.Add(-time.Second)}
	m.preActivateNowFn = clk.get
	m.haWatchdogSessionLockHook = func() { clk.set(until.Add(time.Second)) } // the queue wait spans the deadline
	oracle := newHARefreshOracle9629([]HAGroupStatus{{RGID: 1, Active: true, WatchdogTimestamp: 1}}, 10)
	oracle.leaseUntil[1] = 9 // lapsed
	var sent []HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
			oracle.apply(req.HAState.Groups)
		}
		return nil
	}
	m.mu.Lock() // degraded: m.mu is held
	err := m.UpdateHAWatchdog(1, 100)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("degraded refresh: %v", err)
	}
	if len(sent) != 1 || sent[0].Active {
		t.Fatalf("queued degraded send %+v: RG1 still Active after the queue outlasted its deadline", sent)
	}
	if oracle.forwardingActive(1) {
		t.Fatal("the queued refresh resurrected the lapsed helper lease")
	}
}

// codex-e P3: the merge's EXISTING-entry arm. A live degraded heartbeat
// populates the merged state with RG1 active; the deadline passes with the
// snapshot NOT rebuilt (m.mu still held); the next heartbeat must send RG1
// inactive.
func TestDegradedMergeExpiresAnExistingEntry19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, time.Minute)
	clk := &clock19103{now: until.Add(-time.Second)}
	m.preActivateNowFn = clk.get
	var sends [][]HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sends = append(sends, append([]HAGroupStatus(nil), req.HAState.Groups...))
		}
		return nil
	}
	m.mu.Lock()
	err1 := m.UpdateHAWatchdog(1, 100)
	clk.set(until.Add(time.Second))
	// Inside the 3 s IPC backstop: only the merge seeing the expiry (an
	// active-state change) makes this send due.
	err2 := m.UpdateHAWatchdog(1, 101)
	m.mu.Unlock()
	if err1 != nil || err2 != nil {
		t.Fatalf("degraded refreshes: %v, %v", err1, err2)
	}
	if len(sends) != 2 || !sends[0][0].Active {
		t.Fatalf("setup: sends %+v, want a live RG1-active send, then a second send", sends)
	}
	if sends[1][0].Active {
		t.Fatalf("second send %+v: the merged entry kept RG1 active past its deadline", sends[1])
	}
}

// codex-e P3: a different, legitimately active RG triggers the refresh; the
// expired pre-active RG in the same full-set payload is sent inactive.
func TestDegradedRefreshByAnotherRGExpiresThePreActiveOne19103(t *testing.T) {
	m := sessionTestManager9629(t, map[int]HAGroupStatus{
		1: {Active: false, WatchdogTimestamp: 1},
		2: {Active: true, WatchdogTimestamp: 1},
	})
	until := time.Now().Add(time.Minute)
	clk := &clock19103{now: until.Add(-time.Second)}
	m.preActivateNowFn = clk.get
	m.mu.Lock()
	m.helperStatusObserved = true
	m.lastStatus.HaSessionRefreshSupported = true
	m.helperHAStatePublished = true
	m.publishedSnapshot = 1
	m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 1, Active: true, WatchdogTimestamp: 1}, {RGID: 2, Active: true, WatchdogTimestamp: 1}}
	if m.transferPreActive == nil {
		m.transferPreActive = make(map[int]transferPreActivation)
	}
	m.transferPreActive[1] = transferPreActivation{until: until, routesReady: true, readyEpoch: m.helperEpoch}
	m.publishHAWatchdogSnapshotLocked()
	m.mu.Unlock()
	var sends [][]HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sends = append(sends, append([]HAGroupStatus(nil), req.HAState.Groups...))
		}
		return nil
	}
	active := func(gs []HAGroupStatus, rg int) bool {
		for _, g := range gs {
			if g.RGID == rg {
				return g.Active
			}
		}
		return false
	}
	m.mu.Lock()
	err1 := m.UpdateHAWatchdog(2, 100) // RG2's heartbeat, while RG1 is live
	clk.set(until.Add(time.Second))
	err2 := m.UpdateHAWatchdog(2, 101) // RG2 again, inside the backstop; RG1 now expired
	m.mu.Unlock()
	if err1 != nil || err2 != nil {
		t.Fatalf("degraded refreshes: %v, %v", err1, err2)
	}
	if len(sends) != 2 || !active(sends[0], 1) {
		t.Fatalf("setup: sends %+v, want a first send with RG1 active", sends)
	}
	if active(sends[1], 1) || !active(sends[1], 2) {
		t.Fatalf("RG2-triggered send %+v: want RG1 inactive (expired) and RG2 still active", sends[1])
	}
}

// r24 P3-2: the cluster-truth clause in the deadline derivation. RG1's
// cluster truth turned active (promoted) while its pre-activation entry is
// still present: its Active is NOT the overlay's, so it carries no deadline,
// and it stays active in a degraded send after the old deadline.
func TestPromotedRGCarriesNoPreActivationDeadline19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, time.Minute)
	clk := &clock19103{now: until.Add(-time.Second)}
	m.preActivateNowFn = clk.get
	m.mu.Lock()
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: true, WatchdogTimestamp: 1} // the promotion landed
	m.publishHAWatchdogSnapshotLocked()
	snap := m.haWatchdogSnapshot.Load()
	m.mu.Unlock()
	if _, ok := snap.preActiveUntil[1]; ok {
		t.Fatal("a promoted RG got a pre-activation deadline")
	}
	var sent []HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
		}
		return nil
	}
	clk.set(until.Add(time.Second))
	m.mu.Lock()
	err := m.UpdateHAWatchdog(1, 100)
	m.mu.Unlock()
	if err != nil || len(sent) != 1 || !sent[0].Active {
		t.Fatalf("degraded send after the old deadline = %+v (%v): the promoted RG1 must stay active", sent, err)
	}
}

// codex-e P2-1, through the REAL status loop. The only effective-active RG was
// a pre-activation that has expired, and the helper still reports it active.
// While every poll is off-lock, a concurrent non-HA publisher applies a newer
// status, so every poll reply is discarded. The owed expiry must still reach
// the helper.
func TestDiscardedPollsStillServiceAnOwedExpiry19103(t *testing.T) {
	old := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = old })
	m, _ := stalePollManager16653(t)
	m.mu.Lock()
	m.clusterHA = true
	m.haGroups = map[int]HAGroupStatus{0: {RGID: 0}, 1: {RGID: 1}, 2: {RGID: 2}}
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	m.publishedSnapshot = 1
	m.transferPreActive = map[int]transferPreActivation{
		1: {until: time.Now().Add(-time.Second), routesReady: true, readyEpoch: m.helperEpoch},
	}
	m.mu.Unlock()
	helper := func(rg1Active bool) *ProcessStatus {
		st := armedStatus16653()
		st.HAGroups = []HAGroupStatus{{RGID: 0}, {RGID: 1, Active: rg1Active}, {RGID: 2}}
		return st
	}
	var demoted atomic.Bool
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		switch req.Type {
		case "status":
			// A concurrent non-HA publisher applies a newer status while this
			// poll is off-lock, so this poll's reply will be discarded.
			m.mu.Lock()
			_ = m.applyHelperStatusLocked(helper(!demoted.Load()))
			m.mu.Unlock()
		case "update_ha_state":
			if req.HAState != nil {
				for _, g := range req.HAState.Groups {
					if g.RGID == 1 && !g.Active {
						demoted.Store(true)
					}
				}
			}
		}
		if status != nil {
			*status = *helper(!demoted.Load())
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.statusLoop(ctx, false) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(3 * time.Second)
	for !demoted.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !demoted.Load() {
		t.Fatal("with every poll reply discarded, the owed expiry never reached the helper")
	}
}

// codex-e P2-3, the LOCKED watchdog session arm: groups built under m.mu while
// the pre-activation is live, sent off-lock after waiting on sessionMu past
// its deadline. The sender re-checks the deadline the arm passed along.
func TestQueuedLockedRefreshExpiresAfterTheSessionQueue19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, time.Minute)
	clk := &clock19103{now: until.Add(-time.Second)}
	m.preActivateNowFn = clk.get
	m.haWatchdogSessionLockHook = func() { clk.set(until.Add(time.Second)) }
	var sent []HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
		}
		return nil
	}
	if err := m.UpdateHAWatchdog(1, 100); err != nil { // m.mu free: the locked arm
		t.Fatalf("locked session refresh: %v", err)
	}
	if len(sent) != 1 || sent[0].RGID != 1 {
		t.Fatalf("setup: locked-arm send %+v, want one RG1 refresh", sent)
	}
	if sent[0].Active {
		t.Fatalf("locked-arm send %+v: RG1 still Active after the queue outlasted its deadline", sent)
	}
}

// codex-e P3, the FIRST-entry merge arm: the first degraded heartbeat after
// the deadline records RG1 inactive in the merged state, matching what is
// sent. A second heartbeat inside the 3 s IPC backstop then has nothing to
// send. Recording it active while the sender expires the payload would leave
// the merged state disagreeing with the helper, and fire a spurious send.
func TestExpiredFirstEntryIsRecordedInactive19103(t *testing.T) {
	m, until := degradedPreActiveManager19103(t, time.Minute)
	clk := &clock19103{now: until.Add(time.Second)} // already past the deadline
	m.preActivateNowFn = clk.get
	var sends [][]HAGroupStatus
	m.sessionRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.HAState != nil {
			sends = append(sends, append([]HAGroupStatus(nil), req.HAState.Groups...))
		}
		return nil
	}
	m.mu.Lock()
	err1 := m.UpdateHAWatchdog(1, 100)
	err2 := m.UpdateHAWatchdog(1, 101)
	m.mu.Unlock()
	if err1 != nil || err2 != nil {
		t.Fatalf("degraded refreshes: %v, %v", err1, err2)
	}
	if len(sends) != 1 || sends[0][0].Active {
		t.Fatalf("sends %+v: want exactly one send, RG1 inactive (the merged state matches it, so the second heartbeat owes nothing)", sends)
	}
}

// codex-e's fold-1 re-check P2: the CONTROL-socket inventory publishers built
// their groups and then waited on controlReqMu with no deadline. An off-lock
// owner-RG export can hold that queue for seconds, and the helper's control
// handler mints a FRESH lease from an Active. Shape: an owed RG1 expiry plus a
// pre-active RG2 sibling whose deadline passes while the inventory waits in
// the queue. Both control publishers, syncHAStateLocked and UpdateRGActive,
// must send RG2 inactive and RECORD what they sent.
func TestControlQueueReExpiresTheInventory19103(t *testing.T) {
	for _, publisher := range []string{"syncHAState", "UpdateRGActive"} {
		t.Run(publisher, func(t *testing.T) {
			m, _ := newPreActivateManager18559(t)
			until := time.Now().Add(time.Minute)
			clk := &clock19103{now: until.Add(-time.Second)}
			m.preActivateNowFn = clk.get
			m.mu.Lock()
			m.haGroups[2] = HAGroupStatus{RGID: 2} // cluster truth: inactive
			m.cfg.ControlSocket = "control-19103.sock"
			m.controlRequestHook = nil
			m.transferPreActive = map[int]transferPreActivation{
				1: {until: until.Add(-time.Hour), routesReady: true, readyEpoch: m.helperEpoch}, // the owed expiry
				2: {until: until, routesReady: true, readyEpoch: m.helperEpoch},                 // the expiring sibling
			}
			m.mu.Unlock()
			queued := make(chan struct{}, 1)
			m.controlQueueHook = func(req ControlRequest) {
				if req.Type == "update_ha_state" {
					select {
					case queued <- struct{}{}:
					default:
					}
				}
			}
			var sent []HAGroupStatus
			m.controlLockedTransportHook = func(req ControlRequest) (ControlResponse, error) {
				if req.Type == "update_ha_state" && req.HAState != nil {
					sent = append([]HAGroupStatus(nil), req.HAState.Groups...)
				}
				return ControlResponse{OK: true, Status: readyHelperStatus()}, nil
			}
			m.controlReqMu.Lock() // an off-lock export holds the control queue
			done := make(chan error, 1)
			go func() {
				if publisher == "syncHAState" {
					m.mu.Lock()
					err := m.syncHAStateLocked()
					m.mu.Unlock()
					done <- err
					return
				}
				done <- m.UpdateRGActive(0, false)
			}()
			select {
			case <-queued:
			case <-time.After(5 * time.Second):
				m.controlReqMu.Unlock()
				t.Fatal("the publisher never queued an update_ha_state")
			}
			clk.set(until.Add(time.Second)) // RG2's deadline passes in the queue
			m.controlReqMu.Unlock()
			select {
			case err := <-done:
				if err != nil && err.Error() != "userspace_ctrl map not loaded" {
					t.Fatalf("%s: %v", publisher, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the publisher never finished")
			}
			active := func(gs []HAGroupStatus, rg int) (bool, bool) {
				for _, g := range gs {
					if g.RGID == rg {
						return g.Active, true
					}
				}
				return false, false
			}
			if a, ok := active(sent, 2); !ok || a {
				t.Fatalf("sent inventory %+v: RG2 active=%v present=%v, want present and INACTIVE (its deadline passed in the queue)", sent, a, ok)
			}
			m.mu.Lock()
			recorded := append([]HAGroupStatus(nil), m.haWatchdogHelperInventory...)
			m.mu.Unlock()
			if a, ok := active(recorded, 2); !ok || a {
				t.Fatalf("acknowledged inventory %+v: RG2 must be recorded as SENT (inactive), not as built", recorded)
			}
		})
	}
}

// codex-e's fold-1 re-check: re-expiry must be STRUCTURAL. Every production
// update_ha_state inventory either carries its overlay deadlines into the
// control primitive (which re-expires after controlReqMu) or is the empty
// standalone clear. The session-socket sender is the generation-fenced path,
// which re-expires after sessionMu. A census of the package's non-test
// sources fails on any other construction.
func TestEveryHAInventorySendCarriesItsDeadlines19103(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	controlSites := 0
	var bad []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		fn := ""
		for i, line := range lines {
			if strings.HasPrefix(line, "func ") {
				fn = line
			}
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if !strings.Contains(code, `"update_ha_state"`) {
				continue
			}
			at := fmt.Sprintf("%s:%d", f, i+1)
			switch {
			case strings.Contains(fn, "func reexpireHAInventory("):
				continue // the re-expiry itself
			case strings.Contains(fn, "requestHAWatchdogSessionLockedAtPath("):
				if !strings.Contains(string(raw), "groups = expireHAGroups(groups, activeUntil, m.preActivateNow())") {
					bad = append(bad, at+": the session sender lost its post-queue re-expiry")
				}
				continue
			}
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			lit := strings.Join(lines[i:end], "\n")
			if !strings.Contains(lit, "haActiveUntil:") && !strings.Contains(lit, "Groups: []HAGroupStatus{},") {
				bad = append(bad, at+": an HA inventory sent without its overlay deadlines ("+strings.TrimSpace(line)+")")
			}
			controlSites++
		}
	}
	if controlSites < 3 {
		t.Fatalf("census found %d control-socket inventory sites, want the sync, the election publish and the clear (3)", controlSites)
	}
	if len(bad) > 0 {
		t.Fatalf("HA inventory sends that bypass the re-expiry:\n%s", strings.Join(bad, "\n"))
	}
	pc, err := os.ReadFile("process_control.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pc), "reexpireHAInventory(&req, m.preActivateNow())") {
		t.Fatal("the control primitive no longer re-expires the HA inventory after controlReqMu")
	}
}
