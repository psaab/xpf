package userspace

import (
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
	}{
		{"expired, helper still active, cluster inactive", &transferPreActivation{until: now.Add(-time.Second), routesReady: true}, false, true, true},
		{"live pre-activation", &transferPreActivation{until: now.Add(time.Minute), routesReady: true}, false, true, false},
		{"helper already inactive", &transferPreActivation{until: now.Add(-time.Second), routesReady: true}, false, false, false},
		{"cluster truth active", &transferPreActivation{until: now.Add(-time.Second), routesReady: true}, true, true, false},
		{"no pre-activation entry", nil, false, true, false},
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
				m.transferPreActive[1] = e
			}
			helper := []HAGroupStatus{{RGID: 1, Active: tc.helperActive}}
			if got := m.preActivationExpiryOwedLocked(helper, now); got != tc.want {
				t.Fatalf("owed = %v, want %v", got, tc.want)
			}
		})
	}
}
