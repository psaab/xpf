package cluster

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9715: every installed fabric connection runs its own receiveLoop. While the sync stream moves
// between fabrics, the old loop can still be applying frames it already read while the new loop
// applies newer frames for the same key. These cells drive that interleaving through the REAL apply
// functions:
//   - loop A parks inside its dataplane write or delete (the mock's onSet*/onDelete* hook);
//   - loop B applies the same key on another goroutine.
//
// Each cell gives loop B a bounded time to finish before releasing loop A.
//   - Without applyMu, B finishes while A is parked. That is the interleaving under test.
//   - With applyMu, B blocks on the lock, the wait times out, and releasing A lets B run after A.
//
// The final state is asserted either way, so neither ordering depends on the scheduler. B cannot
// finish early on the fixed code, and on the old code it has already finished when A resumes.
//
// FAIL-ON-REVERT: remove the applyMu acquisition from the function a cell drives, and that cell
// goes RED.

// park9715 parks the FIRST caller of hook until release is closed.
type park9715 struct {
	fired   atomic.Bool
	parked  chan struct{}
	release chan struct{}
}

func newPark9715() *park9715 {
	return &park9715{parked: make(chan struct{}), release: make(chan struct{})}
}

func (p *park9715) hook() {
	if p.fired.CompareAndSwap(false, true) {
		close(p.parked)
		<-p.release
	}
}

// interleave9715 runs a until it parks, then runs b on another goroutine, gives b a bounded time to
// finish, releases a, and waits for both.
func interleave9715(t *testing.T, p *park9715, a, b func()) {
	t.Helper()
	aDone, bDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(aDone); a() }()
	select {
	case <-p.parked:
	case <-time.After(5 * time.Second):
		t.Fatal("FIXTURE: loop A never reached the dataplane hook, so nothing was interleaved")
	}
	go func() { defer close(bDone); b() }()
	// Unserialized, b finishes in microseconds. The wait is long so that load (a mutation matrix, a
	// parallel make test) cannot make b miss it: A would then resume first, the old code would
	// serialize by accident, and the cell would pass on the defect. On the fixed code the full wait
	// is always paid, because b is blocked until A is released.
	select {
	case <-bDone:
	case <-time.After(time.Second):
	}
	close(p.release)
	for _, done := range []chan struct{}{aDone, bDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("an apply did not finish after loop A was released: applyMu deadlock")
		}
	}
}

// installMarkedV4_9715 installs key at generation gen, and marks the content with the same number in
// PolicyID, so the row itself says which install wrote it.
func installMarkedV4_9715(ss *SessionSync, key dataplane.SessionKey, gen uint64) {
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, PolicyID: uint32(gen)}
	val.Generation = gen
	ss.installClusterSyncedV4(key, val)
}

func installMarkedV6_9715(ss *SessionSync, key dataplane.SessionKeyV6, gen uint64) {
	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, PolicyID: uint32(gen)}
	val.Generation = gen
	ss.installClusterSyncedV6(key, val)
}

func storedGenV4_9715(ss *SessionSync, key dataplane.SessionKey) uint64 {
	ss.recvGenMu.Lock()
	defer ss.recvGenMu.Unlock()
	return ss.recvGenV4[key]
}

func storedGenV6_9715(ss *SessionSync, key dataplane.SessionKeyV6) uint64 {
	ss.recvGenMu.Lock()
	defer ss.recvGenMu.Unlock()
	return ss.recvGenV6[key]
}

// The serialized control: the operations of the install cell, applied one after another. This is
// the state every interleaving must converge to.
func TestSerializedApplyKeepsTheNewerInstall_9715(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	key := gen2170KeyV4()

	installMarkedV4_9715(ss, key, 10)
	installMarkedV4_9715(ss, key, 20)
	ss.deleteClusterSyncedV4(key, 15)

	got, ok := dp.v4sessions[key]
	if !ok || got.PolicyID != 20 {
		t.Fatalf("FIXTURE: serialized, the generation-20 install must survive the generation-15 delete "+
			"with its own content; present=%v content generation=%d", ok, got.PolicyID)
	}
	if g := storedGenV4_9715(ss, key); g != 20 {
		t.Fatalf("FIXTURE: serialized, the stored generation must be 20, got %d", g)
	}
}

func TestOlderInstallParkedInItsWriteCannotRegressANewerOneV4_9715(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	key := gen2170KeyV4()
	p := newPark9715()
	dp.onSetV4 = p.hook

	interleave9715(t, p,
		func() { installMarkedV4_9715(ss, key, 10) },
		func() { installMarkedV4_9715(ss, key, 20) })
	ss.deleteClusterSyncedV4(key, 15)

	if g := storedGenV4_9715(ss, key); g != 20 {
		t.Errorf("stored generation = %d, want 20: the older install recorded its generation over the "+
			"newer one once its parked write finished (#9715)", g)
	}
	got, ok := dp.v4sessions[key]
	if !ok {
		t.Fatal("the generation-20 session is gone: after the regression the generation-15 delete was " +
			"admitted and removed it (#9715)")
	}
	if got.PolicyID != 20 {
		t.Errorf("content is from generation %d, want 20: the older install's parked write landed over "+
			"the newer content (#9715)", got.PolicyID)
	}
}

func TestOlderInstallParkedInItsWriteCannotRegressANewerOneV6_9715(t *testing.T) {
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	key := gen2170KeyV6()
	p := newPark9715()
	dp.onSetV6 = p.hook

	interleave9715(t, p,
		func() { installMarkedV6_9715(ss, key, 10) },
		func() { installMarkedV6_9715(ss, key, 20) })
	ss.deleteClusterSyncedV6(key, 15)

	if g := storedGenV6_9715(ss, key); g != 20 {
		t.Errorf("v6: stored generation = %d, want 20 (#9715)", g)
	}
	got, ok := dp.v6sessions[key]
	if !ok {
		t.Fatal("v6: the generation-20 session is gone: the generation-15 delete was admitted after the regression (#9715)")
	}
	if got.PolicyID != 20 {
		t.Errorf("v6: content is from generation %d, want 20 (#9715)", got.PolicyID)
	}
}

func TestDeleteParkedInItsWriteCannotRemoveANewerInstallV4_9715(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	key := gen2170KeyV4()
	installMarkedV4_9715(ss, key, 10)
	p := newPark9715()
	dp.onDeleteV4 = func(k dataplane.SessionKey) {
		if k == key {
			p.hook()
		}
	}

	interleave9715(t, p,
		func() { ss.deleteClusterSyncedV4(key, 12) },
		func() { installMarkedV4_9715(ss, key, 30) })

	got, ok := dp.v4sessions[key]
	if !ok {
		t.Fatal("the generation-30 install is gone: the generation-12 delete passed its guard first, " +
			"parked in its dataplane delete, and removed the newer session afterwards (#9715)")
	}
	if got.PolicyID != 30 {
		t.Errorf("content is from generation %d, want 30 (#9715)", got.PolicyID)
	}
	if g := storedGenV4_9715(ss, key); g != 30 {
		t.Errorf("stored generation = %d, want 30 (#9715)", g)
	}
}

func TestDeleteParkedInItsWriteCannotRemoveANewerInstallV6_9715(t *testing.T) {
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	key := gen2170KeyV6()
	installMarkedV6_9715(ss, key, 10)
	p := newPark9715()
	dp.onDeleteV6 = func(k dataplane.SessionKeyV6) {
		if k == key {
			p.hook()
		}
	}

	interleave9715(t, p,
		func() { ss.deleteClusterSyncedV6(key, 12) },
		func() { installMarkedV6_9715(ss, key, 30) })

	got, ok := dp.v6sessions[key]
	if !ok {
		t.Fatal("v6: the generation-30 install is gone: the parked generation-12 delete removed it afterwards (#9715)")
	}
	if got.PolicyID != 30 {
		t.Errorf("v6: content is from generation %d, want 30 (#9715)", got.PolicyID)
	}
	if g := storedGenV6_9715(ss, key); g != 30 {
		t.Errorf("v6: stored generation = %d, want 30 (#9715)", g)
	}
}

// An install from the peer's PREVIOUS boot (a high generation) is parked in its write when the
// rebooted peer's accepted BulkStart resets the generation maps on the other loop. The rebooted
// peer's counter restarted lower, so its re-prime install must then be admitted.
func TestBulkStartResetIsNotUndoneByAnInstallParkedAcrossIt_9715(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	key := gen2170KeyV4()
	p := newPark9715()
	dp.onSetV4 = p.hook

	interleave9715(t, p,
		func() { installMarkedV4_9715(ss, key, 900) },
		func() { ss.resetRecvGen() })
	installMarkedV4_9715(ss, key, 5)

	got, ok := dp.v4sessions[key]
	if !ok || got.PolicyID != 5 {
		t.Fatalf("the rebooted peer's generation-5 re-prime was refused (present=%v, content generation "+
			"%d): the install parked across the BulkStart reset recorded its pre-reboot generation 900 "+
			"after the reset, the stale-RETAIN #2198 F2 exists to prevent (#9715)", ok, got.PolicyID)
	}
}
