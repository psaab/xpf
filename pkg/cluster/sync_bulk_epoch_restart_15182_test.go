package cluster

import (
	"testing"
)

// #15182 (C03-01): the between-bulks stale-BulkStart guard compared a
// per-daemon-process epoch counter against a high-water that is reset only
// on full disconnect, while the only discriminator it consults (`switched`)
// changes only on OS boot.
//
// The sender half (bulkSendNext in sync_bulk.go) started at zero in every
// daemon process: initGenState seeded genCounter, configGenCounter and
// syncEpoch from MonotonicNanos but never bulkSendNext. A daemon-only
// restart therefore re-emitted epoch 1 while a surviving peer held
// bulkRecvEpoch at a high-water from the dead process. Because the boot
// incarnation is unchanged across a daemon restart, `switched` is false,
// so bulkStartStaleLocked's between-bulks arm
// (`bulkRecvEpoch != 0 && inc.known()`) refused the restarted peer's
// authoritative re-prime: its pre-existing sessions were never
// bulk-transferred (the incremental sweep cannot see sessions older than
// its start) and no BulkEnd reconcile ran.
//
// The fix seeds bulkSendNext from the same MonotonicNanos base in
// initGenState, so the first epoch a restarted process emits within a boot
// is strictly newer than any epoch its predecessor emitted.

// THE DEFECT, sender half bound at the construction site. A SessionSync
// built through the production constructor must draw a first bulk epoch
// strictly newer than a prior process's high-water within the same boot,
// not epoch 1.
func TestBulkSendEpochSeededOnConstruction15182(t *testing.T) {
	sender := &SessionSync{}
	sender.initGenState()

	// A prior process in the same boot plausibly emitted several bulks;
	// any realistic high-water is far below the monotonic seed.
	const priorHighWater = uint64(7)
	if got := sender.bulkSendNext.Load(); got <= priorHighWater {
		t.Fatalf("#15182: bulkSendNext after initGenState = %d, want > %d (the monotonic seed).\n"+
			"  bulkSendNext was the one within-boot counter initGenState left at zero, "+
			"so a restarted daemon re-emits epoch 1 and a surviving peer's between-bulks "+
			"guard refuses its authoritative re-prime", got, priorHighWater)
	}
	first := sender.bulkSendNext.Add(1)
	if first <= priorHighWater {
		t.Fatalf("#15182: first bulk epoch drawn after initGenState = %d, want > %d", first, priorHighWater)
	}
	second := sender.bulkSendNext.Add(1)
	if second <= first {
		t.Fatalf("#15182: bulk epochs must remain strictly increasing, got %d then %d", first, second)
	}
}

// THE DEFECT, end to end through the receiver guard. The receiver has
// completed a bulk at epoch 7 from boot A and sits BETWEEN bulks
// (bulkInProgress false, bulkRecvEpoch 7 standing). A restarted peer
// process — same boot incarnation incA, because a daemon restart does not
// change the OS boot id — sends its first bulk. On unfixed master that
// first epoch is 1, so the start is refused; after the fix the sender's
// first epoch is the monotonic seed, strictly newer than 7, and the
// re-prime is accepted.
//
// The sender's epoch is drawn from a real production-constructed
// SessionSync's counter (the sync_bulk.go draw), not hand-picked, so
// reverting the initGenState seed turns this cell red.
func TestRestartedPeerFirstBulkAcceptedBetweenBulks15182(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)

	sender := &SessionSync{}
	sender.initGenState()
	restartedEpoch := sender.bulkSendNext.Add(1) // sync_bulk.go's draw

	e.prime(1, restartedEpoch, &incA) // same boot id: daemon-only restart

	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != restartedEpoch {
		t.Fatalf("#15182: a restarted peer's first BulkStart (epoch %d, same boot "+
			"incarnation) was refused between bulks (inProgress=%v epoch=%d, want true/%d).\n"+
			"  Its bulkSendNext restarted at 1 while the receiver's bulkRecvEpoch "+
			"high-water (7) survives until full disconnect, and `switched` cannot "+
			"fire because the boot id does not change on a daemon restart — so the "+
			"restarted node's pre-existing sessions are never bulk-transferred",
			restartedEpoch, e.s.bulkInProgress, e.s.bulkRecvEpoch, restartedEpoch)
	}
}

// LOAD-BEARING CONTROL, #9174 V015. A genuinely stale start from the SAME
// process incarnation between bulks must still be refused: seeding the
// sender must not weaken the receiver guard.
func TestStaleBulkStartBetweenBulksStillRefused15182(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)

	e.prime(1, 5, &incA)

	if e.s.bulkInProgress {
		t.Errorf("#15182 control: a stale BulkStart (epoch 5) between bulks must " +
			"still be refused (#9174 V015); the sender seed must not weaken the guard")
	}
	if got := e.s.bulkRecvEpoch; got != 7 {
		t.Errorf("#15182 control: the stale BulkStart clobbered the epoch high-water: got %d, want 7", got)
	}
}

// LOAD-BEARING CONTROL, #8966 within a bulk. A not-newer start while a bulk
// is in progress must still be refused.
func TestStaleBulkStartWithinBulkStillRefused15182(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.prime(0, 7, &incA)
	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 7 {
		t.Fatalf("CONTROL FAILED: first BulkStart did not take (inProgress=%v epoch=%d)",
			e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}

	e.prime(1, 5, &incA)

	if got := e.s.bulkRecvEpoch; got != 7 {
		t.Errorf("#15182 control: a stale BulkStart (epoch 5) within a bulk clobbered "+
			"the in-progress epoch: got %d, want 7 (#8966)", got)
	}
}

// LOAD-BEARING CONTROL, #2198 F2. A rebooted peer (changed boot id)
// legitimately restarts its epoch counter lower; across the incarnation
// switch the lower epoch must still be accepted between bulks. Seeding
// within a boot must not break the cross-boot path, which is admitted via
// `switched`, not via the epoch comparison.
func TestRebootedPeerLowerEpochBetweenBulksStillAccepted15182(t *testing.T) {
	e, _ := newBulkEnv(t)
	e.completeOneBulk(t, 0, 7, &incA)

	e.prime(1, 1, &incB) // epoch 1: the cross-boot restarted counter

	if !e.s.bulkInProgress || e.s.bulkRecvEpoch != 1 {
		t.Fatalf("#15182 control: a REBOOTED peer's epoch-1 BulkStart must still be "+
			"accepted between bulks (inProgress=%v epoch=%d, want true/1) (#2198 F2). "+
			"Refusing it strands the standby with no re-prime",
			e.s.bulkInProgress, e.s.bulkRecvEpoch)
	}
}
