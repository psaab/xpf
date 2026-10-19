package cluster

import (
	"testing"
)

// #14951 (D14-04): SessionSync.peerIdentity never advanced after an
// installConn-classified peer restart. The first retirement (installConn
// supersession/epoch) advanced peerIdentity from A to B via the
// installedPeerIdentityLocked scan and preserved B's pre-evidence sibling —
// but B's later BulkStart switch captured that same B value as its
// "retired" identity, so the sibling announcing B was preserved again and
// peerIdentity stayed at B. On B's own reboot, its corpse therefore read as
// proven-newer (staleConnPreserve) instead of the retired process and was
// never evicted.
//
// The cells below drive the exact reported mechanism: two successive
// installConn-classified restarts, the second classified by its BulkStart,
// asserting peerIdentity advances A→B→C and the intermediate process's
// corpse is evicted on the second reboot. Control: a proven-current
// sibling is still preserved.

const epochC14951 = 102

var incC14951 = bootIncarnation{0xc9, 0x36, 0x0c}

// TestPeerIdentityAdvancesAfterInstallConnClassifiedRestart_14951 is the
// RED/GREEN regression for D14-04.
//
// RED pre-fix: after C primes, peerIdentity stays at B (epoch 101) and B's
// fab1 (C's sibling slot predecessor) remains installed as a preserved
// corpse. GREEN post-fix: peerIdentity is C (epoch 102) and fab1 holds
// nothing — the intermediate corpse was evicted.
func TestPeerIdentityAdvancesAfterInstallConnClassifiedRestart_14951(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)

	// First restart A→B, installConn-classified: B installs fab1 with
	// delayed capabilities, the epoch lands, B's fab0 supersedes A's
	// corpse and retires A. B1 is held pending, proves B, and is promoted;
	// B's prime then preserves both proven-B fabrics.
	b1 := e.connect(1, "B's fabric 1", false)
	e.src.epoch = epochB9818
	b0 := e.connect(0, "B's fabric 0")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.prime(b0, incB9818)
	e.s.mu.Lock()
	if e.s.peerIdentity.epoch != epochB9818 {
		got := e.s.peerIdentity.epoch
		e.s.mu.Unlock()
		t.Fatalf("setup: first retirement must advance peerIdentity to B (epoch %d), got %d", epochB9818, got)
	}
	if e.s.conn0 != b0 || e.s.conn1 != b1 {
		e.s.mu.Unlock()
		t.Fatal("setup: B's proven fabrics must both survive B's prime")
	}
	e.s.mu.Unlock()

	// Second restart B→C, BulkStart-classified: C's sibling installs with
	// delayed capabilities, proves C, and C primes on it. peerIdentity
	// must advance B→C and B's corpse on the other fabric must be evicted
	// (not preserved via staleConnPreserve against the stale B identity).
	c1 := e.connect(1, "C's fabric 1", false)
	announce9818(t, e, c1, epochC14951, incC14951)
	e.prime(c1, incC14951)

	e.s.mu.Lock()
	gotEpoch := e.s.peerIdentity.epoch
	gotBoot := e.s.peerIdentity.boot
	c0Held, c1Held := e.s.conn0, e.s.conn1
	e.s.mu.Unlock()
	if gotEpoch != epochC14951 || gotBoot != incC14951 {
		t.Errorf("peerIdentity after the second (BulkStart-classified) restart = epoch %d, want C (epoch %d)", gotEpoch, epochC14951)
	}
	if c1Held != c1 {
		t.Errorf("fabric 1 holds %s, want C's fabric 1", e.names[c1Held])
	}
	if c0Held != nil {
		t.Errorf("fabric 0 holds %s, want nothing: B's corpse must be evicted on C's switch, not preserved via staleConnPreserve against the stale B peerIdentity", e.names[c0Held])
	}
}

// TestPeerIdentitySecondRestartEvictsIntermediateCorpse_14951 exercises the
// preserve-forever consequence: after A→B is fully established (both B
// fabrics proven-current at B's prime), C's sibling proves C and C's prime
// must evict B's corpse — not preserve it because peerIdentity still
// names B.
//
// RED pre-fix: B's fab0 remains installed after C primes (preserved as
// proven-newer against the stale peerIdentity=B).
func TestPeerIdentitySecondRestartEvictsIntermediateCorpse_14951(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	b1 := e.connect(1, "B's fabric 1", false)
	e.src.epoch = epochB9818
	b0 := e.connect(0, "B's fabric 0")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.prime(b0, incB9818)
	e.s.mu.Lock()
	if e.s.conn0 != b0 || e.s.conn1 != b1 {
		e.s.mu.Unlock()
		t.Fatal("setup: B's proven fabrics must both survive B's prime")
	}
	if e.s.peerIdentity.epoch != epochB9818 {
		got := e.s.peerIdentity.epoch
		e.s.mu.Unlock()
		t.Fatalf("setup: peerIdentity epoch = %d, want %d (B)", got, epochB9818)
	}
	e.s.mu.Unlock()

	c1 := e.connect(1, "C's fabric 1", false)
	announce9818(t, e, c1, epochC14951, incC14951)
	e.prime(c1, incC14951)

	e.s.mu.Lock()
	c0After, c1After := e.s.conn0, e.s.conn1
	epoch := e.s.peerIdentity.epoch
	e.s.mu.Unlock()
	if epoch != epochC14951 {
		t.Errorf("peerIdentity epoch = %d, want %d (C) after C's prime", epoch, epochC14951)
	}
	if c1After != c1 {
		t.Errorf("fabric 1 holds %s, want C's fabric 1", e.names[c1After])
	}
	if c0After != nil {
		t.Errorf("fabric 0 holds %s, want nothing: B's corpse must be evicted on C's switch, not preserved against the stale B peerIdentity", e.names[c0After])
	}
}

// TestPeerIdentityCurrentSiblingStillPreserved_14951 is the adjacent
// control: a sibling that proves the CURRENT (new) process identity is
// still preserved (re-stamped) by a BulkStart switch, exactly as #9818
// requires. GREEN before and after the fix.
func TestPeerIdentityCurrentSiblingStillPreserved_14951(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	b1 := e.connect(1, "B's fabric 1", false)
	e.src.epoch = epochB9818
	b0 := e.connect(0, "B's fabric 0")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.prime(b0, incB9818)
	e.s.mu.Lock()
	c0, c1 := e.s.conn0, e.s.conn1
	epoch := e.s.peerIdentity.epoch
	e.s.mu.Unlock()
	if c0 != b0 || c1 != b1 {
		t.Errorf("control: B's proven-current fabrics must survive B's prime, got fab0=%s fab1=%s", e.names[c0], e.names[c1])
	}
	if epoch != epochB9818 {
		t.Errorf("control: peerIdentity epoch = %d, want %d (B)", epoch, epochB9818)
	}
}
