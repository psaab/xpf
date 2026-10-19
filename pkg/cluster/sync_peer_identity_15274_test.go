package cluster

import (
	"net"
	"testing"
)

// #15274 C03-02: classifyPrimeLocked records the peer process identity
// only on the first incarnated prime (!priorKnown) and handleDisconnect
// never clears it. When a restarted process's heartbeat epoch lands
// before its first install, the #9818 retirement predicate later runs
// against the wrong retired identity.
//
// Scenario (restart-hb-first): A primes (first incarnated prime, so
// peerIdentity=A). A fully disconnects. Process B restarts: its heartbeat
// epoch (101) lands BEFORE any B fabric installs. B's fab1 then installs
// into the empty slot — epochReboot retires nothing visible (registry was
// empty) — and B announces token 222.
// B primes on fab1 with an UNCHANGED boot id (daemon-restart flavour).
//
// The prime is not a boot-id switch, so classifyPrimeLocked takes the
// !switched arm. Post-fix it must adopt the priming connection's proven
// identity (token 222) as the authoritative peerIdentity, and a full
// disconnect must clear peerIdentity so a later restart never inherits it.
//
// Pre-fix: peerIdentity stays A, so a later B→C retirement captures A as
// the retired identity: B's corpse (announcing B) does not sameProcess(A)
// and is preserved/re-stamped as current, while C's live fabric is at
// risk of eviction as the "stale" slot.

const epochB15274 = 101

var incB15274 = incB9636

// TestRestartHeartbeatFirstPrimeAdoptsPrimingIdentity_15274 is the
// RED/GREEN cell for C03-02, following the issue's fix direction and
// acceptance: the restart-hb-first cell reports token 222, advances=1,
// corpse evicted, live fab1 kept.
func TestRestartHeartbeatFirstPrimeAdoptsPrimingIdentity_15274(t *testing.T) {
	e := newRebootEnv9636(t)

	// A established and primed: first incarnated prime records A.
	a := primedAnnouncedA9818(t, e, true)
	// Full disconnect: post-fix this also clears peerIdentity.
	e.s.handleDisconnect(a)

	// B restarts. Its heartbeat epoch lands before its first install.
	e.src.epoch = epochB15274

	// B's fab1 installs (empty registry) and announces B (token for B).
	b1 := e.connect(1, "B's fabric 1", false)
	announceWithToken15274(t, e, b1, epochB15274, incB15274, 222)

	// B primes on fab1 with the SAME boot id A used (daemon restart keeps
	// the boot id; only the epoch/token distinguish the process). This is
	// the !switched prime that must still adopt B's proven identity.
	e.prime(b1, incA9818)

	e.s.mu.Lock()
	gotToken := e.s.peerIdentity.token
	gotEpoch := e.s.peerIdentity.epoch
	e.s.mu.Unlock()
	if gotToken != 222 {
		t.Fatalf("peerIdentity token = %d, want 222 (the priming connection's proven identity); "+
			"classifyPrimeLocked must record the priming identity on every accepted prime with a known identity, not only the first incarnated prime", gotToken)
	}
	if gotEpoch != epochB15274 {
		t.Fatalf("peerIdentity epoch = %d, want %d (B)", gotEpoch, epochB15274)
	}

	// C restarts (new boot id) and primes on fab0 while B's fab1 corpse
	// remains installed: B's corpse must be evicted and C's fab0 kept.
	e.src.epoch = 102
	c0 := e.connect(0, "C's fabric 0", false)
	announceWithToken15274(t, e, c0, 102, incC15274(), 333)
	e.prime(c0, incC15274())

	e.check(rebootWant9636{advances: 2, conn0: c0, conn1: nil, owed: true, arms: 2, dispatches: 2})

	e.s.mu.Lock()
	cTok := e.s.peerIdentity.token
	e.s.mu.Unlock()
	if cTok != 333 {
		t.Errorf("peerIdentity token after C's prime = %d, want 333", cTok)
	}
}

// TestFullDisconnectClearsPeerIdentity_15274 pins the second half of the
// C03-02 fix direction: peerIdentity is incarnation-scoped state, cleared
// on full disconnect beside the other incarnation-scoped clears, and NOT
// cleared on a partial disconnect (same peer process).
func TestFullDisconnectClearsPeerIdentity_15274(t *testing.T) {
	e := newRebootEnv9636(t)
	a0 := primedAnnouncedA9818(t, e, true)
	a1 := e.connect(1, "A's fabric 1")
	announce9818(t, e, a1, epochA9818, incA9818)

	e.s.mu.Lock()
	if !e.s.peerIdentity.known() {
		e.s.mu.Unlock()
		t.Fatal("setup: peerIdentity must be recorded after A's prime")
	}
	e.s.mu.Unlock()

	// Partial disconnect: same process, identity must survive.
	e.s.handleDisconnect(a0)
	e.s.mu.Lock()
	knownAfterPartial := e.s.peerIdentity.known()
	e.s.mu.Unlock()
	if !knownAfterPartial {
		t.Fatal("partial disconnect cleared peerIdentity; the surviving fabric is the same peer process")
	}

	// Full disconnect: identity must be cleared.
	e.s.handleDisconnect(a1)
	e.s.mu.Lock()
	knownAfterFull := e.s.peerIdentity.known()
	e.s.mu.Unlock()
	if knownAfterFull {
		t.Fatal("full disconnect left peerIdentity latched; a restarted process would be retired against the previous process's identity")
	}
}

func incC15274() bootIncarnation { return bootIncarnation{0xd9, 0x36, 0x0d} }

func announceWithToken15274(t *testing.T, e *rebootEnv9636, conn net.Conn, epoch uint64, inc bootIncarnation, token uint64) {
	t.Helper()
	e.s.handleMessage(conn, syncMsgPeerCapabilities, capabilitiesFrameWithToken9818(t, epoch, &inc, token))
}
