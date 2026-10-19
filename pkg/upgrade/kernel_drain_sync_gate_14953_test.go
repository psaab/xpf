package upgrade

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// #14953 (D18-02): DrainAndConfirm never consulted SyncEstablished before
// ForceSecondary. The rolling paths (runRollingWith / runRollingRollbackWith)
// both gate demotion on SyncEstablished; the kernel-drain path gated only on
// PeerAlive, HAProtocolCompatible, SessionSyncWireCompatible (wire VERSION,
// not link state) and PeerTakeoverReady. A peer that is alive and
// wire-compatible but whose session-sync link is DOWN (or "unsynced") would
// be handed every RG by ForceSecondary: the drain-complete predicate does
// include sync, so the demotion then times out and fails back — but the node
// was already demoted into an unsynced peer, churning/blackholing stateful
// sessions for the drain window instead of refusing before any demotion.
//
// The fix mirrors the rolling parity gate: consult SyncEstablished before
// ForceSecondary and refuse (without demoting) when it is not established or
// the check errors. NOT gated behind allowMixedHA: that flag relaxes only
// the exact-equality HA check, and the rolling paths apply their sync gate
// unconditionally.
//
// RED-on-revert: removing the SyncEstablished call site from DrainAndConfirm
// leaves every cell below green except the refusals (they proceed to
// ForceSecondary), and the healthy cell's sync-consulted counter.

// Unsynced peer: alive, compatible, wire-compatible and takeover-ready —
// SyncEstablished is the ONLY unhealthy input, so a refusal here can only
// come from the new gate.
func TestDrainRefusesUnsyncedPeer14953(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, synced: false, compatible: true, peerReady: true,
		drainAfter: 1,
	}
	err := DrainAndConfirm(cl, time.Second, false)
	if err == nil {
		t.Fatal("DrainAndConfirm demoted into an unsynced peer — draining now " +
			"would hand the RGs to a node that has not received this node's " +
			"sessions, blackholing every established stateful flow")
	}
	if !strings.Contains(err.Error(), "session sync not established") {
		t.Fatalf("err = %v; want the session-sync refusal, not some other precheck", err)
	}
	if cl.forced {
		t.Error("the node was force-demoted before the sync gate refused")
	}
}

// A transport failure reading sync state must fail closed: an unreadable
// sync link is not evidence that sync is established.
func TestDrainFailsWhenSyncCheckErrors14953(t *testing.T) {
	t.Parallel()
	cause := errors.New("show chassis cluster information: connection refused")
	cl := &fakeCluster{
		peerAlive: true, synced: true, compatible: true, peerReady: true,
		drainAfter: 1, syncErr: cause,
	}
	err := DrainAndConfirm(cl, time.Second, false)
	if err == nil {
		t.Fatal("DrainAndConfirm proceeded when SyncEstablished errored")
	}
	if !strings.Contains(err.Error(), "session-sync check") ||
		!strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("err = %v; want the sync check's transport error surfaced", err)
	}
	if cl.forced {
		t.Error("the node was force-demoted despite the sync check erroring")
	}
}

// allowMixedHA relaxes only the exact-equality HA check; it must NOT bypass
// the sync-established gate (mirrors the session-sync wire gate discipline).
func TestAllowMixedHADoesNotBypassSyncGate14953(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, synced: false, compatible: false, peerReady: true,
		drainAfter: 1,
	}
	err := DrainAndConfirm(cl, time.Second, true) // allowMixedHA = true
	if err == nil {
		t.Fatal("allowMixedHA bypassed the SyncEstablished gate")
	}
	if !strings.Contains(err.Error(), "session sync not established") {
		t.Fatalf("err = %v; want the session-sync refusal (allowMixedHA correctly "+
			"skipped the HA check, so this must be what refused)", err)
	}
	if cl.forced {
		t.Error("the node was force-demoted before the sync gate refused")
	}
}

// Paired healthy cell: synced peer proceeds AND the gate was consulted, so
// a fix that refused unconditionally — or a revert that dropped the call
// site — is caught.
func TestDrainProceedsOnSyncedPeer14953(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, synced: true, compatible: true, peerReady: true,
		drainAfter: 1,
	}
	before := cl.syncPolls
	if err := DrainAndConfirm(cl, 5*time.Second, false); err != nil {
		t.Fatalf("DrainAndConfirm refused a synced peer: %v", err)
	}
	if !cl.forced {
		t.Fatal("expected ForceSecondary on a synced peer")
	}
	if cl.syncPolls <= before {
		t.Error("DrainAndConfirm never consulted SyncEstablished — the gate is " +
			"not wired, and every assertion about it is vacuous")
	}
}
