package cluster

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #18636: the RG0 authority refused every reverse-tagged install from a fully
// converged peer. The authority's 30 s config-sync reconcile tick reserves a
// wire generation (ReserveConfigGen) BEFORE it finds the config "already
// pushed for epoch/generation" and no-ops, so configGenCounter runs one draw
// per tick past the newest generation the peer was ever sent, and the stale
// check compared the peer's applied generation against that counter. The
// authority now compares against the newest generation actually WRITTEN to the
// current peer incarnation, and keeps the reservation-counter comparison
// (fail-closed) until its first write to that incarnation.

func newConvergedPeer18636(t *testing.T, applied uint64) *SessionSync {
	t.Helper()
	peer := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	peer.IsPrimaryFn = func() bool { return false }
	setConfigEpochPeerTagCapability11055(peer, true)
	peer.recordRecvConfigGen(applied)
	peer.recordAppliedConfigGen(applied)
	return peer
}

func newAuthority18636(t *testing.T, counter uint64) (*SessionSync, *mockSweepDP) {
	t.Helper()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	authority := NewSessionSync(":0", "10.0.0.2:4785", dp)
	authority.IsPrimaryFn = func() bool { return true }
	setConfigEpochPeerTagCapability11055(authority, true)
	authority.configGenCounter.Store(counter)
	return authority, dp
}

func stampedV4FromPeer18636(t *testing.T, peer *SessionSync, port uint16, wantEpoch uint64) (dataplane.SessionKey, dataplane.SessionValue) {
	t.Helper()
	key := configEpochKeyV4(port)
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	peer.stampInstallGenV4(key, &val)
	if val.ConfigEpoch != configEpochReverseTag|wantEpoch {
		t.Fatalf("peer stamp = %#x, want tagged generation %#x", val.ConfigEpoch, configEpochReverseTag|wantEpoch)
	}
	return key, val
}

// THE DEFECT: the peer applied the newest generation the authority sent, and
// two no-op reconcile ticks have since reserved two more. Both families must be
// accepted.
func TestAuthorityAcceptsPeerOnNewestSentGenAfterReservedNoop18636(t *testing.T) {
	const sentGen = uint64(4988897125605)
	peer := newConvergedPeer18636(t, sentGen)
	authority, dp := newAuthority18636(t, sentGen-1)
	gen := authority.ReserveConfigGen() // the push that was actually written
	if gen != sentGen {
		t.Fatalf("reserved %d, want %d", gen, sentGen)
	}
	authority.recordLastSentConfigGen(gen)
	// Two reconcile ticks that found the config already pushed.
	authority.ReserveConfigGen()
	authority.ReserveConfigGen()

	key, val := stampedV4FromPeer18636(t, peer, 61836, sentGen)
	if !authority.installClusterSyncedV4(key, val) {
		t.Fatalf("authority refused a v4 session stamped with the newest config generation it ever sent (counter %d, sent %d): SessionsStaleConfigIgnored=%d",
			authority.configGenCounter.Load(), sentGen, authority.stats.SessionsStaleConfigIgnored.Load())
	}
	key6 := configEpochKeyV6(61837)
	val6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	peer.stampInstallGenV6(key6, &val6)
	if !authority.installClusterSyncedV6(key6, val6) {
		t.Fatal("authority refused a v6 session stamped with the newest config generation it ever sent")
	}
	if len(dp.v4sessions) != 1 || len(dp.v6sessions) != 1 {
		t.Fatalf("installed v4=%d v6=%d, want 1 and 1", len(dp.v4sessions), len(dp.v6sessions))
	}
	if got := authority.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0", got)
	}
}

// The protection is kept: once a NEWER config is actually written, a peer
// still on the previous generation is refused until it applies the new one.
func TestAuthorityRefusesPeerBehindNewestSentGen18636(t *testing.T) {
	const oldGen, newGen = uint64(1000), uint64(1001)
	peer := newConvergedPeer18636(t, oldGen)
	authority, _ := newAuthority18636(t, oldGen-1)
	authority.recordLastSentConfigGen(authority.ReserveConfigGen()) // oldGen
	authority.recordLastSentConfigGen(authority.ReserveConfigGen()) // newGen, a commit
	key, val := stampedV4FromPeer18636(t, peer, 61838, oldGen)
	if authority.installClusterSyncedV4(key, val) {
		t.Fatal("authority admitted a session stamped under the config generation it superseded by a write")
	}
	peer.recordRecvConfigGen(newGen)
	peer.recordAppliedConfigGen(newGen)
	key, val = stampedV4FromPeer18636(t, peer, 61839, newGen)
	if !authority.installClusterSyncedV4(key, val) {
		t.Fatal("authority refused a session stamped with the generation it just wrote")
	}
}

// Before this process has written any config to the peer, a tagged peer
// generation reflects the peer's view of an EARLIER authority process (an
// older boot, or a config edited while this node was down). That keeps the
// original reservation-counter comparison and is refused (fail-closed).
func TestAuthorityRefusesTaggedInstallBeforeFirstSend18636(t *testing.T) {
	const previousProcessGen = uint64(500)
	peer := newConvergedPeer18636(t, previousProcessGen)
	authority, dp := newAuthority18636(t, 900) // a later process's seed
	key, val := stampedV4FromPeer18636(t, peer, 61840, previousProcessGen)
	if authority.installClusterSyncedV4(key, val) {
		t.Fatal("authority admitted a tagged install before its first config write: it must stay fail-closed")
	}
	if len(dp.v4sessions) != 0 || authority.stats.SessionsStaleConfigIgnored.Load() != 1 {
		t.Fatalf("installed=%d stale=%d, want 0 and 1", len(dp.v4sessions), authority.stats.SessionsStaleConfigIgnored.Load())
	}
}

// A new peer incarnation must not be compared against a generation written to
// its predecessor: retirement installs a fresh incarnation state, so the
// threshold falls back to the reservation counter until the first write to the
// new incarnation, and that write re-opens it.
func TestAuthorityThresholdIsScopedToPeerIncarnation18636(t *testing.T) {
	const sentGen = uint64(7000)
	authority, _ := newAuthority18636(t, sentGen-1)
	authority.recordLastSentConfigGen(authority.ReserveConfigGen()) // sentGen, to incarnation A
	authority.ReserveConfigGen()                                    // a no-op reconcile tick
	if got := authority.authorityConfigEpochThreshold(); got != sentGen {
		t.Fatalf("threshold = %d, want the generation written to incarnation A (%d)", got, sentGen)
	}

	authority.mu.Lock()
	authority.retirePeerIncarnationLocked(nil) // incarnation B replaces A
	authority.mu.Unlock()
	setConfigEpochPeerTagCapability11055(authority, true) // B advertises the tag
	if got, want := authority.authorityConfigEpochThreshold(), authority.configGenCounter.Load(); got != want {
		t.Fatalf("threshold after retirement = %d, want the reservation counter %d (nothing written to the new incarnation)", got, want)
	}
	peerB := newConvergedPeer18636(t, sentGen) // a view of the generation sent to A
	key, val := stampedV4FromPeer18636(t, peerB, 61841, sentGen)
	if authority.installClusterSyncedV4(key, val) {
		t.Fatal("authority compared a new peer incarnation against a generation written to its predecessor")
	}

	pushed := authority.ReserveConfigGen() // the reconnect push to B
	authority.recordLastSentConfigGen(pushed)
	peerB.recordRecvConfigGen(pushed)
	peerB.recordAppliedConfigGen(pushed)
	key, val = stampedV4FromPeer18636(t, peerB, 61842, pushed)
	if !authority.installClusterSyncedV4(key, val) {
		t.Fatal("authority refused the new incarnation after writing it a config it applied")
	}
}

// The sent mark is a high-water: a slower fabric connection recording an older
// generation after a newer one must not lower it.
func TestPeerConfigGenSentIsAHighWater18636(t *testing.T) {
	var mark atomic.Uint64
	notePeerConfigGenSent(&mark, 20)
	notePeerConfigGenSent(&mark, 19)
	notePeerConfigGenSent(&mark, 0)
	if got := mark.Load(); got != 20 {
		t.Fatalf("sent high-water = %d, want 20", got)
	}
	notePeerConfigGenSent(&mark, 21)
	if got := mark.Load(); got != 21 {
		t.Fatalf("sent high-water = %d, want 21", got)
	}
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	s.recordLastSentConfigGen(30)
	s.recordLastSentConfigGen(29)
	if got := s.peerIncarnationState().lastSentConfigGen.Load(); got != 30 {
		t.Fatalf("recordLastSentConfigGen lowered the sent mark to %d, want 30", got)
	}
}

// drainPipe18636 returns a connection whose peer end discards everything the
// authority writes, so config writes complete.
func drainPipe18636(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
	return a
}

// Seat AE (#18646 review): the authority's peer-connect push is written to a
// rebooted standby's NEW connection before that connection's BulkStart reports
// the new boot id (#18521 ordering). The BulkStart boot-id switch then retires
// the incarnation. The retirement must seed the sent mark from the priming
// connection that carried the push; otherwise the threshold reverts to the
// reservation counter and, after one no-op reconcile tick, every install the
// rebooted peer stamps with the pushed generation is refused until a re-push
// lands.
func TestBootSwitchKeepsConfigWrittenOnPrimingConn18636(t *testing.T) {
	authority, _ := newAuthority18636(t, 7999)
	conn := drainPipe18636(t)
	var prior, next [bootIncarnationLen]byte
	prior[0], next[0] = 1, 2
	var pushed uint64
	authority.PrimePeerSnapshotIncarnationForTesting(conn, 1, prior, next, func() {
		pushed = authority.ReserveConfigGen()
		if !authority.queueConfig("system { host-name fw0; }", nil, pushed) {
			t.Fatal("peer-connect push was not written on the priming connection")
		}
	})
	setConfigEpochPeerTagCapability11055(authority, true) // the new boot advertises the tag
	if got := authority.peerIncarnationState().lastSentConfigGen.Load(); got != pushed {
		t.Fatalf("after the BulkStart boot switch the sent mark = %d, want the generation written on the priming connection (%d)", got, pushed)
	}
	authority.ReserveConfigGen() // one no-op reconcile tick
	peer := newConvergedPeer18636(t, pushed)
	key, val := stampedV4FromPeer18636(t, peer, 61850, pushed)
	if !authority.installClusterSyncedV4(key, val) {
		t.Fatalf("authority refused the rebooted peer's install stamped with the generation pushed to it (threshold %d)", authority.authorityConfigEpochThreshold())
	}
}

// The same, for the guarded write production pushes use
// (QueueConfigWithPeerSnapshotProtocolAtGeneration).
func TestBootSwitchKeepsGuardedConfigWrittenOnPrimingConn18636(t *testing.T) {
	authority, _ := newAuthority18636(t, 7999)
	conn := drainPipe18636(t)
	var prior, next [bootIncarnationLen]byte
	prior[0], next[0] = 1, 2
	var pushed uint64
	authority.PrimePeerSnapshotIncarnationForTesting(conn, 1, prior, next, func() {
		pushed = authority.ReserveConfigGen()
		if !authority.QueueConfigWithPeerSnapshotProtocolAtGeneration(
			"system { host-name fw0; }", nil, pushed, authority.SnapshotPeerSnapshotProtocol(), 1, 0, nil) {
			t.Fatal("guarded peer-connect push was not written on the priming connection")
		}
	})
	if got := authority.peerIncarnationState().lastSentConfigGen.Load(); got != pushed {
		t.Fatalf("after the BulkStart boot switch the sent mark = %d, want the guarded write's generation %d", got, pushed)
	}
}

// The seed is per connection: a generation recorded without a write on the
// priming connection (sent to the retired incarnation) is NOT carried into the
// new one, which stays fail-closed until something is written to it.
func TestBootSwitchDoesNotCarryConfigSentElsewhere18636(t *testing.T) {
	authority, _ := newAuthority18636(t, 7999)
	authority.recordLastSentConfigGen(authority.ReserveConfigGen()) // to the old boot
	conn := drainPipe18636(t)
	var prior, next [bootIncarnationLen]byte
	prior[0], next[0] = 1, 2
	authority.PrimePeerSnapshotIncarnationForTesting(conn, 1, prior, next, nil)
	if got := authority.peerIncarnationState().lastSentConfigGen.Load(); got != 0 {
		t.Fatalf("the new incarnation inherited sent mark %d that was never written to it", got)
	}
}

// Seat AH (#18646 review): production pushes go through the guarded write
// (writeConfigWithPeerSnapshotGuard, via
// QueueConfigWithPeerSnapshotProtocolAtGeneration). That path must record the
// sent mark too; the twin of the unguarded cell above.
func TestAuthorityAcceptsPeerAfterGuardedPush18636(t *testing.T) {
	authority, _ := newAuthority18636(t, 4999)
	conn := drainPipe18636(t)
	var boot [bootIncarnationLen]byte
	boot[0] = 3
	authority.PrimePeerSnapshotIncarnationForTesting(conn, 1, boot, boot, nil) // no boot switch
	setConfigEpochPeerTagCapability11055(authority, true)
	expected := authority.SnapshotPeerSnapshotProtocol()
	if !expected.Connected {
		t.Fatal("fixture peer is not connected")
	}
	pushed := authority.ReserveConfigGen()
	if !authority.QueueConfigWithPeerSnapshotProtocolAtGeneration(
		"system { host-name fw0; }", nil, pushed, expected, 1, 0, nil) {
		t.Fatal("guarded config push was not written")
	}
	authority.ReserveConfigGen()
	authority.ReserveConfigGen()
	peer := newConvergedPeer18636(t, pushed)
	key, val := stampedV4FromPeer18636(t, peer, 61851, pushed)
	if !authority.installClusterSyncedV4(key, val) {
		t.Fatalf("authority refused a session stamped with the generation its guarded push wrote (threshold %d, counter %d)",
			authority.authorityConfigEpochThreshold(), authority.configGenCounter.Load())
	}
}
