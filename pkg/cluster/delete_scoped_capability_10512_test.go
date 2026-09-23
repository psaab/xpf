package cluster

import (
	"context"
	"net"
	"testing"
	"time"
)

// Incapable peer (advertised, without the bit): scoped deletes withheld,
// counted once per call, both families.
func TestScopedDeleteWithheldFromAnIncapablePeer10512(t *testing.T) {
	for _, source := range []string{"delete_v4", "delete_v6"} {
		s := &SessionSync{}
		s.handleMessage(nil, syncMsgPeerCapabilities,
			capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
		if !s.peerCapabilitiesLearned() {
			t.Fatal("FIXTURE: the capability frame did not land")
		}
		if s.ScopedPolicyDeleteCapable() {
			t.Fatal("FIXTURE: a frame without the bit must not read as scoped capable")
		}
		if !s.suppressScopedDeleteForIncapablePeer(source) {
			t.Fatalf("source %s: scoped delete must be withheld from an incapable peer", source)
		}
		if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 1 {
			t.Fatalf("source %s: DeletesSuppressedScopedPolicy = %d, want 1", source, got)
		}
	}
}

// Capable peer: nothing withheld, nothing counted.
func TestScopedDeleteReachesACapablePeer10512(t *testing.T) {
	s := &SessionSync{}
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity|capFlagScopedPolicyDelete))
	if !s.ScopedPolicyDeleteCapable() {
		t.Fatal("FIXTURE: the advertised bit did not decode")
	}
	if s.suppressScopedDeleteForIncapablePeer("delete_v4") {
		t.Fatal("a capable peer must receive the scoped delete")
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 0 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 0", got)
	}
}

// Unlearned peer: default-DENY. An old peer decodes the legacy prefix and
// bare-deletes, so discovery pass-through would downgrade every scoped
// delete in the window (the NEVER rule) — unlike #9714/#9752 deletes,
// where pass-through is safe because the bytes are identical either way.
func TestScopedDeleteWithheldWhileUnlearned10512(t *testing.T) {
	s := &SessionSync{}
	if s.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: fresh sync must not read as learned")
	}
	if !s.suppressScopedDeleteForIncapablePeer("delete_v4") {
		t.Fatal("an unlearned peer must trigger withhold (default-deny)")
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 1 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 1", got)
	}
}

// Write-time gate, direct: unlearned re-journals (deferred, uncounted);
// learned-incapable drops + counts; capable passes; bare/non-delete/
// malformed frames never hold here.
func TestHoldScopedDeleteForUnverifiedPeer10512(t *testing.T) {
	scoped := encodeDeleteScopedV4(scopedCodecKeyV4(), 1, false, 100007, 0xF10512)
	scoped6 := encodeDeleteScopedV6(scopedCodecKeyV6(), 1, false, 200007, 0xC10512)
	bare := encodeDeleteV4(scopedCodecKeyV4(), 1, false)
	// Unlearned: re-journaled as deferred debt (NOT counted as suppressed).
	s := &SessionSync{}
	if !s.holdScopedDeleteForUnverifiedPeer(scoped) {
		t.Fatal("scoped frame must hold while unlearned")
	}
	if got := scopedJournalLen10512(s); got != 1 {
		t.Fatalf("unlearned frame must re-journal, journal holds %d", got)
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 0 {
		t.Fatalf("counter = %d, want 0 (deferred, not dropped)", got)
	}
	// Incapable (learned, no bit): the learn-trigger already dropped the
	// journaled frame (counted); a direct hold drops + counts again.
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 1 {
		t.Fatalf("counter = %d, want 1 (trigger drop)", got)
	}
	if !s.holdScopedDeleteForUnverifiedPeer(scoped6) {
		t.Fatal("scoped frame must drop for an incapable peer")
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 2 {
		t.Fatalf("counter = %d, want 2", got)
	}
	// Capable: pass through.
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagScopedPolicyDelete))
	if s.holdScopedDeleteForUnverifiedPeer(scoped) {
		t.Fatal("scoped frame must pass for a capable peer")
	}
	// Bare delete, non-delete, malformed: never the gate's business.
	if s.holdScopedDeleteForUnverifiedPeer(bare) {
		t.Fatal("bare frame must never hold at the scoped gate")
	}
	other := make([]byte, syncHeaderSize+1)
	other[4] = syncMsgHeartbeat
	if s.holdScopedDeleteForUnverifiedPeer(other) {
		t.Fatal("non-delete frame must never hold at the scoped gate")
	}
	if s.holdScopedDeleteForUnverifiedPeer([]byte{1, 2, 3}) {
		t.Fatal("malformed frame must never hold at the scoped gate")
	}
}

// Placement pin: a flag flip in testBeforeQueuedWrite — after any
// queue-time check, before the write — still writes zero bytes. The gate
// sits inside writeMu immediately before writeFull, so approval binds to
// this write, not to an earlier observation. The held frame re-journals
// as deferred debt (unlearned), uncounted.
func TestScopedWriteGateSeesHookFlipBeforeWrite10512(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	localConn, peerConn := net.Pipe()
	defer localConn.Close()
	defer peerConn.Close()
	ss.mu.Lock()
	ss.conn0 = localConn
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)
	// Learned + capable at queue time: no queue-time gate would fire.
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagScopedPolicyDelete))
	if !ss.ScopedPolicyDeleteCapable() {
		t.Fatal("FIXTURE: the advertised bit did not decode")
	}
	// Adversarial flip at the last pre-write instant: unlearn the peer.
	ss.testBeforeQueuedWrite = func() {
		ss.peerSnapshotProtocol.Store(0)
		ss.peerCapabilityFlags.Store(0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ss.sendLoop(ctx)
	ss.sendCh <- encodeDeleteScopedV4(scopedCodecKeyV4(), 1, false, 100007, 0xF10512)
	// The peer must receive NOTHING: a deadline read proves zero bytes.
	// (Generous deadline: a failure still fails fast on first byte.)
	peerConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _ := peerConn.Read(buf)
	if n != 0 {
		t.Fatalf("peer received %d bytes of a scoped delete after the flip", n)
	}
	if got := scopedJournalLen10512(ss); got != 1 {
		t.Fatalf("flipped frame must re-journal, journal holds %d", got)
	}
	if got := ss.stats.DeletesSuppressedScopedPolicy.Load(); got != 0 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 0 (deferred, not dropped)", got)
	}
}

// Same-slot supersession clears learned state: the replacement must not
// inherit the old peer's bits before advertising.
func TestSupersessionClearsLearnedCapabilities10512(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)
	frame := capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagScopedPolicyDelete)
	frame = append(frame, byte(SessionSyncWireVersion), 0)
	ss.handleMessage(connA, syncMsgPeerCapabilities, frame)
	if !ss.peerCapabilitiesLearned() || !ss.ScopedPolicyDeleteCapable() {
		t.Fatal("FIXTURE: learning from the current conn must land")
	}
	if got := ss.peerSessionSyncWire.Load(); got == 0 {
		t.Fatal("FIXTURE: wire version must land for a non-vacuous clear assert")
	}
	connB := pipeConn(t)
	installAckTestConn(t, ss, 0, connB) // same-slot replacement: supersedes A
	if ss.peerCapabilitiesLearned() {
		t.Fatal("supersession must clear learned state (snapshot protocol)")
	}
	if got := ss.peerCapabilityFlags.Load(); got != 0 {
		t.Fatalf("supersession must clear capability flags, got %d", got)
	}
	if got := ss.peerSessionSyncWire.Load(); got != 0 {
		t.Fatalf("supersession must clear session-sync wire version, got %d", got)
	}
}

// Stale in-flight capabilities from a superseded connection must not
// re-arm learned state; the current connection's frame still lands.
func TestStaleCapabilitiesIgnoredAfterSupersession10512(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)
	frame := capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagScopedPolicyDelete)
	ss.handleMessage(connA, syncMsgPeerCapabilities, frame)
	if !ss.ScopedPolicyDeleteCapable() {
		t.Fatal("FIXTURE: learning from the current conn must land")
	}
	connB := pipeConn(t)
	installAckTestConn(t, ss, 0, connB) // supersedes A: advance + clear
	if ss.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: supersession must clear before the stale frame lands")
	}
	// The superseded connection's in-flight frame arrives after the swap.
	ss.handleMessage(connA, syncMsgPeerCapabilities, frame)
	if ss.peerCapabilitiesLearned() || ss.ScopedPolicyDeleteCapable() {
		t.Fatal("a stale-conn frame must not re-arm learned state")
	}
	// The current connection's frame still lands (no blanket deny).
	ss.handleMessage(connB, syncMsgPeerCapabilities, frame)
	if !ss.peerCapabilitiesLearned() || !ss.ScopedPolicyDeleteCapable() {
		t.Fatal("the current conn's frame must land")
	}
}

// Pending-retirement promotion (#9818 interplay): a superseded conn that
// proves a NEWER process identity is re-stamped current by noteConn, and
// its capabilities then land (the gate runs AFTER noteConn precisely so
// this promotion is observable — gating first would strand the conn to
// die on timer expiry). Post-supersession state is set up directly;
// install-driven advance is pinned in the cells above.
func TestPendingRetirementCapabilitiesPromoteAndLand10512(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	acA := &authConn{Conn: local}
	installAckTestConn(t, ss, 0, acA)
	// Simulate the post-supersession state: incarnation advanced, A left
	// pending-retirement for the retired process (epoch 100), slot stale.
	ss.mu.Lock()
	ss.peerIncarnation = 1
	acA.pendingRetirement = true
	acA.pendingRetirementGen = 1
	acA.retiredIdentity = peerProcessIdentity{epoch: 100}
	ss.mu.Unlock()
	// A's frame carries a NEWER process identity (epoch 200): promotion,
	// then the capabilities land.
	frame := capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagScopedPolicyDelete)
	frame = append(frame, 0, 0) // wire version [3:5] (UNKNOWN; identity starts at [5:])
	frame = append(frame, make([]byte, bootIncarnationLen)...)
	frame = append(frame, 200, 0, 0, 0, 0, 0, 0, 0) // epoch 200, little-endian
	ss.handleMessage(acA, syncMsgPeerCapabilities, frame)
	if !ss.peerCapabilitiesLearned() || !ss.ScopedPolicyDeleteCapable() {
		t.Fatal("a promoted conn's capabilities must land")
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.conn0Gen != 1 {
		t.Fatalf("promotion must re-stamp the slot to the current incarnation, got gen %d", ss.conn0Gen)
	}
	if ss.peerIdentity.epoch != 200 {
		t.Fatalf("promotion must adopt the proven identity, got epoch %d", ss.peerIdentity.epoch)
	}
}
