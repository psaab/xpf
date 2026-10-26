package cluster

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16859: in fabric-transport mode there is no control interface, so the
// heartbeat never starts and notePeerControlKeyID's only former producer
// (heartbeat admitFrame) never runs. Session sync authenticates the peer
// continuously, but recordAuthenticatedPeer set only the process-lifetime
// bit, so PeerControlKeyID stayed "" and the rotation line rendered
// UNKNOWN / "do NOT finalize" forever — false guidance on the surface that
// decides when to finalize, leaving the retired key valid (#16029).
//
// These cells drive REAL production Managers as the sync auth providers
// (the probe's fixture: both nodes at step 4 — sign B, accept B+A) through
// the real connect handshake and the real #6628 upgrade exchange, then read
// the real controlLinkRotationStatus. No heartbeat is involved anywhere.
//
// FAIL-ON-REVERT: drop the matched-key feed (recordAuthenticatedPeer without
// its key argument, or Manager.noteSyncPeerAuthenticated ignoring it) and
// every "safe to finalize" / PeerControlKeyID assertion below collapses back
// to UNKNOWN.

func rotationManager16859(t *testing.T, nodeID int, signing, additional []byte) *Manager {
	t.Helper()
	m := NewManager(nodeID, 22)
	cfg := &config.ClusterConfig{ControlLinkAuthKey: config.NewSecret(string(signing))}
	if additional != nil {
		cfg.ControlLinkAuthKeyAlt = config.NewSecret(string(additional))
	}
	m.UpdateConfig(cfg)
	return m
}

func rotationSync16859(m *Manager) *SessionSync {
	s := NewSessionSync(":0", ":0", nil)
	s.SetAuthProvider(m)
	return s
}

// TestRotationLineFabricTransportConnect16859 verifies that session sync
// reports the peer signing key only to the connect responder. The initiator
// proves the peer accepts its signing key, not that the peer signs with it,
// so that side must stay UNKNOWN until it gets a peer-signing observation.
func TestRotationLineFabricTransportConnect16859(t *testing.T) {
	// Both nodes at step 4: sign B, accept B+A.
	m0 := rotationManager16859(t, 0, rotKeyB, rotKeyA)
	m1 := rotationManager16859(t, 1, rotKeyB, rotKeyA)
	s0 := rotationSync16859(m0)
	s1 := rotationSync16859(m1)

	// Precondition: no authenticated peer frame seen yet on either node.
	for i, m := range []*Manager{m0, m1} {
		if got := m.PeerControlKeyID(); got != "" {
			t.Fatalf("node%d precondition: PeerControlKeyID = %q, want empty before any handshake", i, got)
		}
		if line := m.controlLinkRotationStatus(); !strings.Contains(line, "UNKNOWN") {
			t.Fatalf("node%d precondition: line must start UNKNOWN, got %q", i, line)
		}
		if m.ControlLinkRotationSafeToFinalize() {
			t.Fatalf("node%d precondition: UNKNOWN must not be safe to finalize", i)
		}
	}

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	ach := runHandshake(s0, ca, true)  // node0 dials: Noise initiator
	bch := runHandshake(s1, cb, false) // node1 accepts: Noise responder
	ar, br := <-ach, <-bch
	if ar.err != nil || br.err != nil {
		t.Fatalf("authenticated session-sync handshake must complete: initiator=%v responder=%v", ar.err, br.err)
	}
	if ar.mode != syncAuthAuthenticated || br.mode != syncAuthAuthenticated {
		t.Fatalf("both ends must authenticate, got initiator=%d responder=%d", ar.mode, br.mode)
	}

	// The responder has identified the initiator's signing key. The
	// initiator's successful handshake only proves its peer accepts B, so
	// it must keep the peer-signing observation UNKNOWN (#17891).
	wantID := controlLinkKeyID(rotKeyB)
	if got := m0.PeerControlKeyID(); got != "" {
		t.Fatalf("initiator: PeerControlKeyID = %q, want unknown because the responder only proved it accepts B (#17891)", got)
	}
	if !m0.HeartbeatPeerAuthSeen() {
		t.Fatal("initiator: the process-lifetime auth bit must still be armed by session sync")
	}
	if m0.ControlLinkRotationSafeToFinalize() || !strings.Contains(m0.controlLinkRotationStatus(), "UNKNOWN") {
		t.Fatalf("initiator: PSK acceptance must not prove peer signing identity or safe finalization, got %q", m0.controlLinkRotationStatus())
	}
	if got := m1.PeerControlKeyID(); got != wantID {
		t.Fatalf("responder: PeerControlKeyID = %q, want signing-key id %q — the session-sync "+
			"handshake must feed the rotation observation in fabric-transport mode (#16859)", got, wantID)
	}
	if !m1.HeartbeatPeerAuthSeen() {
		t.Fatal("responder: the process-lifetime auth bit must still be armed by session sync")
	}
	if !m1.ControlLinkRotationSafeToFinalize() {
		t.Fatal("responder: peer signing the current key must be safe to finalize")
	}
	if line := m1.controlLinkRotationStatus(); !strings.Contains(line, "safe to finalize") {
		t.Fatalf("responder: rotation line must report safe to finalize after an authenticated "+
			"session-sync handshake, got %q", line)
	}
}

// TestRotationLineFabricTransportPeerOnRetiredKey16859 is the control cell:
// a peer still signing the RETIRED key (step 3: node0 signs B accepts B+A,
// node1 still signs A accepts A+B) must render "still signing … do NOT
// finalize" — the feed must carry WHICH key matched, not merely "some key".
func TestRotationLineFabricTransportPeerOnRetiredKey16859(t *testing.T) {
	m0 := rotationManager16859(t, 0, rotKeyB, rotKeyA) // signs B
	m1 := rotationManager16859(t, 1, rotKeyA, rotKeyB) // still signs A
	s0 := rotationSync16859(m0)
	s1 := rotationSync16859(m1)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	// node1 (still on A) initiates to node0, so node0's responder matches A.
	ach := runHandshake(s1, ca, true)
	bch := runHandshake(s0, cb, false)
	ar, br := <-ach, <-bch
	if ar.err != nil || br.err != nil {
		t.Fatalf("step-3 handshake must complete: initiator=%v responder=%v", ar.err, br.err)
	}

	// node0 sees the peer signing A (the retired key from its perspective).
	if got, want := m0.PeerControlKeyID(), controlLinkKeyID(rotKeyA); got != want {
		t.Fatalf("node0: PeerControlKeyID = %q, want retired-key id %q", got, want)
	}
	if m0.ControlLinkRotationSafeToFinalize() {
		t.Fatal("node0: peer still signing the retired key must NOT be safe to finalize")
	}
	if line := m0.controlLinkRotationStatus(); !strings.Contains(line, "still signing") || !strings.Contains(line, "do NOT finalize") {
		t.Fatalf("node0: line must refuse finalize for a peer on the retired key, got %q", line)
	}

	// The initiator (node1) proved node0 accepts A, but cannot infer node0
	// signs with A. In this step-3 state node0 still signs B, so reporting
	// A here would incorrectly tell node1 that retiring its additional B is
	// safe. This is the fail-on-revert regression for #17891.
	if got := m1.PeerControlKeyID(); got != "" {
		t.Fatalf("node1 initiator: PeerControlKeyID = %q, want unknown (PSK acceptance does not identify peer signing key)", got)
	}
	if !m1.HeartbeatPeerAuthSeen() {
		t.Fatal("node1 initiator: successful handshake must still arm the process-lifetime auth bit")
	}
	if m1.ControlLinkRotationSafeToFinalize() {
		t.Fatal("node1 initiator: acceptance of A must not make retiring B safe while node0 signs B")
	}
	if line := m1.controlLinkRotationStatus(); !strings.Contains(line, "UNKNOWN") || !strings.Contains(line, "not known safe to finalize") {
		t.Fatalf("node1 initiator: peer signing key must remain UNKNOWN, got %q", line)
	}
}

// TestRotationLineFabricTransportUpgrade16859 verifies that the #6628
// in-place-upgrade responder records the initiator's signing key, while the
// initiator's proof of peer acceptance does not report the peer's signing key.
// An established unauthenticated connection is upgraded under B.
func TestRotationLineFabricTransportUpgrade16859(t *testing.T) {
	// Both nodes are at step 4 (sign B, accept B+A). Real Managers are the
	// providers so the recorder feed is the production one.
	m0 := rotationManager16859(t, 0, rotKeyB, rotKeyA)
	m1 := rotationManager16859(t, 1, rotKeyB, rotKeyA)

	newEnd := func(m *Manager) *upgEnd {
		s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
		s.SetAuthProvider(m)
		local, remote := tcpPair(t)
		ac := &authConn{Conn: local}
		s.mu.Lock()
		s.conn0 = ac
		s.mu.Unlock()
		return &upgEnd{s: s, ac: ac, wire: remote}
	}
	a := newEnd(m0)
	b := newEnd(m1)

	if a.ac.readAuthed() || a.ac.writeAuthed() || b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("fixture must start unauthenticated")
	}
	assertFrameSequence(t, runUpgrade(t, a, b), upgradeFrameSequence)
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("upgrade must authenticate both ends")
	}

	wantID := controlLinkKeyID(rotKeyB)
	if got := m0.PeerControlKeyID(); got != "" {
		t.Fatalf("initiator: PeerControlKeyID = %q, want unknown because msg2 only proves peer acceptance (#17891)", got)
	}
	if !m0.HeartbeatPeerAuthSeen() || m0.ControlLinkRotationSafeToFinalize() {
		t.Fatalf("initiator: auth proof must arm peer-authenticated state but not safe finalization; bit=%t line=%q",
			m0.HeartbeatPeerAuthSeen(), m0.controlLinkRotationStatus())
	}
	if line := m0.controlLinkRotationStatus(); !strings.Contains(line, "UNKNOWN") {
		t.Fatalf("initiator: rotation line must stay UNKNOWN after the PSK-acceptance proof, got %q", line)
	}
	if got := m1.PeerControlKeyID(); got != wantID {
		t.Fatalf("responder: PeerControlKeyID = %q, want %q after the #6628 upgrade feed (#16859)", got, wantID)
	}
	if !m1.HeartbeatPeerAuthSeen() || !m1.ControlLinkRotationSafeToFinalize() {
		t.Fatalf("responder: authenticated peer signing with B must be safe to finalize; bit=%t line=%q",
			m1.HeartbeatPeerAuthSeen(), m1.controlLinkRotationStatus())
	}
	if line := m1.controlLinkRotationStatus(); !strings.Contains(line, "safe to finalize") {
		t.Fatalf("responder: line must report safe to finalize after the upgrade, got %q", line)
	}
}
