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

// TestRotationLineFabricTransportConnect16859 is the acceptance cell: after
// an authenticated session-sync connect handshake with a peer signing the
// current key, the rotation line must report safe to finalize on BOTH
// nodes (initiator and responder), with no heartbeat ever running.
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

	wantID := controlLinkKeyID(rotKeyB)
	for i, m := range []*Manager{m0, m1} {
		if got := m.PeerControlKeyID(); got != wantID {
			t.Fatalf("node%d: PeerControlKeyID = %q, want signing-key id %q — the session-sync "+
				"handshake must feed the rotation observation in fabric-transport mode (#16859)", i, got, wantID)
		}
		if !m.HeartbeatPeerAuthSeen() {
			t.Fatalf("node%d: the process-lifetime auth bit must still be armed by session sync", i)
		}
		if !m.ControlLinkRotationSafeToFinalize() {
			t.Fatalf("node%d: peer signing the current key must be safe to finalize", i)
		}
		if line := m.controlLinkRotationStatus(); !strings.Contains(line, "safe to finalize") {
			t.Fatalf("node%d: rotation line must report safe to finalize after an authenticated "+
				"session-sync handshake, got %q", i, line)
		}
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

	// node1 (initiator, signing A) authenticated under A, so it records A as
	// the peer's key; A IS node1's signing key, so its own line reads safe —
	// correct: from node1's seat the peer (node0) also accepts/signs in the
	// B+A window and node1's finalize retires B, which node0 no longer needs
	// as its additional once it signs B... the predicate is defined against
	// the local signing key, and this pins that the initiator direction
	// feeds its own signing key rather than nothing.
	if got, want := m1.PeerControlKeyID(), controlLinkKeyID(rotKeyA); got != want {
		t.Fatalf("node1: PeerControlKeyID = %q, want its signing-key id %q", got, want)
	}
}

// TestRotationLineFabricTransportUpgrade16859 covers the second feed the
// issue names: the #6628 in-place upgrade responder's matched key (and the
// initiator's round key). An established unauthenticated connection that
// upgrades under B must feed the rotation line on both ends.
func TestRotationLineFabricTransportUpgrade16859(t *testing.T) {
	// Established unauthenticated ends, then both keyed at step 4 (sign B,
	// accept B+A). Real Managers are the providers so the recorder feed is
	// the production one.
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
	for i, m := range []*Manager{m0, m1} {
		if got := m.PeerControlKeyID(); got != wantID {
			t.Fatalf("node%d: PeerControlKeyID = %q, want %q after the #6628 upgrade feed (#16859)", i, got, wantID)
		}
		if line := m.controlLinkRotationStatus(); !strings.Contains(line, "safe to finalize") {
			t.Fatalf("node%d: line must report safe to finalize after the upgrade, got %q", i, line)
		}
	}
}
