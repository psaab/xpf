package cluster

import (
	"encoding/binary"
	"net"
	"testing"
)

// #14161: the boot-ID incarnation switch restored only the priming
// connection's snapshot version, leaving the previous incarnation's
// capability flags and session-sync wire version in the globals. A new
// boot whose priming connection sent no capability frame (older image,
// or a failed advisory send) therefore inherited the old boot's positive
// bits: stamped installs were released to a peer that cannot decode the
// installing-table tail, and the wire version read as the dead peer's.
//
// Both cells drive the real BulkStart arm so deleting the switch call
// leaves them red for the wiring reason, exactly as #6910's cells do.

func capabilityFrame14161(t *testing.T, snapshot uint16, flags uint8, wire uint16) []byte {
	t.Helper()
	p := make([]byte, 5)
	binary.LittleEndian.PutUint16(p[:2], snapshot)
	p[2] = flags
	binary.LittleEndian.PutUint16(p[3:5], wire)
	return p
}

// The new boot primes on the kept connection but never advertises
// capabilities on it: the prior incarnation's learned state must retire
// with it, leaving the peer unlearned (snapshot 0), incapable, and with
// an unknown wire version.
func TestBootIDSwitchClearsCapabilitiesWhenPrimingConnNeverAdvertised14161(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local0, remote0 := net.Pipe()
	defer local0.Close()
	defer remote0.Close()
	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	ac0 := &authConn{Conn: local0}
	ac1 := &authConn{Conn: local1}
	ss.installConn(0, ac0)
	// The old boot advertises a full modern capability set.
	ss.handleMessage(ac0, syncMsgPeerCapabilities,
		capabilityFrame14161(t, 8, capFlagFenceAck|capFlagPeerDeleteOwnership|
			capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity|
			capFlagScopedPolicyDelete|capFlagConfigAncestry|
			capFlagConfigEpochReverseTag|capFlagIpsecTunnelDiscriminator,
			SessionSyncWireVersion))
	if !ss.peerCapabilitiesLearned() || !ss.InstallTableIdentityCapable() ||
		ss.PeerSessionSyncWireVersion() != SessionSyncWireVersion {
		t.Fatal("FIXTURE: the old boot's advertised capabilities did not land")
	}
	// Old boot primes, then the replacement installs into the empty
	// alternate slot and primes with a DIFFERENT boot id, but sends no
	// capability frame on its own connection.
	incA := incarnation6910(0xA1)
	ss.handleMessage(ac0, syncMsgBulkStart, bulkStartPayload6910(1, incA))
	ss.installConn(1, ac1)
	incB := incarnation6910(0xB2)
	ss.handleMessage(ac1, syncMsgBulkStart, bulkStartPayload6910(2, incB))

	ss.mu.Lock()
	inc, c0, c1 := ss.peerIncarnation, ss.conn0, ss.conn1
	ss.mu.Unlock()
	if inc != 1 || c0 != nil || c1 != net.Conn(ac1) {
		t.Fatalf("FIXTURE: switch state incarnation=%d conn0=%v conn1-kept=%v, want 1/nil/true",
			inc, c0 != nil, c1 == net.Conn(ac1))
	}
	if ss.peerCapabilitiesLearned() {
		t.Fatal("the new boot inherited the old boot's learned snapshot version " +
			"although its priming connection never advertised one")
	}
	if got := ss.peerCapabilityFlags.Load(); got != 0 {
		t.Fatalf("the new boot inherited the old boot's capability flags %#x; gates "+
			"would release stamped installs and deletes to a peer that never advertised them", got)
	}
	if ss.InstallTableIdentityCapable() {
		t.Fatal("InstallTableIdentityCapable survived the boot switch: stamped installs " +
			"would be sent stamp-decoded to a peer that never advertised the decoder")
	}
	if got := ss.PeerSessionSyncWireVersion(); got != 0 {
		t.Fatalf("the new boot inherited the old boot's session-sync wire version %d, want 0 (UNKNOWN)", got)
	}
	if ok, _ := SessionSyncWireCompatible(ss.PeerSessionSyncWireVersion()); !ok {
		t.Fatal("an unknown wire version must stay permitted (predates #7990), not read as the old boot's version")
	}
}

// Companion: when the kept priming connection DID advertise the new
// boot's capabilities before its BulkStart, the switch must restore
// exactly those — the genuinely new bits, not the retired global set.
func TestBootIDSwitchRestoresPrimingConnCapabilities14161(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local0, remote0 := net.Pipe()
	defer local0.Close()
	defer remote0.Close()
	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	ac0 := &authConn{Conn: local0}
	ac1 := &authConn{Conn: local1}
	ss.installConn(0, ac0)
	const oldFlags = capFlagFenceAck | capFlagPeerDeleteOwnership | capFlagInstallTableIdentity
	ss.handleMessage(ac0, syncMsgPeerCapabilities,
		capabilityFrame14161(t, 8, oldFlags, SessionSyncWireVersion))
	if !ss.InstallTableIdentityCapable() {
		t.Fatal("FIXTURE: the old boot's install-table bit did not land")
	}
	incA := incarnation6910(0xA1)
	ss.handleMessage(ac0, syncMsgBulkStart, bulkStartPayload6910(1, incA))
	ss.installConn(1, ac1)
	// The new boot advertises a NARROWER set on its own connection:
	// snapshot v3, fence-ack only, no install-table bit, no wire version.
	const newFlags = capFlagFenceAck
	ss.handleMessage(ac1, syncMsgPeerCapabilities,
		capabilityFrame14161(t, 3, newFlags, 0))
	incB := incarnation6910(0xB2)
	ss.handleMessage(ac1, syncMsgBulkStart, bulkStartPayload6910(2, incB))

	ss.mu.Lock()
	inc := ss.peerIncarnation
	ss.mu.Unlock()
	if inc != 1 {
		t.Fatalf("FIXTURE: peerIncarnation = %d, want 1 (switch did not fire)", inc)
	}
	if got := ss.PeerSnapshotProtocolVersion(); got != 3 {
		t.Fatalf("snapshot version = %d, want the priming connection's 3", got)
	}
	if got := ss.peerCapabilityFlags.Load(); got != uint32(newFlags) {
		t.Fatalf("capability flags = %#x, want the priming connection's %#x (not the retired %#x)",
			got, newFlags, oldFlags)
	}
	if ss.InstallTableIdentityCapable() {
		t.Fatal("the retired boot's install-table bit survived via the priming connection's narrower advertisement")
	}
	if !ss.PeerFenceAckCapable() {
		t.Fatal("the priming connection's genuinely advertised fence-ack bit was lost by the switch")
	}
	if got := ss.PeerSessionSyncWireVersion(); got != 0 {
		t.Fatalf("wire version = %d, want the priming connection's 0 (UNKNOWN)", got)
	}
}
