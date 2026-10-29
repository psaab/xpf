package cluster

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// #18521 follow-up (loss cluster, test-ha-crash phase 3): after fw0's VM was
// force-stopped and restarted, fw1 refused every manual failover onto it for
// 60+ s with "peer config stale ... the standby has not acknowledged applying
// config generation N (peer applied 0)", although fw0 had received the
// peer-connect push and applied it ("config already matches active").
//
// fw1 accepted that ACK. What zeroed it was fw0's cold-prime BulkStart,
// which announces the new boot and arrived AFTER the ACK on the same new
// connection (a restarted standby's first bulk can trail its config ACK by
// seconds when its helper is not ready yet). notePeerBootIncarnation treated
// the boot switch as "the old boot's ACK is void" and zeroed whatever ACK was
// recorded — including the one the new boot had just delivered. With the
// config already in sync nothing re-pushes, so the debt stood until the next
// commit. 2 of 3 cycles: the race is the order of ACK and BulkStart.

func rebootedPeer18521(t *testing.T) (*SessionSync, *authConn, bootIncarnation, bootIncarnation) {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	oldBoot, newBoot := incarnation6910(0xA1), incarnation6910(0xB2)
	// fw1 learned fw0's boot from fw0's earlier bulk, before the crash.
	s.notePeerBootIncarnation(oldBoot)
	local, peer := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		peer.Close()
	})
	ac := &authConn{Conn: local}
	s.installConn(0, ac)
	// The restarted process advertises an ACK-capable capability set and its
	// identity on the new connection, before anything else on that stream.
	s.peerSnaps.peerSnapshotProtocol.Store(8)
	s.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2ConfigApplyAck))
	return s, ac, oldBoot, newBoot
}

func ack18521(t *testing.T, s *SessionSync, conn net.Conn, gen uint64) {
	t.Helper()
	var p [8]byte
	binary.LittleEndian.PutUint64(p[:], gen)
	if !s.handleMessage(conn, syncMsgConfigApplyAck, p[:]) {
		t.Fatalf("config-apply ACK for generation %d was not accepted", gen)
	}
}

// RED before the fix: the new boot's own ACK is wiped by its later BulkStart.
func TestNewBootAckSurvivesItsLaterBulkStart18521(t *testing.T) {
	s, ac, _, newBoot := rebootedPeer18521(t)
	s.noteConnPeerCapabilities(ac, peerProcessIdentity{boot: newBoot, epoch: 2})

	const pushed = uint64(1890891765094)
	s.recordLastSentConfigGen(pushed) // the peer-connect reconcile push
	ack18521(t, s, ac, pushed)
	if stale, reason := s.PeerConfigStale(); stale {
		t.Fatalf("fixture: the ACK did not clear the gate: %s", reason)
	}

	// The restarted standby's cold-prime BulkStart, announcing its new boot.
	if !s.handleMessage(ac, syncMsgBulkStart, bulkStartPayload(1, &newBoot)) {
		t.Fatal("fixture: the new boot's BulkStart was refused")
	}
	if s.PeerBootIncarnation() != newBoot {
		t.Fatal("fixture: the BulkStart did not record the new boot")
	}
	if stale, reason := s.PeerConfigStale(); stale {
		t.Fatalf("the new boot's BulkStart discarded the config-apply ACK that SAME boot had "+
			"already delivered, so the stale-config gate refuses failover onto a standby that "+
			"applied the config (%s). Nothing re-pushes an in-sync config, so this lasted until "+
			"the next commit (#18521)", reason)
	}
	if got := s.PeerAppliedConfigGen(); got != pushed {
		t.Fatalf("applied mark = %d, want %d", got, pushed)
	}
}

// The #11070 intent is unchanged: an ACK delivered by the OLD boot is void
// once the peer announces a different boot.
func TestOldBootAckIsStillDiscardedOnReboot18521(t *testing.T) {
	s, ac, oldBoot, newBoot := rebootedPeer18521(t)
	s.noteConnPeerCapabilities(ac, peerProcessIdentity{boot: oldBoot, epoch: 1})
	const pushed = uint64(77)
	s.recordLastSentConfigGen(pushed)
	ack18521(t, s, ac, pushed)

	if !s.handleMessage(ac, syncMsgBulkStart, bulkStartPayload(1, &newBoot)) {
		t.Fatal("fixture: the new boot's BulkStart was refused")
	}
	stale, reason := s.PeerConfigStale()
	if !stale || !strings.Contains(reason, "peer applied 0") {
		t.Fatalf("an ACK from the previous boot must not satisfy the new boot's debt: stale=%v reason=%q", stale, reason)
	}
}

// A peer that announces no process identity (pre-#9818) leaves its ACK
// unattributed; a reboot keeps the fail-closed reset for it.
func TestUnattributedAckKeepsFailClosedResetOnReboot18521(t *testing.T) {
	s, ac, _, newBoot := rebootedPeer18521(t)
	const pushed = uint64(78)
	s.recordLastSentConfigGen(pushed)
	ack18521(t, s, ac, pushed)
	if !s.handleMessage(ac, syncMsgBulkStart, bulkStartPayload(1, &newBoot)) {
		t.Fatal("fixture: the new boot's BulkStart was refused")
	}
	if stale, _ := s.PeerConfigStale(); !stale {
		t.Fatal("an unattributed ACK survived a peer reboot")
	}
}
