package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
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

// PeerConfigAckOverdue is the daemon's re-push trigger: overdue only for a
// connected, ACK-capable peer whose newest send is unacknowledged past the
// bound — never for a legacy peer (NACK-driven), a disconnected one, or an
// acknowledged send.
func TestPeerConfigAckOverdueBounds18521(t *testing.T) {
	var now int64 = 1_000_000_000_000
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	s.nowMonoFn = func() int64 { return now }
	s.stats.Connected.Store(true)
	s.peerSnaps.peerSnapshotProtocol.Store(8)
	s.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2ConfigApplyAck))
	s.recordLastSentConfigGen(99)
	const after = 10 * time.Second

	if _, _, overdue := s.PeerConfigAckOverdue(after); overdue {
		t.Fatal("a send just made is overdue")
	}
	now += int64(11 * time.Second)
	gen, age, overdue := s.PeerConfigAckOverdue(after)
	if !overdue || gen != 99 || age != 11*time.Second {
		t.Fatalf("PeerConfigAckOverdue = (%d, %v, %v), want (99, 11s, true)", gen, age, overdue)
	}
	s.stats.Connected.Store(false)
	if _, _, overdue := s.PeerConfigAckOverdue(after); overdue {
		t.Fatal("a disconnected peer is overdue (the reconnect push owns it)")
	}
	s.stats.Connected.Store(true)
	s.peerIncarnationState().peerCapabilityFlags2.Store(0)
	if _, _, overdue := s.PeerConfigAckOverdue(after); overdue {
		t.Fatal("a legacy peer is overdue (its gate is NACK-driven)")
	}
	s.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2ConfigApplyAck))
	ack18521(t, s, nil, 99)
	if _, _, overdue := s.PeerConfigAckOverdue(after); overdue {
		t.Fatal("an acknowledged send is overdue")
	}
}

// Review of #18525 round 2 (finding 3): the overdue-ACK re-push runs only on
// the RG0 config authority, but the stale-config gate runs on every demoting
// node, and the send debt is overwritten only by a new send. A node that held
// an uncredited debt and then LOST RG0 by a path its own gate does not guard
// (a monitor-driven weight change) can no longer re-push, never sends again,
// and refused every later data-RG failover with "the standby has not
// acknowledged applying config generation G" — although it is now the
// RECEIVER of the new authority's config. Once this node applies (or re-ACKs)
// a config the peer pushed, the peer and this node hold the same config by
// construction, so the debt for this node's own older send is superseded.
// RED with the debt left standing after the peer's config is applied.
func TestFormerAuthorityDebtSupersededByPeerConfig18525(t *testing.T) {
	const debtGen = uint64(1890891765099)
	const peerGen = uint64(1890891799001)
	rows := []struct {
		name      string
		duplicate bool
	}{
		{"the new authority's config is applied", false},
		{"the new authority re-sends the generation already applied", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
			conn := &captureConn{}
			s.mu.Lock()
			s.conn0 = conn
			s.mu.Unlock()
			s.SetOverdueConfigApplyDebtForTesting(debtGen, 2*time.Minute)
			if row.duplicate {
				s.lastAppliedConfigGen.Store(peerGen)
			}
			var applies int
			s.OnConfigReceived = func(string) error { applies++; return nil }

			m := NewManager(1, 1)
			m.UpdateConfig(makeConfig(makeRG(2, false, map[int]int{0: 100, 1: 200})))
			m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
				{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			}})
			m.mu.Lock()
			m.groups[2].Ready = true
			m.groups[2].ReadySince = time.Now().Add(-time.Hour)
			m.groups[2].ReadinessReasons = nil
			m.mu.Unlock()
			m.runElection()
			if !m.IsLocalPrimary(2) {
				t.Fatal("fixture: this node must own data RG 2")
			}
			m.SetPeerConfigStaleFunc(s.PeerConfigStale)
			if _, err := m.ManualFailover(2); !errors.Is(err, ErrPeerConfigStale) {
				t.Fatalf("fixture: the outstanding debt must refuse the data-RG failover, got %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.configApplyLoop(ctx)
			}()
			s.configApplyCh <- configApplyItem{gen: peerGen, text: "set system host-name new-authority", conn: conn}
			acked := waitFor18521(t, 5*time.Second, func() bool {
				for _, f := range conn.frames() {
					if f.msgType == syncMsgConfigApplyAck && len(f.payload) >= 8 &&
						binary.LittleEndian.Uint64(f.payload[:8]) == peerGen {
						return true
					}
				}
				return false
			})
			cancel()
			<-done
			if !acked {
				t.Fatal("fixture: the peer's config was not acknowledged")
			}
			if row.duplicate != (applies == 0) {
				t.Fatalf("fixture: applies=%d for duplicate=%v", applies, row.duplicate)
			}
			if stale, reason := s.PeerConfigStale(); stale {
				t.Fatalf("this node applied the new authority's config and still refuses handovers "+
					"over its own superseded send: %s (review of #18525 round 2)", reason)
			}
			if _, _, overdue := s.PeerConfigAckOverdue(time.Second); overdue {
				t.Fatal("a superseded debt still reads as an overdue ACK")
			}
			if _, err := m.ManualFailover(2); err != nil {
				t.Fatalf("the data-RG failover is still refused after the debt was superseded: %v", err)
			}
			// A later send by this node (authority again) is a fresh debt,
			// whatever its generation: the superseded one is older.
			s.recordLastSentConfigGen(debtGen)
			if stale, _ := s.PeerConfigStale(); !stale {
				t.Fatal("a send after the supersession recorded no debt: the gate stays open over an " +
					"unacknowledged config")
			}
		})
	}
}
