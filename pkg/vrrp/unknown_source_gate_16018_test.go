package vrrp

import (
	"net"
	"testing"
	"time"
)

// #16018: once a master source is learned and fresh, priority-0/255 adverts
// from other sources must be dropped (counter increments, no state/timer
// effect); genuine priority-0 from the learned source still takes over;
// cold-start and stale-master cases keep RFC behaviour.

func seedLearnedMaster16018(t *testing.T, vi *vrrpInstance, src net.IP) {
	t.Helper()
	vi.recordMasterAdvert(&VRRPPacket{Priority: 100, MaxAdvertInt: 100, SrcIP: src})
}

// Backup + unknown prio-0: no 1ms takeover arm, counter++.
func TestUnknownPrio0BackupNoTakeover16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	seedLearnedMaster16018(t, vi, net.IPv4(10, 0, 0, 2))
	masterDown, _, preemptHold := longTimers(t)
	// Drain any pending masterDown fire then measure: unknown prio-0 must
	// NOT reset it to ~1ms.
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 3)}, masterDown, preemptHold)
	if got := vi.unrecognizedMasterAdverts.Load(); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
	select {
	case <-masterDown.C:
		t.Fatal("unknown prio-0 armed 1ms takeover (masterDown fired)")
	case <-time.After(50 * time.Millisecond):
	}
	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP", vi.getState())
	}
	vi.mu.RLock()
	skip := vi.skipNextPreemptHold
	vi.mu.RUnlock()
	if skip {
		t.Fatal("unknown prio-0 armed skipNextPreemptHold")
	}
}

// Genuine resign from learned source: 1ms takeover still armed.
func TestKnownPrio0BackupTakeover16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	seedLearnedMaster16018(t, vi, net.IPv4(10, 0, 0, 2))
	masterDown, _, preemptHold := longTimers(t)
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 2)}, masterDown, preemptHold)
	if got := vi.unrecognizedMasterAdverts.Load(); got != 0 {
		t.Fatalf("counter = %d, want 0 for learned source", got)
	}
	select {
	case <-masterDown.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("genuine prio-0 did not arm 1ms takeover")
	}
}

// Master + unknown 255: no demotion. Master + unknown prio-0: no effect.
// Known 255 demotes (control, in unknown_master_advert_10719_test.go).
func TestUnknown255MasterNoDemotion16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	vi.setState(StateMaster)
	seedLearnedMaster16018(t, vi, net.IPv4(10, 0, 0, 2))
	masterDown, advert, _ := longTimers(t)
	vi.handleMasterRx(&VRRPPacket{Priority: 255, SrcIP: net.IPv4(10, 0, 0, 3)}, masterDown, advert)
	if vi.getState() != StateMaster {
		t.Fatalf("state = %s, want MASTER (unknown 255 must not demote)", vi.getState())
	}
	if got := vi.unrecognizedMasterAdverts.Load(); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
	vi.handleMasterRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 3)}, masterDown, advert)
	if vi.getState() != StateMaster {
		t.Fatalf("state = %s, want MASTER (unknown 0 must not affect master)", vi.getState())
	}
	if got := vi.unrecognizedMasterAdverts.Load(); got != 2 {
		t.Fatalf("counter = %d, want 2", got)
	}
}

// Backup + unknown 255: no effect beyond the counter (no source replacement,
// no timer arm from the forged owner claim).
func TestUnknown255BackupNoEffect16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	seedLearnedMaster16018(t, vi, net.IPv4(10, 0, 0, 2))
	masterDown, _, preemptHold := longTimers(t)
	vi.handleBackupRx(&VRRPPacket{Priority: 255, SrcIP: net.IPv4(10, 0, 0, 3)}, masterDown, preemptHold)
	select {
	case <-masterDown.C:
		t.Fatal("unknown 255 touched masterDown timer")
	case <-time.After(50 * time.Millisecond):
	}
	vi.mu.RLock()
	src := append(net.IP(nil), vi.lastMasterIPv4[:]...)
	pri := vi.lastMasterPriority
	vi.mu.RUnlock()
	if !src.Equal(net.IPv4(10, 0, 0, 2)) || pri != 100 {
		t.Fatalf("learned master replaced: src=%v pri=%d", src, pri)
	}
	if got := vi.unrecognizedMasterAdverts.Load(); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
}

// IPv6 family gate: unknown v6 0 dropped, learned v6 0 still takes over.
func TestUnknownPrio0IPv6Gate16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	vi.recordMasterAdvert(&VRRPPacket{Priority: 100, MaxAdvertInt: 100, SrcIP: net.ParseIP("fe80::2")})
	masterDown, _, preemptHold := longTimers(t)
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.ParseIP("fe80::3")}, masterDown, preemptHold)
	select {
	case <-masterDown.C:
		t.Fatal("unknown v6 prio-0 armed takeover")
	case <-time.After(50 * time.Millisecond):
	}
	if got := vi.unrecognizedMasterAdverts.Load(); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.ParseIP("fe80::2")}, masterDown, preemptHold)
	select {
	case <-masterDown.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("genuine v6 prio-0 did not arm takeover")
	}
}

// Cold start (no learned source): prio-0 still takes over — gate must not
// brick first election.
func TestColdStartPrio0StillTakesOver16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	masterDown, _, preemptHold := longTimers(t)
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 9)}, masterDown, preemptHold)
	select {
	case <-masterDown.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cold-start prio-0 did not arm takeover")
	}
}

// Stale learned master: unknown prio-0 applies again (silent death rescue).
func TestStaleMasterUnknownPrio0Applies16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	seedLearnedMaster16018(t, vi, net.IPv4(10, 0, 0, 2))
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now().Add(-time.Hour)
	vi.mu.Unlock()
	masterDown, _, preemptHold := longTimers(t)
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 3)}, masterDown, preemptHold)
	select {
	case <-masterDown.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stale-master unknown prio-0 should arm takeover")
	}
}

// Equal-priority tie-break with spoofed source is unchanged (ordinary
// priority, not gated): peer with higher IP still wins when no 0/255.
// (Guarded by existing vrrp_test.go tie-break tests; here we assert an
// ordinary higher-priority advert from unknown source still demotes a
// master — the gate is scoped to 0/255 only.)
func TestOrdinaryHigherPriorityStillDemotes16018(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	vi.setState(StateMaster)
	seedLearnedMaster16018(t, vi, net.IPv4(10, 0, 0, 2))
	masterDown, advert, _ := longTimers(t)
	vi.handleMasterRx(&VRRPPacket{Priority: 200, SrcIP: net.IPv4(10, 0, 0, 3)}, masterDown, advert)
	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP (ordinary 200 must still demote)", vi.getState())
	}
	if got := vi.unrecognizedMasterAdverts.Load(); got != 0 {
		t.Fatalf("counter = %d, want 0 for ordinary priority", got)
	}
}
