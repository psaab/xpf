package daemon

import (
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// burstRec records, per direct-mode burst, one "immediate" frame plus a count
// of "follow-up" frames, mimicking the cluster gated senders: the first frame
// is always sent, then (count-1) follow-ups are each gated on the supplied
// BurstStillValid predicate. This is the #2898 daemon-level analogue of the
// pkg/cluster recordingBurstSend seam.
type burstRec struct {
	mu        sync.Mutex
	immediate int
	followups int
}

// fakeGatedBurst returns a seam fn that simulates a cluster gated burst loop.
// onFirstFollowup fires exactly once, right after the first follow-up frame is
// recorded (before the next iteration's gate check), so a test can drive an
// abdication mid-burst and prove the remaining frames stop.
func fakeGatedBurst(rec *burstRec, onFirstFollowup func()) func(string, net.IP, int, cluster.BurstStillValid) error {
	return func(_ string, _ net.IP, count int, sv cluster.BurstStillValid) error {
		rec.mu.Lock()
		rec.immediate++ // immediate frame is unconditional (never gated)
		rec.mu.Unlock()
		for i := 1; i < count; i++ {
			if sv != nil && !sv() {
				break
			}
			rec.mu.Lock()
			rec.followups++
			first := rec.followups == 1
			rec.mu.Unlock()
			if first && onFirstFollowup != nil {
				onFirstFollowup()
			}
		}
		return nil
	}
}

// directGateTestDaemon builds a cluster-mode Daemon whose active config maps
// reth0 to RG 1 with one IPv4 VIP and a gratuitous-arp-count of 10, so
// directSendGARPs exercises both the ARP and the router link-local NA burst
// paths with a long follow-up loop.
func directGateTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster authentication-key test-cluster-psk-6611\n" +
			"set chassis cluster control-interface em0\n" +
			"set chassis cluster peer-address 10.99.0.2\n" +
			"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n" +
			"set chassis cluster redundancy-group 1 gratuitous-arp-count 10\n" +
			"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
			"set interfaces reth0 unit 0 family inet address 10.0.61.1/24\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Daemon{
		store:             s,
		rgStates:          make(map[int]*rgStateMachine),
		directVIPOwned:    map[int]bool{1: true},
		directAnnounceSeq: map[int]uint64{1: 7},
	}
}

func installBurstSeams(t *testing.T, arp, na func(string, net.IP, int, cluster.BurstStillValid) error) {
	t.Helper()
	prevARP, prevNA := directGARPBurstFn, directNABurstFn
	directGARPBurstFn = arp
	directNABurstFn = na
	t.Cleanup(func() {
		directGARPBurstFn = prevARP
		directNABurstFn = prevNA
	})
}

// TestDirectSendGARPs_AbdicationStopsFollowups is the #2898 fail-on-revert
// guard. directSendGARPs runs as the RG-1 owner; on the FIRST follow-up frame
// the RG abdicates (sequence bumped + ownership cleared, mirroring
// applyDirectVIPOwnership want=false → cancelDirectAnnounce). With the gate
// present every subsequent follow-up — across all VIP and router-LL bursts —
// is suppressed: at most one follow-up frame total. If the gate is removed
// (directSendGARPs reverts to passing a nil predicate / the ungated burst
// senders), every burst runs to completion and this test goes RED.
func TestDirectSendGARPs_AbdicationStopsFollowups(t *testing.T) {
	d := directGateTestDaemon(t)

	var rec burstRec
	abdicate := func() {
		d.directAnnounceMu.Lock()
		d.directAnnounceSeq[1]++
		d.directAnnounceMu.Unlock()
		d.directVIPMu.Lock()
		d.directVIPOwned[1] = false
		d.directVIPMu.Unlock()
	}
	seam := fakeGatedBurst(&rec, abdicate)
	installBurstSeams(t, seam, seam)

	d.directSendGARPs(1)

	if rec.immediate == 0 {
		t.Fatal("no immediate frame sent; the burst path never ran (test seam broken)")
	}
	if rec.followups > 1 {
		t.Fatalf("abdication gate failed: sent %d follow-up frames, want <= 1 "+
			"(direct-mode loop kept re-poisoning caches after abdication — #2898 regression)",
			rec.followups)
	}
}

// TestDirectSendGARPs_OwnedRunsFullBurst proves the gate does not regress the
// legitimate burst: while ownership is held and the sequence is unchanged,
// every follow-up frame of every burst is sent.
func TestDirectSendGARPs_OwnedRunsFullBurst(t *testing.T) {
	d := directGateTestDaemon(t)

	var rec burstRec
	seam := fakeGatedBurst(&rec, nil) // never abdicates
	installBurstSeams(t, seam, seam)

	d.directSendGARPs(1)

	// gratuitous-arp-count 10 → 9 follow-ups per burst. directSendGARPs issues
	// at least the IPv4 VIP ARP burst plus the router link-local NA burst, so a
	// fully-owned run must send strictly more than a single burst's worth.
	if rec.followups < 9 {
		t.Fatalf("owned burst truncated: sent %d follow-up frames, want >= 9 "+
			"(gate suppressed a legitimate burst)", rec.followups)
	}
}

// TestDirectBurstStillValid_Transitions unit-tests the predicate directly:
// true while owned with the captured sequence, false once the sequence is
// superseded by a newer announce OR ownership is lost.
func TestDirectBurstStillValid_Transitions(t *testing.T) {
	d := &Daemon{
		directVIPOwned:    map[int]bool{1: true},
		directAnnounceSeq: map[int]uint64{1: 4},
	}
	pred := d.directBurstStillValid(1, 4)

	if !pred() {
		t.Fatal("predicate false while owned with matching sequence")
	}

	// Newer announce supersedes this burst.
	d.directAnnounceSeq[1] = 5
	if pred() {
		t.Fatal("predicate true after sequence supersession")
	}

	// Restore sequence, drop ownership.
	d.directAnnounceSeq[1] = 4
	if !pred() {
		t.Fatal("predicate false after restoring matching sequence + ownership")
	}
	d.directVIPOwned[1] = false
	if pred() {
		t.Fatal("predicate true after ownership lost")
	}
}
