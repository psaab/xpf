package cluster

import (
	"sync/atomic"
	"testing"
	"time"
)

// #17805: the Manager-owned never-seen clock consumed its only timer when
// fresh sync proof arrived between the clock callback's outer freshness
// check and handlePeerNeverSeen's inner (second) freshness check, then
// expired. The helper suppressed absence confirmation on the true inner
// verdict and returned, but nobody rearmed the clock: with no heartbeat
// receiver and no further UpdateConfig, absence was never confirmed and
// every non-preempt RG stayed secondary indefinitely.
//
// The scripted source below returns false for the outer query, true for
// the helper query, then false thereafter. The counter is atomic because
// peerSyncFreshLocked probes the source under m.mu while the test may
// observe the query count from another goroutine.

// scriptedPeerSyncSource17805 returns scripted freshness verdicts: one
// verdict per PeerRecentlyActiveWithinSilenceWindow probe, sticking at
// the final value once the script is exhausted.
type scriptedPeerSyncSource17805 struct {
	script []bool
	calls  atomic.Int64
}

func (s *scriptedPeerSyncSource17805) IsConnected() bool { return true }
func (s *scriptedPeerSyncSource17805) LastPeerReceiveAge() (time.Duration, bool) {
	return 0, true
}
func (s *scriptedPeerSyncSource17805) PeerRecentlyActiveWithinSilenceWindow() bool {
	n := s.calls.Add(1)
	if int(n) > len(s.script) {
		n = int64(len(s.script))
	}
	return s.script[n-1]
}

// TestNoReceiverNeverSeenFreshProofBetweenChecksRearms17805 is the
// RED-on-revert guard for #17805. A fresh sync proof that appears only
// between the never-seen clock's outer freshness check and
// handlePeerNeverSeen's recheck must suppress that one confirmation
// attempt WITHOUT consuming the clock: once the proof goes stale, the
// rearmed clock must still confirm absence — with no receiver ever
// created and no further UpdateConfig re-apply.
func TestNoReceiverNeverSeenFreshProofBetweenChecksRearms17805(t *testing.T) {
	shortenNeverSeenGrace(t, 60*time.Millisecond)
	src := &scriptedPeerSyncSource17805{script: []bool{false, true, false}}
	m := NewManager(0, 1)
	m.setPeerSyncSourceForTesting(src)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg.ControlInterface = "em0"
	m.UpdateConfig(cfg)
	if m.IsLocalPrimary(0) {
		t.Fatal("setup: node should start secondary before any peer heartbeat")
	}
	// Deliberately no receiver: hbReceiver stays nil for the whole cell.
	if m.HeartbeatRunning() {
		t.Fatal("setup: no heartbeat should be running in the no-receiver cell")
	}
	m.SetRGReady(0, true, nil)

	if !waitPeerConfirmedAbsent(t, m, 5*time.Second) {
		t.Fatal("fresh proof between the two freshness checks consumed the never-seen clock: absence never confirmed")
	}
	if peerEverSeen(m) {
		t.Fatal("confirmed absence must not rewrite peer-ever-seen history")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("ready lone node did not promote after Manager-confirmed absence")
	}
	if got := src.calls.Load(); got < 2 {
		t.Fatalf("scripted source queried %d times; the outer and helper freshness checks must both have run", got)
	}
}
