package daemon

import (
	"testing"
	"time"
)

// #15212 (A24-02): a commit made while the peer is reachable was never marked
// unshared, so a standby apply failure followed by an unplanned RG0 takeover
// silently replaced it. The mark must be recorded for every local promotion
// and cleared only by a positive config-apply ACK at or beyond the carrying
// generation — a mere socket write (or a NACK) is not proof the peer holds it.

func TestReachableCommitSharedOnlyOnApplyAck15212(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.configPeerStateForTest = func() (bool, bool) { return true, true }
	d.store.SetPeerReachableFn(func() bool { return true })
	commitHostName(t, d.store, "reachable-15212")
	text := d.store.ShowActive()
	d.noteConfigSharedWithPeer(text)

	d.store.SetClusterReadOnly(true)
	if _, err := d.store.SyncApply(winnerText9530(t), nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if _, _, ok := d.store.ConfigSyncDivergence(); !ok {
		t.Fatal("reachable commit without an apply ACK was treated as shared; " +
			"its silent replacement must raise a divergence (#15212)")
	}
}

func TestReachableCommitNackedGenerationKeepsMark15212(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.store.SetPeerReachableFn(func() bool { return true })
	commitHostName(t, d.store, "nacked-15212")

	// A NACK for the carrying generation must keep the mark (and re-arm push).
	d.notePeerConfigApplyFailed(42)

	d.store.SetClusterReadOnly(true)
	if _, err := d.store.SyncApply(winnerText9530(t), nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if _, _, ok := d.store.ConfigSyncDivergence(); !ok {
		t.Fatal("NACKed generation cleared the unshared mark; divergence must be raised (#15212)")
	}
}

func TestReachableCommitAckedGenerationClearsMark15212(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.configPeerStateForTest = func() (bool, bool) { return true, true }
	d.store.SetPeerReachableFn(func() bool { return true })
	commitHostName(t, d.store, "acked-15212")

	text := d.store.ShowActive()
	d.noteConfigSharedWithPeerAtGeneration(text, 42)
	d.notePeerConfigApplyAck(41) // stale ACK: must not clear
	d.store.SetClusterReadOnly(true)
	if _, err := d.store.SyncApply(winnerText9530(t), nil); err != nil {
		t.Fatalf("SyncApply stale-ack: %v", err)
	}
	if _, _, ok := d.store.ConfigSyncDivergence(); !ok {
		t.Fatal("stale ACK (41 < 42) cleared the unshared mark (#15212)")
	}
}

func TestReachableCommitExactAckClearsMark15212(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.configPeerStateForTest = func() (bool, bool) { return true, true }
	d.store.SetPeerReachableFn(func() bool { return true })
	commitHostName(t, d.store, "acked-exact-15212")

	text := d.store.ShowActive()
	d.noteConfigSharedWithPeerAtGeneration(text, 42)
	d.notePeerConfigApplyAck(42)

	d.store.SetClusterReadOnly(true)
	if _, err := d.store.SyncApply(winnerText9530(t), nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if _, _, ok := d.store.ConfigSyncDivergence(); ok {
		t.Fatal("ACKed generation still raised a divergence; ACK >= carrying gen must clear (#15212)")
	}
}

// The full issue scenario: reachable commit, push, standby apply failure
// (NACK), then an unplanned RG0 takeover whose pushback replaces the commit.
// The old primary must raise the divergence; before the fix the reachable
// commit was never marked and the replacement was silent.
func TestReachableCommitNackThenTakeoverPushbackAlarms15212(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.configPeerStateForTest = func() (bool, bool) { return true, true }
	d.store.SetPeerReachableFn(func() bool { return true })
	commitHostName(t, d.store, "takeover-15212")
	text := d.store.ShowActive()
	d.noteConfigSharedWithPeerAtGeneration(text, 42)
	d.notePeerConfigApplyFailed(42) // standby failed to apply gen 42

	// Unplanned takeover: the standby (now RG0 primary) pushes its older
	// config back; this node yields and applies it.
	d.store.SetClusterReadOnly(true)
	if _, err := d.store.SyncApply(winnerText9530(t), nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if _, _, ok := d.store.ConfigSyncDivergence(); !ok {
		t.Fatal("takeover pushback silently replaced a reachable commit the standby NACKed (#15212 A24-02)")
	}
}

// Control: the same sequence with a positive ACK instead of a NACK is a
// routine converged failover and must not alarm.
func TestReachableCommitAckThenTakeoverPushbackSilent15212(t *testing.T) {
	d, _ := newReconcileDaemon(t, true /*primary*/, 60*time.Second)
	d.configPeerStateForTest = func() (bool, bool) { return true, true }
	d.store.SetPeerReachableFn(func() bool { return true })
	commitHostName(t, d.store, "takeover-acked-15212")
	text := d.store.ShowActive()
	d.noteConfigSharedWithPeerAtGeneration(text, 42)
	d.notePeerConfigApplyAck(42)

	d.store.SetClusterReadOnly(true)
	if _, err := d.store.SyncApply(winnerText9530(t), nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if _, _, ok := d.store.ConfigSyncDivergence(); ok {
		t.Fatal("ACKed commit raised a divergence on takeover pushback (#15212 control)")
	}
}
