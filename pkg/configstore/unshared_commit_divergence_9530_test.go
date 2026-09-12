package configstore

import (
	"path/filepath"
	"testing"
	"time"
)

// #9530: a commit made on the node that later yields a partition is replaced by
// the winner's older config on heal. SyncApply used to return nil with no trace
// beyond an Info log upstream. Every cell here models the two stores of that
// cluster directly: node 0 is the winner, node 1 the node that yields.

func enter9530(t *testing.T, s *Store) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
}

// commit9530 commits a config differing only in host-name and returns the active
// text, which is what the daemon pushes (ShowActive).
func commit9530(t *testing.T, s *Store, hostName string) string {
	t.Helper()
	if err := s.SetFromInput("system host-name " + hostName); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return s.ShowActive()
}

func sync9530(t *testing.T, s *Store, text string) {
	t.Helper()
	if _, err := s.SyncApply(text, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
}

// winnerConfig9530 is node 0's committed config C0.
func winnerConfig9530(t *testing.T) string {
	t.Helper()
	node0 := newTestStore(t)
	enter9530(t, node0)
	return commit9530(t, node0, "c0")
}

// nodeOne9530 is node 1 in sync with C0, in configure mode, with the peer
// reachability it reports controlled by *reachable.
func nodeOne9530(t *testing.T, path, c0 string, reachable *bool) *Store {
	t.Helper()
	node1 := newTestStoreAt(t, path)
	sync9530(t, node1, c0)
	enter9530(t, node1)
	node1.SetPeerReachableFn(func() bool { return *reachable })
	return node1
}

func digestOfHistorySlot9530(t *testing.T, s *Store, slot int) string {
	t.Helper()
	h := s.ListHistory()
	if slot < 1 || slot > len(h) || h[slot-1] == nil || h[slot-1].Config == nil {
		t.Fatalf("rollback %d is not in history (len %d)", slot, len(h))
	}
	return activeTreeDigest(h[slot-1].Config)
}

// The acceptance fixture: a commit on node 1 during the partition, then the heal
// push of node 0's older config.
func TestHealSyncThatDiscardsAPartitionCommitRaisesADivergence_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	reachable := true
	node1 := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)

	reachable = false // the partition
	tightened := commit9530(t, node1, "tightened")

	node1.SetClusterReadOnly(true) // the heal: node 1 yields
	sync9530(t, node1, c0)

	if got := configTextDigest(node1.ShowActive()); got != configTextDigest(c0) {
		t.Errorf("after the heal node 1 does not run the winner's config (digest %s)", got)
	}
	div, slot, ok := node1.ConfigSyncDivergence()
	if !ok {
		t.Fatalf("#9530: the heal sync replaced the commit node 1 made during the partition, and no divergence was " +
			"recorded. The commit is enforced on neither node and survives only in rollback history")
	}
	if slot != 1 {
		t.Errorf("the divergence names rollback %d, want 1", slot)
	}
	if got := digestOfHistorySlot9530(t, node1, slot); got != configTextDigest(tightened) {
		t.Errorf("rollback %d does not hold the discarded partition commit", slot)
	}
	if div.DiscardedDigest != configTextDigest(tightened) || div.AdoptedDigest != configTextDigest(c0) {
		t.Errorf("divergence digests: discarded %s adopted %s, want %s and %s",
			div.DiscardedDigest, div.AdoptedDigest, configTextDigest(tightened), configTextDigest(c0))
	}

	// A converged re-push of the same config is silent: no new divergence.
	sync9530(t, node1, c0)
	again, _, ok := node1.ConfigSyncDivergence()
	if !ok || !again.At.Equal(div.At) {
		t.Errorf("a converged re-push changed the divergence record (present=%v, at %v -> %v)", ok, div.At, again.At)
	}
}

// The routine RG0 failover: the old primary's commit was made with the peer
// reachable, so the sync that follows its demotion is not a divergence.
func TestCommitMadeWithThePeerReachableIsNotADivergence_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	reachable := true
	node1 := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)
	commit9530(t, node1, "routine")
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	if _, _, ok := node1.ConfigSyncDivergence(); ok {
		t.Errorf("a sync after a commit made with the peer reachable was reported as a divergence; every routine RG0 failover would alarm")
	}
}

// A push of exactly the marked content, made while the peer reads secondary,
// shares it. A push of other content does not.
func TestOnlyAPushOfTheMarkedContentClearsTheMark_9530(t *testing.T) {
	c0 := winnerConfig9530(t)

	reachable := true
	shared := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)
	reachable = false
	tightened := commit9530(t, shared, "tightened")
	shared.NoteActiveSharedWithPeer(tightened)
	shared.SetClusterReadOnly(true)
	sync9530(t, shared, c0)
	if _, _, ok := shared.ConfigSyncDivergence(); ok {
		t.Errorf("the partition commit was pushed to a secondary peer, and the later sync still reported a divergence")
	}

	reachable2 := true
	other := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable2)
	reachable2 = false
	commit9530(t, other, "tightened")
	other.NoteActiveSharedWithPeer(c0)
	other.SetClusterReadOnly(true)
	sync9530(t, other, c0)
	if _, _, ok := other.ConfigSyncDivergence(); !ok {
		t.Errorf("a push of DIFFERENT content cleared the unshared mark, so the heal discarded the partition commit silently")
	}
}

// The mark is persisted: a restart between the partition commit and the heal
// keeps it.
func TestUnsharedMarkSurvivesARestartBeforeTheHeal_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	path := filepath.Join(t.TempDir(), "config")
	reachable := true
	node1 := nodeOne9530(t, path, c0, &reachable)
	reachable = false
	commit9530(t, node1, "tightened")

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	restarted.SetClusterReadOnly(true)
	sync9530(t, restarted, c0)
	if _, _, ok := restarted.ConfigSyncDivergence(); !ok {
		t.Errorf("a restart between the partition commit and the heal lost the unshared mark, and the heal discarded the commit silently")
	}
}

// The mark is sticky: a commit made after the peer is back, on top of unshared
// content, still carries content the peer has not been shown.
func TestALaterCommitCarriesTheUnsharedMark_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	reachable := true
	node1 := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)
	reachable = false
	commit9530(t, node1, "tightened")
	reachable = true
	later := commit9530(t, node1, "tightened-again")
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	div, _, ok := node1.ConfigSyncDivergence()
	if !ok || div.DiscardedDigest != configTextDigest(later) {
		t.Errorf("a commit on top of unshared content dropped the mark (divergence present=%v, discarded %s, want %s)",
			ok, div.DiscardedDigest, configTextDigest(later))
	}
}

// A sync of the marked content itself means the peer holds it: the mark clears,
// and a later sync is not a divergence.
func TestSyncOfTheMarkedContentClearsTheMark_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	reachable := true
	node1 := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)
	reachable = false
	tightened := commit9530(t, node1, "tightened")
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, tightened)
	if _, _, ok := node1.ConfigSyncDivergence(); ok {
		t.Errorf("a sync of the marked content itself was reported as a divergence")
	}
	sync9530(t, node1, c0)
	if _, _, ok := node1.ConfigSyncDivergence(); ok {
		t.Errorf("the peer pushed the marked content back, so it held it; a later sync was still reported as a divergence")
	}
}

// A standalone store has no peer, so nothing is ever unshared.
func TestStandaloneStoreNeverMarks_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	s := newTestStore(t)
	sync9530(t, s, c0)
	enter9530(t, s)
	commit9530(t, s, "local")
	sync9530(t, s, c0)
	if _, _, ok := s.ConfigSyncDivergence(); ok {
		t.Errorf("a store with no peer reachability wired reported a divergence")
	}
}

// The alarm lasts until the active config changes to something else.
func TestDivergenceClearsWhenADifferentConfigArrives_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	reachable := true
	node1 := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)
	reachable = false
	commit9530(t, node1, "tightened")
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	if _, _, ok := node1.ConfigSyncDivergence(); !ok {
		t.Fatalf("setup: no divergence recorded")
	}

	node0 := newTestStore(t)
	enter9530(t, node0)
	commit9530(t, node0, "c0")
	c1 := commit9530(t, node0, "c1-recommitted")
	sync9530(t, node1, c1)
	if _, _, ok := node1.ConfigSyncDivergence(); ok {
		t.Errorf("the operator re-committed on the winner and node 1 received it, but the divergence alarm stayed up")
	}
}

// A commit confirmed made during the partition is a local promotion too.
func TestCommitConfirmedDuringThePartitionIsMarked_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	reachable := true
	node1 := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)
	reachable = false
	if err := node1.SetFromInput("system host-name confirmed-in-partition"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := node1.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	confirmed := node1.ShowActive()
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	div, _, ok := node1.ConfigSyncDivergence()
	if !ok || div.DiscardedDigest != configTextDigest(confirmed) {
		t.Errorf("a commit confirmed made during the partition was discarded by the heal without a divergence (present=%v)", ok)
	}
}

// The commit-confirmed timeout revert is a local promotion. Reverting onto a
// commit that was itself made during the partition keeps that content marked.
func TestTimeoutRevertOntoAPartitionCommitKeepsItMarked_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	reachable := true
	node1 := nodeOne9530(t, filepath.Join(t.TempDir(), "config"), c0, &reachable)
	reachable = false
	first := commit9530(t, node1, "partition-first")
	if err := node1.SetFromInput("system host-name partition-confirmed"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := node1.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	node1.ExitConfigure()
	if _, ok := node1.PromoteRollback(node1.ConfirmGenForTesting()); !ok {
		t.Fatalf("setup: the commit-confirmed timeout revert did not run")
	}
	if configTextDigest(node1.ShowActive()) != configTextDigest(first) {
		t.Fatalf("setup: the revert did not restore the first partition commit")
	}
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c0)
	div, _, ok := node1.ConfigSyncDivergence()
	if !ok || div.DiscardedDigest != configTextDigest(first) {
		t.Errorf("the timeout revert restored a partition commit, and the heal discarded it without a divergence (present=%v)", ok)
	}
}

// A mark that names content this node no longer runs names nothing a sync
// could discard.
func TestStaleMarkNamesNothing_9530(t *testing.T) {
	c0 := winnerConfig9530(t)
	path := filepath.Join(t.TempDir(), "config")
	seed := newTestStoreAt(t, path)
	sync9530(t, seed, c0)
	if err := seed.db.WriteUnshared(&unsharedRecord{Digest: configTextDigest("content this node never ran"), At: time.Now().UTC()}); err != nil {
		t.Fatalf("WriteUnshared: %v", err)
	}

	node1 := newTestStoreAt(t, path)
	if err := node1.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	node0 := newTestStore(t)
	enter9530(t, node0)
	commit9530(t, node0, "c0")
	c1 := commit9530(t, node0, "c1")
	node1.SetClusterReadOnly(true)
	sync9530(t, node1, c1)
	if _, _, ok := node1.ConfigSyncDivergence(); ok {
		t.Errorf("a stale unshared mark, naming content never active here, was reported as a divergence")
	}
}
