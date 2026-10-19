package feeds

import (
	"context"
	"net/http"
	"testing"
)

// TestNonRebasingRotationKeepsEpochAcrossRestart15075 is the decisive
// #15075 (A50-01) regression: a 51%-retained equal-count rotation that does
// NOT rebase the epoch must keep all 100 epoch prefixes in the persisted
// record, not the rotated 100-prefix step-1 set. The pre-#15075 snapshot
// stored the live (rotated) set with Hash=highWaterHash, so restore after
// restart must re-anchor churn on the epoch, not the rotated set.
//
// RED proof (mutant): deleting the Apply epoch copy (or the epoch rebase
// copy in installSnapshot) makes the snapshot carry step1, and the
// post-restart disjoint/2%-of-epoch candidate is measured against the
// rotated set, not the original epoch.
func TestNonRebasingRotationKeepsEpochAcrossRestart15075(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "epoch-15075-feed", retainForever, nil)

	originals := epochPrefixes14395(18, 0, 100) // epoch E
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("seed installed %d, want 100", got)
	}

	// Step 1: retain 51 of epoch, add 49 new. Installs, must NOT rebase epoch.
	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	server.set(epochBody14395(step1), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 || m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatalf("step1 (51%% of epoch) did not install: installed=%d info=%+v", got, m.AllFeeds()[fs.name])
	}

	snap := m.ShrinkHighWaterSnapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot records = %d, want 1: %+v", len(snap), snap)
	}
	// The persisted epoch must be the ORIGINAL 100, not the step-1 set.
	if len(snap[0].Prefixes) != 100 {
		t.Fatalf("snapshot epoch prefixes = %d, want 100 epoch prefixes: %+v", len(snap[0].Prefixes), snap[0])
	}
	epochSet := make(map[string]bool, 100)
	for _, p := range snap[0].Prefixes {
		epochSet[p] = true
	}
	for _, p := range originals {
		if !epochSet[p] {
			t.Fatalf("persisted epoch lost original %s after non-rebasing rotation (snapshot carries rotated set, not epoch)", p)
		}
	}
	// EpochHash must be the digest of the epoch set, distinct from the
	// high-water hash (which now names the rotated step-1 set).
	if snap[0].EpochHash == "" {
		t.Fatalf("snapshot carries no EpochHash: %+v", snap[0])
	}
	wantEpochHash := hashHex14994(hashPrefixes(canonicalize(append([]string(nil), originals...))))
	if snap[0].EpochHash != wantEpochHash {
		t.Fatalf("EpochHash = %q, want epoch digest %q", snap[0].EpochHash, wantEpochHash)
	}
	if snap[0].EpochHash == snap[0].Hash {
		t.Fatalf("EpochHash equals high-water Hash %q; epoch and high-water must diverge after rotation", snap[0].Hash)
	}

	// Cold restart: restore, feed the identical epoch set (control, installs),
	// then step1 (51% of epoch, installs), then a candidate retaining only
	// 2% of the ORIGINAL epoch must be refused against the restored epoch.
	m2, fs2 := coldManager14994(t, snap, "epoch-15075-feed")
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(originals)))
	if got := len(m2.GetPrefixes("epoch-15075-feed")); got != 100 || m2.AllFeeds()["epoch-15075-feed"].ShrinkRefused {
		t.Fatalf("cold install of restored epoch set was refused: prefixes=%d info=%+v", got, m2.AllFeeds()["epoch-15075-feed"])
	}
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step1)))
	if got := len(m2.GetPrefixes("epoch-15075-feed")); got != 100 || m2.AllFeeds()["epoch-15075-feed"].ShrinkRefused {
		t.Fatalf("cold 51%% rotation of restored epoch did not install: prefixes=%d info=%+v", got, m2.AllFeeds()["epoch-15075-feed"])
	}
	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step2)))
	info := m2.AllFeeds()["epoch-15075-feed"]
	if !info.ShrinkRefused {
		t.Fatalf("post-restart 2%%-of-epoch rotation was not refused: prefixes=%d info=%+v", len(m2.GetPrefixes("epoch-15075-feed")), info)
	}
}

// TestRestartBootstrapDisjointAgainstRestoredEpoch15075: the first
// post-restart fetch bootstrapping a wholly disjoint set against a restored
// epoch is refused (or held pending exact-candidate ack); it must NOT
// rebase the epoch unchecked.
func TestRestartBootstrapDisjointAgainstRestoredEpoch15075(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "epoch-15075-boot", retainForever, nil)
	originals := epochPrefixes14395(18, 0, 100)
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	// Non-rebasing rotation so high-water diverges from epoch before restart.
	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	server.set(epochBody14395(step1), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	snap := m.ShrinkHighWaterSnapshot()
	if len(snap) != 1 || len(snap[0].Prefixes) != 100 {
		t.Fatalf("fixture: snapshot does not carry 100 epoch prefixes: %+v", snap)
	}

	// Cold restart: first fetch is a wholly disjoint equal-count set.
	m2, fs2 := coldManager14994(t, snap, "epoch-15075-boot")
	disjoint := epochPrefixes14395(21, 0, 100)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(disjoint)))
	info := m2.AllFeeds()["epoch-15075-boot"]
	if got := len(m2.GetPrefixes("epoch-15075-boot")); got != 0 || !info.ShrinkRefused {
		t.Fatalf("restart bootstrap of disjoint set against restored epoch was not refused: prefixes=%d info=%+v", got, info)
	}
	// Durable epoch unchanged by the refused bootstrap.
	after := m2.ShrinkHighWaterSnapshot()
	if len(after) != 1 || len(after[0].Prefixes) != 100 {
		t.Fatalf("refused restart bootstrap rewrote durable epoch: %+v", after)
	}
	for _, p := range originals {
		found := false
		for _, q := range after[0].Prefixes {
			if p == q {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("durable epoch lost original %s after refused bootstrap", p)
		}
	}
	// Exact acknowledgement installs it and rebases the epoch.
	if err := m2.AcknowledgeFeedShrink("epoch-15075-boot", info.ShrinkRefusalID,
		info.ShrinkCandidateHash, info.ShrinkBaselineHash,
		info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed post-restart rotation"); err != nil {
		t.Fatalf("acknowledging restart churn: %v", err)
	}
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(disjoint)))
	if got := len(m2.GetPrefixes("epoch-15075-boot")); got != 100 || m2.AllFeeds()["epoch-15075-boot"].ShrinkRefused {
		t.Fatalf("acknowledged restart churn did not install: prefixes=%d info=%+v", got, m2.AllFeeds()["epoch-15075-boot"])
	}
}

// TestCorruptEpochHashDropsEpoch15075: a persisted record whose EpochHash
// does not match its prefix set must not restore that set as the churn
// anchor (fail closed: count epoch restores, content epoch is dropped).
func TestCorruptEpochHashDropsEpoch15075(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "epoch-15075-corrupt", retainForever, nil)
	originals := epochPrefixes14395(18, 0, 100)
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	snap := m.ShrinkHighWaterSnapshot()
	if len(snap) != 1 {
		t.Fatalf("fixture snap: %+v", snap)
	}
	// Corrupt the epoch hash.
	snap[0].EpochHash = hashHex14994(hashPrefixes(epochPrefixes14395(19, 0, 100)))

	m2, fs2 := coldManager14994(t, snap, "epoch-15075-corrupt")
	_ = fs2
	m2.mu.RLock()
	got := len(m2.feeds["epoch-15075-corrupt"].epochContentPrefixes)
	m2.mu.RUnlock()
	if got != 0 {
		t.Fatalf("corrupt EpochHash restored %d epoch prefixes, want 0 (epoch dropped)", got)
	}
	// Count baseline still restored.
	if info := m2.AllFeeds()["epoch-15075-corrupt"]; info.ShrinkGuardHighWaterCount != 100 {
		t.Fatalf("count high-water not restored with corrupt epoch: %+v", info)
	}
}
