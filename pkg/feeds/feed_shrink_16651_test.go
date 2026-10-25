package feeds

import (
	"context"
	"net/http"
	"testing"
)

// TestCountOnlyRestoreRebootstrapsEpoch16651 is the #16651 regression for
// the legacy count-only shape: a restored record with a count baseline
// but no epoch prefix set. Pre-fix, the first guarded install passed the
// count high-water but the epoch-rebase gate keyed on !hasRememberedBaseline,
// so the epoch was never established: churn stayed predecessor-only and the
// snapshot re-persisted a count-only record forever. After the fix the
// first install re-bootstraps the epoch (100 prefixes persisted), and the
// classic 51%-retained rotation sequence refuses at step 2 against that
// epoch. A valid-epoch control behaves identically before and after.
//
// RED proof (pre-fix): after the first install the snapshot carries 0
// epoch prefixes and step2 installs instead of refusing.
func TestCountOnlyRestoreRebootstrapsEpoch16651(t *testing.T) {
	originals := epochPrefixes14395(18, 0, 100)
	seedRes := mustParse14994(t, epochBody14395(originals))
	legacySnap := []ShrinkHighWater{{
		Name:  "count-only-16651-feed",
		Count: 100,
		Hash:  hashHex14994(seedRes.hash),
		// No Prefixes / EpochHash: pre-#14395 durable shape.
	}}

	m2, fs2 := coldManager14994(t, legacySnap, "count-only-16651-feed")
	// Sanity: count restored, no epoch.
	m2.mu.RLock()
	if got := len(m2.feeds["count-only-16651-feed"].epochContentPrefixes); got != 0 {
		m2.mu.RUnlock()
		t.Fatalf("fixture: count-only record restored %d epoch prefixes, want 0", got)
	}
	m2.mu.RUnlock()

	// First install identical to the restored baseline: passes every
	// guard (no shrink vs high-water) and must establish the epoch.
	m2.installSnapshot(fs2, seedRes)
	if got := len(m2.GetPrefixes("count-only-16651-feed")); got != 100 || m2.AllFeeds()["count-only-16651-feed"].ShrinkRefused {
		t.Fatalf("first guarded install did not install: prefixes=%d info=%+v", got, m2.AllFeeds()["count-only-16651-feed"])
	}
	snap := m2.ShrinkHighWaterSnapshot()
	if len(snap) != 1 || len(snap[0].Prefixes) != 100 {
		t.Fatalf("first install did not persist re-bootstrapped epoch: %+v", snap)
	}
	if snap[0].EpochHash == "" || snap[0].EpochHash != hashHex14994(hashPrefixes(canonicalSlice16651(t, snap[0].Prefixes))) {
		t.Fatalf("persisted epoch has no/wrong EpochHash: %+v", snap[0])
	}
	epochSet := prefixSet16651(snap[0].Prefixes)
	for _, p := range originals {
		if !epochSet[p] {
			t.Fatalf("re-bootstrapped epoch lost original %s", p)
		}
	}
	m2.mu.RLock()
	gotEpoch := len(m2.feeds["count-only-16651-feed"].epochContentPrefixes)
	m2.mu.RUnlock()
	if gotEpoch != 100 {
		t.Fatalf("live epoch = %d, want 100 after first install", gotEpoch)
	}

	// Step 1: retain 51 of epoch, add 49 new — installs, must NOT rebase.
	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step1)))
	if got := len(m2.GetPrefixes("count-only-16651-feed")); got != 100 || m2.AllFeeds()["count-only-16651-feed"].ShrinkRefused {
		t.Fatalf("step1 (51%% of epoch) did not install: prefixes=%d info=%+v", got, m2.AllFeeds()["count-only-16651-feed"])
	}
	snap = m2.ShrinkHighWaterSnapshot()
	if len(snap) != 1 || len(snap[0].Prefixes) != 100 || !setsEqual16651(prefixSet16651(snap[0].Prefixes), prefixSet16651(originals)) {
		t.Fatalf("step1 rebased the re-bootstrapped epoch: %+v", snap)
	}

	// Step 2: retain 51 of step1 (only 2 originals) — retains 51% of its
	// predecessor but 2% of the epoch, so it must refuse at step 2.
	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step2)))
	info := m2.AllFeeds()["count-only-16651-feed"]
	if !info.ShrinkRefused {
		t.Fatalf("step2 (2%% of re-bootstrapped epoch) was not refused: prefixes=%d info=%+v", len(m2.GetPrefixes("count-only-16651-feed")), info)
	}
	if got := len(m2.GetPrefixes("count-only-16651-feed")); got != 100 {
		t.Fatalf("refusal changed installed set: %d", got)
	}

	// Persistence round trip: a further restart restores the epoch and
	// step2 is still refused (epoch did not vanish again).
	m3, fs3 := coldManager14994(t, m2.ShrinkHighWaterSnapshot(), "count-only-16651-feed")
	m3.mu.RLock()
	restored := len(m3.feeds["count-only-16651-feed"].epochContentPrefixes)
	m3.mu.RUnlock()
	if restored != 100 {
		t.Fatalf("second restart restored %d epoch prefixes, want 100", restored)
	}
	m3.installSnapshot(fs3, mustParse14994(t, epochBody14395(step1)))
	m3.installSnapshot(fs3, mustParse14994(t, epochBody14395(step2)))
	if !m3.AllFeeds()["count-only-16651-feed"].ShrinkRefused {
		t.Fatalf("post-restart step2 was not refused against persisted epoch: %+v", m3.AllFeeds()["count-only-16651-feed"])
	}
}

// TestCorruptEpochRestoreRebootstrapsEpoch16651 covers the digest-mismatch
// shape (#16651): Prefixes present but EpochHash mismatched, so restore
// drops the epoch fail-closed. The first guarded install must establish a
// fresh epoch from the installed set, and rotations then refuse at step 2.
// The digest mismatch itself must still drop the bogus set (unchanged).
func TestCorruptEpochRestoreRebootstrapsEpoch16651(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "corrupt-16651-feed", retainForever, nil)
	originals := epochPrefixes14395(18, 0, 100)
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	snap := m.ShrinkHighWaterSnapshot()
	if len(snap) != 1 {
		t.Fatalf("fixture snap: %+v", snap)
	}
	snap[0].EpochHash = hashHex14994(hashPrefixes(epochPrefixes14395(19, 0, 100)))

	m2, fs2 := coldManager14994(t, snap, "corrupt-16651-feed")
	m2.mu.RLock()
	if got := len(m2.feeds["corrupt-16651-feed"].epochContentPrefixes); got != 0 {
		m2.mu.RUnlock()
		t.Fatalf("corrupt EpochHash restored %d epoch prefixes, want 0", got)
	}
	m2.mu.RUnlock()

	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(originals)))
	if got := len(m2.GetPrefixes("corrupt-16651-feed")); got != 100 || m2.AllFeeds()["corrupt-16651-feed"].ShrinkRefused {
		t.Fatalf("first guarded install did not install: prefixes=%d info=%+v", got, m2.AllFeeds()["corrupt-16651-feed"])
	}
	after := m2.ShrinkHighWaterSnapshot()
	if len(after) != 1 || len(after[0].Prefixes) != 100 || !setsEqual16651(prefixSet16651(after[0].Prefixes), prefixSet16651(originals)) {
		t.Fatalf("corrupt-epoch feed did not persist re-bootstrapped epoch: %+v", after)
	}

	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step1)))
	if m2.AllFeeds()["corrupt-16651-feed"].ShrinkRefused {
		t.Fatalf("step1 (51%% of epoch) was refused: %+v", m2.AllFeeds()["corrupt-16651-feed"])
	}
	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step2)))
	if !m2.AllFeeds()["corrupt-16651-feed"].ShrinkRefused {
		t.Fatalf("step2 (2%% of re-bootstrapped epoch) was not refused: %+v", m2.AllFeeds()["corrupt-16651-feed"])
	}
}

// TestValidEpochControlUnchanged16651 is the control: a feed whose epoch
// restored intact behaves exactly as before — step1 installs without
// rebasing, step2 refuses. This must pass both pre- and post-fix.
func TestValidEpochControlUnchanged16651(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "control-16651-feed", retainForever, nil)
	originals := epochPrefixes14395(18, 0, 100)
	server.set(epochBody14395(originals), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	snap := m.ShrinkHighWaterSnapshot()
	if len(snap) != 1 || len(snap[0].Prefixes) != 100 {
		t.Fatalf("fixture: %+v", snap)
	}

	m2, fs2 := coldManager14994(t, snap, "control-16651-feed")
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(originals)))
	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step1)))
	if m2.AllFeeds()["control-16651-feed"].ShrinkRefused {
		t.Fatalf("control step1 was refused: %+v", m2.AllFeeds()["control-16651-feed"])
	}
	if after := m2.ShrinkHighWaterSnapshot(); len(after) != 1 || !setsEqual16651(prefixSet16651(after[0].Prefixes), prefixSet16651(originals)) {
		t.Fatalf("control epoch rebased on step1: %+v", after)
	}
	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(step2)))
	if !m2.AllFeeds()["control-16651-feed"].ShrinkRefused {
		t.Fatalf("control step2 was not refused: %+v", m2.AllFeeds()["control-16651-feed"])
	}
}

func prefixSet16651(prefixes []string) map[string]bool {
	out := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		out[p] = true
	}
	return out
}

func setsEqual16651(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func canonicalSlice16651(t *testing.T, prefixes []string) []string {
	t.Helper()
	canon := canonicalize(append([]string(nil), prefixes...))
	if len(canon) != len(prefixes) {
		t.Fatalf("persisted epoch not canonical: %d vs %d", len(canon), len(prefixes))
	}
	return canon
}
