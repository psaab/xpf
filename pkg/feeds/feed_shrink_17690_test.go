package feeds

import (
	"testing"
)

// TestOrdinaryRotationEmptyEpochDoesNotRebase17690 is the #17690 regression
// for the over-broad #16651 epoch re-bootstrap. installSnapshot's
// len(epochContentPrefixes)==0 arm fired on ANY empty-epoch install —
// including an ordinary unacknowledged rotation on a live feed that was
// never restored from a durable record — rebasing the content epoch to
// the rotated set. One step later the next 51%-retained rotation is then
// measured against the rotated epoch, not the original set: exactly the
// frog-boil #14395 forbids ("an ordinary unacknowledged install never
// rebases"). The fix scopes the re-bootstrap arm to records that
// RestoreShrinkHighWater actually restored without a usable epoch
// (count-only / corrupt-digest / dropped-legacy shapes), so a merely
// empty epoch on a live feed is never rebased by an ordinary install.
//
// RED proof (pre-fix): after the first rotation the live epoch holds the
// rotated 100 prefixes and the snapshot persists them, so the test fails
// at "ordinary unacknowledged rotation rebased the epoch". The restored
// epoch-less positive arms stay pinned by the #16651 cells.
func TestOrdinaryRotationEmptyEpochDoesNotRebase17690(t *testing.T) {
	m, fs := coldManager14994(t, nil, "empty-epoch-17690-feed")
	originals := epochPrefixes14395(18, 0, 100)

	// Live feed state: a snapshot is installed and enforced, but the feed
	// was NOT restored from a durable record in this process (no shrink
	// history was loaded for it) and its content epoch is empty. This is
	// interleaving (b) from #17690 — emptiness alone, no restore.
	m.mu.Lock()
	fs.prefixes = canonicalize(append([]string(nil), originals...))
	fs.hash = hashPrefixes(fs.prefixes)
	fs.hasSnapshot = true
	fs.shrinkHighWaterCount = len(originals)
	fs.shrinkHighWaterHash = fs.hash
	m.mu.Unlock()

	// Ordinary unacknowledged rotation: retain 51 of the installed set,
	// add 49 new. It passes the predecessor churn floor and installs —
	// but it must NOT create/rebase an epoch.
	step1 := append(append([]string{}, originals[:51]...), epochPrefixes14395(19, 0, 49)...)
	m.installSnapshot(fs, mustParse14994(t, epochBody14395(step1)))
	if got := len(m.GetPrefixes("empty-epoch-17690-feed")); got != 100 || m.AllFeeds()["empty-epoch-17690-feed"].ShrinkRefused {
		t.Fatalf("ordinary rotation did not install: prefixes=%d info=%+v", got, m.AllFeeds()["empty-epoch-17690-feed"])
	}
	m.mu.RLock()
	epochLen := len(m.feeds["empty-epoch-17690-feed"].epochContentPrefixes)
	m.mu.RUnlock()
	if epochLen != 0 {
		t.Fatalf("ordinary unacknowledged rotation rebased the epoch: %d epoch prefixes, want 0 (an ordinary install never rebases)", epochLen)
	}
	snap := m.ShrinkHighWaterSnapshot()
	if len(snap) != 1 || len(snap[0].Prefixes) != 0 {
		t.Fatalf("ordinary rotation persisted an epoch: %+v", snap)
	}

	// A second rotation retaining 51% of its predecessor (but only 2% of
	// the original set) still faces no epoch — none was ever established
	// or acknowledged — so it installs predecessor-only and, crucially,
	// still does not manufacture an epoch for the next step to boil from.
	step2 := append(append([]string{}, originals[:2]...), epochPrefixes14395(19, 0, 49)...)
	step2 = append(step2, epochPrefixes14395(20, 0, 49)...)
	m.installSnapshot(fs, mustParse14994(t, epochBody14395(step2)))
	if got := len(m.GetPrefixes("empty-epoch-17690-feed")); got != 100 || m.AllFeeds()["empty-epoch-17690-feed"].ShrinkRefused {
		t.Fatalf("second predecessor-passing rotation did not install: prefixes=%d info=%+v", got, m.AllFeeds()["empty-epoch-17690-feed"])
	}
	m.mu.RLock()
	epochLen = len(m.feeds["empty-epoch-17690-feed"].epochContentPrefixes)
	m.mu.RUnlock()
	if epochLen != 0 {
		t.Fatalf("second rotation created an epoch: %d epoch prefixes, want 0", epochLen)
	}
}
