package feeds

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestHoldDropRefusedShrinkStaysPinnedUntilAcked12882: a refused drastic
// shrink starts the stale clock; when an explicit hold-interval then drops
// the retained snapshot, the refusal must SURVIVE the drop (#12882). The
// exact refused candidate re-served afterwards must not install as an
// unacknowledged "bootstrap" — it stays refused (previous-good enforcement
// persists through the omitted-binding preflight) until the operator
// acknowledges the surviving tuple, which installs it and rebases the epoch
// high-water.
func TestHoldDropRefusedShrinkStaysPinnedUntilAcked12882(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	var updates int
	m, server, fs := newShrinkFeed11059(t, "pinned-feed", time.Minute, func() error {
		updates++
		return nil
	})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("initial install = %d prefixes, want 100", got)
	}

	// The drastic 100→5 shrink is refused and stamps StaleSince.
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("refused shrink replaced last-good: got %d prefixes, want 100", got)
	}
	refused := m.AllFeeds()[fs.name]
	if !refused.ShrinkRefused || refused.ShrinkRefusalID == 0 ||
		refused.ShrinkCandidateOldCount != 100 || refused.ShrinkCandidateNewCount != 5 {
		t.Fatalf("100→5 shrink was not refused with its tuple: %+v", refused)
	}

	// Hold-interval expiry drops the retained snapshot to empty; the refusal
	// and its acknowledgeable tuple must outlive the dropped baseline.
	now = now.Add(2 * time.Minute)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 0 {
		t.Fatalf("hold expiry retained %d prefixes, want drop-to-empty", got)
	}
	dropped := m.AllFeeds()[fs.name]
	if !dropped.HoldDropped || !dropped.ShrinkRefused {
		t.Fatalf("hold drop erased the outstanding refusal: %+v", dropped)
	}

	// THE PIN: the exact refused candidate re-served after the drop stays
	// refused — pre-fix it installed as an unacknowledged bootstrap.
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 0 {
		t.Fatalf("refused candidate installed after hold drop: got %d prefixes, want 0", got)
	}
	pinned := m.AllFeeds()[fs.name]
	if !pinned.ShrinkRefused {
		t.Fatalf("post-drop re-service cleared the refusal: %+v", pinned)
	}
	if pinned.ShrinkRefusalID != dropped.ShrinkRefusalID ||
		pinned.ShrinkCandidateHash != dropped.ShrinkCandidateHash ||
		pinned.ShrinkBaselineHash != dropped.ShrinkBaselineHash ||
		pinned.ShrinkCandidateOldCount != 100 ||
		pinned.ShrinkCandidateNewCount != 5 {
		t.Fatalf("post-drop refusal lost its acknowledgeable tuple: %+v", pinned)
	}
	if pinned.ShrinkRefusalCount <= dropped.ShrinkRefusalCount {
		t.Fatalf("post-drop re-service did not count as a repeated refusal: %+v", pinned)
	}
	if !strings.Contains(pinned.LastError, "refused shrink re-served after hold-interval drop") {
		t.Fatalf("post-drop refusal error lacks its mechanism: %q", pinned.LastError)
	}
	if !strings.Contains(logs.String(), "REFUSED after hold-interval drop") {
		t.Fatalf("post-drop refusal was not audited:\n%s", logs.String())
	}
	if updates != 2 {
		t.Fatalf("publication count = %d, want initial install plus drop only", updates)
	}

	// The surviving tuple is still acknowledgeable after the drop, and the
	// acknowledged candidate installs and rebases the epoch.
	if err := m.AcknowledgeFeedShrink(fs.name, pinned.ShrinkRefusalID,
		pinned.ShrinkCandidateHash, pinned.ShrinkBaselineHash,
		pinned.ShrinkCandidateOldCount, pinned.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed 5-prefix reduction after hold expiry"); err != nil {
		t.Fatalf("acknowledging the surviving tuple post-drop: %v", err)
	}
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 5 {
		t.Fatalf("acknowledged candidate did not install post-drop: got %d prefixes, want 5", got)
	}
	final := m.AllFeeds()[fs.name]
	if final.ShrinkRefused || final.ShrinkAckPending || final.HoldDropped {
		t.Fatalf("acknowledged install retained refusal state: %+v", final)
	}
	if final.ShrinkGuardHighWaterCount != 5 || final.ShrinkGuardHighWaterHash != final.Hash {
		t.Fatalf("acknowledged post-drop shrink did not rebase the epoch: %+v", final)
	}
	if updates != 3 {
		t.Fatalf("publication count = %d, want install, drop, and acknowledged recovery", updates)
	}
}

// TestHoldDropDifferentCandidateBootstrapsWithAudit12882: the pin binds the
// exact refused candidate only. A different acceptable fetch after the drop
// keeps the deliberate bootstrap doctrine — install, audited against the
// remembered high-water — and clears the refusal.
func TestHoldDropDifferentCandidateBootstrapsWithAudit12882(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	m, server, fs := newShrinkFeed11059(t, "recovered-feed", time.Minute, nil)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if !m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatal("fixture: 100→5 shrink was not refused")
	}
	now = now.Add(2 * time.Minute)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 0 || !m.AllFeeds()[fs.name].HoldDropped {
		t.Fatal("fixture: hold expiry did not drop the snapshot")
	}

	// A different candidate (the first 50 of the original 100 rows — above
	// the retain floor) is not the pinned tuple: it bootstraps with the
	// audit warning against the remembered high-water.
	server.set(shrinkBody11059(50), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 50 {
		t.Fatalf("different post-drop candidate did not bootstrap: got %d prefixes, want 50", got)
	}
	info := m.AllFeeds()[fs.name]
	if info.ShrinkRefused || info.ShrinkRefusalCount != 2 {
		t.Fatalf("bootstrap install did not clear the refusal: %+v", info)
	}
	if !strings.Contains(logs.String(), "bootstrap below or changed from remembered high-water") {
		t.Fatalf("post-drop bootstrap had no audit warning:\n%s", logs.String())
	}
}
