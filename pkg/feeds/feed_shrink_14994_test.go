package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// coldManager14994 builds a fresh manager restored from a durable shrink
// history snapshot and Applies the named feed with cancelled producers,
// returning the live feedState (mirrors the cold path of #11755/#14395).
func coldManager14994(t *testing.T, snap []ShrinkHighWater, name string) (*Manager, *feedState) {
	t.Helper()
	m := New(nil)
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	m.RestoreShrinkHighWater(snap)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
		"server": {Name: "server", URL: "https://127.0.0.1:1/feed", FeedName: name, UpdateInterval: 3600},
	}}
	m.Apply(ctx, cfg)
	m.mu.RLock()
	fs := m.feeds[name]
	m.mu.RUnlock()
	if fs == nil {
		t.Fatalf("Apply did not create feed %q", name)
	}
	select {
	case <-fs.done:
	case <-time.After(time.Second):
		t.Fatal("cancelled cold feed producer did not exit")
	}
	return m, fs
}

func mustParse14994(t *testing.T, body string) fetchResult {
	t.Helper()
	res, err := parseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hashHex14994(h [32]byte) string { return fmt.Sprintf("%x", h) }

// TestColdRestartCountOnlyBootstrapShrinkRefused14994 is the count leg of
// D39-01: a legacy count-only restored record (no epoch prefix set, the
// pre-#14395 durable shape) leaves hasSnapshot=false, so the pre-fix
// hasSnapshot-gated shrink predicate never evaluated the 50000→500 drastic
// shrink and the bootstrap installed it with only an audit warning. After
// the fix the candidate is refused against the restored high-water, installs
// nothing, publishes the refusal via AllFeeds, and installs on exact ack.
// The identical-to-restored control candidate still installs.
func TestColdRestartCountOnlyBootstrapShrinkRefused14994(t *testing.T) {
	// Establish a 50000-prefix epoch, then snapshot it as a legacy
	// count-only record (Prefixes stripped, as pre-#14395 writers did).
	m0, server0, fs0 := newShrinkFeed11059(t, "cold-count-feed", retainForever, nil)
	server0.set(shrinkBody11059(50_000), http.StatusOK)
	m0.fetchFeed(context.Background(), fs0)
	if got := len(m0.GetPrefixes("cold-count-feed")); got != 50_000 {
		t.Fatalf("fixture: seed installed %d, want 50000", got)
	}
	seedRes := mustParse14994(t, shrinkBody11059(50_000))
	legacySnap := []ShrinkHighWater{{
		Name:  "cold-count-feed",
		Count: 50_000,
		Hash:  hashHex14994(seedRes.hash),
	}}

	m2, fs2 := coldManager14994(t, legacySnap, "cold-count-feed")

	// Drastic shrink on cold restart: must be refused, not bootstrap-installed.
	m2.installSnapshot(fs2, mustParse14994(t, shrinkBody11059(500)))
	info := m2.AllFeeds()["cold-count-feed"]
	if got := len(m2.GetPrefixes("cold-count-feed")); got != 0 || !info.ShrinkRefused {
		t.Fatalf("cold-restart drastic shrink installed as bootstrap: prefixes=%d info=%+v", got, info)
	}
	if info.ShrinkCandidateOldCount != 50_000 || info.ShrinkCandidateNewCount != 500 ||
		info.ShrinkGuardHighWaterCount != 50_000 {
		t.Fatalf("cold-restart refusal did not bind restored high-water tuple: %+v", info)
	}
	if !strings.Contains(info.LastError, "high-water") {
		t.Fatalf("cold-restart refusal error does not name high-water baseline: %q", info.LastError)
	}

	// Exact acknowledgement installs the candidate and rebases the epoch.
	if err := m2.AcknowledgeFeedShrink("cold-count-feed", info.ShrinkRefusalID,
		info.ShrinkCandidateHash, info.ShrinkBaselineHash,
		info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed cold-restart reduction"); err != nil {
		t.Fatalf("acknowledging cold-restart shrink: %v", err)
	}
	m2.installSnapshot(fs2, mustParse14994(t, shrinkBody11059(500)))
	if got := len(m2.GetPrefixes("cold-count-feed")); got != 500 || m2.AllFeeds()["cold-count-feed"].ShrinkRefused {
		t.Fatalf("acknowledged cold-restart shrink did not install: prefixes=%d info=%+v", got, m2.AllFeeds()["cold-count-feed"])
	}
	if info := m2.AllFeeds()["cold-count-feed"]; info.ShrinkGuardHighWaterCount != 500 {
		t.Fatalf("acknowledged cold-restart shrink did not rebase high-water: %+v", info)
	}

	// Control: a cold candidate identical to the restored epoch installs.
	m3, fs3 := coldManager14994(t, legacySnap, "cold-count-feed")
	m3.installSnapshot(fs3, seedRes)
	if got := len(m3.GetPrefixes("cold-count-feed")); got != 50_000 || m3.AllFeeds()["cold-count-feed"].ShrinkRefused {
		t.Fatalf("identical-to-restored cold candidate was refused: prefixes=%d info=%+v", got, m3.AllFeeds()["cold-count-feed"])
	}

	// Control: an above-floor cold candidate (30000 >= 50% of 50000) installs.
	m4, fs4 := coldManager14994(t, legacySnap, "cold-count-feed")
	m4.installSnapshot(fs4, mustParse14994(t, shrinkBody11059(30_000)))
	if got := len(m4.GetPrefixes("cold-count-feed")); got != 30_000 || m4.AllFeeds()["cold-count-feed"].ShrinkRefused {
		t.Fatalf("above-floor cold candidate was refused: prefixes=%d info=%+v", got, m4.AllFeeds()["cold-count-feed"])
	}
}

// TestColdRestartEpochChurnRefused14994 is the churn leg of D39-01: even
// when the restored record carries the epoch prefix set (#14395), the
// pre-fix hasSnapshot gate skipped contentChurnTripped on the first cold
// fetch, so an equal-count wholly-disjoint swap of the restored epoch
// installed as bootstrap and then overwrote the durable epoch (wasBootstrap
// epoch rebase + rememberShrinkEpochLocked), destroying the restored churn
// anchor. After the fix the swap is refused against the restored epoch, the
// durable epoch is unchanged, and the candidate installs on exact ack.
func TestColdRestartEpochChurnRefused14994(t *testing.T) {
	m0, server0, fs0 := newShrinkFeed11059(t, "cold-epoch-feed", retainForever, nil)
	originals := epochPrefixes14395(18, 0, 100)
	server0.set(epochBody14395(originals), http.StatusOK)
	m0.fetchFeed(context.Background(), fs0)
	snap := m0.ShrinkHighWaterSnapshot()
	if len(snap) != 1 || len(snap[0].Prefixes) != 100 {
		t.Fatalf("fixture: snapshot does not carry epoch prefixes: %+v", snap)
	}

	m2, fs2 := coldManager14994(t, snap, "cold-epoch-feed")

	disjoint := epochPrefixes14395(19, 0, 100)
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(disjoint)))
	info := m2.AllFeeds()["cold-epoch-feed"]
	if got := len(m2.GetPrefixes("cold-epoch-feed")); got != 0 || !info.ShrinkRefused {
		t.Fatalf("cold-restart disjoint epoch swap installed as bootstrap: prefixes=%d info=%+v", got, info)
	}
	if info.ShrinkCandidateOldCount != 100 || info.ShrinkCandidateNewCount != 100 ||
		info.ShrinkBaselineHash != snap[0].Hash {
		t.Fatalf("cold-restart churn refusal did not bind restored epoch tuple: %+v (want baseline %s)", info, snap[0].Hash)
	}
	if !strings.Contains(info.ShrinkCandidateReason, "epoch") || !strings.Contains(info.LastError, "epoch") {
		t.Fatalf("cold-restart churn refusal does not name epoch baseline: reason=%q err=%q", info.ShrinkCandidateReason, info.LastError)
	}

	// The refusal must not rewrite the durable epoch (pre-fix the bootstrap
	// install overwrote shrinkHistory with the rotated set).
	after := m2.ShrinkHighWaterSnapshot()
	if len(after) != 1 || len(after[0].Prefixes) != 100 {
		t.Fatalf("cold-restart churn refusal rewrote durable epoch: %+v", after)
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
			t.Fatalf("durable epoch lost original %s after refusal: %+v", p, after[0])
		}
	}

	// Exact acknowledgement installs and rebases the epoch.
	if err := m2.AcknowledgeFeedShrink("cold-epoch-feed", info.ShrinkRefusalID,
		info.ShrinkCandidateHash, info.ShrinkBaselineHash,
		info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed cold-restart rotation"); err != nil {
		t.Fatalf("acknowledging cold-restart churn: %v", err)
	}
	m2.installSnapshot(fs2, mustParse14994(t, epochBody14395(disjoint)))
	if got := len(m2.GetPrefixes("cold-epoch-feed")); got != 100 || m2.AllFeeds()["cold-epoch-feed"].ShrinkRefused {
		t.Fatalf("acknowledged cold-restart churn did not install: prefixes=%d info=%+v", got, m2.AllFeeds()["cold-epoch-feed"])
	}
}

// TestRecreatedFeedBootstrapShrinkRefused14994 covers the same-manager
// delete/re-add leg of D39-01: shrinkHistory remembers 100 prefixes, the
// recreated feed has no snapshot, and the pre-fix bootstrap installed a
// 100→5 shrink (or an equal-count disjoint swap vs the remembered epoch)
// with only an audit warning. After the fix both are refused awaiting ack;
// a different above-floor candidate still bootstraps (control).
func TestRecreatedFeedBootstrapShrinkRefused14994(t *testing.T) {
	m := New(nil)
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := func() *config.DynamicAddressConfig {
		return &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
			"server": {Name: "server", URL: "https://127.0.0.1:1/feed", FeedName: "recreated-feed", UpdateInterval: 3600},
		}}
	}
	getState := func() *feedState {
		t.Helper()
		m.mu.RLock()
		fs := m.feeds["recreated-feed"]
		m.mu.RUnlock()
		if fs == nil {
			t.Fatal("Apply did not create feed")
		}
		select {
		case <-fs.done:
		case <-time.After(time.Second):
			t.Fatal("cancelled feed producer did not exit")
		}
		return fs
	}

	m.Apply(ctx, cfg())
	m.installSnapshot(getState(), mustParse14994(t, shrinkBody11059(100)))

	// Delete and re-add: recreated feed is a bootstrap against history.
	m.Apply(ctx, &config.DynamicAddressConfig{})
	m.Apply(ctx, cfg())
	recreated := getState()
	m.installSnapshot(recreated, mustParse14994(t, shrinkBody11059(5)))
	info := m.AllFeeds()["recreated-feed"]
	if got := len(m.GetPrefixes("recreated-feed")); got != 0 || !info.ShrinkRefused {
		t.Fatalf("recreated drastic shrink installed as bootstrap: prefixes=%d info=%+v", got, info)
	}
	if info.ShrinkCandidateOldCount != 100 || info.ShrinkCandidateNewCount != 5 {
		t.Fatalf("recreated refusal did not bind remembered high-water tuple: %+v", info)
	}

	// Acknowledged candidate installs.
	if err := m.AcknowledgeFeedShrink("recreated-feed", info.ShrinkRefusalID,
		info.ShrinkCandidateHash, info.ShrinkBaselineHash,
		info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed recreated reduction"); err != nil {
		t.Fatalf("acknowledging recreated shrink: %v", err)
	}
	m.installSnapshot(recreated, mustParse14994(t, shrinkBody11059(5)))
	if got := len(m.GetPrefixes("recreated-feed")); got != 5 {
		t.Fatalf("acknowledged recreated shrink did not install: prefixes=%d info=%+v", got, m.AllFeeds()["recreated-feed"])
	}

}

// TestRecreatedFeedBootstrapChurnRefused14994: the churn leg of the
// recreate case — a fresh 100-epoch, delete/re-add, then an equal-count
// disjoint swap is refused against the remembered epoch (pre-fix it
// installed as bootstrap). An above-floor different candidate after a
// further recreate bootstraps and clears the refusal (control).
func TestRecreatedFeedBootstrapChurnRefused14994(t *testing.T) {
	m := New(nil)
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := func() *config.DynamicAddressConfig {
		return &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
			"server": {Name: "server", URL: "https://127.0.0.1:1/feed", FeedName: "recreated-feed", UpdateInterval: 3600},
		}}
	}
	getState := func() *feedState {
		t.Helper()
		m.mu.RLock()
		fs := m.feeds["recreated-feed"]
		m.mu.RUnlock()
		if fs == nil {
			t.Fatal("Apply did not create feed")
		}
		select {
		case <-fs.done:
		case <-time.After(time.Second):
			t.Fatal("cancelled feed producer did not exit")
		}
		return fs
	}
	m.Apply(ctx, cfg())
	m.installSnapshot(getState(), mustParse14994(t, shrinkBody11059(100)))
	m.Apply(ctx, &config.DynamicAddressConfig{})
	m.Apply(ctx, cfg())
	recreated := getState()
	swapped := strings.ReplaceAll(shrinkBody11059(100), "198.18.", "198.19.")
	m.installSnapshot(recreated, mustParse14994(t, swapped))
	info := m.AllFeeds()["recreated-feed"]
	if got := len(m.GetPrefixes("recreated-feed")); got != 0 || !info.ShrinkRefused {
		t.Fatalf("recreated disjoint swap installed as bootstrap: prefixes=%d info=%+v", got, info)
	}
	if info.ShrinkCandidateOldCount != 100 || info.ShrinkCandidateNewCount != 100 {
		t.Fatalf("recreated churn refusal tuple wrong: %+v", info)
	}
	// Control: above-floor candidate after a further recreate bootstraps.
	m.Apply(ctx, &config.DynamicAddressConfig{})
	m.Apply(ctx, cfg())
	recreated = getState()
	m.installSnapshot(recreated, mustParse14994(t, shrinkBody11059(76)))
	if got := len(m.GetPrefixes("recreated-feed")); got != 76 || m.AllFeeds()["recreated-feed"].ShrinkRefused {
		t.Fatalf("above-floor recreated candidate did not bootstrap: prefixes=%d info=%+v", got, m.AllFeeds()["recreated-feed"])
	}
}

// TestPostHoldDropDifferentCandidateGuarded14994 extends #12882's doctrine:
// after a hold-interval drop, a DIFFERENT candidate that trips shrink/churn
// vs the remembered epoch must be refused under D39-01 — only candidates
// at/above the floor keep the deliberate bootstrap-with-audit path (that
// control is TestHoldDropDifferentCandidateBootstrapsWithAudit12882, kept
// green). The exact refused candidate stays pinned (#12882, unchanged).
func TestPostHoldDropDifferentCandidateGuarded14994(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "post-drop-feed", time.Minute, nil)
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
		t.Fatalf("fixture: hold expiry did not drop snapshot: prefixes=%d info=%+v", got, m.AllFeeds()[fs.name])
	}

	// A different drastic shrink (10, not the pinned 5) is not the #12882
	// pin, but it trips the shrink guard vs the remembered 100 high-water:
	// it must be refused, not bootstrap-installed.
	server.set(shrinkBody11059(10), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if got := len(m.GetPrefixes(fs.name)); got != 0 || !info.ShrinkRefused {
		t.Fatalf("different post-drop drastic shrink installed as bootstrap: prefixes=%d info=%+v", got, info)
	}
	if info.ShrinkCandidateNewCount != 10 || info.ShrinkCandidateOldCount != 100 {
		t.Fatalf("post-drop different-candidate refusal tuple wrong: %+v", info)
	}
}
