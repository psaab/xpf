package feeds

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestColdRestartRestoresHighWater11755 proves a fresh manager compares its
// first bootstrap with the durable baseline instead of silently forgetting it.
// Superseded by #14994 (D39-01): a first candidate that trips the restored
// shrink guard is no longer installed with only an audit warning — it is
// refused against the restored high-water until the exact candidate is
// acknowledged (see feed_shrink_14994_test.go). The durable restore (count,
// hash, epoch set via ShrinkHighWaterSnapshot/RestoreShrinkHighWater) is
// unchanged; only the bootstrap-install expectation changed, with rationale.
func TestColdRestartRestoresHighWater11755(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	cfg := func() *config.DynamicAddressConfig {
		return &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
			"server": {Name: "server", URL: "https://127.0.0.1:1/feed", FeedName: "cold-feed", UpdateInterval: 3600},
		}}
	}
	getState := func(m *Manager) *feedState {
		t.Helper()
		m.mu.RLock()
		fs := m.feeds["cold-feed"]
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

	m := New(nil)
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Apply(ctx, cfg())
	baseline, err := parseFeed(strings.NewReader(shrinkBody11059(50_000)))
	if err != nil {
		t.Fatal(err)
	}
	m.installSnapshot(getState(m), baseline)

	// Cold restart: a brand-new manager sees the same feed config.
	m2 := New(nil)
	m2.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	m2.RestoreShrinkHighWater(m.ShrinkHighWaterSnapshot())
	m2.Apply(ctx, cfg())
	candidate, err := parseFeed(strings.NewReader(shrinkBody11059(500)))
	if err != nil {
		t.Fatal(err)
	}
	m2.installSnapshot(getState(m2), candidate)

	if got := len(m2.GetPrefixes("cold-feed")); got != 0 {
		t.Fatalf("cold-restart drastic shrink installed as bootstrap (#14994): got %d prefixes, want 0 (refused)", got)
	}
	info := m2.AllFeeds()["cold-feed"]
	if !info.ShrinkRefused || info.ShrinkCandidateOldCount != 50_000 || info.ShrinkCandidateNewCount != 500 {
		t.Fatalf("cold-restart refusal did not bind restored high-water tuple: %+v", info)
	}
	if info.ShrinkGuardHighWaterCount != 50_000 || info.ShrinkGuardHighWaterHash == "" {
		t.Fatalf("cold restart lost high-water tuple: %+v", info)
	}
	if !strings.Contains(logs.String(), "drastic shrink REFUSED") {
		t.Fatalf("cold-restart drastic shrink had no refusal audit:\n%s", logs.String())
	}
	// The exact candidate installs on acknowledgement and rebases.
	if err := m2.AcknowledgeFeedShrink("cold-feed", info.ShrinkRefusalID,
		info.ShrinkCandidateHash, info.ShrinkBaselineHash,
		info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed cold-restart reduction"); err != nil {
		t.Fatalf("acknowledging cold-restart shrink: %v", err)
	}
	m2.installSnapshot(getState(m2), candidate)
	if got := len(m2.GetPrefixes("cold-feed")); got != 500 {
		t.Fatalf("acknowledged cold-restart shrink did not install: got %d prefixes, want 500", got)
	}
}
