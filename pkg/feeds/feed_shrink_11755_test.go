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
func TestColdRestartRestoresHighWater11755(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	cfg := func() *config.DynamicAddressConfig {
		return &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
			"server": {Name: "server", URL: "http://127.0.0.1:1/feed", FeedName: "cold-feed", UpdateInterval: 3600},
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

	if got := len(m2.GetPrefixes("cold-feed")); got != 500 {
		t.Fatalf("bootstrap install changed behavior: got %d prefixes, want 500", got)
	}
	info := m2.AllFeeds()["cold-feed"]
	if info.ShrinkGuardHighWaterCount != 50_000 || info.ShrinkGuardHighWaterHash == "" {
		t.Fatalf("cold restart lost high-water tuple: %+v", info)
	}
	if !strings.Contains(logs.String(), "bootstrap below or changed from remembered high-water") {
		t.Fatalf("cold-restart bootstrap with remembered high-water had no audit warning")
	}
}
