package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// feedCfgWith builds a minimal *config.Config carrying the given dynamic-address
// feed servers and address bindings.
func feedCfgWith(servers map[string]*config.FeedServer, bindings map[string]*config.AddressBinding) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DynamicAddress.FeedServers = servers
	cfg.Security.DynamicAddress.AddressBindings = bindings
	return cfg
}

// TestReconcileFeedsDay2 is the RED-on-revert guard for #5036: a daemon that
// boots with NO feed servers must still pick up a feed server ADDED on a later
// (day-2) config generation, and must join the producer when it is removed.
// Before the fix the feed manager was Apply'd only at boot, so both the add
// and the remove were ignored until restart. Neuter reconcileFeeds's Apply and
// the day-2 add asserts 0 producers instead of 1.
func TestReconcileFeedsDay2(t *testing.T) {
	d := &Daemon{daemonCtx: context.Background()}
	d.ensureFeedManager()
	defer d.feeds.StopAll()

	// Boot-equivalent: no feed servers.
	d.reconcileFeeds(feedCfgWith(nil, nil))
	if n := len(d.feeds.AllFeeds()); n != 0 {
		t.Fatalf("no feed servers configured: want 0 producers, got %d", n)
	}

	// Day-2 ADD: a feed server appears on a later generation. Port 1 fails the
	// fetch fast; we only assert the producer was registered, not that it
	// fetched.
	cfgAdd := feedCfgWith(map[string]*config.FeedServer{
		"threats": {Name: "threats", URL: "http://127.0.0.1:1/threats", UpdateInterval: 3600},
	}, nil)
	d.reconcileFeeds(cfgAdd)
	if n := len(d.feeds.AllFeeds()); n != 1 {
		t.Fatalf("day-2 feed-server ADD: want 1 producer, got %d (reconcile ignored the new server — fail-open)", n)
	}

	// Day-2 REMOVE: the producer must be joined and the namespace cleared.
	d.reconcileFeeds(feedCfgWith(nil, nil))
	if n := len(d.feeds.AllFeeds()); n != 0 {
		t.Fatalf("day-2 feed-server REMOVE: want 0 producers, got %d (stale producer leaked)", n)
	}
}

// TestReconcileFeedsNilManagerSafe: reconcileFeeds must be a no-op when the
// feed manager has not been constructed (e.g. the first boot apply, which runs
// before ensureFeedManager) rather than panicking.
func TestReconcileFeedsNilManagerSafe(t *testing.T) {
	d := &Daemon{daemonCtx: context.Background()} // d.feeds == nil
	d.reconcileFeeds(feedCfgWith(map[string]*config.FeedServer{
		"threats": {Name: "threats", URL: "http://127.0.0.1:1/threats"},
	}, nil))
	if d.feeds != nil {
		t.Fatal("reconcileFeeds must not construct the manager itself (construction is single-threaded at boot)")
	}
}

// TestFeedsConfigHash pins the gate decision (#5036): the hash covers the
// feed-SERVER set but not address bindings, so producers restart on a server
// change but NOT on a binding-only change (which only re-derives the overlay).
func TestFeedsConfigHash(t *testing.T) {
	serverA := func() map[string]*config.FeedServer {
		return map[string]*config.FeedServer{
			"a": {Name: "a", URL: "https://feeds.example/a", UpdateInterval: 60, HoldInterval: 0},
		}
	}

	base := &config.DynamicAddressConfig{FeedServers: serverA()}

	// Deterministic: the same server set hashes identically (map order aside).
	if feedsConfigHash(base) != feedsConfigHash(&config.DynamicAddressConfig{FeedServers: serverA()}) {
		t.Fatal("identical feed-server sets produced different hashes (nondeterministic gate)")
	}

	// Binding-only change: SAME hash — bindings must not restart producers.
	withBinding := &config.DynamicAddressConfig{
		FeedServers:     serverA(),
		AddressBindings: map[string]*config.AddressBinding{"name1": {}},
	}
	if feedsConfigHash(base) != feedsConfigHash(withBinding) {
		t.Fatal("a binding-only change altered the producer hash (would needlessly restart fetchers)")
	}

	// Changed feed URL: DIFFERENT hash — must restart producers.
	changed := &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
		"a": {Name: "a", URL: "https://feeds.example/b", UpdateInterval: 60},
	}}
	if feedsConfigHash(base) == feedsConfigHash(changed) {
		t.Fatal("a changed feed URL did not change the hash (day-2 URL edit would be ignored)")
	}

	// Each runtime guard threshold participates in the producer hash, so a
	// committed tuning change reaches Manager.Apply without a process restart.
	for name, tune := range map[string]func(*config.FeedServer){
		"minimum old count": func(fs *config.FeedServer) { fs.ShrinkGuardMinOldCount = 64 },
		"retained percent":  func(fs *config.FeedServer) { fs.ShrinkGuardMinRetainPercent = 60 },
		"minimum drop":      func(fs *config.FeedServer) { fs.ShrinkGuardMinDrop = 20 },
	} {
		tuned := serverA()
		tune(tuned["a"])
		if feedsConfigHash(base) == feedsConfigHash(&config.DynamicAddressConfig{FeedServers: tuned}) {
			t.Errorf("changing %s did not alter the producer hash", name)
		}
	}

	// Added second server: DIFFERENT hash.
	two := &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
		"a": {Name: "a", URL: "https://feeds.example/a", UpdateInterval: 60},
		"b": {Name: "b", URL: "https://feeds.example/bb", UpdateInterval: 60},
	}}
	if feedsConfigHash(base) == feedsConfigHash(two) {
		t.Fatal("adding a second feed server did not change the hash")
	}

	// Empty vs configured differ.
	if feedsConfigHash(&config.DynamicAddressConfig{}) == feedsConfigHash(base) {
		t.Fatal("empty and configured feed sets hash the same")
	}
}
