package feeds

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestCumulativeShrinkUsesHighWaterBaseline11489(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "cumulative-feed", retainForever, nil)
	server.set(shrinkBody11059(50_000), 200)
	m.fetchFeed(context.Background(), fs)

	// Exactly half of the epoch baseline is still within the legacy boundary.
	server.set(shrinkBody11059(25_000), 200)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 25_000 {
		t.Fatalf("exact-half candidate installed %d prefixes, want 25000", got)
	}
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 25_000 || m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatalf("identical accepted sub-high-water content was refused: installed=%d info=%+v", got, m.AllFeeds()[fs.name])
	}

	// The next exact-half step is less than half of the epoch high-water mark.
	server.set(shrinkBody11059(12_500), 200)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if info.ShrinkCandidateOldCount != 50_000 || info.ShrinkGuardHighWaterCount != 50_000 ||
		info.ShrinkGuardHighWaterHash == "" {
		t.Fatalf("cumulative refusal did not expose its high-water tuple: %+v", info)
	}
	if got := len(m.GetPrefixes(fs.name)); got != 25_000 || !info.ShrinkRefused {
		t.Fatalf("cumulative 50000→25000→12500 bleed was accepted: installed=%d info=%+v", got, info)
	}
	if !strings.Contains(info.LastError, "high-water") {
		t.Fatalf("cumulative refusal did not explain its high-water baseline: %q", info.LastError)
	}

	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID,
		info.ShrinkCandidateHash, info.ShrinkBaselineHash,
		info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed gradual reduction"); err != nil {
		t.Fatalf("acknowledging cumulative reduction: %v", err)
	}
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 12_500 {
		t.Fatalf("acknowledged cumulative reduction installed %d prefixes, want 12500", got)
	}
	if info := m.AllFeeds()[fs.name]; info.ShrinkGuardHighWaterCount != 12_500 ||
		info.ShrinkGuardHighWaterHash != info.Hash {
		t.Fatalf("acknowledged shrink did not establish the new epoch baseline: %+v", info)
	}

	// An acknowledged shrink starts a new baseline epoch. 7000 is above half
	// of 12500 and must not be compared with the pre-ack 50000 high-water mark.
	server.set(shrinkBody11059(7_000), 200)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 7_000 || m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatalf("acknowledged shrink did not rebase the epoch: installed=%d info=%+v", got, m.AllFeeds()[fs.name])
	}
}

func TestEqualCountDisjointSwapIsRefused11489(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	m, server, fs := newShrinkFeed11059(t, "swap-feed", retainForever, nil)
	server.set(shrinkBody11059(100), 200)
	m.fetchFeed(context.Background(), fs)
	baseline := m.AllFeeds()[fs.name]

	// Exactly half of the prior prefixes remains, so the configured overlap
	// floor is inclusive at 50%.
	var partial strings.Builder
	for i := range 50 {
		addr := netip.AddrFrom4([4]byte{198, 18, 0, byte(i)})
		partial.WriteString(addr.String())
		partial.WriteString("/32\n")
	}
	for i := range 50 {
		addr := netip.AddrFrom4([4]byte{198, 19, byte(i >> 8), byte(i)})
		partial.WriteString(addr.String())
		partial.WriteString("/32\n")
	}
	server.set(partial.String(), 200)
	m.fetchFeed(context.Background(), fs)
	baseline = m.AllFeeds()[fs.name]
	if baseline.ShrinkRefused || baseline.Hash == "" {
		t.Fatalf("exactly 50%% prefix overlap was refused: %+v", baseline)
	}

	// Same count, no retained prefixes: count-only shrink checks miss this.
	var body strings.Builder
	for i := range 100 {
		addr := netip.AddrFrom4([4]byte{198, 20, byte(i >> 8), byte(i)})
		body.WriteString(addr.String())
		body.WriteString("/32\n")
	}
	server.set(body.String(), 200)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if got := len(m.GetPrefixes(fs.name)); got != 100 || !info.ShrinkRefused || info.Hash != baseline.Hash {
		t.Fatalf("wholly-disjoint equal-count swap was installed: prefixes=%d baseline=%+v current=%+v", got, baseline, info)
	}
	if !strings.Contains(info.LastError, "overlap") || !strings.Contains(logs.String(), "content-churn") {
		t.Fatalf("swap refusal did not identify/audit content churn: error=%q logs=%s", info.LastError, logs.String())
	}
}

func TestRecreatedFeedAuditsSmallBootstrapAgainstRememberedHighWater11489(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	m := New(nil)
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := func() *config.DynamicAddressConfig {
		return &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
			"server": {Name: "server", URL: "http://127.0.0.1:1/feed", FeedName: "recreated-feed", UpdateInterval: 3600},
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
	first := getState()
	baseline, err := parseFeed(strings.NewReader(shrinkBody11059(100)))
	if err != nil {
		t.Fatal(err)
	}
	m.installSnapshot(first, baseline)

	m.Apply(ctx, &config.DynamicAddressConfig{})
	m.Apply(ctx, cfg())
	recreated := getState()
	candidate, err := parseFeed(strings.NewReader(shrinkBody11059(5)))
	if err != nil {
		t.Fatal(err)
	}
	m.installSnapshot(recreated, candidate)

	if got := len(m.GetPrefixes("recreated-feed")); got != 5 {
		t.Fatalf("bootstrap install changed behavior: got %d prefixes, want 5", got)
	}
	info := m.AllFeeds()["recreated-feed"]
	if info.ShrinkGuardHighWaterCount != 100 || info.ShrinkGuardHighWaterHash == "" {
		t.Fatalf("recreated feed lost remembered high-water state: %+v", info)
	}
	if !strings.Contains(logs.String(), "bootstrap below or changed from remembered high-water") {
		t.Fatalf("small same-name recreate bootstrap had no audit warning:\n%s", logs.String())
	}

	// A count-preserving swap is also visible when re-add makes it a bootstrap,
	// even though there is no live snapshot to run the overlap refusal against.
	m.Apply(ctx, &config.DynamicAddressConfig{})
	m.Apply(ctx, cfg())
	recreated = getState()
	swapped, err := parseFeed(strings.NewReader(strings.ReplaceAll(shrinkBody11059(100), "198.18.", "198.19.")))
	if err != nil {
		t.Fatal(err)
	}
	m.installSnapshot(recreated, swapped)
	if got := len(m.GetPrefixes("recreated-feed")); got != 100 || m.AllFeeds()["recreated-feed"].ShrinkRefused {
		t.Fatalf("recreated equal-count feed did not install cleanly with audit: prefixes=%d info=%+v", got, m.AllFeeds()["recreated-feed"])
	}
	if got := strings.Count(logs.String(), "bootstrap below or changed from remembered high-water"); got != 2 {
		t.Fatalf("small and equal-count recreate bootstraps produced %d audit warnings, want 2:\n%s", got, logs.String())
	}
}
