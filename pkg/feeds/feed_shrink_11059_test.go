package feeds

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// shrinkBody11059 creates distinct canonical /32 rows without crossing a
// whole-address-space union. 50k rows stays comfortably under parseFeed's caps.
func shrinkBody11059(count int) string {
	var body strings.Builder
	for i := range count {
		addr := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		body.WriteString(addr.String())
		body.WriteString("/32\n")
	}
	return body.String()
}

func newShrinkFeed11059(t *testing.T, name string, hold time.Duration, onUpdate func() error) (*Manager, *bodyServer, *feedState) {
	t.Helper()
	server := &bodyServer{}
	ts := httptest.NewServer(server.handler())
	t.Cleanup(ts.Close)
	m := New(onUpdate)
	fs := m.newFeed(name, ts.URL, hold)
	return m, server, fs
}

func captureShrinkLogs11059(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestShrinkRefusalBoundariesThroughFetchFeed11059(t *testing.T) {
	var updates int
	m, server, fs := newShrinkFeed11059(t, "boundary-feed", retainForever, func() error {
		updates++
		return nil
	})

	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	lastSuccess := fs.lastSuccess
	if lastSuccess.IsZero() {
		t.Fatal("initial install did not stamp success")
	}

	server.set(shrinkBody11059(49), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("100→49 replaced last-good: got %d prefixes, want 100", got)
	}
	info := m.AllFeeds()[fs.name]
	if !info.ShrinkRefused || info.ShrinkRefusalID != 1 ||
		info.ShrinkCandidateOldCount != 100 || info.ShrinkCandidateNewCount != 49 ||
		info.ShrinkRefusalCount != 1 || info.ShrinkCandidateHash == "" {
		t.Fatalf("refused candidate status = %+v", info)
	}
	if fs.lastSuccess != lastSuccess || !strings.Contains(info.LastError, "drastic shrink refused") || info.StaleSince.IsZero() {
		t.Fatalf("refusal did not retain success/stale status: %+v", info)
	}
	if updates != 1 {
		t.Fatalf("refused candidate published %d updates, want initial install only", updates)
	}

	// Exactly 50% retained is not below the default floor; this valid candidate
	// must install through the HTTP fetch path, clearing the earlier refusal.
	server.set(shrinkBody11059(50), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 50 {
		t.Fatalf("100→50 did not install: got %d prefixes, want 50", got)
	}
	info = m.AllFeeds()[fs.name]
	if info.ShrinkRefused || info.ShrinkAckPending || !info.StaleSince.IsZero() ||
		info.ShrinkRefusalCount != 1 {
		t.Fatalf("accepted boundary candidate did not clear active refusal: %+v", info)
	}
	if updates != 2 {
		t.Fatalf("updates = %d, want initial install and accepted boundary candidate", updates)
	}
}

func TestShrinkRefusalWarnCadenceAndCounter11059(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	m, server, fs := newShrinkFeed11059(t, "warn-feed", retainForever, nil)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	now = now.Add(10 * time.Minute)
	m.fetchFeed(context.Background(), fs)
	if got := strings.Count(logs.String(), "drastic shrink REFUSED"); got != 1 {
		t.Fatalf("Warn refusal count after repeated fetch = %d, want 1:\n%s", got, logs.String())
	}
	now = now.Add(50 * time.Minute)
	m.fetchFeed(context.Background(), fs)
	if got := strings.Count(logs.String(), "drastic shrink REFUSED"); got != 2 {
		t.Fatalf("hourly re-Warn count = %d, want 2:\n%s", got, logs.String())
	}
	info := m.AllFeeds()[fs.name]
	if !info.ShrinkRefused || info.ShrinkRefusalCount != 3 {
		t.Fatalf("persistent refusal is not exposed as a live alarm/counter: %+v", info)
	}
}

func TestShrinkAckIsBoundToCurrentCandidate11059(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	m, server, fs := newShrinkFeed11059(t, "candidate-feed", retainForever, nil)
	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	first := m.AllFeeds()[fs.name]
	if err := m.AcknowledgeFeedShrink(fs.name, first.ShrinkRefusalID, "operator=alice", "provider confirmed the intended scope"); err != nil {
		t.Fatalf("acknowledging candidate A: %v", err)
	}

	// Candidate B differs in both content and count. The old acknowledgement
	// must not authorize it; a new refusal sequence is exposed for review.
	server.set(shrinkBody11059(4), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("candidate B used candidate A's acknowledgement: installed %d prefixes", got)
	}
	info := m.AllFeeds()[fs.name]
	if !info.ShrinkRefused || info.ShrinkAckPending ||
		info.ShrinkRefusalID != first.ShrinkRefusalID+1 ||
		info.ShrinkCandidateNewCount != 4 {
		t.Fatalf("candidate B refusal/ack state = %+v", info)
	}
	if got := strings.Count(logs.String(), "drastic shrink REFUSED"); got != 2 {
		t.Fatalf("new candidate did not get its own initial Warn: count=%d\n%s", got, logs.String())
	}
	if err := m.AcknowledgeFeedShrink(fs.name, first.ShrinkRefusalID, "operator=alice", "stale approval"); err == nil {
		t.Fatal("stale candidate ID was accepted")
	}
}

func TestNormalInstallClearsPendingShrinkAck11059(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "normal-feed", retainForever, nil)
	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID, "operator=alice", "verified feed update"); err != nil {
		t.Fatalf("arm candidate acknowledgement: %v", err)
	}

	server.set(shrinkBody11059(80), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 80 {
		t.Fatalf("normal 100→80 candidate did not install: got %d prefixes", got)
	}
	info = m.AllFeeds()[fs.name]
	if info.ShrinkRefused || info.ShrinkAckPending || info.ShrinkCandidateHash != "" {
		t.Fatalf("normal install did not clear refusal and pending acknowledgement: %+v", info)
	}
}

func TestShrinkAckRequiresReasonAndInstallsExactCandidate11059(t *testing.T) {
	logs := captureShrinkLogs11059(t)
	m, server, fs := newShrinkFeed11059(t, "ack-feed", retainForever, nil)
	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID, "operator=alice", "   "); err == nil {
		t.Fatal("empty acknowledgement reason was accepted")
	}
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID, "", "reason"); err == nil {
		t.Fatal("missing authenticated actor was accepted")
	}
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID, "operator=alice", "reason\u0085text"); err == nil {
		t.Fatal("acknowledgement reason with a Unicode control character was accepted")
	}
	const actor, reason = "source=grpc;user=alice", "provider incident INC-42 verified"
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID, actor, reason); err != nil {
		t.Fatalf("acknowledging current candidate: %v", err)
	}
	armed := m.AllFeeds()[fs.name]
	if !armed.ShrinkAckPending || armed.ShrinkAckHash != info.ShrinkCandidateHash ||
		armed.ShrinkAckActor != actor || armed.ShrinkAckReason != reason {
		t.Fatalf("AllFeeds omitted exact acknowledgement details: %+v", armed)
	}
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 5 {
		t.Fatalf("acknowledged exact candidate did not install: got %d prefixes", got)
	}
	if info = m.AllFeeds()[fs.name]; info.ShrinkRefused || info.ShrinkAckPending {
		t.Fatalf("successful acknowledged install retained refusal state: %+v", info)
	}
	if !strings.Contains(logs.String(), "actor=\""+actor+"\"") || !strings.Contains(logs.String(), "reason=\""+reason+"\"") {
		t.Fatalf("override log omitted authenticated actor or reason:\n%s", logs.String())
	}
}

func TestShrinkRefusalRespectsConfiguredHoldInterval11059(t *testing.T) {
	var updates int
	m, server, fs := newShrinkFeed11059(t, "held-feed", time.Minute, func() error {
		updates++
		return nil
	})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("first refusal changed last-good set: got %d prefixes", got)
	}

	now = now.Add(time.Minute)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 0 {
		t.Fatalf("expired explicit hold interval retained %d prefixes, want drop-to-empty", got)
	}
	info := m.AllFeeds()[fs.name]
	if !info.HoldDropped || info.ShrinkRefused || !strings.Contains(info.LastError, "drastic shrink refused") {
		t.Fatalf("hold expiry did not drop the retained shrink refusal: %+v", info)
	}
	if updates != 2 {
		t.Fatalf("hold-expiry publication count = %d, want initial install plus drop", updates)
	}
}

func TestShrinkGuardBootstrapExemption11059(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "bootstrap-feed", retainForever, nil)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 5 {
		t.Fatalf("bootstrap candidate was not installed: got %d prefixes", got)
	}
	if info := m.AllFeeds()[fs.name]; info.ShrinkRefused || info.ShrinkRefusalCount != 0 {
		t.Fatalf("bootstrap install incorrectly tripped shrink guard: %+v", info)
	}
}

func TestShrinkGuardRuntimeConfigAndSafeLenientFallback11059(t *testing.T) {
	makeAppliedFeed := func(t *testing.T, fsCfg *config.FeedServer) (*Manager, *feedState) {
		t.Helper()
		m := New(nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		m.Apply(ctx, &config.DynamicAddressConfig{
			FeedServers: map[string]*config.FeedServer{"server": fsCfg},
		})
		m.mu.RLock()
		fs := m.feeds[fsCfg.FeedName]
		m.mu.RUnlock()
		if fs == nil {
			t.Fatal("Apply did not create configured feed")
		}
		select {
		case <-fs.done:
		case <-time.After(time.Second):
			t.Fatal("cancelled refresh loop did not exit")
		}
		return m, fs
	}
	makeConfig := func() *config.FeedServer {
		return &config.FeedServer{
			Name: "server", URL: "https://192.0.2.1/list", FeedName: "configured-feed",
			ShrinkGuardMinOldCount: 100, ShrinkGuardMinRetainPercent: 75, ShrinkGuardMinDrop: 10,
		}
	}

	m, fs := makeAppliedFeed(t, makeConfig())
	if got := fs.shrinkGuard; got != (shrinkGuardThresholds{minOldCount: 100, minRetainPercent: 75, minDrop: 10}) {
		t.Fatalf("committed runtime thresholds = %+v, want old=100 retain=75 drop=10", got)
	}
	baseline, err := parseFeed(strings.NewReader(shrinkBody11059(100)))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := parseFeed(strings.NewReader(shrinkBody11059(70)))
	if err != nil {
		t.Fatal(err)
	}
	m.installSnapshot(fs, baseline)
	m.installSnapshot(fs, candidate)
	if got := len(m.GetPrefixes(fs.name)); got != 100 || !m.AllFeeds()[fs.name].ShrinkRefused {
		t.Fatalf("runtime 75%% threshold did not refuse 100→70: prefixes=%d info=%+v", got, m.AllFeeds()[fs.name])
	}

	bad := makeConfig()
	bad.ShrinkGuardMinOldCount = -1
	bad.ShrinkGuardMinRetainPercent = 101
	bad.ShrinkGuardMinDrop = config.MaxDynamicAddressFeedPrefixes
	mBad, fsBad := makeAppliedFeed(t, bad)
	if got := fsBad.shrinkGuard; got != defaultShrinkGuardThresholds {
		t.Fatalf("malformed lenient values did not fall back safely: got %+v want %+v", got, defaultShrinkGuardThresholds)
	}
	mBad.StopAll()
}

func TestShrinkGuardThresholdBoundaries11059(t *testing.T) {
	for _, tc := range []struct {
		old, next int
		want      bool
	}{
		{50_000, 5, true},
		{100, 49, true},
		{100, 50, false},
		{100, 80, false},
		{20, 1, false},
		{32, 15, true},
	} {
		if got := shrinkGuardTripped(tc.old, tc.next); got != tc.want {
			t.Errorf("shrinkGuardTripped(%d, %d) = %v, want %v", tc.old, tc.next, got, tc.want)
		}
	}
}

func TestApplyDropsPendingShrinkAcknowledgement11059(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "reconfigured-feed", retainForever, nil)
	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	before := m.AllFeeds()[fs.name]
	if err := m.AcknowledgeFeedShrink(fs.name, before.ShrinkRefusalID, "operator=alice", "reviewed exact candidate"); err != nil {
		t.Fatalf("arm acknowledgement: %v", err)
	}
	if !m.AllFeeds()[fs.name].ShrinkAckPending {
		t.Fatal("acknowledgement was not armed before reconfigure")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Apply(ctx, &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"server": {
				Name: "server", URL: fs.url, FeedName: fs.name,
				UpdateInterval: 3600,
			},
		},
	})
	m.mu.RLock()
	replacement := m.feeds[fs.name]
	m.mu.RUnlock()
	if replacement == nil {
		t.Fatal("same-name feed disappeared during Apply")
	}
	select {
	case <-replacement.done:
	case <-time.After(time.Second):
		t.Fatal("cancelled replacement producer did not exit")
	}

	after := m.AllFeeds()[fs.name]
	if after.Prefixes != 100 || after.ShrinkAckPending || after.ShrinkRefused ||
		after.ShrinkRefusalCount != before.ShrinkRefusalCount {
		t.Fatalf("Apply did not preserve last-good/counter while dropping candidate ack: before=%+v after=%+v", before, after)
	}
	if err := m.AcknowledgeFeedShrink(fs.name, before.ShrinkRefusalID, "operator=alice", "stale ack"); err == nil {
		t.Fatal("pre-Apply refusal ID remained acknowledgeable after candidate reset")
	}
}
