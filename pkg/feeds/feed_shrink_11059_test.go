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

func TestDrasticShrinkRefusesAndRetainsLastGood11059(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previousLogger)

	server := &bodyServer{}
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	var updates int
	m := New(func() error { updates++; return nil })
	fs := m.newFeed("large-denylist", ts.URL, retainForever)

	server.set(shrinkBody11059(50_000), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 50_000 {
		t.Fatalf("initial last-good prefixes = %d, want 50000", got)
	}
	lastSuccess := fs.lastSuccess
	if lastSuccess.IsZero() {
		t.Fatal("initial successful fetch did not stamp lastSuccess")
	}

	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 50_000 {
		t.Fatalf("50k→5 stub replaced last-good: got %d prefixes, want 50000", got)
	}
	if fs.lastSuccess != lastSuccess {
		t.Fatalf("refused shrink stamped success: got %v, want %v", fs.lastSuccess, lastSuccess)
	}
	if !strings.Contains(fs.lastError, "drastic shrink refused") || fs.staleSince.IsZero() {
		t.Fatalf("refused shrink was not exposed as stale/error: %+v", m.AllFeeds()[fs.name])
	}
	if updates != 1 {
		t.Fatalf("refused shrink published %d updates, want only initial install", updates)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "drastic shrink REFUSED") {
		t.Fatalf("refused shrink did not alarm at Warn:\n%s", logs.String())
	}

	// Repeated delivery of the same stub remains refused but is log-throttled.
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 50_000 {
		t.Fatalf("repeated stub replaced last-good: got %d prefixes, want 50000", got)
	}
	if !strings.Contains(logs.String(), "still REFUSED") {
		t.Fatalf("repeated stub was not reported at Debug:\n%s", logs.String())
	}

	// The existing zero-prefix parse guard still refuses empty HTTP-200 bodies.
	server.set("# empty provider response\n", http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 50_000 {
		t.Fatalf("zero-prefix response replaced last-good: got %d prefixes, want 50000", got)
	}
	if !strings.Contains(fs.lastError, "no usable prefixes") {
		t.Fatalf("zero-prefix response error = %q, want existing zero-prefix refusal", fs.lastError)
	}
}

func TestDrasticShrinkAllowsNormalChurn11059(t *testing.T) {
	server := &bodyServer{}
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	var updates int
	m := New(func() error { updates++; return nil })
	fs := m.newFeed("ordinary-churn", ts.URL, retainForever)

	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(80), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	if got := len(m.GetPrefixes(fs.name)); got != 80 {
		t.Fatalf("normal 100→80 churn did not install: got %d prefixes, want 80", got)
	}
	if fs.lastError != "" || !fs.staleSince.IsZero() {
		t.Fatalf("successful normal churn left stale markers: %+v", m.AllFeeds()[fs.name])
	}
	if updates != 2 {
		t.Fatalf("normal churn published %d updates, want 2", updates)
	}
}

func TestDrasticShrinkOperatorAcknowledgeIsOneShot11059(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previousLogger)

	server := &bodyServer{}
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	var updates int
	m := New(func() error { updates++; return nil })
	fs := m.newFeed("acknowledged-feed", ts.URL, retainForever)

	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("pre-ack 100→5 shrink installed: got %d prefixes", got)
	}
	if m.AcknowledgeFeedShrink("unknown") {
		t.Fatal("acknowledging an unknown feed unexpectedly succeeded")
	}
	if !m.AcknowledgeFeedShrink(fs.name) {
		t.Fatal("acknowledging a known feed failed")
	}
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 5 {
		t.Fatalf("operator-acknowledged shrink did not install: got %d prefixes, want 5", got)
	}
	if !strings.Contains(logs.String(), "operator-acknowledged") {
		t.Fatalf("accepted shrink did not log its operator override:\n%s", logs.String())
	}

	// The acknowledgment is consumed. Grow above the guard's minimum, then
	// prove a subsequent drastic shrink again retains that new last-good set.
	server.set(shrinkBody11059(100), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(shrinkBody11059(5), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 100 {
		t.Fatalf("one-shot ack bypassed a later shrink: got %d prefixes, want 100", got)
	}
	if updates != 3 {
		t.Fatalf("updates = %d, want initial install, acked shrink, and growth only", updates)
	}
}

func TestShrinkGuardThresholds11059(t *testing.T) {
	for _, tc := range []struct {
		old, next int
		want      bool
	}{
		{50_000, 5, true}, // reported stub case
		{100, 50, false}, // exactly at the 50% retention floor
		{100, 80, false}, // ordinary churn
		{20, 1, false},   // small feeds are exempt from ratio noise
		{32, 15, true},   // relative floor plus absolute drop floor
	} {
		if got := shrinkGuardTripped(tc.old, tc.next); got != tc.want {
			t.Errorf("shrinkGuardTripped(%d, %d) = %v, want %v", tc.old, tc.next, got, tc.want)
		}
	}
}
