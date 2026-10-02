package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestFeedShrinkHighWaterSurvivesColdDaemonRestart11755(t *testing.T) {
	oldPath := feedShrinkHistoryPath
	feedShrinkHistoryPath = filepath.Join(t.TempDir(), "state", "feed-shrink-history.json")
	t.Cleanup(func() { feedShrinkHistoryPath = oldPath })

	var bodyMu sync.RWMutex
	body := feedShrinkBody11755(50_000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bodyMu.RLock()
		current := body
		bodyMu.RUnlock()
		_, _ = w.Write([]byte(current))
	}))
	defer server.Close()

	cfg := feedCfgWith(map[string]*config.FeedServer{
		"server": {Name: "server", URL: server.URL, FeedName: "cold-boot-feed", UpdateInterval: 3600},
	}, nil)
	newDaemon := func() *Daemon {
		d := &Daemon{daemonCtx: context.Background()}
		d.ensureFeedManager()
		d.feeds.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
		t.Cleanup(func() { d.feeds.StopAll() })
		return d
	}
	waitForPrefixes := func(d *Daemon, count int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if info, ok := d.feeds.AllFeeds()["cold-boot-feed"]; ok && info.Prefixes == count {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("feed did not install %d prefixes; status=%+v", count, d.feeds.AllFeeds()["cold-boot-feed"])
	}

	first := newDaemon()
	first.reconcileFeeds(cfg)
	waitForPrefixes(first, 50_000)
	firstInfo := first.feeds.AllFeeds()["cold-boot-feed"]
	if firstInfo.ShrinkGuardHighWaterCount != 50_000 || firstInfo.ShrinkGuardHighWaterHash == "" {
		t.Fatalf("initial install did not establish shrink baseline: %+v", firstInfo)
	}
	first.feeds.StopAll()

	records := readFeedShrinkHistory()
	if len(records) != 1 || records[0].Name != "cold-boot-feed" || records[0].Count != 50_000 || records[0].Hash != firstInfo.ShrinkGuardHighWaterHash {
		t.Fatalf("persisted high-water tuple = %+v, want feed/count/hash from first daemon", records)
	}
	bodyMu.Lock()
	body = feedShrinkBody11755(500)
	bodyMu.Unlock()

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	second := newDaemon()
	second.reconcileFeeds(cfg)
	waitForPrefixes(second, 500)
	secondInfo := second.feeds.AllFeeds()["cold-boot-feed"]
	if secondInfo.ShrinkGuardHighWaterCount != 50_000 || secondInfo.ShrinkGuardHighWaterHash != firstInfo.ShrinkGuardHighWaterHash {
		t.Fatalf("cold daemon restart lost the epoch high-water: first=%+v second=%+v", firstInfo, secondInfo)
	}
	if !strings.Contains(logs.String(), "bootstrap below or changed from remembered high-water") {
		t.Fatalf("cold-boot shrink comparison emitted no audit warning:\n%s", logs.String())
	}
}

func feedShrinkBody11755(count int) string {
	var body strings.Builder
	for i := range count {
		_, _ = fmt.Fprintf(&body, "198.18.%d.%d/32\n", i/256, i%256)
	}
	return body.String()
}
