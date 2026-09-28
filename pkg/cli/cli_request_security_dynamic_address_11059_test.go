package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

func TestLocalDynamicAddressShrinkAckRequiresConfigPermissionAndInstallsCurrentCandidate11059(t *testing.T) {
	var mu sync.RWMutex
	prefixCount := 100
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		count := prefixCount
		mu.RUnlock()
		for i := 0; i < count; i++ {
			_, _ = fmt.Fprintf(w, "198.51.100.%d/32\n", i)
		}
	}))
	defer server.Close()

	manager := feeds.New(nil)
	manager.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		manager.StopAll()
	}()
	manager.Apply(ctx, &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
		"test-server": {
			Name: "test-server", URL: server.URL, FeedName: "ack-feed", UpdateInterval: 1,
		},
	}})

	waitForFeed := func(t *testing.T, predicate func(feeds.FeedInfo) bool) feeds.FeedInfo {
		t.Helper()
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			info, ok := manager.AllFeeds()["ack-feed"]
			if ok && predicate(info) {
				return info
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for feed state: %+v", manager.AllFeeds()["ack-feed"])
		return feeds.FeedInfo{}
	}
	waitForFeed(t, func(info feeds.FeedInfo) bool { return info.Prefixes == 100 && !info.LastFetch.IsZero() })

	mu.Lock()
	prefixCount = 5
	mu.Unlock()
	refused := waitForFeed(t, func(info feeds.FeedInfo) bool { return info.ShrinkRefused })

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	cli := &CLI{
		store:      store,
		uid:        4242,
		username:   "operator",
		userClass:  "operator",
		feedsFn:    manager.AllFeeds,
		feedsAckFn: manager.AcknowledgeFeedShrink,
	}
	command := fmt.Sprintf("request security dynamic-address acknowledge-shrink ack-feed candidate-id %d reason provider confirmed intended scope", refused.ShrinkRefusalID)
	if err := cli.dispatchOperational(command); err == nil || !strings.Contains(err.Error(), "requires a higher login class") {
		t.Fatalf("operator class did not require configure permission: %v", err)
	}
	if info := manager.AllFeeds()["ack-feed"]; !info.ShrinkRefused || info.ShrinkAckPending {
		t.Fatalf("permission-denied acknowledgement changed feed state: %+v", info)
	}

	cli.userClass = "super-user"
	captureStdout(t, func() {
		if err := cli.dispatchOperational(command); err != nil {
			t.Fatalf("authorized local acknowledgement: %v", err)
		}
	})
	armed := manager.AllFeeds()["ack-feed"]
	wantActor := "source=local-shell;uid=4242;user=operator;class=super-user;session=none"
	if !armed.ShrinkAckPending || armed.ShrinkAckActor != wantActor || armed.ShrinkAckReason != "provider confirmed intended scope" {
		t.Fatalf("local command did not arm the current candidate with its authenticated actor: %+v", armed)
	}
	installed := waitForFeed(t, func(info feeds.FeedInfo) bool {
		return info.Prefixes == 5 && !info.ShrinkRefused && !info.ShrinkAckPending
	})
	if installed.ShrinkRefusalID != refused.ShrinkRefusalID {
		t.Fatalf("acknowledgement installed an unrelated candidate: refusal ID changed %d -> %d", refused.ShrinkRefusalID, installed.ShrinkRefusalID)
	}
}
