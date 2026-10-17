package grpcapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

// Zeroize must not leave the feed shrink-guard high-water history behind
// (#12170).
//
// The daemon persists each feed's cumulative-shrink epoch (count + content
// hash) in /var/lib/xpf/feed-shrink-history.json and restores it by feed NAME
// before producers start. None of the wipe legs covered it, so a re-tenanted
// device handed the NEXT tenant's same-named feed the PRIOR tenant's epoch:
// the first fetch bootstraps fine, but every later fetch is compared against
// the inherited high-water mark and refused as a drastic shrink — the feed
// freezes at its first fetch until an operator acknowledges a refusal for a
// baseline that was never theirs.
//
// The cells below pin the fix end to end: a hermetic full wipe must erase the
// history file on BOTH entry paths (gated pending + ungated), the final
// verification must catch a reappeared file, and a fresh feed manager restored
// from the post-wipe state must bootstrap the same name with no inherited
// epoch.

const feedHistory12170 = "stable-feed"

// seedFeedHistory12170 writes a prior-tenant epoch for feedHistory12170: a
// 64-prefix high-water mark through the seam path the wipe must erase.
func seedFeedHistory12170(t *testing.T, path string) {
	t.Helper()
	payload, err := json.Marshal([]feeds.ShrinkHighWater{{
		Name:  feedHistory12170,
		Count: 64,
		Hash:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}})
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, path, payload)
}

// readFeedHistory12170 loads the seam history file the way the daemon does:
// an absent file means no remembered epochs.
func readFeedHistory12170(t *testing.T, path string) []feeds.ShrinkHighWater {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	var records []feeds.ShrinkHighWater
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	return records
}

// serveFeed12170 serves the initial larger prefix set, then swaps to the
// smaller set so one server drives both bootstrap and shrink-candidate fetches.
func serveFeed12170(t *testing.T, big, small int) (url string, cert *x509.Certificate, swap func()) {
	t.Helper()
	var mu sync.RWMutex
	body := feedBody12170(big)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL, server.Certificate(), func() {
		mu.Lock()
		body = feedBody12170(small)
		mu.Unlock()
	}
}

func feedBody12170(count int) string {
	var out strings.Builder
	for i := range count {
		_, _ = fmt.Fprintf(&out, "198.18.%d.%d/32\n", i/256, i%256)
	}
	return out.String()
}

// waitFeedPrefixes12170 waits for the feed to install exactly count prefixes.
func waitFeedPrefixes12170(t *testing.T, m *feeds.Manager, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if info, ok := m.AllFeeds()[feedHistory12170]; ok && info.Prefixes == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("feed did not install %d prefixes; status=%+v", count, m.AllFeeds()[feedHistory12170])
}

// newFeedManager12170 builds a fresh manager over url the way a rebooted
// daemon would: restore the durable epochs first, then Apply the same name.
func newFeedManager12170(t *testing.T, url string, cert *x509.Certificate, historyPath string) *feeds.Manager {
	t.Helper()
	m := feeds.New(func() error { return nil })
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	{
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		m.SetLabFeedTLSRoots(pool)
	}
	m.RestoreShrinkHighWater(readFeedHistory12170(t, historyPath))
	m.Apply(context.Background(), &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{
		"server": {Name: "server", URL: url, FeedName: feedHistory12170, UpdateInterval: 1},
	}})
	t.Cleanup(m.StopAll)
	return m
}

// setupWipe12170 builds a hermetic config root with a seeded prior-tenant
// history file and returns its paths.
func setupWipe12170(t *testing.T) (root, configDir, historyPath string) {
	t.Helper()
	root = t.TempDir()
	hermeticWipe10100(t, root)
	configDir = filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))
	historyPath = filepath.Join(root, "var", "lib", "xpf", "feed-shrink-history.json")
	seedFeedHistory12170(t, historyPath)
	return root, configDir, historyPath
}

func assertHistoryErased12170(t *testing.T, historyPath string) {
	t.Helper()
	if _, err := os.Lstat(historyPath); !os.IsNotExist(err) {
		t.Fatalf("#12170: %s survived the factory reset: the next tenant's same-named "+
			"feed inherits the prior tenant's shrink-guard epoch (err=%v)", historyPath, err)
	}
}
func seedFeedHistoryCrashTemp12170(t *testing.T, historyPath string) string {
	t.Helper()
	tempPath := filepath.Join(filepath.Dir(historyPath), "."+filepath.Base(historyPath)+".tmp-seeded")
	if err := os.MkdirAll(filepath.Dir(historyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`[{"name":"prior-tenant-threat-feed","count":64,"hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]`)
	if err := os.WriteFile(tempPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return tempPath
}

func assertFeedHistoryCrashTempsErased12170(t *testing.T, historyPath string) {
	t.Helper()
	temps, err := feeds.ListShrinkHistoryCrashTemps(historyPath)
	if err != nil {
		t.Fatalf("list feed history crash temps: %v", err)
	}
	if len(temps) != 0 {
		t.Fatalf("feed history crash temps survived: %v", temps)
	}
}

// RED on revert: without the wipe leg the seeded history survives the gated
// (pending) path — the production daemon-gated zeroize.
func TestZeroizeErasesFeedShrinkHistoryPending12170(t *testing.T) {
	root, configDir, historyPath := setupWipe12170(t)
	tempPath := seedFeedHistoryCrashTemp12170(t, historyPath)
	helperPath := filepath.Join(root, "custom", "userspace-dp.json")
	if err := PerformZeroizeWipePending(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperPath); err != nil {
		t.Fatalf("PerformZeroizeWipePending: %v", err)
	}
	assertHistoryErased12170(t, historyPath)
	if _, err := os.Lstat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("feed history crash temp survived pending wipe: %v", err)
	}
	assertFeedHistoryCrashTempsErased12170(t, historyPath)
}

// RED on revert: without the wipe leg the seeded history survives the ungated
// (offline console) path too.
func TestZeroizeErasesFeedShrinkHistoryUngated12170(t *testing.T) {
	root, configDir, historyPath := setupWipe12170(t)
	tempPath := seedFeedHistoryCrashTemp12170(t, historyPath)
	helperPath := filepath.Join(root, "custom", "userspace-dp.json")
	if err := PerformZeroizeWipeUngated(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperPath); err != nil {
		t.Fatalf("PerformZeroizeWipeUngated: %v", err)
	}
	assertHistoryErased12170(t, historyPath)
	if _, err := os.Lstat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("feed history crash temp survived ungated wipe: %v", err)
	}
	assertFeedHistoryCrashTempsErased12170(t, historyPath)
}

// RED on revert: a history file that reappears after the wipe legs (a
// fence-escaper writer completing a full save) must fail final verification
// rather than clear the markers over it.
func TestFinalEraseVerificationCatchesReappearedFeedHistory12170(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	historyPath := filepath.Join(root, "var", "lib", "xpf", "feed-shrink-history.json")
	seedFeedHistory12170(t, historyPath)
	err := zeroizeFinalEraseVerification(zeroizeComplete)
	if err == nil {
		t.Fatal("reappeared feed history must fail final verification, got nil")
	}
	if !strings.Contains(err.Error(), historyPath) {
		t.Fatalf("final-verification error %q does not name feed-history path %s", err, historyPath)
	}
}
func TestFinalEraseVerificationCatchesFeedHistoryCrashTemp12170(t *testing.T) {
	root := t.TempDir()
	isolateZeroizeSealPaths(t, root)
	historyPath := filepath.Join(root, "var", "lib", "xpf", "feed-shrink-history.json")
	tempPath := seedFeedHistoryCrashTemp12170(t, historyPath)
	err := zeroizeFinalEraseVerification(zeroizeComplete)
	if err == nil {
		t.Fatal("reappeared feed history crash temp must fail final verification, got nil")
	}
	if !strings.Contains(err.Error(), "feed shrink history crash temps") ||
		!strings.Contains(err.Error(), tempPath) {
		t.Fatalf("final-verification error %q does not name feed-history crash temp %s", err, tempPath)
	}
}

// RED on revert: the end-to-end re-tenant unfreeze. After a gated zeroize, a
// fresh feed manager (a rebooted daemon) restores from the post-wipe state and
// fetches the SAME feed name with smaller content. Without the wipe leg, the
// inherited 64-prefix epoch refuses a 30-prefix candidate; with the wipe, the
// new tenant's 40-prefix baseline accepts it because the decrease is below
// the configured 16-prefix minimum drop.
func TestZeroizeFreesSameNameFeedFromPriorEpoch12170(t *testing.T) {
	root, configDir, historyPath := setupWipe12170(t)
	helperPath := filepath.Join(root, "custom", "userspace-dp.json")
	if err := PerformZeroizeWipePending(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperPath); err != nil {
		t.Fatalf("PerformZeroizeWipePending: %v", err)
	}

	url, cert, swap := serveFeed12170(t, 40, 30)
	fresh := newFeedManager12170(t, url, cert, historyPath)
	waitFeedPrefixes12170(t, fresh, 40)
	if info := fresh.AllFeeds()[feedHistory12170]; info.ShrinkRefused {
		t.Fatalf("same-name bootstrap must install before the next fetch: %+v", info)
	}
	priorHistoryPath := filepath.Join(root, "prior-tenant", "feed-shrink-history.json")
	seedFeedHistory12170(t, priorHistoryPath)
	priorEpoch := newFeedManager12170(t, url, cert, priorHistoryPath)
	waitFeedPrefixes12170(t, priorEpoch, 40)
	if info := priorEpoch.AllFeeds()[feedHistory12170]; info.ShrinkGuardHighWaterCount != 64 {
		t.Fatalf("control manager did not restore the prior 64-prefix epoch: %+v", info)
	}

	// A candidate of 30 would be refused against the leaked prior-tenant
	// baseline (retained 47% of 64), but it is only a ten-prefix decrease from
	// this tenant's 40-prefix bootstrap and must install under minDrop=16.
	swap()
	deadline := time.Now().Add(10 * time.Second)
	for {
		info := fresh.AllFeeds()[feedHistory12170]
		priorInfo := priorEpoch.AllFeeds()[feedHistory12170]
		if info.ShrinkRefused {
			t.Fatalf("#12170: new tenant's 30-prefix feed was refused against a leaked prior epoch: %+v", info)
		}
		if priorInfo.ShrinkRefused {
			if priorInfo.ShrinkCandidateOldCount != 64 || priorInfo.Prefixes != 40 {
				t.Fatalf("64-prefix control did not refuse 30 against its prior epoch: %+v", priorInfo)
			}
			if info.Prefixes == 30 {
				break
			}
		} else if priorInfo.Prefixes == 30 {
			t.Fatalf("control manager installed 30 prefixes despite its 64-prefix epoch: %+v", priorInfo)
		}
		if time.Now().After(deadline) {
			t.Fatalf("fresh candidate/control refusal did not resolve: fresh=%+v control=%+v", info, priorInfo)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if info := fresh.AllFeeds()[feedHistory12170]; info.ShrinkGuardHighWaterCount != 40 {
		t.Fatalf("installed candidate must retain the new tenant's 40-prefix epoch: high-water=%d (%+v)",
			info.ShrinkGuardHighWaterCount, info)
	}
}
