package daemon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// Keep guard epochs outside active config so same-name feeds retain their
// review baseline across both config removal and daemon restart.
var (
	feedShrinkHistoryPath      = "/var/lib/xpf/feed-shrink-history.json"
	feedShrinkHistoryWriteLock sync.Mutex
)

// ensureFeedManager lazily constructs the dynamic-address feed manager with the
// onUpdate callback that recompiles the dataplane when a feed refresh changes
// the prefix set (#5036). It is idempotent and, in production, is called once
// during single-threaded startup BEFORE the gRPC/HTTP servers accept requests,
// so d.feeds is set exactly once and never reassigned — its pointer stays
// race-free for the concurrent AllFeeds() readers on the show paths. The
// manager holds no refresh goroutines until Apply is called with a non-empty
// feed-server set (reconcileFeeds).
func (d *Daemon) ensureFeedManager() {
	if d.feeds != nil {
		return
	}
	manager := feeds.New(d.onFeedUpdate)
	manager.RestoreShrinkHighWater(readFeedShrinkHistory())
	manager.SetShrinkHighWaterChangedCallback(func() {
		persistFeedShrinkHistory(manager)
	})
	d.feeds = manager
}

func readFeedShrinkHistory() []feeds.ShrinkHighWater {
	data, err := os.ReadFile(feedShrinkHistoryPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		slog.Warn("dynamic-address: failed to read persisted shrink high-water history", "path", feedShrinkHistoryPath, "err", err)
		return nil
	}
	var records []feeds.ShrinkHighWater
	if err := json.Unmarshal(data, &records); err != nil {
		slog.Warn("dynamic-address: invalid persisted shrink high-water history", "path", feedShrinkHistoryPath, "err", err)
		return nil
	}
	return records
}

func persistFeedShrinkHistory(manager *feeds.Manager) {
	if manager == nil {
		return
	}
	feedShrinkHistoryWriteLock.Lock()
	defer feedShrinkHistoryWriteLock.Unlock()
	data, err := json.Marshal(manager.ShrinkHighWaterSnapshot())
	if err != nil {
		slog.Warn("dynamic-address: failed to encode shrink high-water history", "err", err)
		return
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(feedShrinkHistoryPath), 0o700); err != nil {
		slog.Warn("dynamic-address: failed to create shrink high-water history directory", "path", feedShrinkHistoryPath, "err", err)
		return
	}
	if err := fsatomic.WriteFileDurable(feedShrinkHistoryPath, data, 0o600); err != nil {
		slog.Warn("dynamic-address: failed to persist shrink high-water history", "path", feedShrinkHistoryPath, "err", err)
	}
}

// onFeedUpdate is the dynamic-address feed manager's publication callback.
//
// It is a named method rather than an inline closure so a test can drive the
// REAL callback. The property that matters here is WHICH entry point this site
// calls: a test that invokes applyActiveConfigResult directly binds the
// function while leaving the wiring free to regress back to a pre-captured
// config (#6716).
func (d *Daemon) onFeedUpdate() error {
	slog.Info("dynamic-address feed updated, recompiling dataplane")
	if d.store == nil || d.store.ActiveConfig() == nil {
		// No active config to apply the feed content against yet (pre-boot
		// window). Treat as a vacuous success — there is no policy enforcing
		// this feed, and the normal commit path re-reads the live feed
		// snapshot when a config is committed. Returning nil lets the feed
		// manager record the content as published so it does not spin.
		return nil
	}
	// #5646: return the apply RESULT to the feed manager. A rejected apply
	// (preflight reject, compile failure, control-socket error) must NOT be
	// recorded as published, so the next identical feed refetch retries the
	// apply instead of silently dropping the good content (publication debt).
	//
	// #6716: applyActiveConfigResult re-reads the active config under applySem.
	// The nil check above is only the pre-boot guard — a config read out here
	// and applied would revert a commit that landed during the semaphore wait.
	if d.preApplyHookForTest != nil {
		d.preApplyHookForTest()
	}
	return d.applyActiveConfigResult()
}

// feedsConfigHash returns a stable hash over the feed-SERVER configuration that
// governs the running feed-producer set (#5036). It deliberately EXCLUDES
// AddressBindings: bindings drive the per-apply snapshot overlay
// (feedSnapshotsForConfig), not the producer goroutines, so a binding-only
// change must not trigger a producer swap/restart of the fetchers. FeedServers is a
// Go map (nondeterministic iteration), so it is serialized in sorted key order
// with each server's URL/hostname, intervals, shrink-guard thresholds, single
// feed-name, and feed entries (also sorted) — matching every input feeds.Apply's
// plan builder reads.
func feedsConfigHash(da *config.DynamicAddressConfig) [32]byte {
	if da == nil {
		return sha256.Sum256(nil)
	}
	names := make([]string, 0, len(da.FeedServers))
	for name := range da.FeedServers {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fs := da.FeedServers[name]
		if fs == nil {
			continue
		}
		fmt.Fprintf(&b, "S|%s|%s|%s|%d|%d|%s|%d|%d|%d\n",
			name, fs.URL, fs.Hostname, fs.UpdateInterval, fs.HoldInterval, fs.FeedName,
			fs.ShrinkGuardMinOldCount, fs.ShrinkGuardMinRetainPercent, fs.ShrinkGuardMinDrop)
		entries := append([]config.FeedEntry(nil), fs.FeedEntries...)
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Name != entries[j].Name {
				return entries[i].Name < entries[j].Name
			}
			return entries[i].Path < entries[j].Path
		})
		for _, fe := range entries {
			fmt.Fprintf(&b, "E|%s|%s\n", fe.Name, fe.Path)
		}
	}
	return sha256.Sum256([]byte(b.String()))
}

// reconcileFeeds brings the running dynamic-address feed-producer set into
// correspondence with cfg on every applied config generation (#5036).
//
// Before this the feed manager was constructed ONCE at boot and only if
// boot-time feed servers existed, and Manager.Apply was never re-invoked. So a
// feed server ADDED on a later commit was silently ignored (a deny policy bound
// to the new dynamic address armed with zero prefixes — fail-open for deny),
// and a changed/removed server leaked its refresh goroutine and stale snapshot
// namespace until restart.
//
// The manager is now constructed unconditionally at boot (ensureFeedManager),
// so it is always non-nil here; Apply — which swaps to the desired producer set,
// carrying each persisted feed's last-good snapshot forward so a reconfigure
// never opens a fail-open denylist window (#5282) — is gated on feedsConfigHash
// so it runs ONLY when the feed-server configuration actually changes. A feed
// CONTENT refresh re-enters
// applyConfig via the onUpdate callback but leaves the hash unchanged, so it
// does not thrash the fetchers. Callers MUST invoke this BEFORE reading the
// feed overlay (feedSnapshotsForConfig) so the overlay reflects the reconciled
// generation. Apply uses d.daemonCtx (daemon lifetime) so the refresh
// goroutines outlive the request-scoped apply.
func (d *Daemon) reconcileFeeds(cfg *config.Config) {
	if d == nil || d.daemonCtx == nil || cfg == nil || d.feeds == nil {
		return
	}
	da := &cfg.Security.DynamicAddress
	h := feedsConfigHash(da)

	d.feedsMu.Lock()
	defer d.feedsMu.Unlock()
	if h == d.activeFeedsHash {
		return
	}
	d.feeds.Apply(d.daemonCtx, da)
	d.activeFeedsHash = h
	slog.Info("dynamic-address feed producers reconciled", "feed_servers", len(da.FeedServers))
}

// feedSnapshotSetter caches the dynamic-address feed-prefix overlay for the
// next full snapshot build (#2049). Implemented by the userspace dataplane
// manager (SetFeedSnapshots), mirroring routeOverlaySetter.
type feedSnapshotSetter interface {
	SetFeedSnapshots(map[string][]string)
}

// feedSnapshotsForConfig joins the INCOMING config's dynamic-address bindings
// to the live feed snapshots held by the feed manager (#2049). The result is
// an address-name -> union-of-feed-CIDRs overlay that the dataplane manager
// merges into the address book the AF_XDP helper enforces.
//
// Filtering against cfg (not the active config) means a commit that REMOVES or
// edits a binding stops enforcing the removed feed — the overlay only carries
// names that the incoming config still binds. Returns nil when there is no
// feed manager or the config declares no bindings, in which case the dataplane
// clears its overlay (no feed-backed names to enforce).
func (d *Daemon) feedSnapshotsForConfig(cfg *config.Config) map[string][]string {
	if d == nil || d.feeds == nil || cfg == nil {
		return nil
	}
	if len(cfg.Security.DynamicAddress.AddressBindings) == 0 {
		return nil
	}
	return d.feeds.SnapshotForBindings(&cfg.Security.DynamicAddress)
}
