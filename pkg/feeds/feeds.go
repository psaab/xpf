// Package feeds implements dynamic address feed fetching and management.
package feeds

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// retainForever is the sentinel holdInterval meaning "never auto-drop the
// last-good snapshot to empty on persistent failure". This is the DEFAULT
// (operator decision, #2050): a stale DENYLIST that fail-OPENs to empty is
// worse than a stale-but-enforced set, so an unset/zero hold-interval retains
// the last-good snapshot INDEFINITELY. The drop-after-N-seconds behaviour is
// now strictly opt-in via an explicit positive hold-interval.
const retainForever time.Duration = 0

// maxLineBytes is the per-line scanner token cap. The default bufio.Scanner cap
// is 64 KB; a single overlong line silently truncates the whole set with the
// default cap, so we raise it. A line longer than this is treated as a failed
// fetch (bufio.ErrTooLong) rather than a silent truncation — see fetchFeed.
const maxLineBytes = 1 << 20 // 1 MiB

// maxInvalidSample bounds how many distinct malformed lines are retained for
// operator display (#2993). A degraded feed records the total invalid-line
// count plus a small sample so an operator can identify the bad lines without
// the sample growing unbounded for a wholesale-garbage body. This is a COUNT
// bound; each retained entry is additionally BYTE-bounded (see
// maxInvalidSampleBytes, #4922).
const maxInvalidSample = 5

// maxInvalidSampleBytes caps the RAW byte prefix of a single malformed line
// retained in the sample (#4922). A malformed line may be up to maxLineBytes
// (1 MiB) long; the pre-#4922 code appended the whole line VERBATIM, so a
// hostile/broken provider serving near-1-MiB malformed lines could pin ~5 MiB
// of garbage in memory (retained in feedState, deep-copied by AllFeeds) and emit
// multi-MB slog records on the degraded-feed warning — all within the advertised
// feed limits. We now keep only the first maxInvalidSampleBytes bytes of each
// offending line, escaped to a printable form, plus its true byte length, so an
// operator can still triage "line was 1 MiB, starts with <prefix>" without
// retaining the whole thing.
const maxInvalidSampleBytes = 256

// maxInvalidSampleEntryBytes is the HARD per-entry ceiling on a retained sample
// string AFTER escaping + length annotation (#4922). strconv.Quote can expand
// each raw byte to a 4-char \xNN escape, so a maxInvalidSampleBytes-byte prefix
// quotes to at most 4*maxInvalidSampleBytes+2 chars; the truncation annotation
// (" … (<n> bytes total)") adds a small bounded suffix. This constant is the
// assertion anchor for the #4922 fail-on-revert test and the defensive final
// clamp in boundInvalidSample.
const maxInvalidSampleEntryBytes = 4*maxInvalidSampleBytes + 64

// maxInvalidSampleTotalBytes is a belt-and-suspenders ceiling on the SUM of the
// retained sample entry lengths across all maxInvalidSample entries (#4922).
// The per-entry cap already bounds each string; this aggregate budget is a live
// second guard so even a future change that loosens the per-entry cap cannot
// grow the retained sample without bound. In the current tuning it equals the
// count cap times the per-entry cap, so the worst legitimate case (5 fully
// escaped 256-byte prefixes) fits exactly and the gate degrades gracefully only
// if the per-entry cap is later raised.
const maxInvalidSampleTotalBytes = maxInvalidSample * maxInvalidSampleEntryBytes

// maxFeedBodyBytes caps the total HTTP response body a single feed fetch will
// buffer (#3934). Without a cap, a feed server that returns a huge (or
// infinite/chunked) body — or a MITM on a plaintext-http feed URL — can make
// the fetcher buffer an arbitrarily large body into memory and OOM the daemon
// (a remote-triggerable DoS). The body is read through an io.LimitReader; a
// body exceeding this cap fails the whole fetch (retain last-good) rather than
// buffering unboundedly. 32 MiB is comfortably above any legitimate CIDR feed
// yet well under the 64 MiB userspace-dp control-request cap
// (MaxControlRequestBytes, #2744) so a single feed cannot dominate the apply
// snapshot.
const maxFeedBodyBytes = 32 << 20 // 32 MiB

// maxFeedPrefixes caps the number of parsed entries a single feed may install
// (#3934). This is a secondary guard on top of the byte cap: a body of many
// short lines (e.g. bare IPv4 addresses) can stay under the byte cap while
// producing an entry count that would blow the dataplane address-book map. A
// feed exceeding this count fails the whole fetch (retain last-good) — a
// partial-but-huge set is never installed. The count is measured on parsed
// (pre-dedup) entries so memory is bounded during the parse loop.
const maxFeedPrefixes = 1 << 20 // 1,048,576 entries

// httpClientTimeout bounds a single feed fetch end-to-end (connect + headers +
// body read), so a slow-loris feed server that dribbles bytes cannot hold the
// fetch open indefinitely (#3934). The next refresh tick retries.
const httpClientTimeout = 30 * time.Second

// Manager manages dynamic address feed servers and their periodic updates.
type Manager struct {
	mu     sync.RWMutex
	feeds  map[string]*feedState // keyed by feed-name (or feed-server name for single-feed servers)
	client *http.Client
	// onUpdate is the publish callback invoked when a feed refresh produces
	// content that must be (re-)applied to the dataplane. It RETURNS the apply
	// result: a nil return means the content was ACCEPTED (applied), a non-nil
	// return means the apply was REJECTED (preflight reject, compile failure,
	// control-socket error, ...). installSnapshot advances its per-feed
	// publishedHash only on a nil return, so a rejected apply leaves publication
	// debt that the next identical refetch retries — closing #5646 (the pre-fix
	// void callback committed the content hash regardless of the apply result,
	// so an identical refetch saw "unchanged" and the good content sat
	// un-enforced forever).
	onUpdate func() error // callback when feeds are updated; returns apply result

	// now is the clock source, overridable in tests for HoldInterval timing.
	now func() time.Time
}

type feedState struct {
	name string // feed-name or server name
	url  string // fully resolved URL
	// holdInterval is the retain-last-good window on persistent fetch failure.
	// retainForever (0) — the default — means NEVER auto-drop the last-good
	// snapshot to empty; only an explicit positive value arms the
	// drop-after-N-seconds opt-in.
	holdInterval time.Duration

	// Active enforced snapshot (canonicalized, deduped, sorted).
	prefixes    []string
	hash        [32]byte // sha256 over the canonical join; zero when no snapshot
	hasSnapshot bool     // true once a good fetch has installed a snapshot

	// publishedHash is the content hash of the snapshot last CONFIRMED applied
	// to the dataplane — it advances ONLY when the onUpdate publish callback
	// returns nil (apply ACCEPTED). It is deliberately decoupled from hash (the
	// hash of the currently-INSTALLED snapshot): installSnapshot always commits
	// hash to the freshly-fetched content, but fires onUpdate whenever the
	// fetched content differs from publishedHash — not merely from hash. A
	// REJECTED apply therefore leaves publishedHash stale, so an identical
	// refetch still re-fires onUpdate and RETRIES the publish, closing the #5646
	// publication-debt window (the pre-fix code keyed the retry decision off
	// hash, which committed before the void callback, so a rejected apply
	// suppressed every later identical refetch and the good content was never
	// enforced). hasPublished distinguishes "never successfully published" (zero
	// publishedHash) from a genuine all-zero digest, mirroring hasSnapshot.
	publishedHash [32]byte
	hasPublished  bool

	// Parse-quality of the INSTALLED snapshot (#2993). A feed body may mix
	// valid + invalid lines: the valid prefixes are installed but the skipped
	// invalid lines are no longer silent. invalidLines counts every malformed
	// line in the last successfully-installed body; invalidSample keeps up to
	// maxInvalidSample offenders for display, each a byte-bounded, escaped
	// prefix + length annotation (#4922), NOT the verbatim line. Both are
	// zero/nil for a clean body (no behaviour change) and are cleared on a
	// drop-to-empty.
	invalidLines  int
	invalidSample []string

	// Fetch status (separate from the active snapshot).
	lastFetch   time.Time // last SUCCESSFUL fetch (kept name for show-path compat)
	lastSuccess time.Time // alias of lastFetch; explicit success timestamp
	lastError   string    // most recent fetch/parse error ("" when last fetch was good)
	staleSince  time.Time // set when a fetch fails while a good snapshot is retained

	cancel context.CancelFunc
	// done is closed by refreshLoop on exit. #7174 C12a: StopAll waits on it,
	// mirroring pkg/dhcp's dc.done and pkg/rpm's m.wg — the two sibling managers
	// in this daemon that already cancel-and-JOIN. feeds was the only one that
	// cancelled and returned, which made "stopped" mean "asked to stop".
	done chan struct{}
}

// New creates a new feed manager.
// onUpdate is called whenever a feed refresh produces content that differs from
// what was last SUCCESSFULLY applied (not merely a count change, and not merely
// a difference from the last FETCH). It RETURNS the apply result: a nil return
// records the content as published (a later identical refetch is suppressed —
// no thrash), a non-nil return leaves the content unpublished so the next
// identical refetch retries the apply on the normal refresh cadence (#5646).
func New(onUpdate func() error) *Manager {
	return &Manager{
		feeds: make(map[string]*feedState),
		client: &http.Client{
			Timeout: httpClientTimeout,
		},
		onUpdate: onUpdate,
		now:      time.Now,
	}
}

// resolveBaseURL returns the base URL for a feed server.
// Prefers explicit URL; falls back to https://hostname.
func resolveBaseURL(fsCfg *config.FeedServer) string {
	if fsCfg.URL != "" {
		return strings.TrimRight(fsCfg.URL, "/")
	}
	if fsCfg.Hostname != "" {
		return "https://" + strings.TrimRight(fsCfg.Hostname, "/")
	}
	return ""
}

// warnPlaintextFeed emits a one-time (per Apply) warning when a feed URL uses
// plaintext http:// (#3934). A plaintext feed has no transport integrity: a
// MITM can substitute an arbitrary body (including an over-size body aimed at
// the OOM path guarded by maxFeedBodyBytes, or a hostile prefix set). https
// is strongly preferred for any denylist/allowlist source.
func warnPlaintextFeed(name, url string) {
	if strings.HasPrefix(strings.ToLower(url), "http://") {
		slog.Warn("dynamic-address: feed URL is plaintext http (no integrity — a MITM can substitute the feed body); prefer https",
			"name", name, "url", config.RedactURL(url))
	}
}

// resolveHoldInterval maps the configured hold-interval (seconds) to a
// duration. An UNSET (zero) or negative value means retainForever — the
// last-good snapshot is kept indefinitely on persistent failure, never
// auto-dropped to empty (#2050 operator decision: never fail-OPEN a stale
// denylist). Only an explicit positive value arms the drop-after-N-seconds
// opt-in.
func resolveHoldInterval(seconds int) time.Duration {
	if seconds <= 0 || int64(seconds) > config.MaxDurationSeconds {
		return retainForever
	}
	return time.Duration(seconds) * time.Second
}

// feedIntervalSeconds converts a feed `seconds` knob to a Duration, falling
// back for anything outside the accepted range.
//
// #8597 (muse-004 K34), the sibling of the #6769 flow-export fix and the #5723
// RPM fix that were never brought along to this package. `update-interval` and
// `hold-interval` are bounded to [1, config.MaxDurationSeconds] by the strict
// schema (schema_security.go), but the compiler stores them as a plain int from
// strconv.Atoi with NO range check, and the lenient HA-sync / on-disk Load
// ingress DOWNGRADES an out-of-range value to a warning rather than rejecting
// it (#1960 no-brick). So a peer-synced or persisted pathological value reaches
// this package unbounded.
//
// The multiply overflows int64 nanoseconds past MaxDurationSeconds, and the
// wrapped product can be small and POSITIVE — the dangerous half, because both
// consumers only reject `<= 0`. gcd(1e9, 2^64) = 512, so the smallest positive
// residue is 512ns: `update-interval 20211507185753197` armed a 512ns ticker,
// i.e. a self-inflicted HTTP fetch storm against every feed server.
//
// Falling back rather than clamping to the maximum is the #6769 decision,
// reused deliberately: a value this far out of range is a typo or a hostile
// config, not an operator asking for the largest window we allow.
//
// The direction each fallback errs in:
//   - update-interval falls back to the 1h default, so a wrapped value refreshes
//     LESS often, never more. The failure it prevents is availability.
//   - hold-interval falls back to retainForever, so a wrapped value KEEPS the
//     last-good snapshot instead of dropping a DENY feed to empty. That is the
//     #2050 fail-closed direction; the wrap's own behaviour was the opposite,
//     turning "retain forever" into "drop after 512ns of failure".
func feedIntervalSeconds(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 || int64(seconds) > config.MaxDurationSeconds {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// Apply configures feeds from the given dynamic address config.
// Starts background refresh goroutines for each feed server.
// When a feed-server has FeedEntries, each entry becomes a separate feed
// keyed by the feed-name with its per-feed path appended to the base URL.
func (m *Manager) Apply(ctx context.Context, daCfg *config.DynamicAddressConfig) {
	// Build a COMPLETE, deterministic, de-duplicated plan BEFORE mutating
	// m.feeds (#4913, #5282). daCfg.FeedServers is a Go map, so ranging it
	// visits servers in nondeterministic order, and two feed-servers can
	// declare the SAME effective feed name. The pre-#4913 loop assigned
	// m.feeds[name] = fs and started a refresh loop per entry as it went, so a
	// duplicate name OVERWROTE the earlier map entry — orphaning that worker's
	// cancel func (a cancel then reached only the survivor, so the overwritten
	// loop kept fetching / logging / firing onUpdate until the daemon's parent
	// context ended) — and enforcement read whichever provider won the last map
	// iteration (nondeterministic across commits / restarts). Sorting the
	// server keys and keeping only the FIRST occurrence of each effective feed
	// name makes the winner deterministic and guarantees exactly one refresh
	// loop — hence exactly one cancel — per name, so no goroutine is orphaned.
	//
	// Building the plan up front (rather than the pre-#5282 StopAll-then-empty
	// first step) is also what lets a PERSISTED feed carry its last-good
	// snapshot forward across the reconfigure — see the swap below.
	type feedPlan struct {
		name     string
		url      string
		hold     time.Duration
		interval time.Duration
		server   string
	}
	var plans []feedPlan
	if daCfg != nil && len(daCfg.FeedServers) > 0 {
		serverNames := make([]string, 0, len(daCfg.FeedServers))
		for sn := range daCfg.FeedServers {
			serverNames = append(serverNames, sn)
		}
		sort.Strings(serverNames)

		seen := make(map[string]bool)
		for _, sn := range serverNames {
			fsCfg := daCfg.FeedServers[sn]
			if fsCfg == nil {
				continue
			}
			baseURL := resolveBaseURL(fsCfg)
			if baseURL == "" {
				continue
			}
			interval := feedIntervalSeconds(fsCfg.UpdateInterval, time.Hour)
			hold := resolveHoldInterval(fsCfg.HoldInterval)

			plan := func(name, url string) {
				if name == "" {
					return
				}
				if seen[name] {
					// A feed name is an identity: two feeds sharing one would race
					// on m.feeds[name] and orphan a refresh loop. Keep the first
					// (deterministic winner: lexicographically-first server, then
					// declaration order) and drop the duplicate with a warning. The
					// strict compile gate (validateDynamicAddressFeedNameUniqueness
					// Strict) rejects this at commit; this de-dup is the runtime
					// safety net for a leniently-loaded / peer-synced config.
					slog.Warn("dynamic-address: duplicate feed name ignored — only the first declaration starts a refresh loop (declare each feed name once)",
						"name", name, "server", fsCfg.Name, "url", url)
					return
				}
				seen[name] = true
				plans = append(plans, feedPlan{name: name, url: url, hold: hold, interval: interval, server: fsCfg.Name})
			}

			if len(fsCfg.FeedEntries) > 0 {
				// Multiple named feeds with per-feed paths.
				for _, fe := range fsCfg.FeedEntries {
					feedURL := baseURL
					if fe.Path != "" {
						p := fe.Path
						if !strings.HasPrefix(p, "/") {
							p = "/" + p
						}
						feedURL = baseURL + p
					}
					plan(fe.Name, feedURL)
				}
			} else {
				// Single feed (backward compat): keyed by FeedName or server name.
				key := fsCfg.FeedName
				if key == "" {
					key = fsCfg.Name
				}
				plan(key, baseURL)
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Swap the producer set under one lock (#5282). Cancel EVERY existing
	// producer — each captured its old URL/interval via its feedState, so even a
	// feed that persists (same name) with an edited URL/interval needs a fresh
	// refresh loop — but before discarding the old map, carry each PERSISTED
	// feed's last-good ENFORCED snapshot forward into its replacement feedState.
	//
	// This closes the fail-open denylist window that the pre-#5282
	// StopAll-then-empty-then-async-fetch sequence opened: Apply used to replace
	// m.feeds with an EMPTY map as its first step, so a still-present deny feed's
	// overlay compiled to match-NONE from that instant until its NEW fetch
	// landed asynchronously — and if the new endpoint was down, retainForever
	// pinned the EMPTY set indefinitely (traffic that should be DENIED was
	// ALLOWED). Carrying the snapshot forward keeps the last-good prefixes
	// enforced until the new fetch atomically replaces them (installSnapshot).
	//
	// A feed GENUINELY REMOVED from config has no entry in the new plan, so it
	// gets no replacement and its snapshot is dropped (correct — the operator
	// removed it). A brand-NEW feed has no prior snapshot to carry, so until its
	// first successful fetch SnapshotForBindings OMITS its binding (#5645) — the
	// referencing policy then fails CLOSED (unresolved name), not fail-open
	// match-none. This is the first-fetch analogue of the carry-forward below.
	old := m.feeds
	for _, fs := range old {
		if fs.cancel != nil {
			fs.cancel()
		}
	}

	newFeeds := make(map[string]*feedState, len(plans))
	for _, p := range plans {
		// Human-readable hold for the start log: retainForever (the default)
		// would otherwise log as "0s".
		holdStr := "forever"
		if p.hold > 0 {
			holdStr = p.hold.String()
		}
		feedCtx, cancel := context.WithCancel(ctx)
		fs := &feedState{
			name:         p.name,
			url:          p.url,
			holdInterval: p.hold,
			cancel:       cancel,
			done:         make(chan struct{}),
		}
		// Persisted feed (same name survives the reconfigure): inherit the
		// last-good snapshot so there is no fail-open window (#5282).
		if prev, ok := old[p.name]; ok {
			carryForwardSnapshot(fs, prev)
		}
		newFeeds[p.name] = fs
		warnPlaintextFeed(p.name, p.url)
		go m.refreshLoop(feedCtx, fs, p.interval)
		slog.Info("dynamic address feed started",
			"name", p.name, "server", p.server, "url", config.RedactURL(p.url),
			"interval", p.interval, "hold", holdStr,
			"carried_prefixes", len(fs.prefixes))
	}
	m.feeds = newFeeds
}

// carryForwardSnapshot copies a prior feedState's last-good ENFORCED snapshot
// (and its success / parse-quality metadata) into a freshly-built replacement
// during Apply, so a feed that PERSISTS across a reconfigure (same name,
// possibly new URL/interval) keeps enforcing its last-good prefixes until its
// NEW fetch lands and atomically replaces them (#5282). Without this a persisted
// deny feed would compile to match-none for the whole async re-fetch window —
// and indefinitely under retainForever if the new endpoint is down (fail-open).
//
// Both src and dst are accessed with m.mu held by the caller (Apply). The prior
// producer has already been cancelled; its snapshot fields are stable while the
// lock is held, and the slices are deep-copied so the orphaned old feedState
// cannot alias the live one after the lock is released.
//
// The retained FAILURE markers (lastError / staleSince) are intentionally NOT
// carried: the new endpoint gets a clean slate, and the first post-Apply fetch
// re-derives stale state via recordFailure (which re-arms staleSince because the
// carried snapshot is present). This also gives an opt-in hold-interval a FRESH
// window on the new endpoint rather than inheriting a partially-elapsed one — a
// strictly more conservative (later-dropping) choice for the fail-open guard.
func carryForwardSnapshot(dst, src *feedState) {
	if src == nil || !src.hasSnapshot || len(src.prefixes) == 0 {
		return
	}
	dst.prefixes = append([]string(nil), src.prefixes...)
	dst.hash = src.hash
	dst.hasSnapshot = true
	dst.lastFetch = src.lastFetch
	dst.lastSuccess = src.lastSuccess
	dst.invalidLines = src.invalidLines
	dst.invalidSample = append([]string(nil), src.invalidSample...)
	// Carry the published-hash tracking forward too (#5646). The prior
	// producer's snapshot is being re-enforced by the SAME applyConfigLocked
	// that runs this Apply (it reads SnapshotForBindings from the carried
	// prefixes), so its apply state is inherited: if the predecessor had
	// successfully published this content, the replacement inherits
	// publishedHash == hash and does NOT re-fire onUpdate on its first
	// identical refetch (preserves the #5282 no-thrash contract). If the
	// predecessor had unpublished publication DEBT (content fetched but its
	// apply kept being rejected), hasPublished is false here, so the
	// replacement's first fetch re-fires and retries — the debt is not lost
	// across a reconfigure.
	dst.publishedHash = src.publishedHash
	dst.hasPublished = src.hasPublished
}

// StopAll cancels all running feed refresh goroutines.
// #7174 C12a: cancel AND JOIN, mirroring pkg/dhcp's StopAll (`dc.cancel();
// <-dc.done`) and pkg/rpm's (`m.cancel(); m.wg.Wait()`). feeds was the third
// spelling of shutdown in one daemon, and the only one where StopAll could
// return with its goroutines still running.
//
// THE RISK IS CONFIG REPLACEMENT, NOT SHUTDOWN. On daemon exit an unjoined
// fetcher races process teardown and is mostly harmless. On a commit that
// REMOVES a feed, StopAll cleared m.feeds and returned while that feed's fetch
// was still in flight — so it could complete afterwards and install a snapshot
// for a feed the operator had just removed. A shutdown-framed reading of this
// misses that entirely, because teardown hides the window.
//
// Joining is cheap here and that is why it is the right answer rather than a
// bounded-wait hedge: the fetch runs under `http.NewRequestWithContext`, so
// cancelling ABORTS the in-flight request instead of waiting out the client
// timeout. The usual "joining could block for the HTTP timeout" objection is
// not true of this code.
//
// The snapshot-then-join shape (rather than joining under m.mu) is deliberate:
// refreshLoop takes m.mu to install a snapshot, so waiting for it while holding
// the lock would deadlock against the very goroutine being waited on.
func (m *Manager) StopAll() {
	m.mu.Lock()
	stopping := make([]*feedState, 0, len(m.feeds))
	for _, fs := range m.feeds {
		if fs.cancel != nil {
			fs.cancel()
		}
		stopping = append(stopping, fs)
	}
	m.feeds = make(map[string]*feedState)
	m.mu.Unlock()

	for _, fs := range stopping {
		if fs.done != nil {
			<-fs.done
		}
	}
}

// GetPrefixes returns the current enforced prefixes for a named feed.
//
// While a last-good snapshot is installed it is returned (retained
// indefinitely by default on persistent failure; see holdInterval). Before
// the first successful fetch — and after an explicit hold-interval drop —
// there is no snapshot and a non-nil empty slice is returned (fail-closed),
// so callers and JSON encoders see [] rather than null. An unknown feed name
// returns nil.
func (m *Manager) GetPrefixes(name string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if fs, ok := m.feeds[name]; ok {
		// Always return a non-nil slice for a known feed so a feed with no
		// installed snapshot marshals as [] (empty), not null. Copying with a
		// zero-cap make keeps the empty case non-nil.
		out := make([]string, len(fs.prefixes))
		copy(out, fs.prefixes)
		return out
	}
	return nil
}

// SnapshotForBindings resolves each dynamic-address binding to the union of
// its feed-backed prefixes, returning a deep copy keyed by address-name. This
// is the ENFORCEMENT accessor (#2049): the daemon hands the result into the
// userspace dataplane manager, which overlays the prefixes into the address
// book the AF_XDP helper enforces. It is the first production caller of the
// per-feed prefix snapshot — before #2049 the fetched prefixes were
// status-only and never reached the forwarding path.
//
// Resolution semantics:
//   - A binding's FeedNames are unioned (a binding may aggregate several
//     feeds). Prefixes are deduped across feeds and returned sorted.
//   - A binding is ENFORCEABLE only when EVERY one of its feed constituents has
//     an installed snapshot. If ANY feed is unready — before its first
//     successful fetch, an unknown/typo'd feed name, or after an explicit
//     hold-interval drop — the binding is UNRESOLVED and its name is OMITTED
//     from the returned map entirely (#5645, tightened to all-constituent
//     readiness by codex-182). Publishing the READY subset of a composite
//     binding, or a present-but-empty slice for an all-unready one, made the
//     daemon compile a direct feed-bound name to a PARTIAL / match-none address
//     book row: correct for a PERMIT (permit-none / permit-subset), but a DENY
//     policy referencing that name then under-matched (or never fired) and the
//     traffic it must block was PERMITTED for the whole window until every feed
//     succeeded (fail-OPEN). Omitting the whole binding leaves the name
//     unresolved, so the policy lowering treats it as unrepresentable
//     (addrRepresentable -> __unsupported_address__ -> whole-snapshot preflight
//     reject) and the referencing policy fails CLOSED — the same action-agnostic
//     contract #3261 gives an empty static book, and the first-fetch analogue of
//     the #5282 re-fetch window. The daemon ALSO treats a declared-but-omitted
//     binding as unrepresentable even when a STATIC address-book alias of the
//     same name exists (pkg/dataplane/userspace addrRepresentable), so the
//     static subset cannot resurrect a partial deny.
//
// Reading the live last-good snapshot here means a persistent fetch failure
// keeps enforcing the retained prefixes (the #2050 fail-safe). A persisted
// feed carries its last-good snapshot across a reconfigure (#5282), so it still
// has prefixes here and is still published — the omission above only fires for
// a feed with NO prior good fetch. The caller surfaces the enforced set; this
// accessor only joins the data.
func (m *Manager) SnapshotForBindings(daCfg *config.DynamicAddressConfig) map[string][]string {
	if daCfg == nil || len(daCfg.AddressBindings) == 0 {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]string, len(daCfg.AddressBindings))
	for name, binding := range daCfg.AddressBindings {
		if binding == nil || len(binding.FeedNames) == 0 {
			continue
		}
		// #5645 (tightened to all-constituent readiness by codex-182): a binding
		// is UNRESOLVED unless EVERY one of its feeds has an installed snapshot. A
		// ready feed always installs >= 1 prefix (a zero-prefix fetch is rejected
		// as suspect — see readFeed), so "no installed snapshot" is exactly
		// len(fs.prefixes) == 0 (before the first successful fetch, an unknown/
		// typo'd feed name, or after an explicit hold-interval drop) — never a
		// legitimately-empty successful fetch. If ANY constituent is unready, OMIT
		// the whole binding: publishing the ready subset (or an all-unready empty
		// slice) would enforce only a PARTIAL / match-none set, and for a DENY that
		// under-match is fail-OPEN. Omitting keeps the name UNRESOLVED so the
		// referencing policy fails CLOSED (see the doc comment). A persisted feed
		// carried forward across a reconfigure (#5282) still has its last-good
		// prefixes here, so this never re-opens the re-fetch window.
		// #7174 C12b: establish readiness AND the union's upper bound in one
		// pre-pass, before allocating anything.
		//
		// The ruling on that row was to bound the ALLOCATION, not the data.
		// A per-feed cap already exists (maxFeedPrefixes, enforced at fetch),
		// but this union across feeds and bindings previously started from
		// `make([]string, 0)` and an unsized map and regrew on every append —
		// the memory spike the row describes. Capping the DATA was rejected
		// deliberately: these feeds drive security policy, so truncating a
		// deny-list fails OPEN while truncating an allow-list fails CLOSED —
		// the same code with opposite failure directions depending on how the
		// operator uses the feed. That is a product decision and does not
		// belong in an allocation row.
		//
		// The sum of constituent lengths is an upper bound because dedup can
		// only shrink the result, so this never under-allocates and the output
		// is byte-identical to the unsized version.
		//
		// Doing readiness here rather than inside the merge is the second
		// half: a binding with any unready constituent is OMITTED, and the
		// old shape discovered that only after merging every prefix of every
		// feed ahead of the unready one. That work was always discarded.
		total := 0
		allReady := true
		for _, feedName := range binding.FeedNames {
			fs, ok := m.feeds[feedName]
			if !ok || len(fs.prefixes) == 0 {
				allReady = false
				break
			}
			total += len(fs.prefixes)
		}
		if !allReady {
			continue
		}
		seen := make(map[string]struct{}, total)
		merged := make([]string, 0, total)
		for _, feedName := range binding.FeedNames {
			fs := m.feeds[feedName]
			// Dedup across the binding's feeds; deep-copy from the live state.
			for _, p := range fs.prefixes {
				if _, dup := seen[p]; dup {
					continue
				}
				seen[p] = struct{}{}
				merged = append(merged, p)
			}
		}
		sort.Strings(merged)
		out[name] = merged
	}
	return out
}

// AllFeeds returns a snapshot of all feed states for display.
func (m *Manager) AllFeeds() map[string]FeedInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]FeedInfo, len(m.feeds))
	for name, fs := range m.feeds {
		// Copilot #1: surface "" (not 64 zero-hex chars) when no snapshot is
		// installed (before first fetch, or after an explicit hold-interval
		// drop). The zero [32]byte would otherwise format as all-zero hex and
		// masquerade as a real digest.
		hash := ""
		if fs.hasSnapshot {
			hash = fmt.Sprintf("%x", fs.hash)
		}
		result[name] = FeedInfo{
			URL:           fs.url,
			Prefixes:      len(fs.prefixes),
			LastFetch:     fs.lastFetch,
			LastSuccess:   fs.lastSuccess,
			LastError:     fs.lastError,
			StaleSince:    fs.staleSince,
			Hash:          hash,
			InvalidLines:  fs.invalidLines,
			InvalidSample: append([]string(nil), fs.invalidSample...),
			Degraded:      fs.invalidLines > 0,
		}
	}
	return result
}

// FeedInfo holds display information about a feed.
type FeedInfo struct {
	URL       string
	Prefixes  int
	LastFetch time.Time // last successful fetch (alias of LastSuccess for show-path compat)

	// Additive status fields (#2050).
	LastSuccess time.Time // last fully-successful fetch
	LastError   string    // most recent fetch/parse error, "" if last fetch was good
	// StaleSince is set when a RETAINED last-good snapshot started being
	// served as stale (first failure after a good fetch) and is zero when no
	// snapshot is being retained as stale — i.e. zero before the first good
	// fetch, while the current fetch is fresh, and after an explicit
	// hold-interval drop cleared the retained snapshot.
	StaleSince time.Time
	Hash       string // hex sha256 of the canonical prefix set ("" if none)

	// Parse-quality of the installed snapshot (#2993). InvalidLines is the
	// number of malformed lines skipped while parsing the last
	// successfully-installed body; InvalidSample is a bounded sample of those
	// lines — each entry is a byte-bounded, escaped prefix plus the original
	// line's byte length (#4922), safe to print (no raw control bytes) and never
	// the full verbatim line. Degraded is true when InvalidLines > 0 — the feed
	// installed a PARTIAL set (some published lines were dropped), which an
	// operator should investigate even though valid prefixes are enforced.
	InvalidLines  int
	InvalidSample []string
	Degraded      bool
}

func (m *Manager) refreshLoop(ctx context.Context, fs *feedState, interval time.Duration) {
	// #7174 C12a: signal StopAll that this goroutine has genuinely finished.
	// Deferred so it closes on EVERY exit path, including a panic — a join that
	// a panicking producer can strand is a hang, which is worse than the
	// unjoined behaviour it replaced.
	if fs.done != nil {
		defer close(fs.done)
	}
	// Initial fetch
	m.fetchFeed(ctx, fs)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.fetchFeed(ctx, fs)
		}
	}
}

// fetchResult is the parsed outcome of a single feed read, separated from the
// snapshot-mutation step so the parse path is independently testable.
type fetchResult struct {
	prefixes []string // canonicalized, deduped, sorted
	hash     [32]byte

	// invalidLines counts malformed lines skipped during parse; invalidSample
	// holds up to maxInvalidSample byte-bounded, escaped offenders (#2993,
	// byte-bounded in #4922). A clean body leaves both zero/nil.
	invalidLines  int
	invalidSample []string
}

// fetchFeed performs a single GET, parses + canonicalizes the body, and applies
// it to the feed state. A fetch is considered SUCCESSFUL only if the transport
// read completes without error AND the parsed set is non-empty. On any failure
// the last-good snapshot is RETAINED — indefinitely by default, or until an
// explicit positive hold-interval elapses (the opt-in drop-to-empty).
// lastFetch/lastSuccess are stamped only on success.
func (m *Manager) fetchFeed(ctx context.Context, fs *feedState) {
	res, err := m.readFeed(ctx, fs)
	if err != nil {
		m.recordFailure(fs, err)
		return
	}
	m.installSnapshot(fs, res)
}

// readFeed issues the HTTP request and parses the body into a canonical set.
// It returns an error (and no snapshot is installed) on transport failure,
// non-200 status, a scanner error (including bufio.ErrTooLong for an overlong
// line), an over-size body / over-count entry set (maxFeedBodyBytes /
// maxFeedPrefixes, #3934), or a zero-prefix successful response (treated as
// suspect — a hijacked or misconfigured endpoint serving an empty body must
// not silently wipe an enforced set). The transport itself is bounded by the
// client's httpClientTimeout (slow-loris protection).
func (m *Manager) readFeed(ctx context.Context, fs *feedState) (fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fs.url, nil)
	if err != nil {
		return fetchResult{}, fmt.Errorf("invalid URL: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return fetchResult{}, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fetchResult{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return parseFeed(resp.Body)
}

// countingReader wraps an io.Reader and tracks the total number of bytes read
// through it, so parseFeed can DETECT (not merely truncate at) an over-size
// body: the body is read through io.LimitReader(r, maxFeedBodyBytes+1), and if
// the counter passes maxFeedBodyBytes the feed exceeded the cap (#3934).
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// parseFeed reads CIDR/IP lines from r and returns a canonicalized set.
// Reads io.Reader (not http.Response) so it is unit-testable in isolation.
//
// The body is bounded on TWO axes (#3934) so a huge/infinite body or a MITM on
// a plaintext-http feed cannot OOM the daemon:
//   - total bytes: read through io.LimitReader(r, maxFeedBodyBytes+1); a body
//     larger than maxFeedBodyBytes fails the whole fetch (retain last-good),
//   - parsed entries: a body producing more than maxFeedPrefixes parsed entries
//     fails the whole fetch (never install a partial-but-huge set).
//
// Both over-limit conditions return an error so fetchFeed→recordFailure keeps
// the last-good snapshot rather than wiping or truncating the enforced set.
func parseFeed(r io.Reader) (fetchResult, error) {
	var prefixes []string
	var invalidLines int
	var invalidSample []string
	var invalidSampleBytes int   // running total of retained sample-entry lengths (#4922)
	var refusedDefaultRoutes int // #9248: whole-address-space lines refused
	// Cap the total bytes buffered. Read one byte past the cap so a body that
	// exactly fills the cap is accepted while anything larger is detected.
	cr := &countingReader{r: io.LimitReader(r, maxFeedBodyBytes+1)}
	scanner := bufio.NewScanner(cr)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Validate + canonicalize as CIDR or plain IP.
		if _, ipNet, err := net.ParseCIDR(line); err == nil && isDefaultRoute9248(ipNet) {
			// #9248: a feed line naming the whole address space is refused, not
			// installed. Feed prefixes become the address set a policy MATCHES
			// (pkg/dataplane/userspace policies_lower / policies_addrbook), so
			// one `0.0.0.0/0` or `::/0` line in content this box does not author
			// turns every policy on that dynamic address into "match anything":
			// a permit fails open and a deny drops everything. No real feed
			// entry is the default route -- bogon lists stop at /3 and /4 -- so
			// only /0 is refused, and it is counted and sampled exactly like a
			// malformed line so the feed reports DEGRADED instead of a clean
			// success. A feed whose only entry was the default route is left
			// with no usable prefixes and fails with a reason that says so.
			//
			// The test is on the CANONICAL form, the string that would be
			// installed, not on the parsed mask length: `::ffff:0:0/96` is a /96
			// mapped-IPv6 prefix that net.IPNet renders as `0.0.0.0/0`.
			//
			// BOUNDARY, stated: this guards an accidental whole-space line. It is
			// not protection from a hostile provider, which can list 0.0.0.0/1
			// and 128.0.0.0/1 and cover the same space.
			refusedDefaultRoutes++
			invalidLines++
			if len(invalidSample) < maxInvalidSample && invalidSampleBytes < maxInvalidSampleTotalBytes {
				entry := boundInvalidSample("default route refused: " + line)
				invalidSample = append(invalidSample, entry)
				invalidSampleBytes += len(entry)
			}
		} else if err == nil {
			// Normalize to masked network form (e.g. 192.0.2.5/24 -> 192.0.2.0/24).
			prefixes = append(prefixes, ipNet.String())
		} else if ip := net.ParseIP(line); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				prefixes = append(prefixes, fmt.Sprintf("%s/32", v4.String()))
			} else {
				prefixes = append(prefixes, fmt.Sprintf("%s/128", ip.String()))
			}
		} else {
			// A non-comment line that is neither a CIDR nor a bare IP. Feed
			// providers occasionally emit stray text, but a malformed line can
			// also be THE line that matters for a denylist (#2993). We still
			// skip it (the published valid prefixes are installed), but it is no
			// longer silent: count it and keep a bounded sample so the fetch is
			// observably degraded rather than reporting a clean success.
			//
			// #4922: retain only a BYTE-bounded, escaped prefix of each offender
			// (not the verbatim line, which the scanner admits up to
			// maxLineBytes = 1 MiB). Bounding here, at the retention point, means
			// installSnapshot, AllFeeds' deep copy, and the degraded-feed
			// slog.Warn all inherit the small, safe form — a hostile provider
			// serving near-1-MiB garbage lines can no longer pin megabytes in
			// memory or emit multi-MB log records. Both a COUNT cap
			// (maxInvalidSample) and an aggregate BYTE budget
			// (maxInvalidSampleTotalBytes) gate the append.
			invalidLines++
			if len(invalidSample) < maxInvalidSample && invalidSampleBytes < maxInvalidSampleTotalBytes {
				entry := boundInvalidSample(line)
				invalidSample = append(invalidSample, entry)
				invalidSampleBytes += len(entry)
			}
		}
		// Entry cap: bail as soon as the parsed set exceeds the per-feed limit
		// so the slice memory stays bounded during the loop and a huge feed is
		// rejected rather than truncated-and-installed (#3934).
		if len(prefixes) > maxFeedPrefixes {
			return fetchResult{}, fmt.Errorf("feed exceeds max entry count %d", maxFeedPrefixes)
		}
	}
	if err := scanner.Err(); err != nil {
		// Overlong line (bufio.ErrTooLong) or transport read error mid-stream.
		// Treat the entire read as failed — never install a truncated set.
		return fetchResult{}, fmt.Errorf("read body: %w", err)
	}
	if cr.n > maxFeedBodyBytes {
		// Body exceeded the size cap (the LimitReader delivered the extra
		// sentinel byte). Fail the whole fetch — never install a truncated set,
		// and keep the last-good snapshot (#3934).
		return fetchResult{}, fmt.Errorf("feed body exceeds max size %d bytes", maxFeedBodyBytes)
	}

	canon := canonicalize(prefixes)
	if len(canon) == 0 && refusedDefaultRoutes > 0 {
		// #9248: say WHY, instead of the generic zero-prefix error below.
		return fetchResult{}, fmt.Errorf("feed contained no usable prefixes: its %d whole-address-space "+
			"entr(y/ies) (0.0.0.0/0, ::/0 or a mapped equivalent) are refused", refusedDefaultRoutes)
	}
	if len(canon) == 0 {
		// Zero-prefix HTTP-200: suspect. Retain last-good rather than installing
		// an empty set that would fail-open an enforced denylist.
		return fetchResult{}, fmt.Errorf("feed returned no usable prefixes")
	}

	return fetchResult{
		prefixes:      canon,
		hash:          hashPrefixes(canon),
		invalidLines:  invalidLines,
		invalidSample: invalidSample,
	}, nil
}

// isDefaultRoute9248 reports whether a parsed prefix is the whole IPv4 or IPv6
// address space (#9248).
func isDefaultRoute9248(n *net.IPNet) bool {
	s := n.String()
	return s == "0.0.0.0/0" || s == "::/0"
}

// boundInvalidSample renders a malformed feed line into the small, safe form
// retained for the degraded-feed sample (#4922). It:
//
//   - truncates the line to at most maxInvalidSampleBytes RAW bytes,
//   - escapes the (possibly truncated) prefix with strconv.Quote so NUL,
//     newline, control bytes, and invalid UTF-8 become printable \x.. / \n
//     escapes — never raw control bytes into a slog record or a CLI show,
//   - annotates a truncated line with its ORIGINAL byte length so an operator
//     can still see "this line was 1 MiB, starts with <prefix>".
//
// A short line (< the byte cap) is returned quoted-but-otherwise-intact, so the
// diagnostic value for the common stray-text case is preserved. A final
// defensive clamp guarantees the result never exceeds maxInvalidSampleEntryBytes
// even if strconv.Quote's expansion is looser than assumed; the clamp keeps the
// string printable (it only trims already-escaped ASCII).
func boundInvalidSample(line string) string {
	orig := len(line)
	prefix := line
	truncated := false
	if orig > maxInvalidSampleBytes {
		prefix = line[:maxInvalidSampleBytes]
		truncated = true
	}
	out := strconv.Quote(prefix)
	if truncated {
		out = fmt.Sprintf("%s … (%d bytes total)", out, orig)
	}
	if len(out) > maxInvalidSampleEntryBytes {
		out = out[:maxInvalidSampleEntryBytes]
	}
	return out
}

// canonicalize dedups and sorts the prefix list. Input prefixes are already in
// masked/normalized string form from parseFeed.
func canonicalize(prefixes []string) []string {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(prefixes))
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// hashPrefixes returns the sha256 of the canonical (sorted, deduped) set.
// The input must already be sorted+deduped so the hash is content-stable.
func hashPrefixes(canon []string) [32]byte {
	h := sha256.New()
	for _, p := range canon {
		h.Write([]byte(p))
		h.Write([]byte{'\n'})
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// installSnapshot replaces the active snapshot with a fresh good fetch, stamps
// success, clears stale/error state, and (re-)publishes to the dataplane when
// the fetched content differs from what was last SUCCESSFULLY applied.
//
// The publish decision is keyed off publishedHash — the hash last CONFIRMED
// applied — NOT off the installed-content hash. This is the #5646 fix: the
// pre-fix code committed the content hash and then fired a VOID onUpdate, so a
// REJECTED apply (preflight reject #3261/#5645, compile failure, control-socket
// error) left the hash committed and every later identical refetch saw
// "unchanged" and skipped onUpdate — the good content sat un-enforced forever
// (publication debt). onUpdate now returns the apply result: publishedHash
// advances only on a nil (accepted) return, so a rejected apply leaves the
// content unpublished and the next identical refetch RE-FIRES onUpdate to retry
// the apply. The retry fires on the normal refresh cadence (one publish attempt
// per fetch), never a tight loop.
func (m *Manager) installSnapshot(fs *feedState, res fetchResult) {
	m.mu.Lock()
	// changed = the installed enforced content differs from the prior install.
	// Drives the display/degraded logging (a content change), independent of
	// whether that content has been PUBLISHED.
	changed := !fs.hasSnapshot || fs.hash != res.hash
	// needsPublish = the fetched content differs from what was last CONFIRMED
	// applied. Drives the onUpdate publish/retry. A rejected apply leaves
	// publishedHash stale, so this stays true on an identical refetch → retry.
	needsPublish := !fs.hasPublished || fs.publishedHash != res.hash
	oldCount := len(fs.prefixes)
	now := m.now()
	fs.prefixes = res.prefixes
	fs.hash = res.hash
	fs.hasSnapshot = true
	fs.lastFetch = now
	fs.lastSuccess = now
	fs.lastError = ""
	fs.staleSince = time.Time{}
	fs.invalidLines = res.invalidLines
	fs.invalidSample = res.invalidSample
	m.mu.Unlock()

	slog.Info("dynamic-address: feed updated",
		"name", fs.name, "prefixes", len(res.prefixes), "previous", oldCount,
		"changed", changed, "needs_publish", needsPublish, "invalid_lines", res.invalidLines)

	// A degraded install (some published lines skipped) is loud, but only on a
	// content change so a persistently-malformed-but-stable feed does not flood
	// the journal on every refresh tick (#2993). The per-fetch invalid count is
	// always carried in the Info line above and surfaced via FeedInfo.
	if changed && res.invalidLines > 0 {
		slog.Warn("dynamic-address: feed installed a PARTIAL set — skipped invalid lines (degraded)",
			"name", fs.name, "prefixes", len(res.prefixes),
			"invalid_lines", res.invalidLines, "invalid_sample", res.invalidSample)
	}

	if !needsPublish {
		// Already applied this exact content — no republish, no thrash.
		return
	}

	// Publish to the dataplane. A nil callback (no consumer wired) is treated as
	// a vacuous success so publishedHash tracks the installed content and a
	// later identical refetch is still suppressed.
	var applyErr error
	if m.onUpdate != nil {
		applyErr = m.onUpdate()
	}
	if applyErr != nil {
		// Apply REJECTED: do NOT advance publishedHash. The content is installed
		// (fs.prefixes/fs.hash) and enforced-in-intent, but the dataplane did
		// not accept it. Leaving publishedHash stale means the next identical
		// refetch re-fires this path and retries the apply (#5646). This is
		// publication debt, surfaced loudly but bounded to one retry per fetch.
		slog.Warn("dynamic-address: feed apply REJECTED — good content not yet enforced (publication debt), will retry on next refresh",
			"name", fs.name, "prefixes", len(res.prefixes), "err", applyErr)
		return
	}
	m.mu.Lock()
	fs.publishedHash = res.hash
	fs.hasPublished = true
	m.mu.Unlock()
}

// recordFailure handles a failed fetch under the retain-last-good policy:
//   - records LastError (does NOT stamp lastFetch/lastSuccess),
//   - if a good snapshot is being retained, sets StaleSince on the first
//     failure (the feed ENTERING stale) and keeps the snapshot,
//   - by DEFAULT (holdInterval == retainForever) the snapshot is retained
//     INDEFINITELY — never auto-dropped to empty, because a stale-but-enforced
//     denylist beats a fail-OPEN empty one (#2050 operator decision),
//   - ONLY when an explicit positive hold-interval is configured AND it has
//     elapsed (measured from StaleSince) is the snapshot dropped to empty
//     (fail-closed) with an onUpdate so enforcement sees the now-empty set;
//     StaleSince is then cleared (no snapshot is retained as stale anymore,
//     Copilot #2).
//
// A one-time slog.Warn fires when the feed first ENTERS the stale state, not
// on every failing tick, so a persistently-down feed does not flood the log.
func (m *Manager) recordFailure(fs *feedState, ferr error) {
	m.mu.Lock()
	now := m.now()
	fs.lastError = redactFeedURLInError9164(ferr.Error(), fs.url)

	enteredStale := false
	dropped := false
	if fs.hasSnapshot && len(fs.prefixes) > 0 {
		if fs.staleSince.IsZero() {
			fs.staleSince = now
			enteredStale = true
		}
		// retainForever (the default) never drops; only an explicit positive
		// hold-interval arms the timed drop-to-empty.
		if fs.holdInterval > 0 && now.Sub(fs.staleSince) >= fs.holdInterval {
			fs.prefixes = nil
			fs.hash = [32]byte{}
			fs.hasSnapshot = false
			// Copilot #2: no snapshot is retained as stale anymore — clear
			// StaleSince so FeedInfo.StaleSince matches its docstring.
			fs.staleSince = time.Time{}
			// No snapshot remains, so its parse-quality is meaningless — clear
			// the degraded markers too (#2993).
			fs.invalidLines = 0
			fs.invalidSample = nil
			// #5646: reset the published-hash tracking. The enforced set is now
			// empty; if this feed later RECOVERS and refetches its prior content,
			// installSnapshot must re-fire onUpdate to re-enforce it. Leaving a
			// stale publishedHash equal to the recovered content would suppress
			// that re-apply and leave the recovered denylist un-enforced.
			fs.publishedHash = [32]byte{}
			fs.hasPublished = false
			dropped = true
		}
	}
	m.mu.Unlock()

	switch {
	case dropped:
		slog.Warn("dynamic-address: hold interval elapsed, dropping stale feed to empty",
			"name", fs.name, "err", ferr, "hold", fs.holdInterval)
		if m.onUpdate != nil {
			// #9527: the drop-to-empty has NO fixed safety direction. It depends
			// on how the operator uses the feed: an empty denylist stops denying
			// (fail-OPEN, which is why hold-interval is opt-in), and an empty
			// allowlist stops permitting.
			//
			// And for any enforced policy that references a binding on this feed,
			// the empty set does not reach the dataplane at all:
			//   - SnapshotForBindings omits the binding;
			//   - the policy lowers to __unsupported_address__;
			//   - the helper's integrity preflight rejects the whole snapshot and
			//     keeps the previous-good one (fresh boot: default-deny).
			//
			// That keeps the last-good prefixes enforced: still DENYING them for
			// a denylist, still PERMITTING them for an allowlist. So retention is
			// not "strictly safer" than an empty set. The userspace manager warns
			// on that reject and records ProcessStatus reject reasons (#3261); an
			// error returned by onUpdate is only logged here. publishedHash was
			// already reset above, so a later recovery re-publishes regardless.
			if err := m.onUpdate(); err != nil {
				slog.Warn("dynamic-address: drop-to-empty apply rejected — dataplane retains last-good set",
					"name", fs.name, "err", err)
			}
		}
	case enteredStale:
		// One-time loud warning on entry to the stale state. Subsequent
		// failing ticks are logged at Debug to avoid flooding the journal for
		// a persistently-down feed.
		slog.Warn("dynamic-address: feed entered STALE — fetch failed, retaining last-good snapshot",
			// #9164: the REDACTED text, not `ferr`. Go's transport error quotes
			// the URL it dialled, and a dynamic-address feed routinely carries a
			// per-tenant bearer token in its query string.
			"name", fs.name, "err", fs.lastError, "retain",
			func() string {
				if fs.holdInterval > 0 {
					return fs.holdInterval.String()
				}
				return "forever"
			}())
	default:
		slog.Debug("dynamic-address: fetch failed, retaining last-good",
			"name", fs.name, "err", ferr)
	}
}

// redactFeedURLInError9164 removes a feed URL's credential from a transport
// error string, leaving the rest of the diagnostic intact.
//
// #9164: `recordFailure` stored `ferr.Error()` verbatim into `lastError` and
// logged the error object, and Go's transport error quotes the URL it dialled:
//
//	Get "https://127.0.0.1:1/list.txt?token=BEARER_TOKEN_ABC123": dial tcp ...
//
// so a per-tenant bearer token reached journald and every support bundle. The
// repo states outright that this is the common shape -- "dynamic-address feeds
// routinely carry per-tenant bearer tokens in the URL". `config.RedactURL` was
// already called two sites away and simply not here.
//
// WHY NOT `config.RedactURL(ferr.Error())`, which is the obvious fix: that
// helper is sound on a URL and NOT on arbitrary text. An error string is not a
// URL -- it has a prefix, a quoted URL and a trailing diagnostic -- and feeding
// it in hits exactly the unparsed-input case the helper cannot reason about.
// Redacting the URL we ALREADY HAVE and substituting it is sound by
// construction: `fs.url` is the operator's configured string, so
// `config.RedactURL` gets the input it was written for.
//
// TWO SPELLINGS HAVE TO BE REPLACED, and that is a measurement rather than
// caution. `net/http`'s own `stripPassword` (client.go) rewrites a basic-auth
// PASSWORD to `***` before the error is formatted, so the error contains a
// string that is NOT `fs.url`. Replacing only the raw URL would silently miss
// every password case -- and leave the USERNAME, which `stripPassword` does not
// touch. Replacing only the masked form would miss the query-token case, which
// is the one this product actually has.
func redactFeedURLInError9164(errText, rawURL string) string {
	if errText == "" || rawURL == "" {
		return errText
	}
	redacted := config.RedactURL(rawURL)
	if redacted == rawURL {
		// Nothing to hide -- no credential in the configured URL. Returning the
		// text untouched keeps the no-credential diagnostic byte-identical,
		// which is what the control row asserts.
		return errText
	}
	out := strings.ReplaceAll(errText, rawURL, redacted)

	// The password-masked spelling net/http emits. Built from the same URL so
	// it cannot drift from what the transport actually prints.
	if u, err := url.Parse(rawURL); err == nil && u.User != nil {
		if _, hasPw := u.User.Password(); hasPw {
			masked := *u
			masked.User = url.UserPassword(u.User.Username(), "***")
			out = strings.ReplaceAll(out, masked.String(), redacted)
		}
	}
	return out
}
