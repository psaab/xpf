// Package feeds implements dynamic address feed fetching and management.
package feeds

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/psaab/xpf/pkg/config"
)

// retainForever is the sentinel holdInterval meaning "never auto-drop the
// last-good snapshot to empty on persistent failure". This is the DEFAULT
// (operator decision, #2050): a stale DENYLIST that fail-OPENs to empty is
// worse than a stale-but-enforced set, so an unset/zero hold-interval retains
// the last-good snapshot INDEFINITELY. The drop-after-N-seconds behaviour is
// now strictly opt-in via an explicit positive hold-interval.
const retainForever time.Duration = 0

// Default drastic-shrink guard thresholds (#11059). Runtime behavior is
// configured per feed-server in the committed config; these defaults apply
// when a leaf is omitted or malformed on a lenient load.
const (
	feedShrinkGuardMinOldCountDefault      = config.DefaultDynamicAddressShrinkGuardMinOldCount
	feedShrinkGuardMinRetainPercentDefault = config.DefaultDynamicAddressShrinkGuardRetainPct
	feedShrinkGuardMinDropDefault          = config.DefaultDynamicAddressShrinkGuardMinDrop
	feedShrinkWarnInterval                 = time.Hour
	feedDropRetryInitialDelay              = 5 * time.Second
	feedDropRetryMaxDelay                  = time.Hour
	maxShrinkAckReasonBytes                = 512
)

type shrinkGuardThresholds struct {
	minOldCount      int
	minRetainPercent int
	minDrop          int
}

var defaultShrinkGuardThresholds = shrinkGuardThresholds{
	minOldCount:      feedShrinkGuardMinOldCountDefault,
	minRetainPercent: feedShrinkGuardMinRetainPercentDefault,
	minDrop:          feedShrinkGuardMinDropDefault,
}

func resolveShrinkGuardThresholds(fsCfg *config.FeedServer) shrinkGuardThresholds {
	thresholds := defaultShrinkGuardThresholds
	if fsCfg == nil {
		return thresholds
	}
	for _, knob := range []struct {
		name string
		got  int
		min  int
		max  int
		dst  *int
	}{
		{"shrink-guard-min-old-count", fsCfg.ShrinkGuardMinOldCount, 1, maxFeedPrefixes, &thresholds.minOldCount},
		{"shrink-guard-min-retain-percent", fsCfg.ShrinkGuardMinRetainPercent, 1, 100, &thresholds.minRetainPercent},
		{"shrink-guard-min-drop", fsCfg.ShrinkGuardMinDrop, 1, maxFeedPrefixes - 1, &thresholds.minDrop},
	} {
		if knob.got == 0 {
			continue
		}
		if knob.got < knob.min || knob.got > knob.max {
			slog.Warn("dynamic-address: invalid shrink-guard value on lenient config load; using safe default",
				"setting", knob.name, "value", knob.got, "default", *knob.dst)
			continue
		}
		*knob.dst = knob.got
	}
	return thresholds
}

func validShrinkGuardThresholds(t shrinkGuardThresholds) bool {
	return t.minOldCount >= 1 && t.minOldCount <= maxFeedPrefixes &&
		t.minRetainPercent >= 1 && t.minRetainPercent <= 100 &&
		t.minDrop >= 1 && t.minDrop < maxFeedPrefixes
}

// Manager manages dynamic address feed servers and their periodic updates.
type Manager struct {
	mu    sync.RWMutex
	feeds map[string]*feedState // keyed by feed-name (or feed-server name for single-feed servers)
	// shrinkHistory retains each feed's cumulative-shrink epoch across
	// same-manager removal/recreation and is initialized from the daemon's
	// durable high-water record at cold boot.
	shrinkHistory map[string]feedShrinkHistory
	client        *http.Client

	// privateFeedAllowlist is the explicit lab override for destinations that
	// would otherwise be refused by the feed SSRF guard. It is global to this
	// manager rather than attached to a feed, so a lab process can make one
	// deliberate reachability decision for all of its fixtures.
	privateFeedAllowlist []netip.Prefix

	// resolveFeedIPs is nil in production and exists only as a package-local
	// seam for deterministic resolver-rebinding tests. The production path uses
	// net.DefaultResolver and never re-resolves after validation.
	resolveFeedIPs func(context.Context, string) ([]netip.Addr, error)

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
	onUpdate               func() error // callback when feeds are updated; returns apply result
	onShrinkHistoryChanged func()

	// now is the clock source, overridable in tests for HoldInterval timing.
	now func() time.Time
}

// ShrinkHighWater is the durable per-feed cumulative-shrink epoch baseline.
// Prefixes carries the epoch content set (#14395): the exact prefixes
// installed at the last acknowledged epoch, so content churn can be
// measured against the epoch rather than the immediate predecessor
// across restarts. EpochHash (#15075) is that set's own digest, persisted
// separately from Hash (the count high-water hash) so the epoch set can be
// validated on restore even after an ordinary non-rebasing rotation has
// advanced the high-water past the epoch. Records written before #14395
// have no Prefixes; they restore the count epoch only and the content epoch
// re-bootstraps on the first install (the pre-existing bootstrap audit
// path). Records written before #15075 carry Prefixes without EpochHash;
// they restore any canonical set within the cap (#14994/#16427): their
// Prefixes field was the epoch set, and Hash names the possibly-rotated
// high-water set, so requiring digest == Hash would drop exactly the
// rotated epochs the epoch exists to anchor.
type ShrinkHighWater struct {
	Name     string   `json:"name"`
	Count    int      `json:"count"`
	Hash     string   `json:"hash"`
	Prefixes []string `json:"prefixes,omitempty"`
	// EpochHash is the hashPrefixes digest of Prefixes (#15075): the epoch
	// content set is validated against its own digest on restore, not
	// against Hash (the count high-water hash, which an ordinary
	// non-rebasing rotation advances past the epoch set). Empty on records
	// written before #15075; those restore any canonical Prefixes set
	// within the cap (#14994/#16427), since no epoch digest was persisted
	// to validate against and Hash may already have rotated past the epoch.
	EpochHash string `json:"epoch_hash,omitempty"`
}

type feedShrinkHistory struct {
	highWaterCount int
	highWaterHash  [32]byte
	epochPrefixes  []string
	epochHash      [32]byte
}

var emptyFeedHash = sha256.Sum256(nil)

type feedState struct {
	name string // feed-name or server name
	url  string // fully resolved URL
	// holdInterval is the retain-last-good window on persistent fetch failure.
	// retainForever (0) — the default — means NEVER auto-drop the last-good
	// snapshot to empty; only an explicit positive value arms the
	// drop-after-N-seconds opt-in.
	holdInterval time.Duration
	shrinkGuard  shrinkGuardThresholds
	// A feed's cumulative-shrink baseline is the largest installed set in its
	// current epoch. It decays only when that exact shrink candidate is
	// acknowledged. Manager history carries it across reconfigurations and is
	// persisted by the daemon for cold boot.
	shrinkHighWaterCount int
	shrinkHighWaterHash  [32]byte

	// epochContentPrefixes is the exact prefix set installed at the last
	// acknowledged epoch (bootstrap install or an acknowledged install);
	// epochContentHash is its hashPrefixes digest. Content churn is
	// measured against this set, NOT the immediate predecessor (#14395):
	// otherwise three successive 51%-retained rotations fully replace a
	// feed with zero refusals. The epoch is never moved by an ordinary
	// unacknowledged install. It is persisted alongside the high-water
	// count/hash in ShrinkHighWater.Prefixes.
	epochContentPrefixes []string
	epochContentHash     [32]byte

	// The active refused candidate and one-shot acknowledgement are runtime
	// status, not persisted across a producer replacement. The refusal counter,
	// candidate sequence, and warning cadence survive same-name Apply swaps.
	// The baseline hash pins the installed snapshot reviewed against the delta;
	// the candidate old count may be the epoch high-water count instead.
	shrinkRefused           bool
	shrinkRefusalCount      uint64
	shrinkRefusalID         uint64
	shrinkCandidateHash     [32]byte
	shrinkBaselineHash      [32]byte
	shrinkCandidateOldCount int
	shrinkCandidateNewCount int
	shrinkCandidateReason   string
	shrinkLastWarn          time.Time
	shrinkAckPending        bool
	shrinkAckRefusalID      uint64
	shrinkAckCandidateHash  [32]byte
	shrinkAckBaselineHash   [32]byte
	shrinkAckOldCount       int
	shrinkAckNewCount       int
	shrinkAckActor          string
	shrinkAckReason         string

	// Active enforced snapshot (canonicalized, deduped, sorted).
	prefixes    []string
	hash        [32]byte // sha256 over the canonical join; zero when no snapshot
	hasSnapshot bool     // true once a good fetch has installed a snapshot
	// holdDropped marks a feed whose snapshot was dropped by its hold-interval,
	// as opposed to one never fetched (#9689). Cleared by the next install.
	holdDropped bool

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
	// A rejected apply leaves the published hash unconfirmed: publication
	// debt survives identical refetches until an apply is accepted.
	publishUnconfirmed bool
	// A rejected hold-drop keeps publication debt but backs off retries of the
	// unchanged empty target. A successful apply/fetch clears this state.
	dropRetryDelay time.Duration
	dropRetryAt    time.Time

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
		feeds:         make(map[string]*feedState),
		shrinkHistory: make(map[string]feedShrinkHistory),
		client: &http.Client{
			Timeout: httpClientTimeout,
			// An explicit transport prevents HTTP(S)_PROXY and ALL_PROXY
			// environment variables from changing feed egress.
			Transport:     &http.Transport{Proxy: nil},
			CheckRedirect: checkFeedRedirect,
		},
		onUpdate: onUpdate,
		now:      time.Now,
	}
}

// SetShrinkHighWaterChangedCallback installs a callback invoked after a feed's
// durable shrink baseline advances. The callback runs without the manager lock.
func (m *Manager) SetShrinkHighWaterChangedCallback(callback func()) {
	m.mu.Lock()
	m.onShrinkHistoryChanged = callback
	m.mu.Unlock()
}

// RestoreShrinkHighWater loads validated per-feed baselines before Apply starts
// producers. Invalid records are ignored so one malformed entry cannot prevent
// other feeds from recovering their epochs.
func (m *Manager) RestoreShrinkHighWater(records []ShrinkHighWater) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shrinkHistory == nil {
		m.shrinkHistory = make(map[string]feedShrinkHistory)
	}
	for name := range m.shrinkHistory {
		delete(m.shrinkHistory, name)
	}
	for _, record := range records {
		if record.Name == "" || record.Count <= 0 || record.Count > maxFeedPrefixes || len(record.Hash) != 64 {
			continue
		}
		raw, err := hex.DecodeString(record.Hash)
		if err != nil || len(raw) != 32 {
			continue
		}
		var hash [32]byte
		copy(hash[:], raw)
		hist := feedShrinkHistory{highWaterCount: record.Count, highWaterHash: hash}
		// #14395 epoch content, #15075 restore key: accept only a canonical
		// set, bounded by the feed entry cap. When EpochHash is present,
		// the set must match it — the epoch set's OWN digest, persisted
		// separately from Hash. Hash is the count high-water hash (the
		// largest installed set), which an ordinary non-rebasing rotation
		// advances past the epoch set, so keying the epoch restore on Hash
		// silently dropped every such epoch and left churn unanchored
		// across the restart. Records written before #15075 have no
		// EpochHash: keep the #14994 acceptance — any canonical set within
		// the cap (#16427). Their Prefixes field was the epoch set and no
		// epoch digest was persisted to validate against (there is no MAC
		// either way), so requiring digest == Hash adds no integrity and
		// drops exactly the rotated epochs. A corrupt (non-canonical) set,
		// or a set whose digest mismatches a present EpochHash, is dropped
		// fail-closed: the count epoch still restores and the content epoch
		// then re-bootstraps under the #14994 remembered-baseline guard.
		if len(record.Prefixes) > 0 && len(record.Prefixes) <= maxFeedPrefixes {
			canon := canonicalize(append([]string(nil), record.Prefixes...))
			if len(canon) == len(record.Prefixes) {
				digest := hashPrefixes(canon)
				accept := true
				if record.EpochHash != "" {
					accept = false
					if raw, err := hex.DecodeString(record.EpochHash); err == nil && len(raw) == 32 {
						var want [32]byte
						copy(want[:], raw)
						accept = digest == want
					}
				}
				if accept {
					hist.epochPrefixes = canon
					hist.epochHash = digest
				}
			}
		}
		m.shrinkHistory[record.Name] = hist
	}
}

// ShrinkHighWaterSnapshot returns a deterministic copy suitable for durable
// storage. Refusal and acknowledgement state is intentionally excluded.
func (m *Manager) ShrinkHighWaterSnapshot() []ShrinkHighWater {
	m.mu.RLock()
	defer m.mu.RUnlock()
	records := make([]ShrinkHighWater, 0, len(m.shrinkHistory))
	for name, history := range m.shrinkHistory {
		if history.highWaterCount <= 0 {
			continue
		}
		rec := ShrinkHighWater{
			Name: name, Count: history.highWaterCount, Hash: fmt.Sprintf("%x", history.highWaterHash),
		}
		if len(history.epochPrefixes) > 0 {
			rec.Prefixes = append([]string(nil), history.epochPrefixes...)
			rec.EpochHash = fmt.Sprintf("%x", history.epochHash)
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records
}

// SetPrivateFeedAllowlist installs the explicit lab override for private feed
// destinations. An empty slice restores the default-deny policy. Invalid
// prefixes are ignored; valid prefixes are masked before storage so the
// allowlist has deterministic network semantics.
//
// This is intentionally a manager-level escape hatch rather than a feed-server
// configuration knob. A private destination is reachable only when the lab
// process makes one deliberate decision for the manager that owns its feeds.
func (m *Manager) SetPrivateFeedAllowlist(prefixes []netip.Prefix) {
	valid := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			valid = append(valid, prefix.Masked())
		}
	}
	m.mu.Lock()
	m.privateFeedAllowlist = valid
	m.mu.Unlock()
}

// SetLabFeedTLSRoots installs extra TLS root certificates for feed fetches.
// It is the HTTPS counterpart of SetPrivateFeedAllowlist: an explicit
// lab-only escape hatch so test fixtures served by httptest TLS servers
// (with self-signed certificates) can be fetched through Apply, which now
// refuses plaintext-http feeds (#14385). It is not a feed-server
// configuration knob and production code never calls it — the daemon's
// manager keeps the system roots only. Passing nil restores system roots.
func (m *Manager) SetLabFeedTLSRoots(pool *x509.CertPool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		return
	}
	tr, ok := m.client.Transport.(*http.Transport)
	if !ok || tr == nil {
		return
	}
	cfg := tr.TLSClientConfig.Clone()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.RootCAs = pool
	tr.TLSClientConfig = cfg
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
		name        string
		url         string
		hold        time.Duration
		interval    time.Duration
		server      string
		shrinkGuard shrinkGuardThresholds
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
			// #14385 (DR5-H13): refuse plaintext-http feed servers. A
			// plaintext feed has no transport integrity and no per-feed
			// signature/hash exists in this package, so a MITM-substituted
			// body would install as enforced policy. Skip the whole server
			// (no worker, no snapshot): bound address-names stay
			// unresolvable and fail CLOSED per #5645. This is the
			// load-bearing runtime half — it also covers leniently-loaded /
			// peer-synced configs the strict compiler gate only warns on.
			if isPlaintextFeedURL(baseURL) {
				slog.Warn("dynamic-address: refusing plaintext-http feed server (no integrity — a MITM can substitute the feed body); use https",
					"server", fsCfg.Name, "url", config.RedactURL(baseURL))
				continue
			}
			interval := feedIntervalSeconds(fsCfg.UpdateInterval, time.Hour)
			hold := resolveHoldInterval(fsCfg.HoldInterval)
			shrinkGuard := resolveShrinkGuardThresholds(fsCfg)

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
						"name", name, "server", fsCfg.Name, "url", config.RedactURL(url))
					return
				}
				seen[name] = true
				plans = append(plans, feedPlan{
					name: name, url: url, hold: hold, interval: interval,
					server: fsCfg.Name, shrinkGuard: shrinkGuard,
				})
			}

			if len(fsCfg.FeedEntries) > 0 {
				// Multiple named feeds with per-feed paths.
				for _, fe := range fsCfg.FeedEntries {
					joined := joinFeedURL(baseURL, fe.Path)
					if joined == "" {
						// #14723: malformed / mistakable per-feed path.
						// Register NO feed (fail-closed: the bound name
						// stays unresolvable, #5645) rather than fetching
						// the base endpoint under this feed's name. The
						// strict compiler gate rejects the same config
						// at commit; this covers lenient loads.
						slog.Warn("dynamic-address: refusing feed with malformed path (no feed registered; bound address-name fails closed)",
							"name", fe.Name, "server", fsCfg.Name, "path", config.RedactURL(fe.Path))
						continue
					}
					plan(fe.Name, joined)
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
			shrinkGuard:  p.shrinkGuard,
			cancel:       cancel,
			done:         make(chan struct{}),
		}
		// Persisted feed (same name survives the reconfigure): inherit the
		// last-good snapshot so there is no fail-open window (#5282).
		if prev, ok := old[p.name]; ok {
			carryForwardSnapshot(fs, prev)
		} else if history, ok := m.shrinkHistory[p.name]; ok {
			fs.shrinkHighWaterCount = history.highWaterCount
			fs.shrinkHighWaterHash = history.highWaterHash
			if len(history.epochPrefixes) > 0 {
				fs.epochContentPrefixes = append([]string(nil), history.epochPrefixes...)
				fs.epochContentHash = history.epochHash
			}
		}
		newFeeds[p.name] = fs
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
// window on the new endpoint rather than inheriting a partially-elapsed one —
// a strictly more conservative (later-dropping) choice for the fail-open guard.
//
// The holdDropped marker is different: it records an already-enforced
// hold-interval drop, not transient failure state. A dropped feed has no
// snapshot, so it must be carried before the snapshot guard below; otherwise a
// persisted hold-dropped feed becomes indistinguishable from a never-fetched
// feed after reconfiguration and #9689's fail-mode-drop semantics are lost.
func carryForwardSnapshot(dst, src *feedState) {
	dst.holdDropped = src.holdDropped
	// Counts and the sequence survive a same-name reconfigure, but the
	// refused candidate and its acknowledgement are tied to the prior producer
	// configuration. The new endpoint must be fetched and reviewed afresh.
	dst.shrinkRefusalCount = src.shrinkRefusalCount
	dst.shrinkRefusalID = src.shrinkRefusalID
	dst.shrinkLastWarn = src.shrinkLastWarn
	dst.shrinkHighWaterCount = src.shrinkHighWaterCount
	dst.shrinkHighWaterHash = src.shrinkHighWaterHash
	dst.epochContentPrefixes = append([]string(nil), src.epochContentPrefixes...)
	dst.epochContentHash = src.epochContentHash
	// Carry the last confirmed publish state across a same-name producer
	// replacement. The daemon's apply re-enforces a carried snapshot; matching
	// content stays no-thrash, while an existing content mismatch remains
	// publication debt and is retried on the first fetch. Preserve this marker
	// even for a hold-dropped feed: if its empty apply was rejected, the old
	// published hash is needed to keep that debt visible until a later apply.
	dst.publishedHash = src.publishedHash
	dst.hasPublished = src.hasPublished
	dst.publishUnconfirmed = src.publishUnconfirmed
	if !src.hasSnapshot || len(src.prefixes) == 0 {
		return
	}
	dst.prefixes = append([]string(nil), src.prefixes...)
	dst.hash = src.hash
	dst.hasSnapshot = true
	dst.lastFetch = src.lastFetch
	dst.lastSuccess = src.lastSuccess
	dst.invalidLines = src.invalidLines
	dst.invalidSample = append([]string(nil), src.invalidSample...)
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
//   - A binding is ENFORCEABLE when EVERY one of its feed constituents has an
//     installed snapshot. If ANY feed is unready — before its first successful
//     fetch, an unknown/typo'd feed name, or after an explicit hold-interval
//     drop — the default/`retain` binding is UNRESOLVED and its name is
//     OMITTED from the returned map (#5645, tightened to all-constituent
//     readiness by codex-182). `fail-mode drop` is the deliberate exception:
//     when EVERY unready constituent was hold-dropped, the binding is published
//     with a PRESENT-BUT-EMPTY slice so the operator's drop intent is visible
//     to policy lowering (#9689/#10014). A ready constituent can never produce
//     an empty slice (zero-prefix fetches are rejected), so this empty row
//     means all constituents were hold-dropped. Publishing a READY subset of a
//     composite binding, or an empty slice for any other unready case, would
//     compile a direct feed-bound name to a PARTIAL / match-none address-book
//     row: correct for a PERMIT (permit-none / permit-subset), but a DENY
//     policy referencing that name then under-matched (or never fired) and the
//     traffic it must block was PERMITTED for the whole window until every
//     feed succeeded (fail-OPEN). Omitting a genuinely unresolved binding
//     leaves the name unresolved, so policy lowering treats it as
//     unrepresentable (addrRepresentable -> __unsupported_address__ ->
//     whole-snapshot preflight reject) and the referencing policy fails CLOSED.
//     The daemon ALSO treats a declared-but-omitted binding as unrepresentable
//     even when a STATIC address-book alias of the same name exists
//     (pkg/dataplane/userspace addrRepresentable), so the static subset cannot
//     resurrect a partial deny.
//
// Reading the live last-good snapshot here means a persistent fetch failure
// keeps enforcing the retained prefixes (the #2050 fail-safe). A persisted
// feed carries its last-good snapshot across a reconfigure (#5282), so it still
// has prefixes here and is still published — the omission above only fires for
// a feed with NO prior good fetch. The merged union is also re-checked against
// the whole-address-space refusal (#14392): per-feed parse refuses a single
// feed covering a whole family (#10711), but two half-space feeds bound to one
// name would otherwise union to permit-all / deny-all, so a covering union is
// omitted with the same fail-closed semantics and a warning. The caller
// surfaces the enforced set; this accessor only joins the data.
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
		// legitimately-empty successful fetch. If ANY constituent is unready,
		// omit the whole binding UNLESS fail-mode is `drop` AND every unready
		// constituent was hold-dropped. That explicit #9689 path publishes a
		// PRESENT-BUT-EMPTY row when all constituents were dropped; the empty row
		// is the operator's match-none DROP intent, not an unresolved feed. For
		// every other unready case, omitting keeps the name UNRESOLVED so the
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
		// half: a binding with any unready constituent is OMITTED unless the
		// explicit #9689 fail-mode-drop/all-hold-dropped exception applies. The
		// old shape discovered readiness only after merging every prefix of
		// every feed ahead of the unready one; that work was always discarded.
		total := 0
		allReady := true
		// #9689: whether every unready constituent was dropped by its
		// hold-interval, as opposed to never fetched or unknown. Only then may a
		// `fail-mode drop` binding be published instead of omitted: the operator
		// chose that a feed down past its hold interval stops constraining the
		// policy. A never-fetched or unknown feed still omits the binding (#5645).
		unreadyAllHoldDropped := true
		for _, feedName := range binding.FeedNames {
			fs, ok := m.feeds[feedName]
			if !ok || len(fs.prefixes) == 0 {
				allReady = false
				if !ok || !fs.holdDropped {
					unreadyAllHoldDropped = false
					break
				}
				continue
			}
			total += len(fs.prefixes)
		}
		if !allReady && !(binding.FailMode == "drop" && unreadyAllHoldDropped) {
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
		// #14392 (DR7-H5): the per-feed guard in parseFeed (#10711) checks
		// each feed alone, but the ENFORCEMENT unit is the binding union:
		// two halves (0.0.0.0/1 + 128.0.0.0/1, or ::/1 + 8000::/1) pass
		// per-feed and would publish as permit-all / deny-all. Re-check
		// the merged union here. On coverage, OMIT the binding (the
		// existing #5645 fail-closed omission: the referencing policy
		// stays unresolved and previous-good stays enforced) and warn
		// naming the binding. Never install a truncated union. The
		// #9689 fail-mode-drop empty row is unaffected:
		// coversWholeAddressSpace([]) is false.
		if coversWholeAddressSpace(merged) {
			slog.Warn("dynamic-address: feed binding union covers a whole address space; omitting binding (#14392)",
				"binding", name, "feeds", strings.Join(binding.FeedNames, ","))
			continue
		}
		out[name] = merged
	}
	return out
}

// feedPublicationDebt reports whether the desired installed state has not
// been confirmed applied. A hold-drop desires the empty set, represented by
// emptyFeedHash even though it has no installed snapshot slice.
func feedPublicationDebt(fs *feedState) bool {
	if fs.publishUnconfirmed {
		return true
	}
	if fs.hasSnapshot {
		return !fs.hasPublished || fs.publishedHash != fs.hash
	}
	return fs.holdDropped && (!fs.hasPublished || fs.publishedHash != emptyFeedHash)
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
		publishedHash := ""
		if fs.hasSnapshot {
			hash = fmt.Sprintf("%x", fs.hash)
		}
		if fs.hasPublished {
			publishedHash = fmt.Sprintf("%x", fs.publishedHash)
		}
		publicationDebt := feedPublicationDebt(fs)
		candidateHash := ""
		candidateBaselineHash := ""
		if fs.shrinkRefused {
			candidateHash = fmt.Sprintf("%x", fs.shrinkCandidateHash)
			candidateBaselineHash = fmt.Sprintf("%x", fs.shrinkBaselineHash)
		}
		ackHash := ""
		ackBaselineHash := ""
		if fs.shrinkAckPending {
			ackHash = fmt.Sprintf("%x", fs.shrinkAckCandidateHash)
			ackBaselineHash = fmt.Sprintf("%x", fs.shrinkAckBaselineHash)
		}
		highWaterHash := ""
		if fs.shrinkHighWaterCount > 0 {
			highWaterHash = fmt.Sprintf("%x", fs.shrinkHighWaterHash)
		}
		shrinkPolicy := thresholdsForFeed(fs)
		result[name] = FeedInfo{
			URL:                         fs.url,
			Prefixes:                    len(fs.prefixes),
			LastFetch:                   fs.lastFetch,
			LastSuccess:                 fs.lastSuccess,
			LastError:                   fs.lastError,
			StaleSince:                  fs.staleSince,
			Hash:                        hash,
			PublishedHash:               publishedHash,
			HasPublished:                fs.hasPublished,
			PublicationDebt:             publicationDebt,
			InvalidLines:                fs.invalidLines,
			InvalidSample:               append([]string(nil), fs.invalidSample...),
			Degraded:                    fs.invalidLines > 0,
			HoldDropped:                 fs.holdDropped,
			ShrinkRefused:               fs.shrinkRefused,
			ShrinkRefusalCount:          fs.shrinkRefusalCount,
			ShrinkRefusalID:             fs.shrinkRefusalID,
			ShrinkCandidateHash:         candidateHash,
			ShrinkBaselineHash:          candidateBaselineHash,
			ShrinkCandidateOldCount:     fs.shrinkCandidateOldCount,
			ShrinkCandidateNewCount:     fs.shrinkCandidateNewCount,
			ShrinkAckPending:            fs.shrinkAckPending,
			ShrinkAckActor:              fs.shrinkAckActor,
			ShrinkAckHash:               ackHash,
			ShrinkAckBaselineHash:       ackBaselineHash,
			ShrinkCandidateReason:       fs.shrinkCandidateReason,
			ShrinkGuardHighWaterCount:   fs.shrinkHighWaterCount,
			ShrinkGuardHighWaterHash:    highWaterHash,
			ShrinkAckReason:             fs.shrinkAckReason,
			ShrinkGuardMinOldCount:      shrinkPolicy.minOldCount,
			ShrinkGuardMinRetainPercent: shrinkPolicy.minRetainPercent,
			ShrinkGuardMinDrop:          shrinkPolicy.minDrop,
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
	// HoldDropped is true after a hold-interval drop and until the next
	// successful fetch (#9689).
	HoldDropped bool
	// PublishedHash is the hex sha256 of the snapshot last CONFIRMED applied
	// to the dataplane ("" when nothing has ever been published). Hash above
	// is the INSTALLED snapshot; the two differ while publication debt is
	// outstanding (a rejected onUpdate apply, #10974). HasPublished
	// distinguishes "never successfully published" from a genuine digest, and
	// PublicationDebt reports installed != published — the content is fetched
	// but the dataplane did not accept it, so every consumer showing the
	// installed set as enforced must instead flag the debt.
	PublishedHash   string
	HasPublished    bool
	PublicationDebt bool

	// ShrinkRefused is the live refusal alarm; ShrinkRefusalCount is the
	// manager-lifetime per-feed counter. The candidate tuple is present only
	// while a refusal remains current and binds the delta to the last-good
	// baseline hash.
	ShrinkRefused       bool
	ShrinkRefusalCount  uint64
	ShrinkRefusalID     uint64
	ShrinkCandidateHash string
	ShrinkBaselineHash  string
	// Candidate old count is the high-water count for cumulative shrink, or
	// current count for content-overlap refusals.
	ShrinkCandidateOldCount     int
	ShrinkCandidateNewCount     int
	ShrinkCandidateReason       string
	ShrinkGuardHighWaterCount   int
	ShrinkGuardHighWaterHash    string
	ShrinkAckPending            bool
	ShrinkAckActor              string
	ShrinkAckHash               string
	ShrinkAckBaselineHash       string
	ShrinkAckReason             string
	ShrinkGuardMinOldCount      int
	ShrinkGuardMinRetainPercent int
	ShrinkGuardMinDrop          int
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
	var holdTimer *time.Timer
	var holdExpiry <-chan time.Time
	resetHoldTimer := func() {
		if holdTimer != nil && !holdTimer.Stop() {
			select {
			case <-holdTimer.C:
			default:
			}
		}
		delay, armed := m.holdExpiryDelay(fs)
		if !armed {
			holdExpiry = nil
			return
		}
		if holdTimer == nil {
			holdTimer = time.NewTimer(delay)
		} else {
			holdTimer.Reset(delay)
		}
		holdExpiry = holdTimer.C
	}
	defer func() {
		if holdTimer != nil {
			holdTimer.Stop()
		}
	}()
	resetHoldTimer()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.fetchFeed(ctx, fs)
			resetHoldTimer()
		case <-holdExpiry:
			m.expireStaleHold(fs)
			resetHoldTimer()
		}
	}
}

// AcknowledgeFeedShrink arms a one-shot bypass for the exact refusal shown by
// AllFeeds. Every tuple field is matched because refusal IDs can be reused
// after a feed is removed, recreated, or the manager restarts.
func (m *Manager) AcknowledgeFeedShrink(name string, refusalID uint64, candidateHash, baselineHash string, oldCount, newCount int, actor, reason string) error {
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if strings.TrimSpace(name) == "" || refusalID == 0 {
		return fmt.Errorf("feed name and nonzero refusal ID are required")
	}
	if len(candidateHash) != sha256.Size*2 || len(baselineHash) != sha256.Size*2 || oldCount <= 0 || oldCount > maxFeedPrefixes || newCount < 0 || newCount > maxFeedPrefixes {
		return fmt.Errorf("acknowledgement requires valid candidate and baseline hashes and old/new counts")
	}
	if actor == "" || len(actor) > 1024 {
		return fmt.Errorf("authenticated actor is required")
	}
	if reason == "" || len(reason) > maxShrinkAckReasonBytes {
		return fmt.Errorf("acknowledgement reason must contain 1-%d bytes", maxShrinkAckReasonBytes)
	}
	for _, value := range []string{actor, reason} {
		for _, r := range value {
			if unicode.IsControl(r) {
				return fmt.Errorf("acknowledgement actor and reason must not contain control characters")
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	fs, ok := m.feeds[name]
	if !ok {
		return fmt.Errorf("dynamic-address feed %q does not exist", name)
	}
	if !fs.shrinkRefused {
		return fmt.Errorf("dynamic-address feed %q has no current refused shrink", name)
	}
	// The installed-baseline currency check applies only while a snapshot is
	// installed: after a hold-interval drop there is no installed hash to
	// compare against, yet the surviving refusal still names the baseline
	// that was dropped (#12882) and stays acknowledgeable. Any install
	// clears the refusal, so a surviving tuple is never stale. For an epoch
	// churn refusal (#14395) the baseline is the epoch set, which may
	// legitimately differ from the installed set; currency then requires
	// the baseline to still be the live epoch (or the installed set when
	// no epoch exists).
	baselineCurrent := !fs.hasSnapshot || fs.hash == fs.shrinkBaselineHash ||
		(len(fs.epochContentPrefixes) > 0 && fs.epochContentHash == fs.shrinkBaselineHash)
	if fs.shrinkRefusalID != refusalID ||
		candidateHash != fmt.Sprintf("%x", fs.shrinkCandidateHash) ||
		baselineHash != fmt.Sprintf("%x", fs.shrinkBaselineHash) ||
		!baselineCurrent ||
		oldCount != fs.shrinkCandidateOldCount ||
		newCount != fs.shrinkCandidateNewCount {
		return fmt.Errorf("dynamic-address feed %q refusal candidate tuple is stale", name)
	}
	fs.shrinkAckPending = true
	fs.shrinkAckRefusalID = refusalID
	fs.shrinkAckCandidateHash = fs.shrinkCandidateHash
	fs.shrinkAckBaselineHash = fs.shrinkBaselineHash
	fs.shrinkAckOldCount = fs.shrinkCandidateOldCount
	fs.shrinkAckNewCount = fs.shrinkCandidateNewCount
	fs.shrinkAckActor = actor
	fs.shrinkAckReason = reason
	return nil
}

func clearShrinkAck(fs *feedState) {
	fs.shrinkAckPending = false
	fs.shrinkAckRefusalID = 0
	fs.shrinkAckCandidateHash = [32]byte{}
	fs.shrinkAckBaselineHash = [32]byte{}
	fs.shrinkAckOldCount = 0
	fs.shrinkAckNewCount = 0
	fs.shrinkAckActor = ""
	fs.shrinkAckReason = ""
}

func clearShrinkCandidate(fs *feedState) {
	fs.shrinkRefused = false
	fs.shrinkCandidateHash = [32]byte{}
	fs.shrinkBaselineHash = [32]byte{}
	fs.shrinkCandidateOldCount = 0
	fs.shrinkCandidateReason = ""
	fs.shrinkCandidateNewCount = 0
	clearShrinkAck(fs)
}

func retainedPrefixCount(oldPrefixes, candidate []string) int {
	oldIndex, candidateIndex, retained := 0, 0, 0
	for oldIndex < len(oldPrefixes) && candidateIndex < len(candidate) {
		switch {
		case oldPrefixes[oldIndex] < candidate[candidateIndex]:
			oldIndex++
		case oldPrefixes[oldIndex] > candidate[candidateIndex]:
			candidateIndex++
		default:
			retained++
			oldIndex++
			candidateIndex++
		}
	}
	return retained
}

func contentChurnTripped(oldPrefixes, candidate []string, thresholds shrinkGuardThresholds) bool {
	oldCount := len(oldPrefixes)
	if !validShrinkGuardThresholds(thresholds) || oldCount < thresholds.minOldCount {
		return false
	}
	return int64(retainedPrefixCount(oldPrefixes, candidate))*100 <
		int64(oldCount)*int64(thresholds.minRetainPercent)
}

func (m *Manager) rememberShrinkHighWaterLocked(name string, count int, hash [32]byte) {
	m.rememberShrinkEpochLocked(name, count, hash, nil, [32]byte{})
}

// rememberShrinkEpochLocked records the count high-water and, when
// epochPrefixes is non-nil, the epoch content set (#14395). A nil epoch
// leaves any previously remembered epoch content untouched, so count-only
// advances never erase the content anchor.
func (m *Manager) rememberShrinkEpochLocked(name string, count int, hash [32]byte, epochPrefixes []string, epochHash [32]byte) {
	if m.shrinkHistory == nil {
		m.shrinkHistory = make(map[string]feedShrinkHistory)
	}
	hist := m.shrinkHistory[name]
	hist.highWaterCount = count
	hist.highWaterHash = hash
	if epochPrefixes != nil {
		hist.epochPrefixes = append([]string(nil), epochPrefixes...)
		hist.epochHash = epochHash
	}
	m.shrinkHistory[name] = hist
}

func (fs *feedState) shrinkCandidateMatches(hash, baselineHash [32]byte, oldCount, newCount int) bool {
	return fs.shrinkRefused &&
		fs.shrinkCandidateHash == hash &&
		fs.shrinkBaselineHash == baselineHash &&
		fs.shrinkCandidateOldCount == oldCount &&
		fs.shrinkCandidateNewCount == newCount
}

func (fs *feedState) shrinkAckMatches(hash, baselineHash [32]byte, oldCount, newCount int) bool {
	return fs.shrinkAckPending &&
		fs.shrinkAckRefusalID == fs.shrinkRefusalID &&
		fs.shrinkAckCandidateHash == hash &&
		fs.shrinkAckBaselineHash == baselineHash &&
		fs.shrinkAckOldCount == oldCount &&
		fs.shrinkAckNewCount == newCount &&
		fs.shrinkCandidateMatches(hash, baselineHash, oldCount, newCount)
}

// shrinkGuardTripped reports whether installing newCount prefixes over a
// last-good snapshot is a drastic shrink under the runtime defaults.
func shrinkGuardTripped(oldCount, newCount int) bool {
	return shrinkGuardTrippedWithThresholds(oldCount, newCount, defaultShrinkGuardThresholds)
}

func shrinkGuardTrippedWithThresholds(oldCount, newCount int, thresholds shrinkGuardThresholds) bool {
	if !validShrinkGuardThresholds(thresholds) || oldCount < thresholds.minOldCount {
		return false
	}
	if newCount >= oldCount || oldCount-newCount < thresholds.minDrop {
		return false
	}
	return int64(newCount)*100 < int64(oldCount)*int64(thresholds.minRetainPercent)
}

// malformedShrinkTripped16085 reports whether a degraded candidate — one whose
// body carried malformed (skipped) lines — drops a previously-enforced prefix
// while the count/churn guards above are inert. This is the #16085 small-feed
// hole: a 10-entry deny feed whose 3 corrupted lines parse to a 7-entry subset
// passes every default floor (old 10 < 32, drop 3 < 16, retained 7/10 >= 50%),
// so the reduced set installed and silently stopped enforcing 3 prefixes.
//
// The comparison baseline is the currently INSTALLED set (fs.prefixes), NOT
// the epoch: an ordinary growth or clean reduction installs a set that
// diverges from the epoch (which only rebases on bootstrap/acknowledgement,
// #14395), so comparing against the epoch would both miss a corrupted
// installed prefix added after the epoch and falsely refuse degraded growth
// that drops only long-gone epoch prefixes. The epoch is used only as a
// fallback when nothing is installed. Any dropped installed prefix trips —
// no size, drop, or percentage floor — because a malformed line is never
// evidence the provider intended to withdraw that prefix. A degraded
// candidate that ADDS or ROTATES above the installed set without dropping an
// installed prefix does not trip here; the large-feed shrink/churn guards
// (including the #14395 epoch guard) govern those candidates unchanged.
func malformedShrinkTripped16085(invalidLines int, installed, candidate []string) bool {
	if invalidLines <= 0 || len(installed) == 0 {
		return false
	}
	return retainedPrefixCount(installed, candidate) < len(installed)
}

func thresholdsForFeed(fs *feedState) shrinkGuardThresholds {
	if fs != nil && validShrinkGuardThresholds(fs.shrinkGuard) {
		return fs.shrinkGuard
	}
	return defaultShrinkGuardThresholds
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
// The shrink guard compares counts with the per-feed epoch high-water baseline
// and also checks retained exact-prefix overlap with the epoch content set.
// Refusals retain the installed set (or, with no live snapshot, install
// nothing), mark stale, alarm, and publish nothing until the exact candidate
// is acknowledged. A true bootstrap (no remembered baseline) is installable;
// a feed with no live snapshot but a remembered baseline — cold restart,
// same-manager re-created, or post-hold-drop (#14994) — is NOT a true
// bootstrap: a candidate that trips the remembered shrink/churn guards is
// refused awaiting ack, and only a candidate at or above those floors
// installs, with the bootstrap audit warning when it differs from the
// remembered high-water. A hold-interval drop does not release the refusal
// (#12882): the exact refused candidate re-served after the drop is refused
// again (previous-good enforcement persists via the omitted-binding
// preflight) until its exact acknowledgement lands; a different candidate
// install clears the refusal. Beside those size floors, a degraded
// candidate (one whose body skipped malformed lines) that drops a
// previously-enforced installed prefix is refused at ANY size (#16085):
// the floors are inert for a small deny feed — 10 entries losing 3 to
// origin corruption retain 70% with a drop of 3 — so without this the
// valid subset installed and silently unenforced the corrupted prefixes.
// That refusal binds the installed set as its baseline and uses the same
// exact-candidate acknowledgement.
func (m *Manager) installSnapshot(fs *feedState, res fetchResult) {
	m.mu.Lock()
	// Staleness suppress (#9916 F-133): Apply swaps the producer set without
	// joining the replaced loops, so an in-flight old fetch can complete
	// post-swap. Its content would install into an orphaned feedState (harmless)
	// but its onUpdate would fire a spurious dataplane apply against the NEW
	// state. A feedState still current is exactly the map's entry for its name
	// (same pointer — Apply allocates a fresh feedState per entry, so a
	// persisted name's old and new pointers always differ, and a removed feed
	// has no entry). Stale completions are dropped silently at Debug: they are
	// expected on every reconfigure, not an error.
	//
	// Residual window, stated: the guard runs under m.mu but onUpdate fires
	// outside it (it must — onUpdate re-enters the daemon apply, which reads
	// this same map). An old fetch that passes the guard just before Apply
	// swaps still fires once post-swap. That apply is content-safe (the new map
	// carries the old snapshot forward, and the dataplane apply is idempotent),
	// merely redundant — and it cannot deadlock, because Apply does not join
	// (joining under the daemon applySem would wedge against this same onUpdate).
	if cur, ok := m.feeds[fs.name]; !ok || cur != fs {
		m.mu.Unlock()
		slog.Debug("dynamic-address: stale feed completion suppressed (post-swap)",
			"name", fs.name)
		return
	}
	priorHighWaterCount := fs.shrinkHighWaterCount
	priorHighWaterHash := fs.shrinkHighWaterHash
	wasBootstrap := !fs.hasSnapshot
	// changed = the installed enforced content differs from the prior install.
	// Drives the display/degraded logging (a content change), independent of
	// whether that content has been PUBLISHED.
	changed := !fs.hasSnapshot || fs.hash != res.hash
	// needsPublish = the fetched content differs from what was last CONFIRMED
	// applied. Drives the onUpdate publish/retry. A rejected apply leaves
	// publishedHash stale, so this stays true on an identical refetch → retry.
	// An unconfirmed hold-drop is the same hazard in the other direction: the
	// rejected empty apply staged (and possibly landed) the dropped overlay,
	// so recovery must republish even content identical to publishedHash.
	needsPublish := !fs.hasPublished || fs.publishedHash != res.hash ||
		(fs.holdDropped && feedPublicationDebt(fs)) || fs.publishUnconfirmed
	oldCount := len(fs.prefixes)
	baselineHash := fs.hash
	// #14994 (D39-01): a feed with no live snapshot but a remembered
	// shrink baseline — cold restart (RestoreShrinkHighWater), same-manager
	// delete/re-add (shrinkHistory via Apply), or post-hold-drop — is not a
	// true bootstrap. Its first candidate is compared with the remembered
	// high-water count/hash and, when restored, the remembered epoch
	// content set, and a candidate that trips those guards is refused
	// awaiting the exact acknowledgement exactly as a candidate over a
	// live snapshot is. Comparing against that remembered baseline must
	// not rebase it on growth before acknowledgement (#14395): the epoch
	// non-rebase on ordinary growth is intentional and unchanged.
	hasRememberedBaseline := !fs.hasSnapshot && fs.shrinkHighWaterCount > 0
	if hasRememberedBaseline {
		baselineHash = fs.shrinkHighWaterHash
	}
	if fs.hasSnapshot && fs.shrinkHighWaterCount == 0 {
		fs.shrinkHighWaterCount = oldCount
		fs.shrinkHighWaterHash = fs.hash
	}
	thresholds := thresholdsForFeed(fs)
	highWaterCount := fs.shrinkHighWaterCount
	if highWaterCount == 0 {
		highWaterCount = oldCount
	}
	shrinkTripped := (fs.hasSnapshot || hasRememberedBaseline) && baselineHash != res.hash &&
		shrinkGuardTrippedWithThresholds(highWaterCount, len(res.prefixes), thresholds)
	// #14395: churn is measured against the EPOCH baseline, not the
	// immediate predecessor. A 51%-retained rotation installs (51% of the
	// epoch is at/above the floor) but does NOT move the epoch; a later
	// rotation retaining <50% of the epoch is refused even though it
	// retains 51% of its predecessor. Fall back to fs.prefixes only while
	// no epoch exists (snapshot predating the epoch field; the first
	// install below then establishes the epoch). On a no-snapshot feed
	// the remembered epoch (when restored) is that baseline (#14994).
	churnBaseline := fs.epochContentPrefixes
	if len(churnBaseline) == 0 {
		churnBaseline = fs.prefixes
	}
	churnTripped := (fs.hasSnapshot || len(fs.epochContentPrefixes) > 0) &&
		contentChurnTripped(churnBaseline, res.prefixes, thresholds)
	epochChurnTripped := churnTripped && len(fs.epochContentPrefixes) > 0
	// #16085: a degraded (malformed-line) candidate that drops a
	// previously-enforced prefix is refused at ANY size. The count/churn
	// floors above (default old>=32, drop>=16, retain>=50%) leave a small
	// deny feed — e.g. 10 entries losing 3 to origin corruption — wholly
	// unguarded: the 7-entry subset installed and silently stopped
	// enforcing the corrupted prefixes. Malformed lines are not evidence
	// of an intended withdrawal, so any installed prefix they remove
	// trips this guard; the refusal reuses the exact-candidate
	// acknowledgement workflow below. The baseline is the INSTALLED set
	// (fs.prefixes), never the epoch: installed and epoch diverge after
	// ordinary growth / clean reduction, and only an installed prefix was
	// actually enforced. Live snapshots only: a candidate with no installed
	// set drops nothing previously enforced, and a remembered-baseline
	// (cold/recreated/post-drop) first fetch keeps the #14994 floors —
	// refusing it here on malformed lines alone could wedge a legitimate
	// small feed whose first body is degraded.
	malformedTripped := fs.hasSnapshot && baselineHash != res.hash &&
		malformedShrinkTripped16085(res.invalidLines, fs.prefixes, res.prefixes)
	bootstrapDiffersFromHighWater := !fs.hasSnapshot && fs.shrinkHighWaterCount > 0 &&
		len(res.prefixes) <= fs.shrinkHighWaterCount &&
		(len(res.prefixes) < fs.shrinkHighWaterCount || res.hash != fs.shrinkHighWaterHash)
	// #12882: an outstanding refusal SURVIVES a hold-interval drop, so the
	// exact refused candidate cannot return as an unacknowledged bootstrap.
	// The pin matches the fetch against the remembered candidate tuple and
	// anchors its baseline hash and old count on that tuple rather than the
	// emptied installed state. A different candidate is NOT pinned by this
	// tuple, but under #14994 it is still compared with the remembered
	// high-water/epoch above: only a candidate at or above those floors
	// takes the bootstrap-with-audit path (and clears the refusal); a
	// tripping candidate is refused as a fresh candidate, as before a drop.
	refusedAfterDrop := !fs.hasSnapshot && fs.shrinkRefused &&
		res.hash == fs.shrinkCandidateHash &&
		len(res.prefixes) == fs.shrinkCandidateNewCount
	rememberedHighWaterCount := fs.shrinkHighWaterCount
	rememberedHighWaterHash := fs.shrinkHighWaterHash

	// Refusals and their acknowledgements bind to the exact content/baseline
	// tuple. For a cumulative shrink, old_count is the epoch high-water count;
	// for content churn, it is the epoch baseline count/hash (#14395), so an
	// acknowledgement reviews the epoch the candidate was refused against.
	guardBypass := false
	guardActor := ""
	guardReason := ""
	var guardBaselineHash [32]byte
	candidateOldCount := oldCount
	var candidateReason string
	if shrinkTripped {
		candidateOldCount = highWaterCount
		candidateReason = "cumulative high-water shrink"
	}
	if churnTripped {
		if candidateReason != "" {
			candidateReason += " and "
		}
		candidateReason += "epoch retained content overlap below floor"
		// The ack tuple must bind the epoch baseline, not the predecessor:
		// the operator reviews candidate-vs-epoch, and AcknowledgeFeedShrink's
		// installed-hash currency check is bypassed for epoch baselines
		// (the installed set may legitimately differ from the epoch).
		baselineHash = fs.epochContentHash
		if len(fs.epochContentPrefixes) == 0 {
			baselineHash = fs.hash
		}
		candidateOldCount = len(churnBaseline)
		if shrinkTripped {
			candidateOldCount = highWaterCount
		}
	}
	if malformedTripped && !shrinkTripped && !churnTripped {
		if candidateReason != "" {
			candidateReason += " and "
		}
		candidateReason += "malformed lines dropped previously-enforced prefixes"
		// The ack tuple binds the INSTALLED baseline the candidate was
		// measured against: fs.hash (the installed set's digest) with the
		// installed count. Binding the epoch hash/count here would pair a
		// hash the candidate was never compared with a count from a
		// different set once installed and epoch have diverged (ordinary
		// growth / clean reduction), and AcknowledgeFeedShrink's currency
		// check requires the installed hash anyway.
		baselineHash = fs.hash
		candidateOldCount = oldCount
	}
	if refusedAfterDrop {
		baselineHash = fs.shrinkBaselineHash
		candidateOldCount = fs.shrinkCandidateOldCount
	}
	if shrinkTripped || churnTripped || malformedTripped || refusedAfterDrop {
		newCount := len(res.prefixes)
		if fs.shrinkAckMatches(res.hash, baselineHash, candidateOldCount, newCount) {
			guardBypass = true
			guardActor = fs.shrinkAckActor
			guardReason = fs.shrinkAckReason
			guardBaselineHash = fs.shrinkAckBaselineHash
			clearShrinkAck(fs)
		} else {
			sameCandidate := fs.shrinkCandidateMatches(res.hash, baselineHash, candidateOldCount, newCount)
			if !sameCandidate {
				fs.shrinkRefusalID++
				fs.shrinkRefused = true
				fs.shrinkCandidateHash = res.hash
				fs.shrinkBaselineHash = baselineHash
				fs.shrinkCandidateOldCount = candidateOldCount
				fs.shrinkCandidateNewCount = newCount
				fs.shrinkCandidateReason = candidateReason
				clearShrinkAck(fs)
			}
			fs.shrinkRefusalCount++
			now := m.now()
			warn := !sameCandidate ||
				fs.shrinkLastWarn.IsZero() ||
				now.Sub(fs.shrinkLastWarn) >= feedShrinkWarnInterval
			if warn {
				fs.shrinkLastWarn = now
			}
			var ferr error
			switch {
			case refusedAfterDrop:
				ferr = fmt.Errorf(
					"refused shrink re-served after hold-interval drop: candidate %d prefixes vs %d remembered high-water; the exact acknowledgement is required to install this candidate (previous-good enforcement retained)",
					newCount, highWaterCount)
			case shrinkTripped:
				ferr = fmt.Errorf(
					"drastic shrink refused against epoch high-water baseline: candidate %d prefixes vs %d high-water (%d currently installed); retain-percent floor %d%% and minimum drop %d; retaining last-good snapshot",
					newCount, highWaterCount, oldCount, thresholds.minRetainPercent, thresholds.minDrop)
			case epochChurnTripped:
				ferr = fmt.Errorf(
					"epoch content overlap below floor: candidate %d prefixes retain less than %d%% of the %d epoch-baseline prefixes (%d currently installed); retaining last-good snapshot",
					newCount, thresholds.minRetainPercent, len(churnBaseline), oldCount)
			case malformedTripped:
				ferr = fmt.Errorf(
					"malformed lines dropped previously-enforced prefixes: candidate %d prefixes with %d invalid line(s) dropped %d of %d installed prefixes; retaining last-good snapshot",
					newCount, res.invalidLines, len(fs.prefixes)-retainedPrefixCount(fs.prefixes, res.prefixes), len(fs.prefixes))
			default:
				ferr = fmt.Errorf(
					"content overlap below floor: candidate %d prefixes retain less than %d%% of the %d currently installed prefixes; retaining last-good snapshot",
					newCount, thresholds.minRetainPercent, oldCount)
			}
			failure := m.recordFailureLocked(fs, ferr)
			refusalID := fs.shrinkRefusalID
			refusalCount := fs.shrinkRefusalCount
			refusalReason := fs.shrinkCandidateReason
			candidateHash := fmt.Sprintf("%x", res.hash)
			refusalBaselineHash := fmt.Sprintf("%x", baselineHash)
			m.mu.Unlock()
			logMessage := "dynamic-address: feed drastic shrink REFUSED — retaining last-good snapshot"
			if refusedAfterDrop {
				logMessage = "dynamic-address: feed drastic shrink REFUSED after hold-interval drop — awaiting exact acknowledgement"
			} else if malformedTripped && !shrinkTripped && !churnTripped {
				logMessage = "dynamic-address: feed malformed-shrink REFUSED — retaining last-good snapshot"
			} else if churnTripped && !shrinkTripped {
				logMessage = "dynamic-address: feed content-churn REFUSED — retaining last-good snapshot"
			}
			if warn {
				slog.Warn(logMessage,
					"name", fs.name, "refusal_id", refusalID, "candidate_hash", candidateHash,
					"baseline_hash", refusalBaselineHash, "candidate_prefixes", newCount,
					"previous_prefixes", oldCount, "guard_baseline_prefixes", candidateOldCount,
					"guard_reason", refusalReason, "refusal_count", refusalCount)
			} else {
				slog.Debug(strings.Replace(logMessage, " REFUSED", " still REFUSED", 1),
					"name", fs.name, "refusal_id", refusalID, "candidate_hash", candidateHash,
					"baseline_hash", refusalBaselineHash, "candidate_prefixes", newCount,
					"previous_prefixes", oldCount, "guard_baseline_prefixes", candidateOldCount,
					"guard_reason", refusalReason, "refusal_count", refusalCount)
			}
			m.finishFailure(fs, failure, false)
			return
		}
	}
	now := m.now()
	fs.prefixes = res.prefixes
	fs.hash = res.hash
	fs.hasSnapshot = true
	fs.holdDropped = false
	fs.dropRetryDelay = 0
	fs.dropRetryAt = time.Time{}
	fs.lastFetch = now
	fs.lastSuccess = now
	fs.lastError = ""
	fs.staleSince = time.Time{}
	fs.invalidLines = res.invalidLines
	fs.invalidSample = res.invalidSample
	newCount := len(res.prefixes)
	if guardBypass || newCount >= fs.shrinkHighWaterCount {
		fs.shrinkHighWaterCount = newCount
		fs.shrinkHighWaterHash = res.hash
	}
	// #14395 epoch rebase: ONLY a true bootstrap (no remembered baseline)
	// or an acknowledged (guardBypass) install moves the content epoch. An
	// ordinary unacknowledged install — including equal-count rotations
	// that pass the epoch floor — never rebases, so cumulative rotation
	// cannot boil the frog. The same non-rebase applies to growth on a
	// remembered-baseline feed (#14994): comparing a growing candidate
	// against the restored epoch must not move shrinkHighWaterHash/
	// epochContentPrefixes ahead of that epoch before acknowledgement
	// (#14395 intentional non-rebase on growth, preserved). When the epoch
	// rebases on acknowledgement, the count high-water rebases with it to
	// the acknowledged set (mirrors the existing acknowledged-shrink epoch
	// semantics).
	epochRebased := false
	if (wasBootstrap && !hasRememberedBaseline) || guardBypass {
		fs.epochContentPrefixes = append([]string(nil), res.prefixes...)
		fs.epochContentHash = res.hash
		epochRebased = true
		if guardBypass {
			fs.shrinkHighWaterCount = newCount
			fs.shrinkHighWaterHash = res.hash
		}
	}
	if epochRebased {
		m.rememberShrinkEpochLocked(fs.name, fs.shrinkHighWaterCount, fs.shrinkHighWaterHash, fs.epochContentPrefixes, fs.epochContentHash)
	} else {
		m.rememberShrinkHighWaterLocked(fs.name, fs.shrinkHighWaterCount, fs.shrinkHighWaterHash)
	}
	historyChanged := fs.shrinkHighWaterCount != priorHighWaterCount ||
		fs.shrinkHighWaterHash != priorHighWaterHash || epochRebased
	historyChangedCallback := m.onShrinkHistoryChanged
	// Any successful install re-baselines last-good and clears an outstanding
	// refusal/acknowledgement. An ack can never apply to a later candidate.
	clearShrinkCandidate(fs)
	m.mu.Unlock()
	if historyChanged && historyChangedCallback != nil {
		historyChangedCallback()
	}
	if bootstrapDiffersFromHighWater {
		slog.Warn("dynamic-address: bootstrap below or changed from remembered high-water — installing with audit warning",
			"name", fs.name, "remembered_prefixes", rememberedHighWaterCount,
			"remembered_hash", fmt.Sprintf("%x", rememberedHighWaterHash),
			"candidate_prefixes", newCount, "candidate_hash", fmt.Sprintf("%x", res.hash))
	}

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

	if guardBypass {
		slog.Warn("dynamic-address: feed installed the exact acknowledged drastic-shrink candidate",
			"name", fs.name, "refusal_id", fs.shrinkRefusalID, "candidate_hash", fmt.Sprintf("%x", res.hash),
			"baseline_hash", fmt.Sprintf("%x", guardBaselineHash), "prefixes", len(res.prefixes),
			"previous", oldCount, "actor", guardActor, "reason", guardReason)
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
		// Apply rejection can be followed by a refetch whose content hash
		// equals the last confirmed hash (for example, recovery after a
		// rejected hold-drop). Preserve explicit debt in that case.
		m.mu.Lock()
		if cur, ok := m.feeds[fs.name]; ok && cur == fs {
			fs.publishUnconfirmed = true
		}
		m.mu.Unlock()
		slog.Warn("dynamic-address: feed apply REJECTED — good content not yet enforced (publication debt), will retry on next refresh",
			"name", fs.name, "prefixes", len(res.prefixes), "err", applyErr)
		return
	}
	m.mu.Lock()
	// Recheck currency before advancing: fs may have gone stale during the long
	// onUpdate apply above. Advancing an orphan's publishedHash is harmless (the
	// orphan is discarded) but pointless; the live entry tracks its own state.
	if cur, ok := m.feeds[fs.name]; ok && cur == fs {
		fs.publishedHash = res.hash
		fs.hasPublished = true
		fs.publishUnconfirmed = false
	}
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
//     Copilot #2). The drop RETAINS an outstanding refused-shrink candidate
//     (#12882): the exact refused candidate must not resurface as an
//     unacknowledged bootstrap once the snapshot it was refused against is
//     gone, so the refusal and its acknowledgeable tuple survive the drop
//     and installSnapshot keeps re-refusing that exact candidate.
//
// A one-time slog.Warn fires when the feed first ENTERS the stale state, not
// on every failing tick, so a persistently-down feed does not flood the log.
type feedFailureTransition struct {
	current      bool
	enteredStale bool
	dropped      bool
	retryDropped bool
	lastError    string
	holdInterval time.Duration
}

// recordFailureLocked applies the shared retain/drop policy. The caller holds
// m.mu so refusal failures and ordinary fetch errors observe the same explicit
// hold-interval behavior.
func (m *Manager) recordFailureLocked(fs *feedState, ferr error) feedFailureTransition {
	if cur, ok := m.feeds[fs.name]; !ok || cur != fs {
		return feedFailureTransition{}
	}
	now := m.now()
	fs.lastError = redactFeedURLInError9164(ferr.Error(), fs.url)
	transition := feedFailureTransition{
		current:      true,
		lastError:    fs.lastError,
		holdInterval: fs.holdInterval,
	}
	if fs.hasSnapshot && len(fs.prefixes) > 0 {
		if fs.staleSince.IsZero() {
			fs.staleSince = now
			transition.enteredStale = true
		}
		if fs.holdInterval > 0 && now.Sub(fs.staleSince) >= fs.holdInterval {
			dropSnapshotToEmptyLocked(fs)
			transition.dropped = true
		}
	}
	// A rejected hold-drop remains publication debt, but frequent fetches must
	// not repeatedly run the full config apply when that desired state is still
	// rejected. Retry on an exponential schedule; a changed successful fetch
	// still publishes through installSnapshot immediately.
	if !transition.dropped && fs.holdDropped && feedPublicationDebt(fs) &&
		(fs.dropRetryAt.IsZero() || !now.Before(fs.dropRetryAt)) {
		transition.retryDropped = true
	}
	return transition
}

func dropSnapshotToEmptyLocked(fs *feedState) {
	fs.prefixes = nil
	fs.hash = [32]byte{}
	fs.hasSnapshot = false
	fs.staleSince = time.Time{}
	fs.invalidLines = 0
	fs.invalidSample = nil
	fs.holdDropped = true
	// #12882: an outstanding refused shrink SURVIVES the drop. Clearing it
	// here made the hold expiry a laundering step — the next fetch of the
	// exact refused candidate arrived with no live snapshot, skipped the
	// hasSnapshot-keyed guards, and installed the refused relaxation as an
	// unacknowledged "bootstrap" (audit warning only). The refusal and its
	// candidate tuple stay acknowledgeable instead; installSnapshot
	// re-refuses the exact candidate until the acknowledgement lands, and
	// any different acceptable fetch installs and clears it as before.
}

func (m *Manager) recordFailure(fs *feedState, ferr error) {
	m.mu.Lock()
	transition := m.recordFailureLocked(fs, ferr)
	m.mu.Unlock()
	if !transition.current {
		slog.Debug("dynamic-address: stale feed failure suppressed (post-swap)",
			"name", fs.name)
		return
	}
	m.finishFailure(fs, transition, true)
}

// holdDeadlineLocked returns the wall-clock time at which a current feed's
// retained snapshot reaches its hold deadline. It is the single source for
// both arming (holdExpiryDelay) and expiry (expireStaleHold): the refresh
// loop only makes progress if an armed timer implies the expiry path either
// drops the snapshot or computes a positive delay. Callers must hold m.mu
// (read or write); staleSince keeps its monotonic reading across calls.
func (m *Manager) holdDeadlineLocked(fs *feedState) (time.Time, bool) {
	if cur, ok := m.feeds[fs.name]; !ok || cur != fs ||
		fs.holdInterval <= 0 || !fs.hasSnapshot || len(fs.prefixes) == 0 ||
		fs.staleSince.IsZero() {
		return time.Time{}, false
	}
	return fs.staleSince.Add(fs.holdInterval), true
}

// holdExpiryDelay returns the time until a current feed's retained snapshot
// reaches its hold deadline. The refresh loop uses this to wake independently
// of the (potentially much longer) fetch cadence.
func (m *Manager) holdExpiryDelay(fs *feedState) (time.Duration, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	deadline, ok := m.holdDeadlineLocked(fs)
	if !ok {
		return 0, false
	}
	delay := deadline.Sub(m.now())
	if delay < 0 {
		delay = 0
	}
	return delay, true
}

// expireStaleHold applies a due hold expiry without waiting for another fetch
// failure. The drop is applied under m.mu; its log and onUpdate publication
// run outside m.mu, as in recordFailure.
func (m *Manager) expireStaleHold(fs *feedState) {
	m.mu.Lock()
	deadline, ok := m.holdDeadlineLocked(fs)
	if !ok {
		m.mu.Unlock()
		return
	}
	if m.now().Before(deadline) {
		m.mu.Unlock()
		return
	}
	transition := feedFailureTransition{
		current:      true,
		dropped:      true,
		lastError:    fs.lastError,
		holdInterval: fs.holdInterval,
	}
	dropSnapshotToEmptyLocked(fs)
	m.mu.Unlock()
	m.finishFailure(fs, transition, false)
}

func (m *Manager) finishFailure(fs *feedState, transition feedFailureTransition, logRetained bool) {
	if transition.dropped || transition.retryDropped {
		if transition.dropped {
			slog.Warn("dynamic-address: hold interval elapsed, dropping stale feed to empty",
				"name", fs.name, "err", transition.lastError, "hold", transition.holdInterval)
		}
		var applyErr error
		if m.onUpdate != nil {
			// An empty set has no fixed safety direction: a denylist stops
			// denying while an allowlist stops permitting. The existing binding
			// fail-mode controls the dataplane consequence; keep the hold policy
			// shared by ordinary fetch failures and shrink refusals.
			applyErr = m.onUpdate()
		}
		m.mu.Lock()
		if cur, ok := m.feeds[fs.name]; ok && cur == fs && fs.holdDropped {
			if applyErr != nil {
				fs.publishUnconfirmed = true
				if fs.dropRetryDelay == 0 {
					fs.dropRetryDelay = feedDropRetryInitialDelay
				} else if fs.dropRetryDelay < feedDropRetryMaxDelay {
					fs.dropRetryDelay *= 2
					if fs.dropRetryDelay > feedDropRetryMaxDelay {
						fs.dropRetryDelay = feedDropRetryMaxDelay
					}
				}
				fs.dropRetryAt = m.now().Add(fs.dropRetryDelay)
			} else {
				fs.dropRetryDelay = 0
				fs.dropRetryAt = time.Time{}
				fs.publishedHash = emptyFeedHash
				fs.publishUnconfirmed = false
				fs.hasPublished = true
			}
		}
		m.mu.Unlock()
		if applyErr != nil {
			slog.Warn("dynamic-address: drop-to-empty apply not confirmed — dataplane state may differ",
				"name", fs.name, "err", applyErr, "retry", transition.retryDropped)
			return
		}
		if transition.retryDropped {
			slog.Info("dynamic-address: retried hold-drop apply accepted",
				"name", fs.name)
		}
		return
	}
	if !logRetained {
		return
	}
	if transition.enteredStale {
		slog.Warn("dynamic-address: feed entered STALE — fetch failed, retaining last-good snapshot",
			"name", fs.name, "err", transition.lastError, "retain",
			func() string {
				if transition.holdInterval > 0 {
					return transition.holdInterval.String()
				}
				return "forever"
			}())
		return
	}
	slog.Debug("dynamic-address: fetch failed, retaining last-good",
		"name", fs.name, "err", transition.lastError)
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
	// No early return when the configured URL is clean: the transport may
	// still quote a changed URL carrying a credential (#12883). The scrub
	// below is a no-op on credential-free URLs, so the no-credential
	// control diagnostic stays byte-identical.
	redacted := config.RedactURL(rawURL)
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
	// #12883: the transport may quote a URL that differs from the configured
	// one — a same-origin redirect target, or a scheme/host-normalized
	// spelling — whose query token the literal passes above cannot know.
	// Scrub every remaining URL-shaped token in the text through the same
	// RedactURL definition.
	return scrubURLsInText12883(out)
}

// scrubURLsInText12883 redacts every scheme:// token in text (terminated by
// whitespace or a quote) via config.RedactURL.
func scrubURLsInText12883(text string) string {
	var b strings.Builder
	rest := text
	for {
		i := strings.Index(rest, "://")
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		// The scheme starts after the last delimiter before "://".
		start := strings.LastIndexAny(rest[:i], " 	\"'`(<[{") + 1
		end := i + 3
		for end < len(rest) && !strings.ContainsRune(" 	\"'`>", rune(rest[end])) {
			end++
		}
		b.WriteString(rest[:start])
		b.WriteString(config.RedactURL(rest[start:end]))
		rest = rest[end:]
	}
}
