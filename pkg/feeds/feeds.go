// Package feeds implements dynamic address feed fetching and management.
package feeds

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
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

// maxFeedPrefixes aliases the config-time limit so operators cannot configure
// a threshold the parser can never reach.
const maxFeedPrefixes = config.MaxDynamicAddressFeedPrefixes

// httpClientTimeout bounds a single feed fetch end-to-end (connect + headers +
// body read), so a slow-loris feed server that dribbles bytes cannot hold the
// fetch open indefinitely (#3934). The next refresh tick retries.
const httpClientTimeout = 30 * time.Second

// feedDialAttemptTimeout bounds each pinned dial attempt so a blackholed
// first answer cannot consume the whole shared fetch budget and starve
// reachable later answers (serial fallback without Happy Eyeballs). It is a
// var so tests can shrink it; production stays well under httpClientTimeout.
var feedDialAttemptTimeout = 5 * time.Second

// Default drastic-shrink guard thresholds (#11059). Runtime behavior is
// configured per feed-server in the committed config; these defaults apply
// when a leaf is omitted or malformed on a lenient load.
const (
	feedShrinkGuardMinOldCountDefault      = config.DefaultDynamicAddressShrinkGuardMinOldCount
	feedShrinkGuardMinRetainPercentDefault = config.DefaultDynamicAddressShrinkGuardRetainPct
	feedShrinkGuardMinDropDefault          = config.DefaultDynamicAddressShrinkGuardMinDrop
	feedShrinkWarnInterval                 = time.Hour
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

// maxFeedRedirects preserves net/http's built-in redirect bound after the
// client installs the feed-specific CheckRedirect policy below.
const maxFeedRedirects = 10

// sameOriginFeedURL reports whether two HTTP URLs share an origin. Origins are
// defined by scheme, hostname, and effective port; credentials and paths are
// intentionally excluded.
func sameOriginFeedURL(a, b *url.URL) bool {
	if a == nil || b == nil || a.Hostname() == "" || b.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) ||
		!strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return feedOriginPort(a) == feedOriginPort(b)
}

func feedOriginPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// checkFeedRedirect permits only same-origin redirects. A provider-controlled
// Location must never turn the configured feed URL into an SSRF primitive.
func checkFeedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if len(via) >= maxFeedRedirects {
		return fmt.Errorf("dynamic-address: stopped after %d redirects", maxFeedRedirects)
	}

	previous := via[len(via)-1]
	if previous != nil && req != nil && sameOriginFeedURL(previous.URL, req.URL) {
		return nil
	}

	from := "<unknown>"
	if via[0] != nil && via[0].URL != nil {
		from = config.RedactURL(via[0].URL.String())
	}
	slog.Warn("dynamic-address: cross-origin feed redirect refused", "from", from)
	// Keep the provider-supplied Location out of url.Error; readFeed closes
	// this response and rejects the retained 302 with a generic status error.
	return http.ErrUseLastResponse
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
type ShrinkHighWater struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Hash  string `json:"hash"`
}

type feedShrinkHistory struct {
	highWaterCount int
	highWaterHash  [32]byte
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
		m.shrinkHistory[record.Name] = feedShrinkHistory{highWaterCount: record.Count, highWaterHash: hash}
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
		records = append(records, ShrinkHighWater{
			Name: name, Count: history.highWaterCount, Hash: fmt.Sprintf("%x", history.highWaterHash),
		})
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

// blockedFeedDestinationPrefixes contains address space that is not a public
// feed destination. netip.Addr's classification methods cover the RFC1918,
// RFC4193, loopback, and link-local classes; these explicit prefixes add the
// cloud metadata/CGNAT and special-purpose ranges that are still otherwise
// classified as global unicast by the standard library.
var blockedFeedDestinationPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT; Alibaba metadata is within it.
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments.
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking/special-purpose.
}

func (m *Manager) privateFeedAllowlistSnapshot() []netip.Prefix {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]netip.Prefix(nil), m.privateFeedAllowlist...)
}

func feedDestinationAllowed(ip netip.Addr, allowlist []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, prefix := range allowlist {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func feedDestinationBlocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() ||
		!ip.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range blockedFeedDestinationPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveFeedIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		return []netip.Addr{literal.Unmap()}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve feed destination: %w", err)
	}
	return ips, nil
}

// resolveAndValidateFeedDestination resolves a feed hostname once and
// validates every answer before the transport is allowed to dial. Refusing
// the whole answer set when any member is forbidden prevents a resolver from
// selecting a private answer after a public answer was observed.
func (m *Manager) resolveAndValidateFeedDestination(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, fmt.Errorf("empty feed destination host")
	}

	var (
		ips []netip.Addr
		err error
	)
	m.mu.RLock()
	resolve := m.resolveFeedIPs
	m.mu.RUnlock()
	if resolve != nil {
		ips, err = resolve(ctx, host)
	} else {
		ips, err = resolveFeedIPs(ctx, host)
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve feed destination returned no addresses")
	}

	allowlist := m.privateFeedAllowlistSnapshot()
	unique := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() {
			return nil, fmt.Errorf("feed destination resolved to an invalid address")
		}
		if feedDestinationBlocked(ip) && !feedDestinationAllowed(ip, allowlist) {
			return nil, fmt.Errorf("feed destination resolves to a blocked address")
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	return unique, nil
}

// pinnedFeedClient clones the feed transport with a dialer that uses only the
// already-validated addresses. The request URL retains its hostname for Host
// and TLS SNI, but no later transport operation can perform a fresh DNS
// lookup, closing the resolve/check/dial TOCTOU window.
func pinnedFeedClient(base *http.Client, ips []netip.Addr, port string) (*http.Client, error) {
	if base == nil {
		return nil, fmt.Errorf("feed client is nil")
	}
	baseTransport, ok := base.Transport.(*http.Transport)
	if !ok || baseTransport == nil {
		return nil, fmt.Errorf("feed client transport cannot pin destination")
	}
	transport := baseTransport.Clone()
	transport.DialTLSContext = nil
	baseDialContext := baseTransport.DialContext
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var lastErr error
		for _, ip := range ips {
			switch {
			case network == "tcp4" && !ip.Is4():
				continue
			case network == "tcp6" && !ip.Is6():
				continue
			}
			target := net.JoinHostPort(ip.String(), port)
			attemptCtx, cancelAttempt := context.WithTimeout(ctx, feedDialAttemptTimeout)
			var conn net.Conn
			var err error
			if baseDialContext != nil {
				conn, err = baseDialContext(attemptCtx, network, target)
			} else {
				conn, err = dialer.DialContext(attemptCtx, network, target)
			}
			cancelAttempt()
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no validated address matches network %q", network)
	}
	client := *base
	client.Transport = transport
	return &client, nil
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
	// Carry the last confirmed publish state across a same-name producer
	// replacement. The daemon's apply re-enforces a carried snapshot; matching
	// content stays no-thrash, while an existing content mismatch remains
	// publication debt and is retried on the first fetch. Preserve this marker
	// even for a hold-dropped feed: if its empty apply was rejected, the old
	// published hash is needed to keep that debt visible until a later apply.
	dst.publishedHash = src.publishedHash
	dst.hasPublished = src.hasPublished
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
		out[name] = merged
	}
	return out
}

// feedPublicationDebt reports whether the desired installed state has not
// been confirmed applied. A hold-drop desires the empty set, represented by
// emptyFeedHash even though it has no installed snapshot slice.
func feedPublicationDebt(fs *feedState) bool {
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
	fetchCtx, cancelFetch := context.WithTimeout(ctx, httpClientTimeout)
	defer cancelFetch()
	req, err := http.NewRequestWithContext(fetchCtx, "GET", fs.url, nil)
	if err != nil {
		return fetchResult{}, fmt.Errorf("invalid URL: %w", err)
	}
	if req.URL.Hostname() == "" {
		return fetchResult{}, fmt.Errorf("invalid URL: empty feed destination host")
	}
	port := feedOriginPort(req.URL)
	if port == "" {
		return fetchResult{}, fmt.Errorf("invalid URL: unsupported feed destination scheme")
	}

	// Resolve and validate exactly once under the same deadline as the request.
	// The pinned client below retains the hostname in req.URL (for Host/TLS SNI)
	// while dialing only this validated address set, so a DNS answer cannot
	// change between validation and dial.
	ips, err := m.resolveAndValidateFeedDestination(fetchCtx, req.URL.Hostname())
	if err != nil {
		return fetchResult{}, fmt.Errorf("feed destination refused: %w", err)
	}
	client, err := pinnedFeedClient(m.client, ips, port)
	if err != nil {
		return fetchResult{}, fmt.Errorf("feed destination refused: %w", err)
	}
	// Each fetch gets a cloned transport so its dialer can be pinned. Close
	// idle connections after the body is consumed; otherwise a zero
	// IdleConnTimeout would retain one transport/read-loop per refresh.
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
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
// It refuses both explicit default-route entries (#9248) and a canonical
// prefix union that covers an entire address family (#10711).
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
			// The assembled prefix set is also checked below: a provider must
			// not evade this refusal by splitting the address space into ranges.
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
	if coversWholeAddressSpace(canon) {
		return fetchResult{}, fmt.Errorf(
			"feed prefix union covers a whole address space (IPv4 or IPv6); refusing the feed (#10711)")
	}
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

// coversWholeAddressSpace reports whether prefixes cover all of either
// address family. It sorts their address ranges and looks for an uninterrupted
// run from the family's unspecified address through its maximum address.
// Input is the canonicalized set from parseFeed.
func coversWholeAddressSpace(prefixes []string) bool {
	ranges := make([]netip.Prefix, 0, len(prefixes))
	for _, text := range prefixes {
		if prefix, err := netip.ParsePrefix(text); err == nil {
			ranges = append(ranges, prefix.Masked())
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if cmp := ranges[i].Addr().Compare(ranges[j].Addr()); cmp != 0 {
			return cmp < 0
		}
		return ranges[i].Bits() < ranges[j].Bits()
	})

	for first := 0; first < len(ranges); {
		is4 := ranges[first].Addr().Is4()
		last := first + 1
		for last < len(ranges) && ranges[last].Addr().Is4() == is4 {
			last++
		}

		var coveredThrough netip.Addr
		coveredFromZero := false
		for _, prefix := range ranges[first:last] {
			start := prefix.Addr()
			end := prefixLastAddress(prefix)
			if !coveredFromZero {
				if !start.IsUnspecified() {
					break
				}
				coveredThrough = end
				coveredFromZero = true
			} else {
				next := coveredThrough.Next()
				if !next.IsValid() {
					return true
				}
				if start.Compare(next) > 0 {
					break
				}
				if end.Compare(coveredThrough) > 0 {
					coveredThrough = end
				}
			}
			if !coveredThrough.Next().IsValid() {
				return true
			}
		}
		first = last
	}
	return false
}

// prefixLastAddress returns the inclusive upper bound of a masked prefix.
func prefixLastAddress(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		bytes := prefix.Addr().As4()
		hostBits := 32 - prefix.Bits()
		for i := len(bytes) - 1; i >= 0 && hostBits > 0; i-- {
			setBits := hostBits
			if setBits > 8 {
				setBits = 8
			}
			bytes[i] |= byte((1 << uint(setBits)) - 1)
			hostBits -= setBits
		}
		return netip.AddrFrom4(bytes)
	}

	bytes := prefix.Addr().As16()
	hostBits := 128 - prefix.Bits()
	for i := len(bytes) - 1; i >= 0 && hostBits > 0; i-- {
		setBits := hostBits
		if setBits > 8 {
			setBits = 8
		}
		bytes[i] |= byte((1 << uint(setBits)) - 1)
		hostBits -= setBits
	}
	return netip.AddrFrom16(bytes)
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
	if fs.shrinkRefusalID != refusalID ||
		candidateHash != fmt.Sprintf("%x", fs.shrinkCandidateHash) ||
		baselineHash != fmt.Sprintf("%x", fs.shrinkBaselineHash) ||
		fs.hash != fs.shrinkBaselineHash ||
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
	if m.shrinkHistory == nil {
		m.shrinkHistory = make(map[string]feedShrinkHistory)
	}
	m.shrinkHistory[name] = feedShrinkHistory{highWaterCount: count, highWaterHash: hash}
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
// and also checks retained exact-prefix overlap with the current last-good set.
// Refusals retain the installed set, mark stale, alarm, and publish nothing
// until the exact candidate is acknowledged. Bootstrap is installable; a
// same-manager re-created feed with fewer prefixes or changed same-sized
// content is installed with an audit warning instead of a silent bootstrap.
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
	// changed = the installed enforced content differs from the prior install.
	// Drives the display/degraded logging (a content change), independent of
	// whether that content has been PUBLISHED.
	changed := !fs.hasSnapshot || fs.hash != res.hash
	// needsPublish = the fetched content differs from what was last CONFIRMED
	// applied. Drives the onUpdate publish/retry. A rejected apply leaves
	// publishedHash stale, so this stays true on an identical refetch → retry.
	needsPublish := !fs.hasPublished || fs.publishedHash != res.hash
	oldCount := len(fs.prefixes)
	baselineHash := fs.hash
	if fs.hasSnapshot && fs.shrinkHighWaterCount == 0 {
		fs.shrinkHighWaterCount = oldCount
		fs.shrinkHighWaterHash = fs.hash
	}
	thresholds := thresholdsForFeed(fs)
	highWaterCount := fs.shrinkHighWaterCount
	if highWaterCount == 0 {
		highWaterCount = oldCount
	}
	shrinkTripped := fs.hasSnapshot && fs.hash != res.hash &&
		shrinkGuardTrippedWithThresholds(highWaterCount, len(res.prefixes), thresholds)
	churnTripped := fs.hasSnapshot &&
		contentChurnTripped(fs.prefixes, res.prefixes, thresholds)
	bootstrapDiffersFromHighWater := !fs.hasSnapshot && fs.shrinkHighWaterCount > 0 &&
		len(res.prefixes) <= fs.shrinkHighWaterCount &&
		(len(res.prefixes) < fs.shrinkHighWaterCount || res.hash != fs.shrinkHighWaterHash)
	rememberedHighWaterCount := fs.shrinkHighWaterCount
	rememberedHighWaterHash := fs.shrinkHighWaterHash

	// Refusals and their acknowledgements bind to the exact content/baseline
	// tuple. For a cumulative shrink, old_count is the epoch high-water count;
	// for content churn alone, it is the currently installed count.
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
		candidateReason += "retained content overlap below floor"
	}
	if fs.hasSnapshot && (shrinkTripped || churnTripped) {
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
			if shrinkTripped {
				ferr = fmt.Errorf(
					"drastic shrink refused against epoch high-water baseline: candidate %d prefixes vs %d high-water (%d currently installed); retain-percent floor %d%% and minimum drop %d; retaining last-good snapshot",
					newCount, highWaterCount, oldCount, thresholds.minRetainPercent, thresholds.minDrop)
			} else {
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
			if churnTripped && !shrinkTripped {
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
	m.rememberShrinkHighWaterLocked(fs.name, fs.shrinkHighWaterCount, fs.shrinkHighWaterHash)
	historyChanged := fs.shrinkHighWaterCount != priorHighWaterCount ||
		fs.shrinkHighWaterHash != priorHighWaterHash
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
	// Recheck currency before advancing: fs may have gone stale during the long
	// onUpdate apply above. Advancing an orphan's publishedHash is harmless (the
	// orphan is discarded) but pointless; the live entry tracks its own state.
	if cur, ok := m.feeds[fs.name]; ok && cur == fs {
		fs.publishedHash = res.hash
		fs.hasPublished = true
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
//     Copilot #2).
//
// A one-time slog.Warn fires when the feed first ENTERS the stale state, not
// on every failing tick, so a persistently-down feed does not flood the log.
type feedFailureTransition struct {
	current      bool
	enteredStale bool
	dropped      bool
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
	clearShrinkCandidate(fs)
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

func (m *Manager) finishFailure(fs *feedState, transition feedFailureTransition, logRetained bool) {
	if transition.dropped {
		slog.Warn("dynamic-address: hold interval elapsed, dropping stale feed to empty",
			"name", fs.name, "err", transition.lastError, "hold", transition.holdInterval)
		if m.onUpdate != nil {
			// An empty set has no fixed safety direction: a denylist stops
			// denying while an allowlist stops permitting. The existing binding
			// fail-mode controls the dataplane consequence; keep the hold policy
			// shared by ordinary fetch failures and shrink refusals.
			if err := m.onUpdate(); err != nil {
				slog.Warn("dynamic-address: drop-to-empty apply rejected — dataplane retains last-good set",
					"name", fs.name, "err", err)
				return
			}
		}
		m.mu.Lock()
		if cur, ok := m.feeds[fs.name]; ok && cur == fs && fs.holdDropped {
			fs.publishedHash = emptyFeedHash
			fs.hasPublished = true
		}
		m.mu.Unlock()
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
