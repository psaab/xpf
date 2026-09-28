// Package api REST credential brute-force throttle (#10825).
//
// Before this file, REST Basic/API-key checks were constant-time but
// unlimited-rate: no delay, lockout, source cap, or failure budget. An
// off-loopback listener therefore admitted network online-guessing of
// human-chosen Basic passwords at whatever rate the attacker could sustain,
// and #10832's counted audit (denyaudit.SurfaceRESTAPIAuthFail) observed the
// failures without ever stopping them.
//
// The throttle is TWO budgets, and both must exist:
//
//   - per-source+account: 5 failures in 10 minutes locks that (IP, account)
//     pair for 5 minutes, doubling per consecutive lockout (cap 1h). A success
//     clears the pair outright, so a legit caller with correct credentials
//     never trips it and recovers immediately.
//   - per-source: 20 failures in 10 minutes from one IP (ANY account) locks
//     the whole source. Without this an attacker rotates Basic usernames (or
//     Bearer values) and no single compound key ever fills. A success clears
//     only the pair, never the source: a success proves nothing about the
//     other failures from that IP.
//
// Both budgets are checked BEFORE the credential verify, so a locked-out
// caller never reaches the (post-#10826 bcrypt) compare — the lockout is what
// bounds attacker-driven verify CPU. Every lockout rejection is still counted
// under the existing rest_api_auth_fail surface (a lockout rejection IS an
// authentication failure); no second surface is created for the same event.
//
// State lives on the middleware instance, never in a package global: the
// static authMiddleware owns a tracker in its closure, and the live-swap
// dynamicAuthMiddleware uses the Server's (Server.throttle, lazily built).
// Per-instance state keeps test servers isolated without a reset hook and
// keeps the two legs of one server under one budget. The table is bounded
// (4096 entries; expired-first sweep, then arbitrary evict) so the key space
// — which includes attacker-influenced usernames — cannot grow memory
// without bound; see the denyaudit fixed-bucket rationale for the doctrine.
//
// There is deliberately NO loopback exemption. The nil-auth loopback path
// (dynamicAuthMiddleware's pass-through) never consults the tracker at all —
// there is no credential to fail — so local automation on an open loopback
// listener is untouched. A loopback listener WITH api-auth is throttled like
// any other: success resets, so correct credentials never notice.
package api

import (
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// authThrottleAccountFailures is the per-(source, account) failure budget
	// within authThrottleWindow before that pair locks.
	authThrottleAccountFailures = 5
	// authThrottleSourceFailures is the per-source failure budget within
	// authThrottleWindow before the whole source IP locks. Higher than the
	// pair budget: it exists to catch username/token rotation, not to punish
	// one fat-fingered account.
	authThrottleSourceFailures = 20
	// authThrottleWindow is the rolling window both budgets are counted in.
	authThrottleWindow = 10 * time.Minute
	// authThrottleBaseLockout is the first lockout duration; consecutive
	// lockouts double up to authThrottleMaxLockout.
	authThrottleBaseLockout = 5 * time.Minute
	authThrottleMaxLockout  = time.Hour
	// authThrottleMaxEntries bounds each tracker table. Past it, an insert
	// sweeps expired buckets and then evicts arbitrarily — eviction only
	// forgives failures early (fail-open on memory pressure, never fail-closed
	// into a permanent lockout).
	authThrottleMaxEntries = 4096
)

// authFailureBucket is one lockout cell: either a (source, account) pair or a
// whole source IP.
type authFailureBucket struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
	lockouts    int // consecutive lockouts; sets the escalated duration
}

// authFailureTracker counts REST credential failures against the two #10825
// budgets. The zero value is not usable; build with newAuthFailureTracker.
type authFailureTracker struct {
	mu       sync.Mutex
	now      func() time.Time
	accounts map[string]*authFailureBucket
	sources  map[string]*authFailureBucket
}

func newAuthFailureTracker(clock func() time.Time) *authFailureTracker {
	if clock == nil {
		clock = time.Now
	}
	return &authFailureTracker{
		now:      clock,
		accounts: make(map[string]*authFailureBucket),
		sources:  make(map[string]*authFailureBucket),
	}
}

// setClockForTest replaces the clock. Tests advance time without sleeping;
// production never replaces it.
func (t *authFailureTracker) setClockForTest(clock func() time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = clock
}

// locked reports whether (source, account) is currently locked under either
// budget, and how long until the governing lockout lifts. Read-only: checking
// never extends a lockout.
func (t *authFailureTracker) locked(source, account string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	longest := time.Duration(0)
	locked := false
	for _, b := range []*authFailureBucket{t.accounts[source+"\x00"+account], t.sources[source]} {
		if b == nil {
			continue
		}
		if remaining := b.lockedUntil.Sub(now); remaining > 0 {
			locked = true
			if remaining > longest {
				longest = remaining
			}
		}
	}
	return locked, longest
}

// chargeLocked applies one failure to a bucket: windowed counting, lockout at
// threshold with doubling escalation, full forgiveness after a quiet window.
func (t *authFailureTracker) chargeLocked(b *authFailureBucket, now time.Time, threshold int) {
	if now.Before(b.lockedUntil) {
		// Failures during a live lockout are dropped, rather than extending
		// the deadline or escalating on checks that never ran.
		return
	}
	if now.Sub(b.windowStart) > authThrottleWindow {
		// A full quiet window forgives everything, including the escalation
		// level: a caller who stopped failing is not the same threat as one
		// who never stopped.
		b.failures = 0
		b.lockouts = 0
		b.windowStart = now
	}
	b.failures++
	if b.failures < threshold {
		return
	}
	b.lockouts++
	d := authThrottleBaseLockout << (b.lockouts - 1)
	if d <= 0 || d > authThrottleMaxLockout {
		d = authThrottleMaxLockout
	}
	b.lockedUntil = now.Add(d)
	b.failures = 0
	b.windowStart = now
}

// recordFailure charges both independent budgets. The compound account key is
// caller-claimed, so the source-only bucket remains necessary to stop username
// rotation.
func (t *authFailureTracker) recordFailure(source, account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.chargeLocked(t.accountBucketLocked(source+"\x00"+account), now, authThrottleAccountFailures)
	t.chargeLocked(t.sourceBucketLocked(source), now, authThrottleSourceFailures)
}

// recordSuccess clears the (source, account) pair outright — a success proves
// the pair's recent failures are over — and leaves the source budget alone: a
// success for one account says nothing about the other failures from that IP.
func (t *authFailureTracker) recordSuccess(source, account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.accounts, source+"\x00"+account)
}

func (t *authFailureTracker) accountBucketLocked(key string) *authFailureBucket {
	b := t.accounts[key]
	if b == nil {
		t.sweepIfFullLocked()
		b = &authFailureBucket{windowStart: t.now()}
		t.accounts[key] = b
	}
	return b
}

func (t *authFailureTracker) sourceBucketLocked(source string) *authFailureBucket {
	b := t.sources[source]
	if b == nil {
		t.sweepIfFullLocked()
		b = &authFailureBucket{windowStart: t.now()}
		t.sources[source] = b
	}
	return b
}

// sweepIfFullLocked keeps the tables bounded. Expired buckets go first; if
// the tables are still over budget the remainder is evicted arbitrarily (map
// order), which only forgives failures early.
func (t *authFailureTracker) sweepIfFullLocked() {
	if len(t.accounts)+len(t.sources) < authThrottleMaxEntries {
		return
	}
	now := t.now()
	sweep := func(m map[string]*authFailureBucket) {
		for k, b := range m {
			if now.After(b.lockedUntil) && now.Sub(b.windowStart) > authThrottleWindow {
				delete(m, k)
			}
		}
	}
	sweep(t.accounts)
	sweep(t.sources)
	for k := range t.accounts {
		if len(t.accounts)+len(t.sources) < authThrottleMaxEntries {
			return
		}
		delete(t.accounts, k)
	}
	for k := range t.sources {
		if len(t.accounts)+len(t.sources) < authThrottleMaxEntries {
			return
		}
		delete(t.sources, k)
	}
}

// throttle returns the server's REST credential-failure tracker, building it
// on first use. Lazy because test servers are built as bare &Server{} as
// often as through NewServer, and a nil tracker must never mean "no
// throttle" — it must mean "not built yet".
func (s *Server) throttle() *authFailureTracker {
	s.authThrottleMu.Lock()
	defer s.authThrottleMu.Unlock()
	if s.authThrottle == nil {
		s.authThrottle = newAuthFailureTracker(nil)
	}
	return s.authThrottle
}

// throttleIdentity derives the (source, account) pair a request is budgeted
// under. Source is the TCP peer IP (RemoteAddr without the port). Account is
// the unverified Basic username the request claims — verification happens
// later, and the lockout must key on the CLAIMED account or an attacker
// guessing passwords for one user never fills any bucket — or "api-key" for
// Bearer / X-API-Key presentations (which name no user) and "none" when the
// request carries no credential at all.
func throttleIdentity(r *http.Request) (source, account string) {
	source = r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		source = host
	}
	account = "none"
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			if payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err == nil {
				if user, _, ok := strings.Cut(string(payload), ":"); ok {
					account = user
				} else {
					account = "unknown"
				}
			} else {
				account = "unknown"
			}
		} else {
			account = "api-key"
		}
	} else if r.Header.Get("X-API-Key") != "" {
		account = "api-key"
	}
	if account == "" {
		// An empty Basic username (`:password`) still fills a bucket rather
		// than merging into "none": it presented a credential shape.
		account = "unknown"
	}
	return source, account
}

// writeAuthLockedOut emits the 429 + Retry-After response for a request
// refused by the #10825 failure budget. 429 (not 401) so automation can tell
// "wrong credential" from "try again later", and the Retry-After names the
// wait honestly — the client learns nothing a clock would not tell it.
func writeAuthLockedOut(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(retryAfter / time.Second)
	if retryAfter%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.Header().Set("WWW-Authenticate", `Basic realm="xpf API"`)
	writeJSON(w, http.StatusTooManyRequests, Response{
		Success: false,
		Error:   "too many failed authentication attempts; retry later",
	})
}
