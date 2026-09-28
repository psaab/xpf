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
	// Identity namespaces keep Basic usernames separate from API keys and
	// malformed Basic presentations.
	authThrottleBasicAccountPrefix  = "basic:"
	authThrottleInvalidBasicAccount = "basic-invalid"
	authThrottleAPIKeyAccount       = "api-key"
)

// authFailureBucket is one lockout cell: either a (source, account) pair or a
// whole source IP. inFlight counts reservations admitted but not yet completed;
// it bounds concurrent verifier work and is never cleared by success or window
// resets, only by completion.
type authFailureBucket struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
	lockouts    int // consecutive lockouts; sets the escalated duration
	lastFailure time.Time
	inFlight    int // admitted reservations awaiting completion
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
	for _, b := range [2]*authFailureBucket{t.accounts[source+"\x00"+account], t.sources[source]} {
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

// authThrottleReservation owns one admitted verifier attempt until exactly one
// completion records its outcome. Both bucket reservations are made under the
// same mutex, so concurrent bcrypt work cannot exceed either failure budget.
type authThrottleReservation struct {
	source       string
	claimed      string
	account      *authFailureBucket
	sourceBucket *authFailureBucket
	completed    bool
}

// reserve atomically checks active lockouts and reserves one slot in each
// existing budget before any credential verification begins. If outstanding
// verifiers occupy every slot, refuse transiently for one second rather than
// running unbounded work or charging a request whose credential was not checked.
func (t *authFailureTracker) reserve(source, account string) (authThrottleReservation, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	accountKey := source + "\x00" + account
	accountBucket := t.accounts[accountKey]
	sourceBucket := t.sources[source]
	if wait := authThrottleWaitLocked(now, accountBucket, sourceBucket); wait > 0 {
		return authThrottleReservation{}, wait
	}
	resetExpiredFailuresLocked(accountBucket, now)
	resetExpiredFailuresLocked(sourceBucket, now)

	if (accountBucket != nil && accountBucket.failures+accountBucket.inFlight >= authThrottleAccountFailures) ||
		(sourceBucket != nil && sourceBucket.failures+sourceBucket.inFlight >= authThrottleSourceFailures) {
		return authThrottleReservation{}, time.Second
	}
	needed := 0
	if accountBucket == nil {
		needed++
	}
	if sourceBucket == nil {
		needed++
	}
	if !t.makeRoomLocked(needed, now, accountBucket, sourceBucket) {
		return authThrottleReservation{}, time.Second
	}
	if accountBucket == nil {
		accountBucket = &authFailureBucket{windowStart: now}
		t.accounts[accountKey] = accountBucket
	}
	if sourceBucket == nil {
		sourceBucket = &authFailureBucket{windowStart: now}
		t.sources[source] = sourceBucket
	}

	accountBucket.inFlight++
	sourceBucket.inFlight++
	return authThrottleReservation{
		source:       source,
		claimed:      account,
		account:      accountBucket,
		sourceBucket: sourceBucket,
	}, 0
}

func authThrottleWaitLocked(now time.Time, account, source *authFailureBucket) time.Duration {
	wait := time.Duration(0)
	for _, bucket := range [2]*authFailureBucket{account, source} {
		if bucket == nil {
			continue
		}
		if remaining := bucket.lockedUntil.Sub(now); remaining > wait {
			wait = remaining
		}
	}
	return wait
}

// resetExpiredFailuresLocked forgives completed failures whose accounting
// window has elapsed without disturbing outstanding verifier reservations.
func resetExpiredFailuresLocked(bucket *authFailureBucket, now time.Time) {
	if bucket == nil {
		return
	}
	quietSince := bucket.windowStart
	if bucket.lockouts > 0 {
		quietSince = authThrottleQuietSince(bucket)
	}
	if now.Sub(quietSince) <= authThrottleWindow {
		return
	}
	bucket.failures = 0
	bucket.lockouts = 0
	bucket.lockedUntil = time.Time{}
	bucket.lastFailure = time.Time{}
	bucket.windowStart = now
}

// complete releases both reservations. Failure charges each budget once;
// success clears only the claimed and verified account buckets, never source
// failures. In-flight counts survive clears so older admitted checks remain
// bounded and their eventual failures still charge exactly once.
func (t *authFailureTracker) complete(reservation *authThrottleReservation, success bool, verified string) {
	if reservation == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if reservation.completed {
		return
	}
	reservation.completed = true
	now := t.now()
	reservation.account.inFlight--
	reservation.sourceBucket.inFlight--
	if success {
		t.clearAccountLocked(reservation.source, reservation.claimed, now)
		if verified != "" && verified != reservation.claimed {
			t.clearAccountLocked(reservation.source, verified, now)
		}
		if reservation.sourceBucket.inFlight == 0 &&
			reservation.sourceBucket.failures == 0 &&
			reservation.sourceBucket.lockouts == 0 {
			delete(t.sources, reservation.source)
		}
		return
	}
	t.chargeLocked(reservation.account, now, authThrottleAccountFailures)
	t.chargeLocked(reservation.sourceBucket, now, authThrottleSourceFailures)
}

func (t *authFailureTracker) clearAccountLocked(source, account string, now time.Time) {
	key := source + "\x00" + account
	bucket := t.accounts[key]
	if bucket == nil {
		return
	}
	bucket.failures = 0
	bucket.lockouts = 0
	bucket.lockedUntil = time.Time{}
	bucket.lastFailure = time.Time{}
	bucket.windowStart = now
	if bucket.inFlight == 0 {
		delete(t.accounts, key)
	}
}

// makeRoomLocked keeps the tracker bounded without evicting buckets with
// admitted verifier work or buckets participating in this admission.
func (t *authFailureTracker) makeRoomLocked(needed int, now time.Time, protectAccount, protectSource *authFailureBucket) bool {
	if len(t.accounts)+len(t.sources)+needed <= authThrottleMaxEntries {
		return true
	}
	sweepAuthThrottleBuckets(t.accounts, now, protectAccount, protectSource)
	sweepAuthThrottleBuckets(t.sources, now, protectAccount, protectSource)
	for key, bucket := range t.accounts {
		if len(t.accounts)+len(t.sources)+needed <= authThrottleMaxEntries {
			return true
		}
		if authThrottleBucketEvictable(bucket, protectAccount, protectSource) {
			delete(t.accounts, key)
		}
	}
	for key, bucket := range t.sources {
		if len(t.accounts)+len(t.sources)+needed <= authThrottleMaxEntries {
			return true
		}
		if authThrottleBucketEvictable(bucket, protectAccount, protectSource) {
			delete(t.sources, key)
		}
	}
	return len(t.accounts)+len(t.sources)+needed <= authThrottleMaxEntries
}

func sweepAuthThrottleBuckets(buckets map[string]*authFailureBucket, now time.Time, protectAccount, protectSource *authFailureBucket) {
	for key, bucket := range buckets {
		if authThrottleBucketEvictable(bucket, protectAccount, protectSource) &&
			now.After(bucket.lockedUntil) &&
			now.Sub(authThrottleQuietSince(bucket)) > authThrottleWindow {
			delete(buckets, key)
		}
	}
}

func authThrottleBucketEvictable(bucket, protectAccount, protectSource *authFailureBucket) bool {
	return bucket.inFlight == 0 && bucket != protectAccount && bucket != protectSource
}

func authThrottleQuietSince(bucket *authFailureBucket) time.Time {
	if bucket.lockouts == 0 {
		return bucket.windowStart
	}
	if bucket.lastFailure.After(bucket.lockedUntil) {
		return bucket.lastFailure
	}
	return bucket.lockedUntil
}

// chargeLocked applies one failure to a bucket: windowed counting, lockout at
// threshold with doubling escalation, full forgiveness after a quiet window.
// Escalation is forgiven only after a quiet interval beginning at lockout
// expiry; subsequent failures restart that interval.
func (t *authFailureTracker) chargeLocked(b *authFailureBucket, now time.Time, threshold int) {
	if now.Before(b.lockedUntil) {
		// Failures during a live lockout are dropped, rather than extending
		// the deadline or escalating on checks that never ran.
		return
	}
	quietSince := b.windowStart
	if b.lockouts > 0 {
		quietSince = authThrottleQuietSince(b)
	}
	if now.Sub(quietSince) > authThrottleWindow {
		b.failures = 0
		b.lockouts = 0
		b.windowStart = now
	}
	b.lastFailure = now
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
	b.windowStart = b.lockedUntil
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
// the pair's recent failures are over — and leaves the source budget alone.
func (t *authFailureTracker) recordSuccess(source, account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clearAccountLocked(source, account, t.now())
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
	sweepAuthThrottleBuckets(t.accounts, now, nil, nil)
	sweepAuthThrottleBuckets(t.sources, now, nil, nil)
	for k, b := range t.accounts {
		if len(t.accounts)+len(t.sources) < authThrottleMaxEntries {
			return
		}
		if authThrottleBucketEvictable(b, nil, nil) {
			delete(t.accounts, k)
		}
	}
	for k, b := range t.sources {
		if len(t.accounts)+len(t.sources) < authThrottleMaxEntries {
			return
		}
		if authThrottleBucketEvictable(b, nil, nil) {
			delete(t.sources, k)
		}
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
// under. Source is the TCP peer IP (RemoteAddr without the port). Basic
// usernames use a namespace distinct from API-key and malformed presentations,
// preventing user-controlled names from sharing those fixed buckets.
func throttleIdentity(r *http.Request) (source, account string) {
	source = r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		source = host
	}
	account = "none"
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
			if err != nil {
				account = authThrottleInvalidBasicAccount
			} else if user, _, ok := strings.Cut(string(payload), ":"); ok {
				account = authThrottleBasicAccountPrefix + user
			} else {
				account = authThrottleInvalidBasicAccount
			}
		} else {
			account = authThrottleAPIKeyAccount
		}
	} else if r.Header.Get("X-API-Key") != "" {
		account = authThrottleAPIKeyAccount
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
