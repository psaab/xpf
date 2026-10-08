// Package api REST credential brute-force throttle (#10825).
//
// Before this file, REST Basic/API-key checks were constant-time but
// unlimited-rate: no delay, lockout, source cap, or failure budget. An
// off-loopback listener therefore admitted network online-guessing of
// human-chosen Basic passwords at whatever rate the attacker could sustain,
// and #10832's counted audit (denyaudit.SurfaceRESTAPIAuthFail) observed the
// failures without ever stopping them.
//
// The throttle has THREE budgets, all checked before credential verification:
//
//   - per-source+account: 5 failures in 10 minutes locks that (source, account)
//     pair for 5 minutes, doubling per consecutive lockout (cap 1h). A clean
//     success clears the pair outright.
//   - global claimed Basic username: 5 failures in 10 minutes lock that
//     username across every source handled by this middleware/Server. A clean
//     Basic success clears this bucket; other identities do not.
//   - per-source-prefix: 20 failures in 10 minutes from one IPv4 address or
//     IPv6 /64 (ANY account) locks the whole source. A success never clears
//     source failures, which still protect against username/token rotation.
//
// All three budgets are checked BEFORE the credential verify, so a locked-out
// caller never reaches the (post-#10826 bcrypt) compare — the lockout is what
// bounds attacker-driven verify CPU. Every lockout rejection is still counted
// under the existing rest_api_auth surface (a lockout rejection IS an
// authentication failure); no second surface is created for the same event.
//
// State lives on the middleware instance, never in a package global: the
// static authMiddleware owns a tracker in its closure, and the live-swap
// dynamicAuthMiddleware uses the Server's (Server.throttle, lazily built).
// Per-instance state keeps test servers isolated without a reset hook and
// keeps the two legs of one server under one budget. Separate Server instances,
// process restarts, and HA peers get independent, fresh budgets; this is
// intentionally not a cluster-wide or restart-persistent attempt counter. The
// table is bounded (4096 entries; expired-first sweep, then arbitrary evict)
// so the key space — which includes attacker-influenced usernames — cannot grow
// memory without bound; see the denyaudit fixed-bucket rationale for the doctrine.
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
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// authThrottleAccountFailures is the per-(source, account) failure budget
	// within authThrottleWindow before that pair locks.
	authThrottleAccountFailures = 5
	// authThrottleGlobalBasicFailures locks a claimed Basic username across
	// sources after the same number of failures as the existing pair budget.
	authThrottleGlobalBasicFailures = authThrottleAccountFailures
	// authThrottleSourceFailures is the per-source-prefix failure budget within
	// authThrottleWindow before the whole source locks. IPv6 sources use /64.
	authThrottleSourceFailures = 20
	// authThrottleWindow is the rolling window for all failure budgets.
	authThrottleWindow = 10 * time.Minute
	// authThrottleBaseLockout is the first lockout duration; consecutive
	// lockouts double up to authThrottleMaxLockout.
	authThrottleBaseLockout = 5 * time.Minute
	authThrottleMaxLockout  = time.Hour
	// authThrottleMaxEntries bounds the combined tracker tables. Insertions sweep
	// expired buckets and evict unlocked failures; active lockouts are never
	// evicted. Admission is refused if no unlocked bucket can make room, keeping
	// the table bounded without erasing a live Retry-After.
	authThrottleMaxEntries = 4096
	// Identity namespaces keep Basic usernames, Bearer presentations, malformed
	// Basic headers, unsupported Authorization schemes, and API keys from
	// sharing account lockouts.
	authThrottleBasicAccountPrefix          = "basic:"
	authThrottleInvalidBasicAccount         = "basic-invalid"
	authThrottleBearerAccount               = "bearer"
	authThrottleInvalidAuthorizationAccount = "authorization-invalid"
	authThrottleAPIKeyAccount               = "api-key"
)

// authFailureBucket is one lockout cell: a (source, account) pair, a global
// claimed Basic account, or a whole source prefix. inFlight counts reservations
// admitted but not yet completed; it bounds concurrent verifier work and is
// never cleared by success or window resets, only by completion.
type authFailureBucket struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
	lockouts    int // consecutive lockouts; sets the escalated duration
	lastFailure time.Time
	inFlight    int // admitted reservations awaiting completion
}

// authFailureTracker counts REST credential failures against the #10825
// source/pair budgets and #11492 global Basic-account budget. The zero value is
// not usable; build with newAuthFailureTracker.
type authFailureTracker struct {
	mu             sync.Mutex
	now            func() time.Time
	accounts       map[string]*authFailureBucket
	globalAccounts map[string]*authFailureBucket
	sources        map[string]*authFailureBucket
}

func newAuthFailureTracker(clock func() time.Time) *authFailureTracker {
	if clock == nil {
		clock = time.Now
	}
	return &authFailureTracker{
		now:            clock,
		accounts:       make(map[string]*authFailureBucket),
		globalAccounts: make(map[string]*authFailureBucket),
		sources:        make(map[string]*authFailureBucket),
	}
}

// setClockForTest replaces the clock. Tests advance time without sleeping;
// production never replaces it.
func (t *authFailureTracker) setClockForTest(clock func() time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = clock
}

// locked reports whether the source/account, global Basic-account, or source
// prefix is currently locked. Read-only: checking never extends a lockout.
func (t *authFailureTracker) locked(source, account string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	longest := time.Duration(0)
	locked := false
	for _, b := range [3]*authFailureBucket{
		t.accounts[source+"\x00"+account],
		t.globalAccounts[globalBasicAccountKey(account)],
		t.sources[source],
	} {
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
// completion records its outcome. All applicable bucket reservations are made
// under the same mutex, so concurrent bcrypt work cannot exceed any budget.
type authThrottleReservation struct {
	source        string
	claimed       string
	account       *authFailureBucket
	globalAccount *authFailureBucket
	sourceBucket  *authFailureBucket
	completed     bool
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
	globalKey := globalBasicAccountKey(account)
	accountBucket := t.accounts[accountKey]
	globalBucket := t.globalAccounts[globalKey]
	sourceBucket := t.sources[source]
	if wait := authThrottleWaitLocked(now, accountBucket, globalBucket, sourceBucket); wait > 0 {
		return authThrottleReservation{}, wait
	}
	resetExpiredFailuresLocked(accountBucket, now)
	resetExpiredFailuresLocked(globalBucket, now)
	resetExpiredFailuresLocked(sourceBucket, now)

	if (accountBucket != nil && accountBucket.failures+accountBucket.inFlight >= authThrottleAccountFailures) ||
		(globalBucket != nil && globalBucket.failures+globalBucket.inFlight >= authThrottleGlobalBasicFailures) ||
		(sourceBucket != nil && sourceBucket.failures+sourceBucket.inFlight >= authThrottleSourceFailures) {
		return authThrottleReservation{}, time.Second
	}
	needed := 0
	if accountBucket == nil {
		needed++
	}
	if globalKey != "" && globalBucket == nil {
		needed++
	}
	if sourceBucket == nil {
		needed++
	}
	if !t.makeRoomLocked(needed, now, accountBucket, globalBucket, sourceBucket) {
		return authThrottleReservation{}, time.Second
	}
	if accountBucket == nil {
		accountBucket = &authFailureBucket{windowStart: now}
		t.accounts[accountKey] = accountBucket
	}
	if globalKey != "" && globalBucket == nil {
		globalBucket = &authFailureBucket{windowStart: now}
		t.globalAccounts[globalKey] = globalBucket
	}
	if sourceBucket == nil {
		sourceBucket = &authFailureBucket{windowStart: now}
		t.sources[source] = sourceBucket
	}

	accountBucket.inFlight++
	if globalBucket != nil {
		globalBucket.inFlight++
	}
	sourceBucket.inFlight++
	return authThrottleReservation{
		source:        source,
		claimed:       account,
		account:       accountBucket,
		globalAccount: globalBucket,
		sourceBucket:  sourceBucket,
	}, 0
}

func authThrottleWaitLocked(now time.Time, account, globalAccount, source *authFailureBucket) time.Duration {
	wait := time.Duration(0)
	for _, bucket := range [3]*authFailureBucket{account, globalAccount, source} {
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

// complete releases all reservations. Clean Basic success clears that account
// across sources; all clean successes clear their source/account pair but
// never source failures. When a bad Authorization header falls back to a valid
// X-API-Key, it charges the failed identity and source while clearing only the
// successfully verified key bucket.
func (t *authFailureTracker) complete(reservation *authThrottleReservation, authorized bool, verified string, authorizationFailed bool) {
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
	if reservation.globalAccount != nil {
		reservation.globalAccount.inFlight--
	}
	reservation.sourceBucket.inFlight--
	if authorized && !authorizationFailed {
		t.clearAccountLocked(reservation.source, reservation.claimed, now)
		t.clearGlobalBasicAccountLocked(reservation.claimed, now)
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
	if authorized && authorizationFailed && verified != "" && verified != reservation.claimed {
		t.clearAccountLocked(reservation.source, verified, now)
	}
	t.chargeLocked(reservation.account, now, authThrottleAccountFailures)
	if reservation.globalAccount != nil {
		t.chargeLocked(reservation.globalAccount, now, authThrottleGlobalBasicFailures)
	}
	t.chargeLocked(reservation.sourceBucket, now, authThrottleSourceFailures)
}

func (t *authFailureTracker) clearAccountLocked(source, account string, now time.Time) {
	key := source + "\x00" + account
	bucket := t.accounts[key]
	if bucket == nil {
		return
	}
	clearAuthThrottleBucket(bucket, now)
	if bucket.inFlight == 0 {
		delete(t.accounts, key)
	}
}

func (t *authFailureTracker) clearGlobalBasicAccountLocked(account string, now time.Time) {
	key := globalBasicAccountKey(account)
	bucket := t.globalAccounts[key]
	if bucket == nil {
		return
	}
	clearAuthThrottleBucket(bucket, now)
	if bucket.inFlight == 0 {
		delete(t.globalAccounts, key)
	}
}

func clearAuthThrottleBucket(bucket *authFailureBucket, now time.Time) {
	bucket.failures = 0
	bucket.lockouts = 0
	bucket.lockedUntil = time.Time{}
	bucket.lastFailure = time.Time{}
	bucket.windowStart = now
}

// makeRoomLocked keeps the combined tracker bounded without evicting buckets
// with admitted verifier work, active lockouts, or buckets participating in
// this admission.
func (t *authFailureTracker) makeRoomLocked(needed int, now time.Time, protected ...*authFailureBucket) bool {
	if t.entryCountLocked()+needed <= authThrottleMaxEntries {
		return true
	}
	sweepAuthThrottleBuckets(t.accounts, now, protected...)
	sweepAuthThrottleBuckets(t.globalAccounts, now, protected...)
	sweepAuthThrottleBuckets(t.sources, now, protected...)
	for _, buckets := range []map[string]*authFailureBucket{t.accounts, t.globalAccounts, t.sources} {
		for key, bucket := range buckets {
			if t.entryCountLocked()+needed <= authThrottleMaxEntries {
				return true
			}
			if authThrottleBucketEvictable(bucket, now, protected...) {
				delete(buckets, key)
			}
		}
	}
	return t.entryCountLocked()+needed <= authThrottleMaxEntries
}

func (t *authFailureTracker) entryCountLocked() int {
	return len(t.accounts) + len(t.globalAccounts) + len(t.sources)
}

func sweepAuthThrottleBuckets(buckets map[string]*authFailureBucket, now time.Time, protected ...*authFailureBucket) {
	for key, bucket := range buckets {
		if authThrottleBucketEvictable(bucket, now, protected...) &&
			now.After(bucket.lockedUntil) &&
			now.Sub(authThrottleQuietSince(bucket)) > authThrottleWindow {
			delete(buckets, key)
		}
	}
}

func authThrottleBucketEvictable(bucket *authFailureBucket, now time.Time, protected ...*authFailureBucket) bool {
	if bucket.inFlight != 0 || bucket.lockedUntil.After(now) {
		return false
	}
	for _, active := range protected {
		if bucket == active {
			return false
		}
	}
	return true
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

// recordFailure charges the per-source/account pair, global claimed Basic
// account when applicable, and source-prefix budgets.
func (t *authFailureTracker) recordFailure(source, account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.chargeLocked(t.accountBucketLocked(source+"\x00"+account), now, authThrottleAccountFailures)
	if key := globalBasicAccountKey(account); key != "" {
		t.chargeLocked(t.globalAccountBucketLocked(key), now, authThrottleGlobalBasicFailures)
	}
	t.chargeLocked(t.sourceBucketLocked(source), now, authThrottleSourceFailures)
}

// recordSuccess clears the source/account pair and the corresponding global
// Basic bucket, but leaves source-prefix failures alone.
func (t *authFailureTracker) recordSuccess(source, account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.clearAccountLocked(source, account, now)
	t.clearGlobalBasicAccountLocked(account, now)
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

func (t *authFailureTracker) globalAccountBucketLocked(key string) *authFailureBucket {
	b := t.globalAccounts[key]
	if b == nil {
		t.sweepIfFullLocked()
		b = &authFailureBucket{windowStart: t.now()}
		t.globalAccounts[key] = b
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

// sweepIfFullLocked keeps all tracker tables within the shared entry budget.
// Expired buckets go first; only unlocked failures may be evicted to make room.
func (t *authFailureTracker) sweepIfFullLocked() {
	if t.entryCountLocked() < authThrottleMaxEntries {
		return
	}
	now := t.now()
	sweepAuthThrottleBuckets(t.accounts, now)
	sweepAuthThrottleBuckets(t.globalAccounts, now)
	sweepAuthThrottleBuckets(t.sources, now)
	for _, buckets := range []map[string]*authFailureBucket{t.accounts, t.globalAccounts, t.sources} {
		for key, bucket := range buckets {
			if t.entryCountLocked() < authThrottleMaxEntries {
				return
			}
			if authThrottleBucketEvictable(bucket, now) {
				delete(buckets, key)
			}
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

// throttleIdentity derives the source-prefix and claimed account a request is
// budgeted under. IPv6 addresses sharing a /64 use the same source bucket;
// Basic usernames also have a source-independent global account bucket.
// Bearer presentations and malformed/unsupported Authorization headers use
// fixed namespaces distinct from API-key identity.
func throttleIdentity(r *http.Request) (source, account string) {
	source = normalizeAuthThrottleSource(r.RemoteAddr)
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
		} else if strings.HasPrefix(auth, "Bearer ") {
			account = authThrottleBearerAccount
		} else {
			account = authThrottleInvalidAuthorizationAccount
		}
	} else if r.Header.Get("X-API-Key") != "" {
		account = authThrottleAPIKeyAccount
	}
	return source, account
}

func globalBasicAccountKey(account string) string {
	if strings.HasPrefix(account, authThrottleBasicAccountPrefix) &&
		len(account) > len(authThrottleBasicAccountPrefix) {
		return account
	}
	return ""
}

func normalizeAuthThrottleSource(remoteAddr string) string {
	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	} else {
		trimmed := strings.Trim(remoteAddr, "[]")
		if _, err := netip.ParseAddr(trimmed); err != nil {
			return remoteAddr
		}
		host = trimmed
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return remoteAddr
	}
	addr = addr.Unmap()
	if addr.Is6() {
		addr = addr.WithZone("")
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
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
