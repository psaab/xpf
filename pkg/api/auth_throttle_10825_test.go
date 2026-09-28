package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/denyaudit"
)

func TestRESTAuthFailureBudgetLocksAccountAndCountsEveryFailure10825(t *testing.T) {
	before := denyaudit.Total(denyaudit.SurfaceRESTAPIAuthFail)
	h := authMiddleware(AuthConfig{Users: map[string]string{"operator": "correct-password"}}, true,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for n := range authThrottleAccountFailures {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = "198.51.100.20:43000"
		r.SetBasicAuth("operator", "wrong-password")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("bad credential %d returned %d, want 401 before lockout threshold", n+1, w.Code)
		}
	}
	locked := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	locked.RemoteAddr = "198.51.100.20:43000"
	locked.SetBasicAuth("operator", "correct-password")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, locked)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("correct credential during lockout returned %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("lockout response omitted Retry-After")
	}
	if got := denyaudit.Total(denyaudit.SurfaceRESTAPIAuthFail) - before; got != authThrottleAccountFailures+1 {
		t.Fatalf("REST api-auth audit counter advanced by %d, want %d (including lockout refusal)", got, authThrottleAccountFailures+1)
	}
}

func TestRESTAuthSourceBudgetStopsUsernameRotation10825(t *testing.T) {
	h := authMiddleware(AuthConfig{Users: map[string]string{"operator": "correct-password"}}, true,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for n := range authThrottleSourceFailures {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = "198.51.100.21:43000"
		r.SetBasicAuth(fmt.Sprintf("rotating-user-%d", n), "wrong-password")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("rotating credential %d returned %d, want 401 before source threshold", n, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = "198.51.100.21:43000"
	r.SetBasicAuth("operator", "correct-password")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("username rotation evaded source budget: status %d, want 429", w.Code)
	}
	// A different source is independent; one attacker cannot lock out all
	// operators merely by choosing a claimed account name.
	other := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	other.RemoteAddr = "198.51.100.22:43000"
	other.SetBasicAuth("operator", "correct-password")
	otherResponse := httptest.NewRecorder()
	h.ServeHTTP(otherResponse, other)
	if otherResponse.Code != http.StatusNoContent {
		t.Fatalf("independent source returned %d, want 204", otherResponse.Code)
	}
}

func TestAuthFailureTrackerSuccessResetAndEscalatingLockout10825(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tracker := newAuthFailureTracker(func() time.Time { return now })
	for range authThrottleAccountFailures {
		tracker.recordFailure("192.0.2.1", "operator")
	}
	if locked, wait := tracker.locked("192.0.2.1", "operator"); !locked || wait != authThrottleBaseLockout {
		t.Fatalf("first lockout = (%v, %v), want (true, %v)", locked, wait, authThrottleBaseLockout)
	}
	now = now.Add(authThrottleBaseLockout)
	for range authThrottleAccountFailures {
		tracker.recordFailure("192.0.2.1", "operator")
	}
	if locked, wait := tracker.locked("192.0.2.1", "operator"); !locked || wait != 2*authThrottleBaseLockout {
		t.Fatalf("repeated lockout = (%v, %v), want (true, %v)", locked, wait, 2*authThrottleBaseLockout)
	}
	tracker.recordSuccess("192.0.2.1", "other-account")
	if locked, _ := tracker.locked("192.0.2.1", "operator"); !locked {
		t.Fatal("success for another account cleared the operator lockout")
	}
}

func TestAuthThrottleAdmissionCapsConcurrentVerifierWork10825(t *testing.T) {
	cases := []struct {
		name         string
		budget       int
		workers      int
		varyAccounts bool
	}{
		{name: "claimed-account", budget: authThrottleAccountFailures, workers: authThrottleAccountFailures + 8},
		{name: "source", budget: authThrottleSourceFailures, workers: authThrottleSourceFailures + 8, varyAccounts: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := newAuthFailureTracker(nil)
			start := make(chan struct{})
			entered := make(chan struct{}, tc.workers)
			results := make(chan time.Duration, tc.workers)
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseAll()

			var current, peak atomic.Int64
			check := func(AuthConfig, bool, *http.Request) (bool, string, bool) {
				active := current.Add(1)
				for {
					previous := peak.Load()
					if active <= previous || peak.CompareAndSwap(previous, active) {
						break
					}
				}
				entered <- struct{}{}
				<-release
				current.Add(-1)
				return false, "", false
			}
			for i := 0; i < tc.workers; i++ {
				go func(i int) {
					<-start
					r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
					r.RemoteAddr = "198.51.100.50:43000"
					account := "operator"
					if tc.varyAccounts {
						account = fmt.Sprintf("rotating-%d", i)
					}
					r.SetBasicAuth(account, "invalid")
					_, retry := throttledAuthCheckWithCheck(tracker, AuthConfig{}, true, r, check)
					results <- retry
				}(i)
			}
			close(start)

			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			for i := 0; i < tc.budget; i++ {
				select {
				case <-entered:
				case <-timer.C:
					t.Fatalf("only %d verifier calls entered; expected %d", i, tc.budget)
				}
			}
			for i := 0; i < tc.workers-tc.budget; i++ {
				select {
				case retry := <-results:
					if retry <= 0 {
						t.Fatalf("unadmitted request %d got retry-after %v", i, retry)
					}
				case <-timer.C:
					t.Fatalf("only %d over-budget requests were refused", i)
				}
			}

			releaseAll()
			for i := 0; i < tc.budget; i++ {
				select {
				case retry := <-results:
					if retry != 0 {
						t.Fatalf("admitted verifier %d returned retry-after %v", i, retry)
					}
				case <-timer.C:
					t.Fatalf("only %d admitted checks completed", i)
				}
			}
			if got := peak.Load(); got != int64(tc.budget) {
				t.Fatalf("peak concurrent verifier work = %d, want budget %d", got, tc.budget)
			}
		})
	}
}

func TestInvalidAuthorizationFallsBackToValidAPIKeyIdentity10825(t *testing.T) {
	const apiKey = "deployment-secret-key"
	cfg := AuthConfig{
		Users:         map[string]string{"claimed-user": "correct-password"},
		APIKeys:       map[string]bool{apiKey: true},
		APIKeyNames:   map[string]string{apiKey: "deployment"},
		APIKeyClasses: map[string]string{apiKey: "operator"},
	}
	cases := []struct {
		name, authorization, claimed string
	}{
		{name: "invalid-bearer", authorization: "Bearer invalid-token", claimed: authThrottleBearerAccount},
		{name: "invalid-basic", authorization: basicAuth("claimed-user", "wrong-password"), claimed: "basic:claimed-user"},
		{name: "unknown-scheme", authorization: "Token invalid-token", claimed: authThrottleInvalidAuthorizationAccount},
		{name: "lowercase-bearer", authorization: "bearer invalid-token", claimed: authThrottleInvalidAuthorizationAccount},
		{name: "bare-basic", authorization: "Basic", claimed: authThrottleInvalidAuthorizationAccount},
		{name: "bare-bearer", authorization: "Bearer", claimed: authThrottleInvalidAuthorizationAccount},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
			r.RemoteAddr = "198.51.100.51:43000"
			r.Header.Set("Authorization", tc.authorization)
			r.Header.Set("X-API-Key", apiKey)

			if !authCheck(cfg, true, r) {
				t.Fatal("authCheck rejected the valid X-API-Key fallback")
			}
			if authorized, verified, authorizationFailed := authCheckCredential(cfg, true, r); !authorized || verified != "api-key" || !authorizationFailed {
				t.Fatalf("fallback result = (%v, %q, %v), want (true, api-key, failed Authorization)", authorized, verified, authorizationFailed)
			}
			identity, class, ok := credentialPrincipalIdentity(cfg, r)
			if !ok || identity != "deployment" || class != "operator" {
				t.Fatalf("credential principal = (%q, %q, %v), want (deployment, operator, true)", identity, class, ok)
			}
			_, claimed := throttleIdentity(r)
			if claimed != tc.claimed {
				t.Fatalf("claimed throttle identity = %q, want %q", claimed, tc.claimed)
			}
		})
	}
}

func TestAuthFallbackChargesClaimedAndSourceAndClearsVerifiedBucket10825(t *testing.T) {
	const (
		source = "198.51.100.52"
		apiKey = "deployment-secret-key"
	)
	cfg := AuthConfig{
		Users:         map[string]string{"claimed-user": "correct-password"},
		APIKeys:       map[string]bool{apiKey: true},
		APIKeyNames:   map[string]string{apiKey: "deployment"},
		APIKeyClasses: map[string]string{apiKey: "operator"},
	}
	tracker := newAuthFailureTracker(nil)
	for _, account := range []string{"basic:claimed-user", "api-key", "unrelated"} {
		for range 2 {
			tracker.recordFailure(source, account)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = source + ":43000"
	r.SetBasicAuth("claimed-user", "wrong-password")
	r.Header.Set("X-API-Key", apiKey)
	if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); !authorized || retry != 0 {
		t.Fatalf("valid key fallback returned (%v, %v), want success without lockout", authorized, retry)
	}

	tracker.mu.Lock()
	claimedBucket := tracker.accounts[source+"\x00basic:claimed-user"]
	verifiedBucket := tracker.accounts[source+"\x00api-key"]
	unrelatedBucket := tracker.accounts[source+"\x00unrelated"]
	sourceBucket := tracker.sources[source]
	tracker.mu.Unlock()
	if claimedBucket == nil || claimedBucket.failures != 3 {
		t.Fatalf("fallback did not charge its failed Basic account: %+v, want three failures", claimedBucket)
	}
	if verifiedBucket != nil {
		t.Fatalf("successful API-key fallback retained its cleared bucket: %+v", verifiedBucket)
	}
	if unrelatedBucket == nil || unrelatedBucket.failures != 2 {
		t.Fatalf("unrelated account failures = %+v, want two preserved failures", unrelatedBucket)
	}
	if sourceBucket == nil || sourceBucket.failures != 7 || sourceBucket.inFlight != 0 {
		t.Fatalf("source budget = %+v, want seven failures and no reservations", sourceBucket)
	}
	if len(tracker.accounts) != 2 {
		t.Fatalf("account buckets = %d, want only charged Basic and unrelated buckets", len(tracker.accounts))
	}

	// An invalid Authorization plus a bad fallback key charges the claimed
	// Basic account and source, and does not create a verified API-key bucket.
	r = httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = source + ":43000"
	r.SetBasicAuth("claimed-user", "wrong-password")
	r.Header.Set("X-API-Key", "wrong-key")
	if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); authorized || retry != 0 {
		t.Fatalf("invalid request returned (%v, %v), want ordinary authentication failure", authorized, retry)
	}
	tracker.mu.Lock()
	claimedBucket = tracker.accounts[source+"\x00basic:claimed-user"]
	verifiedBucket = tracker.accounts[source+"\x00api-key"]
	sourceBucket = tracker.sources[source]
	tracker.mu.Unlock()
	if claimedBucket == nil || claimedBucket.failures != 4 {
		t.Fatalf("invalid claimed-account bucket = %+v, want four failures", claimedBucket)
	}
	if verifiedBucket != nil {
		t.Fatalf("invalid request created an API-key account bucket: %+v", verifiedBucket)
	}
	if sourceBucket == nil || sourceBucket.failures != 8 {
		t.Fatalf("source failures after invalid request = %+v, want eight", sourceBucket)
	}
}

func TestRESTAuthWrongBasicGuessesWithValidAPIKeyFallbackStillLockOut10825(t *testing.T) {
	const (
		source = "198.51.100.54"
		apiKey = "deployment-secret-key"
	)
	h := authMiddleware(AuthConfig{
		Users:   map[string]string{"administrator": "correct-password"},
		APIKeys: map[string]bool{apiKey: true},
	}, true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < authThrottleAccountFailures; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = source + ":43000"
		r.SetBasicAuth("administrator", fmt.Sprintf("wrong-password-%d", i))
		r.Header.Set("X-API-Key", apiKey)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("valid API-key fallback attempt %d returned %d, want 204", i, w.Code)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = source + ":43000"
	r.SetBasicAuth("administrator", "another-wrong-password")
	r.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("locked Basic account with valid fallback returned %d, Retry-After=%q; want 429",
			w.Code, w.Header().Get("Retry-After"))
	}

	// The lockout is account-scoped. A clean request using the valid key stays
	// available while the source budget remains below its separate threshold.
	r = httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = source + ":43000"
	r.Header.Set("X-API-Key", apiKey)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("clean API-key request after Basic lockout returned %d, want 204", w.Code)
	}
}

func TestRESTAuthInvalidAuthorizationDoesNotLockValidAPIKeyBucket10825(t *testing.T) {
	const apiKey = "deployment-secret-key"
	for _, tc := range []struct {
		name          string
		scheme        string
		validFallback bool
	}{
		{name: "invalid Bearer only", scheme: "Bearer"},
		{name: "invalid Bearer with valid key fallback", scheme: "Bearer", validFallback: true},
		{name: "unknown scheme only", scheme: "Token"},
		{name: "unknown scheme with valid key fallback", scheme: "Token", validFallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := authMiddleware(AuthConfig{APIKeys: map[string]bool{apiKey: true}}, true,
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			server := httptest.NewServer(h)
			defer server.Close()

			request := func(authorization, fallbackKey string) int {
				req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/config", nil)
				if err != nil {
					t.Fatal(err)
				}
				if authorization != "" {
					req.Header.Set("Authorization", authorization)
				}
				if fallbackKey != "" {
					req.Header.Set("X-API-Key", fallbackKey)
				}
				resp, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				return resp.StatusCode
			}

			for i := 0; i < authThrottleAccountFailures; i++ {
				fallback := ""
				want := http.StatusUnauthorized
				if tc.validFallback {
					fallback = apiKey
					want = http.StatusNoContent
				}
				if got := request(fmt.Sprintf("%s invalid-%d", tc.scheme, i), fallback); got != want {
					t.Fatalf("invalid %s attempt %d returned %d, want %d", tc.scheme, i+1, got, want)
				}
			}
			if got := request("", apiKey); got != http.StatusNoContent {
				t.Fatalf("clean API-key request after invalid Bearer guesses returned %d, want 204", got)
			}
		})
	}
}

func TestTaggedVerifierReplayNeverAuthenticates10825(t *testing.T) {
	for _, tagged := range []string{
		"$xpf-invalid$replayed-verifier",
		"$xpf-bcrypt$malformed-verifier",
	} {
		t.Run(tagged, func(t *testing.T) {
			cfg := AuthConfig{
				Users:   map[string]string{"operator": tagged},
				APIKeys: map[string]bool{tagged: true},
			}
			if verifyAuthSecret(tagged, tagged) {
				t.Fatal("tagged verifier replay authenticated as plaintext")
			}
			if checkAuthorization(basicAuth("operator", tagged), cfg) {
				t.Fatal("tagged verifier replay authenticated as a Basic password")
			}
			if constantTimeAPIKeyMatch(cfg, tagged) {
				t.Fatal("tagged verifier replay authenticated as an API key")
			}
		})
	}
}

func TestAuthFailureEscalationCapAndPostLockoutQuietReset10825(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tracker := newAuthFailureTracker(func() time.Time { return now })
	const source, account = "192.0.2.55", "operator"
	accountKey := source + "\x00" + account
	lockouts := []time.Duration{
		authThrottleBaseLockout,
		2 * authThrottleBaseLockout,
		4 * authThrottleBaseLockout,
		8 * authThrottleBaseLockout,
		authThrottleMaxLockout,
	}
	for i, want := range lockouts {
		for range authThrottleAccountFailures {
			tracker.recordFailure(source, account)
		}
		bucket := tracker.accounts[accountKey]
		if bucket == nil || bucket.lockedUntil.Sub(now) != want {
			t.Fatalf("lockout %d = %+v, want duration %v", i+1, bucket, want)
		}
		now = bucket.lockedUntil
	}

	// Immediate post-expiry attempts keep escalating at the advertised cap.
	for range authThrottleAccountFailures {
		tracker.recordFailure(source, account)
	}
	bucket := tracker.accounts[accountKey]
	if bucket == nil || bucket.lockedUntil.Sub(now) != authThrottleMaxLockout {
		t.Fatalf("lockout after reaching cap = %+v, want duration %v", bucket, authThrottleMaxLockout)
	}
	now = bucket.lockedUntil

	// A failure shortly before the ten-minute quiet interval ends restarts the
	// quiet clock. Crossing the original expiry+window boundary is insufficient.
	now = now.Add(authThrottleWindow - time.Minute)
	tracker.recordFailure(source, account)
	now = now.Add(2 * time.Minute)
	for range authThrottleAccountFailures - 1 {
		tracker.recordFailure(source, account)
	}
	bucket = tracker.accounts[accountKey]
	if bucket == nil || bucket.lockedUntil.Sub(now) != authThrottleMaxLockout {
		t.Fatalf("lockout after interrupted quiet period = %+v, want capped duration %v", bucket, authThrottleMaxLockout)
	}

	// Only a full quiet interval after this lockout expires forgives escalation.
	now = bucket.lockedUntil.Add(authThrottleWindow + time.Second)
	for range authThrottleAccountFailures {
		tracker.recordFailure(source, account)
	}
	bucket = tracker.accounts[accountKey]
	if bucket == nil || bucket.lockedUntil.Sub(now) != authThrottleBaseLockout {
		t.Fatalf("lockout after genuine quiet interval = %+v, want base duration %v", bucket, authThrottleBaseLockout)
	}
}

func TestAuthThrottleReservationFailureCompletesExactlyOnce10825(t *testing.T) {
	tracker := newAuthFailureTracker(nil)
	reservation, retry := tracker.reserve("192.0.2.99", "operator")
	if retry != 0 {
		t.Fatalf("initial reservation returned retry-after %v", retry)
	}
	tracker.complete(&reservation, false, "", false)
	tracker.complete(&reservation, false, "", false)

	tracker.mu.Lock()
	account := tracker.accounts["192.0.2.99\x00operator"]
	source := tracker.sources["192.0.2.99"]
	tracker.mu.Unlock()
	if account == nil || account.failures != 1 || account.inFlight != 0 {
		t.Fatalf("account bucket after duplicate completion = %+v, want one failure and no reservation", account)
	}
	if source == nil || source.failures != 1 || source.inFlight != 0 {
		t.Fatalf("source bucket after duplicate completion = %+v, want one failure and no reservation", source)
	}
}

func TestAuthThrottleAdmissionResetsExpiredFailuresPreservingInflight10825(t *testing.T) {
	now := time.Unix(1_800_100_000, 0)
	tracker := newAuthFailureTracker(func() time.Time { return now })
	const source, account = "192.0.2.100", "operator"
	for range authThrottleAccountFailures - 1 {
		tracker.recordFailure(source, account)
	}

	first, retry := tracker.reserve(source, account)
	if retry != 0 {
		t.Fatalf("first reservation returned retry-after %v", retry)
	}
	now = now.Add(authThrottleWindow + time.Second)
	second, retry := tracker.reserve(source, account)
	if retry != 0 {
		t.Fatalf("reservation remained saturated after failure window expired: retry-after %v", retry)
	}

	tracker.mu.Lock()
	accountBucket := tracker.accounts[source+"\x00"+account]
	sourceBucket := tracker.sources[source]
	tracker.mu.Unlock()
	if accountBucket == nil || accountBucket.failures != 0 || accountBucket.inFlight != 2 {
		t.Fatalf("account bucket after expiration = %+v, want zero failures and two in-flight reservations", accountBucket)
	}
	if sourceBucket == nil || sourceBucket.failures != 0 || sourceBucket.inFlight != 2 {
		t.Fatalf("source bucket after expiration = %+v, want zero failures and two in-flight reservations", sourceBucket)
	}

	tracker.complete(&first, false, "", false)
	tracker.complete(&second, false, "", false)
	tracker.mu.Lock()
	accountBucket = tracker.accounts[source+"\x00"+account]
	sourceBucket = tracker.sources[source]
	tracker.mu.Unlock()
	if accountBucket == nil || accountBucket.failures != 2 || accountBucket.inFlight != 0 {
		t.Fatalf("account bucket after completions = %+v, want two failures and no reservations", accountBucket)
	}
	if sourceBucket == nil || sourceBucket.failures != 2 || sourceBucket.inFlight != 0 {
		t.Fatalf("source bucket after completions = %+v, want two failures and no reservations", sourceBucket)
	}
}

func TestBasicUsernameCannotCollideWithAPIKeyThrottleBucket10825(t *testing.T) {
	const (
		source = "198.51.100.53"
		apiKey = "deployment-secret-key"
	)
	cfg := AuthConfig{
		Users:   map[string]string{"api-key": "correct-password"},
		APIKeys: map[string]bool{apiKey: true},
	}
	tracker := newAuthFailureTracker(nil)
	for range authThrottleAccountFailures {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = source + ":43000"
		r.SetBasicAuth("api-key", "wrong-password")
		if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); authorized || retry != 0 {
			t.Fatalf("invalid Basic attempt returned (%v, %v), want ordinary failure", authorized, retry)
		}
	}

	if locked, _ := tracker.locked(source, authThrottleBasicAccountPrefix+"api-key"); !locked {
		t.Fatal("Basic user api-key did not fill its namespaced account bucket")
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = source + ":43000"
	r.Header.Set("X-API-Key", apiKey)
	if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); !authorized || retry != 0 {
		t.Fatalf("valid API-key principal was affected by Basic user lockout: (%v, %v)", authorized, retry)
	}
	if locked, _ := tracker.locked(source, authThrottleAPIKeyAccount); locked {
		t.Fatal("successful API-key principal unexpectedly has an account lockout")
	}

	tracker.mu.Lock()
	basicBucket := tracker.accounts[source+"\x00"+authThrottleBasicAccountPrefix+"api-key"]
	apiKeyBucket := tracker.accounts[source+"\x00"+authThrottleAPIKeyAccount]
	sourceBucket := tracker.sources[source]
	tracker.mu.Unlock()
	if basicBucket == nil || basicBucket.failures != 0 || basicBucket.lockouts != 1 {
		t.Fatalf("Basic user bucket after API-key success = %+v, want its lockout preserved", basicBucket)
	}
	if apiKeyBucket != nil {
		t.Fatalf("API-key success retained its cleared bucket: %+v", apiKeyBucket)
	}
	if sourceBucket == nil || sourceBucket.failures != authThrottleAccountFailures {
		t.Fatalf("shared source bucket = %+v, want %d preserved failures", sourceBucket, authThrottleAccountFailures)
	}

	malformed := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	malformed.Header.Set("Authorization", "Basic !!!")
	_, malformedIdentity := throttleIdentity(malformed)
	named := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	named.SetBasicAuth("unknown", "wrong-password")
	_, namedIdentity := throttleIdentity(named)
	if malformedIdentity != authThrottleInvalidBasicAccount || namedIdentity != authThrottleBasicAccountPrefix+"unknown" ||
		malformedIdentity == namedIdentity {
		t.Fatalf("malformed/name identities = (%q, %q), want distinct invalid and basic:unknown buckets", malformedIdentity, namedIdentity)
	}
}
