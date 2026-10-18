package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// #14711: a dual-header request (Authorization + X-API-Key) must be
// budgeted under the api-key bucket as well as the claimed Authorization
// identity. Before the fix throttleIdentity picked only the Authorization
// identity, so the api-key pair bucket was never reserved, checked, or
// charged.

func TestDualHeaderValidKeyDoesNotBypassAPIKeyLockout14711(t *testing.T) {
	const (
		source = "198.51.100.147"
		apiKey = "deployment-secret-key"
	)
	cfg := AuthConfig{APIKeys: map[string]bool{apiKey: true}}
	tracker := newAuthFailureTracker(nil)
	// Lock (source, api-key) with key-only failures through the real
	// throttled credential path.
	for i := range authThrottleAccountFailures {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = source + ":43000"
		r.Header.Set("X-API-Key", "wrong-key")
		if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); authorized || retry != 0 {
			t.Fatalf("key-only bad attempt %d = (%v, %v), want ordinary failure", i, authorized, retry)
		}
	}
	if locked, _ := tracker.locked(source, authThrottleAPIKeyAccount); !locked {
		t.Fatal("api-key bucket not locked after key-only failures")
	}

	// A dual-header request presenting the valid key behind a failing
	// Authorization header must not authorize while that lock is active.
	for _, authorization := range []string{
		basicAuth("dummy", "wrong-password"),
		"Bearer wrong-token", "Basic !!!", "Digest wrong-token",
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = source + ":43000"
		r.Header.Set("Authorization", authorization)
		r.Header.Set("X-API-Key", apiKey)
		authorized, retry := throttledAuthCheck(tracker, cfg, true, r)
		if authorized || retry <= 0 {
			t.Fatalf("%q dual-header valid key during lockout = (%v, %v), want refusal", authorization, authorized, retry)
		}
		called := false
		check := func(AuthConfig, bool, *http.Request) (bool, string, bool) {
			called = true
			return false, "", true
		}
		throttledAuthCheckWithCheck(tracker, cfg, true, r, check)
		if called {
			t.Fatalf("%q lockout reached credential verifier", authorization)
		}
	}
}

func TestDualHeaderBadKeyAttemptsLockAPIKeyBucket14711(t *testing.T) {
	const source = "198.51.100.148"
	cfg := AuthConfig{
		Users:   map[string]string{"operator": "correct-password"},
		APIKeys: map[string]bool{"deployment-secret-key": true},
	}
	tracker := newAuthFailureTracker(nil)

	// Rotating dummy Basic usernames dodge each basic:<user> pair bucket;
	// only the source budget (20) bounded these before the fix, never the
	// api-key pair budget (5).
	for i := range 15 {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = source + ":43000"
		r.SetBasicAuth(fmt.Sprintf("dummy-%d", i), "wrong-password")
		r.Header.Set("X-API-Key", "wrong-key")
		authorized, retry := throttledAuthCheck(tracker, cfg, true, r)
		if authorized || (i < authThrottleAccountFailures && retry != 0) ||
			(i >= authThrottleAccountFailures && retry <= 0) {
			t.Fatalf("attempt %d = (%v, %v), want lockout starting at sixth request", i+1, authorized, retry)
		}
	}
	if locked, _ := tracker.locked(source, authThrottleAPIKeyAccount); !locked {
		t.Fatal("api-key bucket not locked after dual-header bad-key attempts")
	}

	// Once locked, even the valid key alone from the same source is refused.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = source + ":43000"
	r.Header.Set("X-API-Key", "deployment-secret-key")
	if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); authorized || retry <= 0 {
		t.Fatalf("valid key after dual-header lockout = (%v, %v), want refused with retry-after", authorized, retry)
	}
}

func TestDualHeaderBadKeyChargesAPIKeyBucket14711(t *testing.T) {
	const source = "198.51.100.149"
	cfg := AuthConfig{
		Users:   map[string]string{"operator": "correct-password"},
		APIKeys: map[string]bool{"deployment-secret-key": true},
	}
	tracker := newAuthFailureTracker(nil)
	for i := range 3 {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		r.RemoteAddr = source + ":43000"
		r.SetBasicAuth(fmt.Sprintf("dummy-%d", i), "wrong-password")
		r.Header.Set("X-API-Key", "wrong-key")
		if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); authorized || retry != 0 {
			t.Fatalf("dual bad attempt %d = (%v, %v), want ordinary failure", i, authorized, retry)
		}
	}
	tracker.mu.Lock()
	bucket := tracker.accounts[source+"\x00"+authThrottleAPIKeyAccount]
	tracker.mu.Unlock()
	if bucket == nil || bucket.failures != 3 {
		t.Fatalf("api-key bucket after 3 dual failures = %+v, want 3 failures", bucket)
	}
}

func TestDualHeaderUnusedFallbackPreservesFailures14711(t *testing.T) {
	const source = "198.51.100.150"
	cfg := AuthConfig{Users: map[string]string{"operator": "correct-password"}}
	tracker := newAuthFailureTracker(nil)
	tracker.recordFailure(source, authThrottleAPIKeyAccount)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	r.RemoteAddr = source + ":43000"
	r.SetBasicAuth("operator", "correct-password")
	r.Header.Set("X-API-Key", "unevaluated-key")
	if authorized, retry := throttledAuthCheck(tracker, cfg, true, r); !authorized || retry != 0 {
		t.Fatalf("valid primary = (%v, %v), want success", authorized, retry)
	}
	bucket := tracker.accounts[source+"\x00"+authThrottleAPIKeyAccount]
	if bucket == nil || bucket.failures != 1 || bucket.inFlight != 0 {
		t.Fatalf("unevaluated key bucket = %+v, want preserved failure without reservation", bucket)
	}
	if tracker.sources[source].failures != 1 {
		t.Fatal("successful primary charged source")
	}
}

func TestDualHeaderReservationCapacityAndCompletion14711(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tracker := newAuthFailureTracker(func() time.Time { return now })
	const source = "198.51.100.151"
	// Four buckets are needed for a new dual Basic request, not three.
	for i := range authThrottleMaxEntries - 3 {
		tracker.accounts[fmt.Sprintf("locked-%d", i)] = &authFailureBucket{
			lockedUntil: now.Add(time.Hour),
		}
	}
	if _, retry := tracker.reserve(source, "basic:operator", true); retry != time.Second {
		t.Fatalf("capacity refusal = %v, want 1s", retry)
	}
	if tracker.entryCountLocked() != authThrottleMaxEntries-3 {
		t.Fatal("capacity refusal partially reserved buckets")
	}
	delete(tracker.accounts, "locked-0")
	reservation, retry := tracker.reserve(source, "basic:operator", true)
	if retry != 0 || tracker.entryCountLocked() != authThrottleMaxEntries {
		t.Fatalf("four available slots not admitted: retry=%v entries=%d", retry, tracker.entryCountLocked())
	}
	tracker.complete(&reservation, false, "", true)
	tracker.complete(&reservation, false, "", true)
	for _, bucket := range []*authFailureBucket{
		reservation.account, reservation.secondAccount, reservation.globalAccount, reservation.sourceBucket,
	} {
		if bucket == nil || bucket.inFlight != 0 || bucket.failures != 1 {
			t.Fatalf("duplicate completion leaked or double-charged bucket: %+v", bucket)
		}
	}
}
