package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
