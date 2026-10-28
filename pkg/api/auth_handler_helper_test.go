package api

import (
	"net/http"
	"testing"
	"time"
)

// productionAuthHandler builds the handler the production listeners serve:
// a Server seeded with cfg behind the dynamic auth middleware (#17209).
// metricsRequireAuth mirrors the per-leg bind classification from
// listenerHandler: true on a non-loopback bind, false on loopback.
// cfg.MetricsRequireAuth is folded in exactly as production does. The
// returned Server is exposed so a test can drive live swaps
// (ReplaceAuth / ReplaceMetricsRequireAuth) on the same handler.
func productionAuthHandler(t *testing.T, cfg AuthConfig, metricsRequireAuth bool, next http.Handler) (*Server, http.Handler) {
	t.Helper()
	s := &Server{}
	local := cfg
	cfgCopy := &local
	if cfgCopy.MetricsRequireAuth {
		s.metricsGate.Store(true)
	}
	s.auth.Store(cfgCopy)
	slot := s.newAuthSlot()
	slot.bindRequiresAuth = metricsRequireAuth
	return s, s.dynamicAuthMiddleware(metricsRequireAuth, slot, next)
}

// productionAuthHandlerOnly is productionAuthHandler for tests that do not
// need the Server.
func productionAuthHandlerOnly(t *testing.T, cfg AuthConfig, metricsRequireAuth bool, next http.Handler) http.Handler {
	t.Helper()
	_, h := productionAuthHandler(t, cfg, metricsRequireAuth, next)
	return h
}

// chargeFailures charges n failed credential attempts for one
// (source, account) pair through the production reserve/complete path
// (#17209). It replaces the deleted legacy recordFailure/recordSuccess
// helpers: every charge is a reservation admission followed by a failed
// completion, so a fixture can only reach states the production path can
// reach (in particular, failures during a live lockout are dropped).
func chargeFailures(t *testing.T, tracker *authFailureTracker, source, account string, n int) {
	t.Helper()
	for range n {
		reservation, retry := tracker.reserve(source, account, false)
		if retry > 0 {
			t.Fatalf("chargeFailures(%s, %s) step refused with retry-after %v", source, account, retry)
		}
		tracker.complete(&reservation, false, "", false)
	}
}

// seedTwoPreThresholdFailures seeds exactly two sub-threshold failures for
// (source, account), source charges included, BEFORE any production
// admission in the test converts the state. It exists for one fixture
// whose asserted totals sum the honest pre-threshold charges of several
// accounts; it must not be used to build lockouts or post-lockout
// states, which chargeFailures owns (#17209).
func seedTwoPreThresholdFailures(t *testing.T, tracker *authFailureTracker, source, account string) {
	t.Helper()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	now := tracker.now()
	ab := tracker.accounts[source+"\x00"+account]
	if ab == nil {
		ab = &authFailureBucket{windowStart: now}
		tracker.accounts[source+"\x00"+account] = ab
	}
	for range 2 {
		tracker.chargeLocked(ab, now, authThrottleAccountFailures)
	}
	if key := globalBasicAccountKey(account); key != "" {
		gb := tracker.globalAccounts[key]
		if gb == nil {
			gb = &authFailureBucket{windowStart: now}
			tracker.globalAccounts[key] = gb
		}
		for range 2 {
			tracker.chargeLocked(gb, now, authThrottleGlobalBasicFailures)
		}
	}
	sb := tracker.sources[source]
	if sb == nil {
		sb = &authFailureBucket{windowStart: now}
		tracker.sources[source] = sb
	}
	for range 2 {
		tracker.chargeLocked(sb, now, authThrottleSourceFailures)
	}
}

// clearPairSuccess records one clean success for (source, account) through
// the production reserve/complete path (#17209): the pair (and the global
// Basic bucket for that username) is cleared, as a successful credential
// verify clears it; the source-prefix budget is left alone.
func clearPairSuccess(t *testing.T, tracker *authFailureTracker, source, account string) {
	t.Helper()
	reservation, retry := tracker.reserve(source, account, false)
	if retry > 0 {
		t.Fatalf("clearPairSuccess(%s, %s) refused with retry-after %v", source, account, retry)
	}
	tracker.complete(&reservation, true, account, false)
}

// chargeAttempted makes one best-effort failed charge through the
// production reserve/complete path (#17209). Unlike chargeFailures it
// does not fail the test when admission is refused: the saturation
// cells assert on the state afterwards, and a refused admission (no
// bucket inserted) is exactly the state they expect.
func chargeAttempted(tracker *authFailureTracker, source, account string) {
	reservation, retry := tracker.reserve(source, account, false)
	if retry > 0 {
		return
	}
	tracker.complete(&reservation, false, "", false)
}

// probePairLocked reports whether any budget covering (source, account) is
// currently locked out, with the longest remaining lockout. Read-only:
// probing never extends a lockout. Test-only observer over the tracker
// tables (#17209 replaces the production-dead locked method).
func probePairLocked(tracker *authFailureTracker, source, account string) (bool, time.Duration) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	now := tracker.now()
	longest := time.Duration(0)
	locked := false
	for _, b := range [3]*authFailureBucket{
		tracker.accounts[source+"\x00"+account],
		tracker.globalAccounts[globalBasicAccountKey(account)],
		tracker.sources[source],
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
