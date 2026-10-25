package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

// TestNatPoolStatsRespectsWalkLimiter6216 is a FAIL-ON-REVERT guard for #6216:
// natPoolStatsHandler's interface-mode full-table session walk must draw from
// the shared sessionWalkLimiter (#5708/#5433) like every other REST scan
// endpoint. Before the fix the handler called IterateSessions with no
// admission gate, so a burst of NAT-pool-stats requests each drove an
// unbounded concurrent walk, contending with session installs / the periodic
// sweep on the shared control socket.
//
// The test saturates the shared limiter (capacity 1, slot held) and asserts a
// NAT-pool-stats request is rejected with HTTP 429. Reverting the handler to
// the ungated IterateSessions makes it proceed to the walk and return 200 —
// the assertion then fails.
func TestNatPoolStatsRespectsWalkLimiter6216(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	// Hold the single slot so the handler's AcquireCtx must reject.
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire the only walk slot: %v", err)
	}
	defer release()

	// Interface-mode source-NAT config (hasInterfaceRule=true) + a loaded dp
	// with SNAT sessions, so the handler reaches the gated walk path.
	dp := &natIfaceSNATSessionsDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint32{"trust": 2, "guest": 4, "wan": 5},
		},
	}
	s := &Server{store: newIfaceNATStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil)
	s.natPoolStatsHandler(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("natPoolStats status = %d while the shared session-walk slot is held; "+
			"want 429 (handler not bounded by sessionWalkLimiter #6216); body: %s",
			rr.Code, rr.Body.String())
	}
}
