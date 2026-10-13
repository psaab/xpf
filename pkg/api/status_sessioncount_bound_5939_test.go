// #5939: statusHandler (GET /api/v1/status) calls SessionCount() — a full v4+v6
// session-map iteration holding the per-bucket BPF-map locks for O(table), the
// SAME lock-contention DoS class #5708/#5782 bounded — with no limiter gate. It
// now draws from the shared diagcmd.SessionWalkLimiter (the instance the
// /security/sessions* scans already use, sessions.go) and fails fast with HTTP
// 429 on contention, mirroring sessionsHandler.
//
// FAIL-ON-REVERT: remove the sessionWalkLimiter.Acquire()/429 branch from
// statusHandler and an over-cap request proceeds straight to the SessionCount
// walk and returns 200 with the count — the 429 + "SessionCount not walked"
// assertions below go RED.
package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

// statusCountDP is an apiRuntimeDataPlane fake: IsLoaded true and a controllable
// SessionCount that records whether it was invoked (so a gated over-cap request
// proves it did NOT walk). Embeds *dataplane.Manager for the rest of the
// interface, mirroring blockingSessionDP / cancelCountDP.
type statusCountDP struct {
	*dataplane.Manager
	v4, v6     int
	countCalls int32
}

func (*statusCountDP) IsLoaded() bool { return true }

func (d *statusCountDP) SessionCount() (int, int) {
	atomic.AddInt32(&d.countCalls, 1)
	return d.v4, d.v6
}

func (d *statusCountDP) SessionCountContext(context.Context) (int, int, error) {
	atomic.AddInt32(&d.countCalls, 1)
	return d.v4, d.v6, nil
}

func TestRESTStatusSessionCountBound_5939(t *testing.T) {
	// The handler must draw from the PROCESS-WIDE shared limiter so the REST
	// status count is aggregated with the session scans (a mix of scrapers
	// cannot collectively exceed the budget).
	if sessionWalkLimiter != diagcmd.SessionWalkLimiter {
		t.Fatal("pkg/api sessionWalkLimiter is not the shared diagcmd.SessionWalkLimiter instance")
	}

	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	dp := &statusCountDP{Manager: dataplane.New(), v4: 3, v6: 5}
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}

	// (a) Saturated limiter → HTTP 429 and NO walk.
	rr := httptest.NewRecorder()
	s.statusHandler(rr, httptest.NewRequest("GET", "/api/v1/status", nil))
	if rr.Code != http.StatusTooManyRequests {
		release()
		t.Fatalf("statusHandler with a saturated session-walk limiter: code=%d, want 429 (admission gate not consulted); body: %s", rr.Code, rr.Body.String())
	}
	if n := atomic.LoadInt32(&dp.countCalls); n != 0 {
		release()
		t.Fatalf("SessionCount walked %d times despite a saturated limiter — the gate must fail fast BEFORE the walk", n)
	}

	// (b) After the slot frees → 200 with the real count.
	release()
	rr = httptest.NewRecorder()
	s.statusHandler(rr, httptest.NewRequest("GET", "/api/v1/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("statusHandler after slot release: code=%d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"session_count":8`)) {
		t.Fatalf("admitted status body missing the real session count (v4=3+v6=5); got: %s", rr.Body.String())
	}
	if n := atomic.LoadInt32(&dp.countCalls); n != 1 {
		t.Fatalf("SessionCount invoked %d times on the admitted path, want exactly 1", n)
	}
}
