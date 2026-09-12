package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// #9811 on the /health surface. A commit-confirmed auto-rollback promotes the
// store FIRST and then applies; when that apply fails, every other field in this
// payload — and `show configuration`, and the peer the rolled-back config was
// re-synced to — names C1 while the dataplane still enforces C2 under the #5679
// contract. /health reported healthy throughout.
//
// The three cells are a set: the 503, the control that a converged node is NOT
// pulled from rotation, and the #5031 redaction. Any one alone is satisfied by an
// implementation the other two reject.

func TestHealthIsDegradedWhileTheConfigApplyDebtIsOwed9811(t *testing.T) {
	s := &Server{
		configApplyDebtFn: func() (bool, uint64, string) {
			return true, 3, "helper control socket: connection refused"
		},
	}
	rr := httptest.NewRecorder()
	s.healthHandler(rr, httptest.NewRequest("GET", "/health", nil))

	if rr.Code != 503 {
		t.Errorf("status = %d, want 503 — the node forwards a configuration it does not report, so an orchestrator steering traffic at it is acting on a false premise (#9811)", rr.Code)
	}
	data := unmarshalHealthData(t, rr.Body.String())
	if st, _ := data["status"].(string); st != "degraded" {
		t.Errorf("status = %q, want \"degraded\"", st)
	}
	if owed, _ := data["config_apply_debt_owed"].(bool); !owed {
		t.Error("config_apply_debt_owed missing or false while the debt is owed")
	}
	// The COUNT is the field that distinguishes a retry owner that is running
	// and failing from one that is not running at all, which is the difference
	// between "converging" and "stuck". A payload that reports only the boolean
	// cannot answer that.
	if n, _ := data["config_apply_failure_count"].(float64); n != 3 {
		t.Errorf("config_apply_failure_count = %v, want 3", data["config_apply_failure_count"])
	}
}

// The control, and it is what stops this from being an outage of its own: a
// converged node must NOT be pulled from rotation. An implementation that
// returned 503 whenever the callback is wired would satisfy the cell above.
func TestHealthIsOKWhenNoConfigApplyDebtIsOwed9811(t *testing.T) {
	s := &Server{
		configApplyDebtFn: func() (bool, uint64, string) {
			// A node that HAS failed and converged: the count stands, the debt
			// does not. It must be in rotation.
			return false, 7, ""
		},
	}
	rr := httptest.NewRecorder()
	s.healthHandler(rr, httptest.NewRequest("GET", "/health", nil))

	if rr.Code != 200 {
		t.Errorf("status = %d, want 200 — a node that converged after a failure is healthy; pulling it over a historical count is a new outage", rr.Code)
	}
	data := unmarshalHealthData(t, rr.Body.String())
	if st, _ := data["status"].(string); st != "ok" {
		t.Errorf("status = %q, want \"ok\"", st)
	}
	if n, _ := data["config_apply_failure_count"].(float64); n != 7 {
		t.Errorf("config_apply_failure_count = %v, want the historical 7 to remain visible", data["config_apply_failure_count"])
	}
}

// #5031: /health is unconditionally unauthenticated. A raw apply error is copied
// from the dataplane publish and can quote config internals or a value a
// validator echoed, so it must never reach this body — same rule the compile and
// bootstrap error strings already follow, applied to the field added here rather
// than rediscovered later.
func TestHealthDoesNotLeakTheApplyErrorDetail9811(t *testing.T) {
	const secret = "S3CR3T-psk-9811-do-not-leak"
	s := &Server{
		configApplyDebtFn: func() (bool, uint64, string) {
			return true, 1, "publish ipsec pre-shared-key " + secret + ": EINVAL"
		},
	}
	rr := httptest.NewRecorder()
	s.healthHandler(rr, httptest.NewRequest("GET", "/health", nil))

	if body := rr.Body.String(); strings.Contains(body, secret) {
		t.Fatalf("unauthenticated /health body leaked the raw apply error sentinel (#5031):\n%s", body)
	}
	data := unmarshalHealthData(t, rr.Body.String())
	if _, present := data["config_apply_last_error"]; present {
		t.Error("config_apply_last_error must be absent from the unauthenticated /health body")
	}
	// The SIGNAL must survive the redaction, or this cell would be satisfied by
	// omitting the whole mechanism.
	if st, _ := data["status"].(string); st != "degraded" {
		t.Errorf("status = %q, want \"degraded\" — the signal must survive redaction", st)
	}
}
