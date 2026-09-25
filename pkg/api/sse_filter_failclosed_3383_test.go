package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

// TestLogStreamRejectsTypoFilters guards #3383 (HC-10): a misspelled
// severity/category on the SSE log stream must be rejected with 400 before the
// connection switches to event-stream, rather than fail open (stream
// everything). SSE is consumed by automation, so a silent widening of a live
// feed is a monitoring hazard.
//
// FAIL-ON-REVERT: reverting to logging.ParseSeverity / the lenient
// parseCategories (0 = no filter on a typo) makes these requests return 200
// text/event-stream instead of 400.
func TestLogStreamRejectsTypoFilters(t *testing.T) {
	s := &Server{eventBuf: logging.NewEventBuffer(16)}

	cases := []string{
		"/api/v1/logs/stream?severity=warnng",
		"/api/v1/logs/stream?severity=critical",
		"/api/v1/logs/stream?category=polciy",
		"/api/v1/logs/stream?category=session,polciy",
		"/api/v1/events/stream?category=sesion",
		// empty tokens (malformed list) must also reject, not widen.
		"/api/v1/logs/stream?category=,",
		"/api/v1/logs/stream?category=policy,",
		"/api/v1/events/stream?category=,session",
	}
	for _, url := range cases {
		t.Run(url, func(t *testing.T) {
			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()
			if isEventStreamURL(url) {
				s.eventStreamHandler(w, req)
			} else {
				s.logStreamHandler(w, req)
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want %d (4xx reject); body=%q",
					url, w.Code, http.StatusBadRequest, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); ct == "text/event-stream" {
				t.Fatalf("%s: switched to SSE on a bad filter (Content-Type=%q)", url, ct)
			}
		})
	}
}

func isEventStreamURL(url string) bool {
	return len(url) >= len("/api/v1/events/stream") && url[:len("/api/v1/events/stream")] == "/api/v1/events/stream"
}

// TestEventRecordSeverityScreenPermit guards #3383 (HC-11): a SCREEN_DROP with
// action=permit is the #2234 scan-table-pressure alarm — the packet still
// forwards, so it must be classified as SyslogNotice, mirroring the canonical
// logging.eventSeverity, NOT SyslogError. The buggy version paged drop-severity
// alerts for forwarded packets and let them pass a severity=error filter.
//
// FAIL-ON-REVERT: reverting eventRecordSeverity to a type-only SyslogError for
// every SCREEN_DROP makes the permit case return SyslogError.
func TestEventRecordSeverityScreenPermit(t *testing.T) {
	if got := eventRecordSeverity(logging.EventRecord{Type: "SCREEN_DROP", Action: "permit"}); got != logging.SyslogNotice {
		t.Errorf("SCREEN_DROP/permit severity = %d, want SyslogNotice(%d)", got, logging.SyslogNotice)
	}
	if got := eventRecordSeverity(logging.EventRecord{Type: "SCREEN_DROP", Action: "deny"}); got != logging.SyslogError {
		t.Errorf("SCREEN_DROP/deny severity = %d, want SyslogError(%d)", got, logging.SyslogError)
	}
	if got := eventRecordSeverity(logging.EventRecord{Type: "POLICY_DENY", Action: "deny"}); got != logging.SyslogWarning {
		t.Errorf("POLICY_DENY severity = %d, want SyslogWarning(%d)", got, logging.SyslogWarning)
	}
}

// TestMatchCategoryUnknownFailsClosed guards #3383 (LC-02): an unknown event
// type must not be delivered under a narrow (nonzero) category mask.
//
// FAIL-ON-REVERT: restoring `default: return true` in matchCategory makes the
// unknown type pass.
func TestMatchCategoryUnknownFailsClosed(t *testing.T) {
	if matchCategory("FUTURE_EVENT", logging.CategorySession) {
		t.Error("unknown event type passed a narrow category mask; want fail-closed")
	}
}

func TestD11DenyReasonSurvivesOperatorLogFormatting11017(t *testing.T) {
	rec := logging.EventRecord{
		Type: "POLICY_DENY", Action: "deny", Reason: "D11 ZONE_UNZONED",
	}
	const want = `RT_FLOW POLICY_DENY src= dst= proto= action=deny policy=0 zone=0->0 reason="D11 ZONE_UNZONED"`
	if got := formatLogMessage(rec); got != want {
		t.Fatalf("D11 denial log message=%q, want %q", got, want)
	}
	if !matchCategory(rec.Type, logging.CategoryPolicy) ||
		eventRecordSeverity(rec) != logging.SyslogWarning {
		t.Fatal("D11 POLICY_DENY did not retain the operator policy-deny category/severity")
	}
}
