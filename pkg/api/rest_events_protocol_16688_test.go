package api

import (
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

// #16688: the REST events handler built EventFilter{Protocol: raw} and
// the matcher compared it with EqualFold against the rendered name, so
// ?protocol=6/58/50/icmp6 and typos all silently returned no events.
// The handler now resolves via the logging/appid SSOT and rejects an
// unknown token with HTTP 400, mirroring the session protocol filter.
//
// FAIL-ON-REVERT: restoring the raw builder makes the numeric/alias
// cases return 0 events (HTTP 200) and makes ?protocol=tcpx return
// HTTP 200 with 0 events, flipping this test red. Name rows are the
// unchanged control.
func TestRESTEventsProtocolNumericAliasAndBogus16688(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "10.0.0.1:1", Protocol: "TCP", ProtocolNum: 6, Action: "permit"})
	eb.Add(logging.EventRecord{Type: "POLICY_DENY", SrcAddr: "10.0.0.2:1", Protocol: "ESP", ProtocolNum: 50, Action: "deny"})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "10.0.0.3:1", Protocol: "ICMPv6", ProtocolNum: 58, Action: "permit"})
	s := &Server{eventBuf: eb}

	okCases := []struct {
		proto string
		want  string
	}{
		{"6", "10.0.0.1:1"},
		{"tcp", "10.0.0.1:1"},
		{"TCP", "10.0.0.1:1"},
		{"50", "10.0.0.2:1"},
		{"esp", "10.0.0.2:1"},
		{"58", "10.0.0.3:1"},
		{"icmp6", "10.0.0.3:1"},
		{"icmpv6", "10.0.0.3:1"},
	}
	for _, tc := range okCases {
		rr := httptest.NewRecorder()
		s.eventsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/events?protocol="+tc.proto, nil))
		if rr.Code != 200 {
			t.Fatalf("events?protocol=%s status = %d; want 200; body=%s", tc.proto, rr.Code, rr.Body.String())
		}
		evs := decodeEvents(t, rr.Body.Bytes())
		if len(evs) != 1 || evs[0].SrcAddr != tc.want {
			t.Fatalf("events?protocol=%s = %+v; want exactly the %q event", tc.proto, evs, tc.want)
		}
	}

	// Absent protocol stays match-all.
	rr := httptest.NewRecorder()
	s.eventsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/events", nil))
	if rr.Code != 200 {
		t.Fatalf("unfiltered events status = %d; want 200", rr.Code)
	}
	if evs := decodeEvents(t, rr.Body.Bytes()); len(evs) != 3 {
		t.Fatalf("unfiltered events returned %d; want 3", len(evs))
	}

	for _, bad := range []string{"tcpx", "bogus", "256"} {
		rr := httptest.NewRecorder()
		s.eventsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/events?protocol="+bad, nil))
		if rr.Code != 400 {
			t.Fatalf("events?protocol=%s status = %d; want 400; body=%s", bad, rr.Code, rr.Body.String())
		}
	}
}
