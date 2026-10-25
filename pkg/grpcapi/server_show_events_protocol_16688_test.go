package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #16688: GetEvents built EventFilter{Protocol: req.Protocol} raw, and
// the matcher compared it with EqualFold against the rendered name, so
// protocol "6"/"58"/"50"/"icmp6" and typos all silently returned no
// events. GetEvents now resolves via the logging/appid SSOT and rejects
// an unknown token with InvalidArgument.
//
// FAIL-ON-REVERT: restoring the raw builder makes the numeric/alias
// cases return 0 events and makes "tcpx" return success with 0 events,
// flipping this test red. Name rows are the unchanged control.
func TestGetEventsProtocolNumericAliasAndBogus16688(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "tcp", Protocol: "TCP", ProtocolNum: 6, Action: "permit"})
	eb.Add(logging.EventRecord{Type: "POLICY_DENY", SrcAddr: "esp", Protocol: "ESP", ProtocolNum: 50, Action: "deny"})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "icmpv6", Protocol: "ICMPv6", ProtocolNum: 58, Action: "permit"})
	s := &Server{eventBuf: eb}

	okCases := []struct {
		proto string
		want  string
	}{
		{"6", "tcp"},
		{"tcp", "tcp"},
		{"TCP", "tcp"},
		{"50", "esp"},
		{"esp", "esp"},
		{"58", "icmpv6"},
		{"icmp6", "icmpv6"},
		{"icmpv6", "icmpv6"},
	}
	for _, tc := range okCases {
		resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Protocol: tc.proto})
		if err != nil {
			t.Fatalf("GetEvents(protocol=%q) = %v; want success", tc.proto, err)
		}
		if len(resp.Events) != 1 || resp.Events[0].SrcAddr != tc.want {
			t.Fatalf("GetEvents(protocol=%q) = %v; want exactly the %q event", tc.proto, resp.Events, tc.want)
		}
	}

	// Absent protocol stays match-all.
	resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents() = %v; want success", err)
	}
	if len(resp.Events) != 3 {
		t.Fatalf("GetEvents() returned %d events; want 3 (no protocol filter)", len(resp.Events))
	}

	for _, bad := range []string{"tcpx", "bogus", "256"} {
		_, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Protocol: bad})
		if err == nil {
			t.Fatalf("GetEvents(protocol=%q) = nil error; want InvalidArgument", bad)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("GetEvents(protocol=%q) code = %v; want InvalidArgument (err=%v)", bad, status.Code(err), err)
		}
	}
}
