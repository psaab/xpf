package logging

import (
	"strings"
	"testing"
)

// #16688: ParseEventFilterArgs stored the protocol token raw and
// EventFilter.matches compared it with EqualFold against the rendered
// name (TCP/ICMPv6/ESP), so `protocol 6` (the value the view prints as
// protocol-id="6"), `58`, `50`, `icmp6`, and a typo like `tcpx` all
// yielded an empty answer with no error — a forensic false negative on
// every surface sharing this matcher (local CLI, remote ShowText, gRPC
// GetEvents, REST).
//
// FAIL-ON-REVERT: restoring the raw store + EqualFold(name) match makes
// the numeric/alias cases below return 0 events and makes `tcpx` parse
// without error, flipping this test red. The name rows are the control:
// they matched before and must keep matching unchanged.

func seedEventProtocols16688(t *testing.T) *EventBuffer {
	t.Helper()
	eb := NewEventBuffer(32)
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "tcp", Protocol: "TCP", ProtocolNum: 6, Action: "permit"})
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "udp", Protocol: "UDP", ProtocolNum: 17, Action: "permit"})
	eb.Add(EventRecord{Type: "POLICY_DENY", SrcAddr: "esp", Protocol: "ESP", ProtocolNum: 50, Action: "deny"})
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "icmpv6", Protocol: "ICMPv6", ProtocolNum: 58, Action: "permit"})
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "gre", Protocol: "GRE", ProtocolNum: 47, Action: "permit"})
	// Legacy/hand-built record: rendered name only, no ProtocolNum.
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "legacy-tcp", Protocol: "TCP", ProtocolNum: 0, Action: "permit"})
	// Numeric-only protocol (ospf renders as "89").
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "ospf", Protocol: "89", ProtocolNum: 89, Action: "permit"})
	// Protocol 0 (HOPOPT) rendered numerically.
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "hopopt", Protocol: "0", ProtocolNum: 0, Action: "permit"})
	return eb
}

func srcAddrs16688(recs []EventRecord) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.SrcAddr
	}
	return out
}

func TestEventFilterProtocolNumericAndAlias16688(t *testing.T) {
	eb := seedEventProtocols16688(t)

	cases := []struct {
		token string
		want  []string // SrcAddr values, order-insensitive (Latest is newest-first)
	}{
		// Defect cells: numeric + alias forms that silently matched nothing.
		{"6", []string{"tcp", "legacy-tcp"}},
		{"58", []string{"icmpv6"}},
		{"50", []string{"esp"}},
		{"icmp6", []string{"icmpv6"}},
		{"icmpv6", []string{"icmpv6"}},
		{"ICMPv6", []string{"icmpv6"}},
		{"47", []string{"gre"}},
		{"89", []string{"ospf"}},
		{"ospf", []string{"ospf"}},
		{"0", []string{"hopopt"}},
		// Control cells: name rows unchanged.
		{"tcp", []string{"tcp", "legacy-tcp"}},
		{"TCP", []string{"tcp", "legacy-tcp"}},
		{"udp", []string{"udp"}},
		{"17", []string{"udp"}},
		{"esp", []string{"esp"}},
		{"gre", []string{"gre"}},
		{"icmp", nil}, // exact: must not match ICMPv6 (#2939)
	}
	for _, tc := range cases {
		t.Run("protocol="+tc.token, func(t *testing.T) {
			_, f, err := ParseEventFilterArgs([]string{"protocol", tc.token}, nil, false)
			if err != nil {
				t.Fatalf("ParseEventFilterArgs(protocol %q) error = %v; want success", tc.token, err)
			}
			got := eb.LatestFiltered(32, f)
			if len(got) != len(tc.want) {
				t.Fatalf("protocol %q: got %d events %v; want %d %v", tc.token, len(got), srcAddrs16688(got), len(tc.want), tc.want)
			}
			seen := map[string]bool{}
			for _, r := range got {
				seen[r.SrcAddr] = true
			}
			for _, w := range tc.want {
				if !seen[w] {
					t.Fatalf("protocol %q: missing %q in %v; want %v", tc.token, w, srcAddrs16688(got), tc.want)
				}
			}
		})
	}
}

func TestParseEventFilterArgsUnknownProtocol16688(t *testing.T) {
	for _, tok := range []string{"tcpx", "bogus", "256", "-1", "999", "6.5"} {
		_, _, err := ParseEventFilterArgs([]string{"protocol", tok}, nil, false)
		if err == nil {
			t.Fatalf("protocol %q: got nil error; want unknown-protocol usage error", tok)
		}
		if !strings.Contains(err.Error(), "unknown protocol") {
			t.Fatalf("protocol %q: error = %q; want it to contain %q", tok, err.Error(), "unknown protocol")
		}
	}
	eb := seedEventProtocols16688(t)
	// A bogus token stored directly (bypassing the parser) must match
	// nothing, never widen to any protocol.
	if got := eb.LatestFiltered(32, EventFilter{Protocol: "tcpx"}); len(got) != 0 {
		t.Fatalf("direct EventFilter{Protocol:tcpx} matched %d events; want 0 (fail closed)", len(got))
	}
	// Substring token via a direct filter still matches nothing (#2939):
	// "C" is unresolvable, so it fails closed rather than over-matching
	// TCP/ICMP/ICMPv6 as the old substring/EqualFold match risked.
	if got := eb.LatestFiltered(32, EventFilter{Protocol: "C"}); len(got) != 0 {
		t.Fatalf("direct EventFilter{Protocol:C} matched %d events; want 0", len(got))
	}
	// Direct literal filters resolve through the same table (mirrors the
	// #13553 literal-filter contract for monitorFlowFilter).
	if got := eb.LatestFiltered(32, EventFilter{Protocol: "6"}); len(got) != 2 {
		t.Fatalf("direct EventFilter{Protocol:6} matched %d events; want 2 (tcp + legacy-tcp)", len(got))
	}
	if got := eb.LatestFiltered(32, EventFilter{ProtocolNum: 50, HasProtocol: true}); len(got) != 1 || got[0].SrcAddr != "esp" {
		t.Fatalf("direct EventFilter{50} = %v; want exactly the esp event", srcAddrs16688(got))
	}
	// Protocol 0 is a real filter, not "empty".
	if (EventFilter{ProtocolNum: 0, HasProtocol: true}).IsEmpty() {
		t.Fatal("EventFilter{HasProtocol:true, ProtocolNum:0}.IsEmpty() = true; want false — protocol 0 is a real filter")
	}
	if got := eb.LatestFiltered(32, EventFilter{ProtocolNum: 0, HasProtocol: true}); len(got) != 1 || got[0].SrcAddr != "hopopt" {
		t.Fatalf("direct EventFilter{0} = %v; want exactly the hopopt event", srcAddrs16688(got))
	}
}
