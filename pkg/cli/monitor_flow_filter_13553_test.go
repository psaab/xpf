package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

// #13553: the documented numeric protocol form ("protocol 6") and the Junos
// interface form ("interface ge-0/0/0") were stored raw and compared against
// the record's rendered protocol name ("TCP") and Linux interface name
// ("ge-0-0-0"), so both accepted forms never matched any event.
func TestMonitorFlowFilter13553ProtocolForms(t *testing.T) {
	cases := []struct {
		name    string
		token   string
		recName string
		recNum  uint8
		wantHit bool
	}{
		{"numeric tcp", "6", "TCP", 6, true},
		{"lower tcp", "tcp", "TCP", 6, true},
		{"upper tcp", "TCP", "TCP", 6, true},
		{"numeric udp", "17", "UDP", 17, true},
		{"numeric icmpv6", "58", "ICMPv6", 58, true},
		{"numeric ipv6-encap", "41", "IPV6", 41, true},
		{"unnamed numeric", "89", "89", 89, true},
		{"named ospf renders numeric", "ospf", "89", 89, true},
		{"numeric mismatch", "6", "UDP", 17, false},
		{"named mismatch", "tcp", "UDP", 17, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &CLI{}
			if err := c.handleMonitorSecurityFlowFilter([]string{"f1", "protocol", tc.token}); err != nil {
				t.Fatalf("handler: %v", err)
			}
			f, ok := c.monitorFlow.filters["f1"]
			if !ok {
				t.Fatalf("protocol %q was not installed", tc.token)
			}
			canonical, _ := normalizeMonitorProtocol(tc.token)
			if f.Protocol != canonical {
				t.Fatalf("stored protocol = %q, want canonical %q", f.Protocol, canonical)
			}
			rec := &logging.EventRecord{Protocol: tc.recName, ProtocolNum: tc.recNum}
			if got := f.matches(rec); got != tc.wantHit {
				t.Fatalf("filter protocol %q vs record %s/%d: matches=%v, want %v (stored %q)",
					tc.token, tc.recName, tc.recNum, got, tc.wantHit, f.Protocol)
			}
		})
	}
}

func TestMonitorFlowFilter13553InvalidProtocolRejected(t *testing.T) {
	for _, token := range []string{"bogus", "999", "-1", "6.5"} {
		c := &CLI{}
		if err := c.handleMonitorSecurityFlowFilter([]string{"f1", "protocol", token}); err != nil {
			t.Fatalf("handler(%q): %v", token, err)
		}
		if _, ok := c.monitorFlow.filters["f1"]; ok {
			t.Fatalf("invalid protocol %q was installed; it can never match", token)
		}
	}
}

func TestMonitorFlowFilter13553InterfaceForms(t *testing.T) {
	for _, token := range []string{"ge-0/0/0", "ge-0-0-0"} {
		c := &CLI{}
		if err := c.handleMonitorSecurityFlowFilter([]string{"f1", "interface", token}); err != nil {
			t.Fatalf("handler: %v", err)
		}
		f, ok := c.monitorFlow.filters["f1"]
		if !ok {
			t.Fatalf("interface %q was not installed", token)
		}
		if f.Iface != "ge-0-0-0" {
			t.Fatalf("stored interface = %q, want Linux canonical ge-0-0-0", f.Iface)
		}
		if !f.matches(&logging.EventRecord{IngressIface: "ge-0-0-0"}) {
			t.Fatalf("filter interface %q (stored %q) did not match Linux-form record ge-0-0-0", token, f.Iface)
		}
		if !f.matches(&logging.EventRecord{IngressIface: "ge-0/0/0"}) {
			t.Fatalf("filter interface %q (stored %q) did not match Junos-form record ge-0/0/0", token, f.Iface)
		}
		if f.matches(&logging.EventRecord{IngressIface: "ge-0-0-1"}) {
			t.Fatalf("filter interface %q matched a different interface ge-0-0-1", token)
		}
	}
}

// Directly constructed filters (the form existing tests and snapshots use)
// must also match: canonicalization cannot live only in one constructor.
func TestMonitorFlowFilter13553LiteralFilterMatches(t *testing.T) {
	f := &monitorFlowFilter{Name: "lit", Protocol: "6", Iface: "ge-0/0/0"}
	rec := &logging.EventRecord{Protocol: "TCP", ProtocolNum: 6, IngressIface: "ge-0-0-0"}
	if !f.matches(rec) {
		t.Fatal("literal filter {Protocol:6, Iface:ge-0/0/0} did not match TCP/ge-0-0-0 record")
	}
}
