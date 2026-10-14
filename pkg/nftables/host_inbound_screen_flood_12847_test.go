package nftables

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// D3-13 (#12847): a same-zone view without an unambiguous ingress device
// relies on the destination-address fallback for its kernel flood screen.
func TestHostInboundScreenFloodRulesMixedDirectAndAddressFallback12847(t *testing.T) {
	views := []HostInboundZoneView{
		{
			Zone: "wan", IngressNetdevs: []string{"ge-0-0-0"},
			V4Addrs: []string{"192.0.2.1"}, V6Addrs: []string{"2001:db8::1"},
			UDPFloodThreshold: 20, ICMPFloodThreshold: 30,
			SYNFloodThreshold: 100, SYNFloodSrcThreshold: 5,
		},
		{
			Zone: "wan", // ambiguous ingress: destination fallback only
			V4Addrs: []string{"192.0.2.2"}, V6Addrs: []string{"2001:db8::2"},
			UDPFloodThreshold: 20, ICMPFloodThreshold: 30,
			SYNFloodThreshold: 100, SYNFloodSrcThreshold: 5,
		},
	}
	rules := HostInboundScreenFloodRules(views)
	for _, tc := range []struct{ family, addr string }{
		{"ip", "192.0.2.2"}, {"ip6", "2001:db8::2"},
	} {
		found := false
		for _, r := range rules {
			if r.Family != tc.family {
				continue
			}
			if len(r.IngressNetdevs) == 1 && r.IngressNetdevs[0] == "ge-0-0-0" {
				for _, addr := range r.Addresses {
					found = found || addr == tc.addr
				}
			}
		}
		if !found {
			t.Errorf("no destination-fallback flood rule for %s address %s: %+v", tc.family, tc.addr, rules)
		}
	}
	direct := false
	for _, r := range rules {
		if len(r.IngressNetdevs) == 1 && r.IngressNetdevs[0] == "ge-0-0-0" {
			direct = true
		}
	}
	if !direct {
		t.Fatalf("direct-ingress flood rule lost: %+v", rules)
	}

	// Pin actual kernel rule emission too: address fallback and direct ingress
	// both must appear in the built plan rather than merely the normalized
	// intermediate rule.
	p := newBuildPlan(t, "xpf_12847", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{Views: views})
	if p.err != nil {
		t.Fatalf("build mixed-scope plan: %v", p.err)
	}
	fallbackFlood := false
	for _, emitted := range p.rules {
		rendered := canonRule(p, emitted)
		fallbackFlood = fallbackFlood || (strings.Contains(rendered, "c0000202") &&
			strings.Contains(rendered, "unknown(*expr.Dynset)"))
	}
	if !fallbackFlood {
		t.Fatalf("kernel flood rules omit ambiguous-view destination fallback:\n%s", canonRules(p))
	}
}

func TestHostInboundScreenFloodRulesVRFPlusAddressFallback12847(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "wan", IngressVRFScopes: []config.HostInboundVRFIngressScope{
			{Master: "vrf-blue", Slaves: []string{"ge-0-0-2"}},
		}, V4Addrs: []string{"192.0.2.10"}, UDPFloodThreshold: 20},
		{Zone: "wan", V4Addrs: []string{"192.0.2.20"}, UDPFloodThreshold: 20},
	}
	rules := HostInboundScreenFloodRules(views)
	fallback, vrf := false, false
	for _, r := range rules {
		if r.Family != "ip" {
			continue
		}
		for _, a := range r.Addresses {
			fallback = fallback || a == "192.0.2.20"
		}
		if len(r.IngressVRFScopes) == 1 && r.IngressVRFScopes[0].Master == "vrf-blue" {
			vrf = true
		}
	}
	if !fallback || !vrf {
		t.Fatalf("VRF and address fallback scopes not both present (fallback=%v, vrf=%v): %+v", fallback, vrf, rules)
	}
	p := newBuildPlan(t, "xpf_12847_vrf", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{Views: views})
	if p.err != nil {
		t.Fatalf("build VRF mixed-scope plan: %v", p.err)
	}
	fallbackFlood := false
	for _, emitted := range p.rules {
		rendered := canonRule(p, emitted)
		fallbackFlood = fallbackFlood || (strings.Contains(rendered, "c0000214") &&
			strings.Contains(rendered, "unknown(*expr.Dynset)"))
	}
	if !fallbackFlood {
		t.Fatalf("kernel flood rules omit address fallback beside VRF ingress:\n%s", canonRules(p))
	}
}

func TestHostInboundScreenFloodRulesAddressOnlyUnchanged12847(t *testing.T) {
	rules := HostInboundScreenFloodRules([]HostInboundZoneView{{
		Zone: "wan", V4Addrs: []string{"192.0.2.1"}, UDPFloodThreshold: 20,
	}})
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1: %+v", len(rules), rules)
	}
	r := rules[0]
	if len(r.IngressNetdevs) != 0 || len(r.IngressVRFScopes) != 0 ||
		len(r.Addresses) != 1 || r.Addresses[0] != "192.0.2.1" {
		t.Fatalf("address-only rule shape changed: %+v", r)
	}
}
