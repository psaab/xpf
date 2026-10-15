package nftables

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// D5-03 (#13172): flood screens must judge the withheld lifeline-shared
// addresses in IngressDenyV4/V6 (#12229) and must never degrade an
// empty-slave VRF scope into an unscoped global flood drop.
func TestHostInboundScreenFloodRulesIngressDenyAndEmptyVRF13172(t *testing.T) {
	// (1) IngressDeny-only view with ambiguous ingress: destination-fallback
	// screens must be emitted for the withheld addresses.
	denyRules := HostInboundScreenFloodRules([]HostInboundZoneView{{
		Zone: "wan", ICMPFloodThreshold: 100, UDPFloodThreshold: 50,
		IngressDenyV4: []string{"192.0.2.60"}, IngressDenyV6: []string{"2001:db8::60"},
	}})
	v4Scoped, v6Scoped := false, false
	for _, r := range denyRules {
		if len(r.IngressNetdevs) != 0 || len(r.IngressVRFScopes) != 0 {
			t.Fatalf("IngressDeny fallback rule unexpectedly ingress-scoped: %+v", r)
		}
		for _, a := range r.Addresses {
			if r.Family == "ip" && a == "192.0.2.60" {
				v4Scoped = true
			}
			if r.Family == "ip6" && a == "2001:db8::60" {
				v6Scoped = true
			}
		}
	}
	if !v4Scoped || !v6Scoped {
		t.Fatalf("IngressDeny addresses missing from flood screens (v4=%v v6=%v): %+v", v4Scoped, v6Scoped, denyRules)
	}

	// (2) Empty-slave VRF scope with only a regular address: the rule must
	// stay destination-scoped to that address, never unscoped global.
	rules := HostInboundScreenFloodRules([]HostInboundZoneView{{
		Zone: "wan", ICMPFloodThreshold: 100,
		V4Addrs:          []string{"192.0.2.61"},
		IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-red", Slaves: nil}},
	}})
	if len(rules) == 0 {
		t.Fatalf("no flood rules for empty-slave VRF view: %+v", rules)
	}
	for _, r := range rules {
		if r.Family != "ip" {
			t.Fatalf("empty-slave VRF view leaked into %s rule (want address-scoped v4 only): %+v", r.Family, r)
		}
		if len(r.IngressVRFScopes) != 0 || len(r.Addresses) != 1 || r.Addresses[0] != "192.0.2.61" {
			t.Fatalf("empty-slave VRF scope must yield address-scoped rule, got %+v", r)
		}
	}

	// (3) Empty-slave VRF scope with no addresses at all: no rule at all
	// (fail-closed = do not invent a global drop).
	emptyRules := HostInboundScreenFloodRules([]HostInboundZoneView{{
		Zone: "wan", ICMPFloodThreshold: 100,
		IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-red", Slaves: nil}},
	}})
	if len(emptyRules) != 0 {
		t.Fatalf("empty-slave VRF view with no addresses emitted unscoped rules: %+v", emptyRules)
	}
}
