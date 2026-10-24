package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16204: a forwarding instance (VRFName=="" && TableID>0) has no VRF
// device; carrying dynamic protocols it must not emit a second/illegal
// unscoped `router bgp` (or any protocol) stanza. Strict/daemon assembly
// normally nils these fields — this is the renderer-level backstop for
// tolerant/peer-fed instances. Normal VRF control and the legacy
// VRFName==""&&TableID==0 shape must be unaffected.

func TestForwardingInstanceBGPEmitsNoStanza16204(t *testing.T) {
	fwdBGP := &config.BGPConfig{
		LocalAS:   65099,
		RouterID:  "9.9.9.9",
		Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.99", PeerAS: 65098, FamilyInet: true}},
	}
	fc := &FullConfig{
		BGP: &config.BGPConfig{
			LocalAS:   65001,
			RouterID:  "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true}},
		},
		Instances: []InstanceConfig{
			{Name: "fwd1", VRFName: "", TableID: 100, BGP: fwdBGP},
			{
				Name:    "cust-a",
				VRFName: "vrf-cust-a",
				BGP: &config.BGPConfig{
					LocalAS:   65010,
					RouterID:  "2.2.2.2",
					Neighbors: []*config.BGPNeighbor{{Address: "10.1.1.2", PeerAS: 65011, FamilyInet: true}},
				},
			},
			// Legacy shape: empty VRFName with no table — historically
			// the master table; the belt keyed on TableID>0 must not
			// swallow it.
			{
				Name: "legacy",
				BGP: &config.BGPConfig{
					LocalAS:   65020,
					RouterID:  "3.3.3.3",
					Neighbors: []*config.BGPNeighbor{{Address: "10.2.2.2", PeerAS: 65021, FamilyInet: true}},
				},
			},
		},
	}
	got := New().buildManagedSection(fc)

	// Anti-vacuity: global and normal VRF controls render.
	if !strings.Contains(got, "router bgp 65001\n") {
		t.Fatalf("global router bgp stanza missing (anti-vacuity):\n%s", got)
	}
	if !strings.Contains(got, "router bgp 65010 vrf vrf-cust-a\n") {
		t.Fatalf("normal VRF router bgp stanza missing (control):\n%s", got)
	}
	// Legacy instance still renders (preserved shape).
	if !strings.Contains(got, "router bgp 65020\n") {
		t.Errorf("legacy VRFName==\"\" TableID==0 instance must still render:\n%s", got)
	}
	// Forwarding instance must emit nothing: no stanza, no neighbour.
	if strings.Contains(got, "65099") || strings.Contains(got, "192.0.2.99") || strings.Contains(got, "9.9.9.9") {
		t.Errorf("forwarding instance BGP leaked into rendered config:\n%s", got)
	}
	if n := strings.Count(got, "router bgp "); n != 3 {
		t.Errorf("want exactly 3 router bgp stanzas (global+VRF+legacy), got %d:\n%s", n, got)
	}
}

func TestForwardingInstanceAllProtocolsSkipped16204(t *testing.T) {
	fc := &FullConfig{
		Instances: []InstanceConfig{{
			Name:    "fwd1",
			VRFName: "",
			TableID: 4242,
			OSPF: &config.OSPFConfig{Areas: []*config.OSPFArea{{
				ID:         "0.0.0.0",
				Interfaces: []*config.OSPFInterface{{Name: "reth0"}},
			}}},
			OSPFv3: &config.OSPFv3Config{Areas: []*config.OSPFv3Area{{
				ID:         "0.0.0.0",
				Interfaces: []*config.OSPFv3Interface{{Name: "reth0"}},
			}}},
			RIP:  &config.RIPConfig{Interfaces: []string{"reth0"}},
			ISIS: &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Interfaces: []*config.ISISInterface{{Name: "reth0"}}},
			BGP: &config.BGPConfig{
				LocalAS:   65099,
				Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.99", PeerAS: 65098, FamilyInet: true}},
			},
		}},
	}
	got := New().buildManagedSection(fc)
	for _, bad := range []string{"router ospf", "router ospf6", "router rip", "router isis", "router bgp"} {
		if strings.Contains(got, bad) {
			t.Errorf("forwarding instance emitted %q stanza:\n%s", bad, got)
		}
	}
}
