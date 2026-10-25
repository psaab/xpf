package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16572: a modelled `disable` must render NOTHING for the disabled
// scope — no `ip ospf area` on an excluded interface, no `router ospf`
// for a whole-protocol shut, and likewise for ospf3/isis/rip/bgp.
// Controls pin that enabled siblings render byte-identically in kind.

func TestOSPFInterfaceDisableRendersNothing16572(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/0.0"},
		{Name: "ge-0/0/1.0", Disable: true},
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "ge-0/0/1.0") {
		t.Fatalf("disabled OSPF interface rendered:\n%s", got)
	}
	// Control: the enabled sibling still activates.
	if !strings.Contains(got, "interface ge-0/0/0.0\n") || !strings.Contains(got, " ip ospf area 0.0.0.0\n") {
		t.Fatalf("enabled OSPF sibling must still activate:\n%s", got)
	}
	// Passive-interface directive must not resurrect a disabled
	// interface either.
	ospf.Areas[0].Interfaces[1].Passive = true
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "ge-0/0/1.0") {
		t.Fatalf("disabled+passive OSPF interface rendered:\n%s", got)
	}
}

func TestOSPFProtocolDisableRendersNothing16572(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Disable: true, RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/0.0"},
	}}}}
	if got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil); got != "" {
		t.Fatalf("protocol-disabled OSPF must render nothing, got:\n%s", got)
	}
	// Control without the flag renders the stanza.
	ospf.Disable = false
	if got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil); !strings.Contains(got, "router ospf\n") {
		t.Fatalf("enabled OSPF control must render router ospf:\n%s", got)
	}
}

func TestOSPF3DisableRendersNothing16572(t *testing.T) {
	m := New()
	v3 := &config.OSPFv3Config{Areas: []*config.OSPFv3Area{{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{
		{Name: "ge-0/0/0.0"},
		{Name: "ge-0/0/1.0", Disable: true},
	}}}}
	got := m.generateProtocols(nil, v3, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "ge-0/0/1.0") {
		t.Fatalf("disabled OSPFv3 interface rendered:\n%s", got)
	}
	if !strings.Contains(got, " ipv6 ospf6 area 0.0.0.0\n") {
		t.Fatalf("enabled OSPFv3 sibling must still activate:\n%s", got)
	}
	v3.Disable = true
	if got := m.generateProtocols(nil, v3, nil, nil, nil, "", 0, nil, nil); got != "" {
		t.Fatalf("protocol-disabled OSPFv3 must render nothing, got:\n%s", got)
	}
}

func TestISISDisableRendersNothing16572(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", Interfaces: []*config.ISISInterface{
		{Name: "ge-0-0-0"},
		{Name: "ge-0-0-1", Disable: true},
	}}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	if strings.Contains(got, "ge-0-0-1") {
		t.Fatalf("disabled IS-IS interface rendered:\n%s", got)
	}
	if !strings.Contains(got, " ip router isis xpf\n") {
		t.Fatalf("enabled IS-IS sibling must still activate:\n%s", got)
	}
	isis.Disable = true
	if got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil); got != "" {
		t.Fatalf("protocol-disabled IS-IS must render nothing, got:\n%s", got)
	}
}

func TestRIPDisableRendersNothing16572(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{Interfaces: []string{"ge-0-0-0"}, Disable: true}
	if got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil); got != "" {
		t.Fatalf("protocol-disabled RIP must render nothing, got:\n%s", got)
	}
	rip.Disable = false
	if got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil); !strings.Contains(got, "router rip") {
		t.Fatalf("enabled RIP control must render router rip:\n%s", got)
	}
}

func TestBGPDisableRendersNothing16572(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
		{Address: "192.0.2.1", PeerAS: 65002},
		{Address: "192.0.2.2", PeerAS: 65002, Disable: true},
		{Address: "192.0.2.3", PeerAS: 65002, BFD: true, Disable: true},
	}}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "192.0.2.2") || strings.Contains(got, "192.0.2.3") {
		t.Fatalf("disabled BGP neighbor rendered:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 192.0.2.1 remote-as 65002") {
		t.Fatalf("enabled BGP neighbor must still render:\n%s", got)
	}
	// Whole-protocol disable renders no stanza at all.
	bgp.Disable = true
	if got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil); strings.Contains(got, "router bgp") {
		t.Fatalf("protocol-disabled BGP must render no router bgp:\n%s", got)
	}
}
