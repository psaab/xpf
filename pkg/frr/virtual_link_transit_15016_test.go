package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15016 (A12-04): render belt + ordering. A VL whose effective transit
// is the backbone or a stub/NSSA area is omitted with a warning; a valid
// VL is emitted in a `router ospf` stanza AFTER the interface blocks so
// the transit area is activated before FRR evaluates the virtual link
// on first load.

func TestVirtualLinkTransitOmit15016(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
		{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.0"}}},
		{ID: "0.0.0.1", AreaType: "stub", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/1.0"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.3", TransitArea: "0.0.0.1"}}},
		{ID: "0.0.0.2", AreaType: "nssa", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/2.0"}}},
		{ID: "0.0.0.3", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/3.0"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.4", TransitArea: "0.0.0.2"}}},
	}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	for _, bad := range []string{
		"area 0.0.0.0 virtual-link 10.0.0.2",
		"area 0.0.0.1 virtual-link 10.0.0.3",
		"area 0.0.0.2 virtual-link 10.0.0.4",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted FRR-refused %q:\n%s", bad, got)
		}
	}
	// Controls: non-VL area stanzas survive.
	if !strings.Contains(got, "area 0.0.0.1 stub") {
		t.Errorf("renderer dropped valid stub stanza:\n%s", got)
	}
	if !strings.Contains(got, "area 0.0.0.2 nssa") {
		t.Errorf("renderer dropped valid nssa stanza:\n%s", got)
	}
}

func TestVirtualLinkAfterInterfaces15016(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
		{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
	}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	vlLine := "area 0.0.0.1 virtual-link 10.0.0.2\n"
	if !strings.Contains(got, vlLine) {
		t.Fatalf("valid virtual-link missing:\n%s", got)
	}
	ifaceIdx := strings.Index(got, "interface ge-0/0/0.0\n")
	areaIdx := strings.Index(got, " ip ospf area 0.0.0.1\n")
	if ifaceIdx < 0 || areaIdx < 0 {
		t.Fatalf("interface activation missing:\n%s", got)
	}
	// VL must be in a router ospf stanza after the interface blocks.
	secondRouter := strings.LastIndex(got, "router ospf")
	vlIdx := strings.Index(got, vlLine)
	if secondRouter < 0 || vlIdx < secondRouter || vlIdx < areaIdx {
		t.Fatalf("virtual-link not after interface activation (router=%d vl=%d area=%d):\n%s", secondRouter, vlIdx, areaIdx, got)
	}
	// The trailing stanza must be a proper router ospf block.
	tail := got[secondRouter:]
	if !strings.HasPrefix(tail, "router ospf\n") || !strings.Contains(tail, " "+vlLine) {
		t.Fatalf("virtual-link not inside trailing router ospf stanza:\n%s", got)
	}
}

func TestVirtualLinkValidCustomTransitStillRendersAfter15016(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
		{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.3", TransitArea: "0.0.0.2"}}},
		{ID: "0.0.0.2", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/1.0"}}},
	}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "area 0.0.0.2 virtual-link 10.0.0.3\n") {
		t.Fatalf("valid custom-transit virtual-link missing:\n%s", got)
	}
}
