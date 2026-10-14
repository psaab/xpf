package nftables

import (
	"strings"
	"testing"
)

// #12959 (follow-up #12846): the netlink fence WG admits must mirror the text
// oracle's steady-state zone mapping, including the lifeline-shared addresses
// withheld into IngressDenyV4/V6, in both the cold-boot/lo0 and the
// coverage-gap tables.

func fenceWGIngressDenyViews12959() []HostInboundZoneView {
	return []HostInboundZoneView{
		{
			Zone:           "untrust",
			V4Addrs:        []string{"198.51.100.1"},
			V6Addrs:        []string{"2001:db8:a::1"},
			IngressDenyV4:  []string{"192.0.2.1"},
			IngressDenyV6:  []string{"2001:db8::1"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
		{
			Zone:           "trust",
			V4Addrs:        []string{"10.2.2.1"},
			SystemServices: []string{"ssh"},
			IngressNetdevs: []string{"ge-0-0-2"},
		},
	}
}

// fenceWGHasAcceptFor12959 reports whether the plan holds a UDP-dport WG
// accept naming addr (hex canonical form), mirroring the 11572 helpers.
func fenceWGHasAcceptFor12959(t *testing.T, p *nlPlan, addr string) bool {
	t.Helper()
	want := addrHex(t, addr)
	for _, rule := range p.rules {
		line := canonRule(p, rule)
		if strings.Contains(line, want) && strings.Contains(line, "ca6c") && strings.Contains(line, "verdict(1)") {
			return true
		}
	}
	return false
}

func TestFenceWGIngressDenyAdmittedNetlink12959(t *testing.T) {
	views := fenceWGIngressDenyViews12959()
	wgZonePorts := map[string][]uint16{"untrust": {51820}}

	t.Run("cold-boot", func(t *testing.T) {
		p := newBuildPlan(t, HostInboundTableName, hostInboundPriority)
		buildHostInboundFenceNetlink(p, FenceSpec{Views: views, WGZonePorts: wgZonePorts})
		assertFenceWGIngressDenyAccept12959(t, p)
	})

	t.Run("lo0", func(t *testing.T) {
		p := newBuildPlan(t, Lo0TableName, lo0FilterPriority)
		buildLo0FenceNetlink(p, FenceSpec{Views: views, WGZonePorts: wgZonePorts})
		assertFenceWGIngressDenyAccept12959(t, p)
	})
}

func assertFenceWGIngressDenyAccept12959(t *testing.T, p *nlPlan) {
	t.Helper()
	if p.err != nil {
		t.Fatalf("build fence: %v", p.err)
	}
	for _, addr := range []string{"192.0.2.1", "2001:db8::1"} {
		if !fenceWGHasAcceptFor12959(t, p, addr) {
			t.Errorf("fence lacks scoped WG accept for IngressDeny address %s\nrules:\n%s", addr, canonRules(p))
		}
	}
	// Non-owner ingress and unconfigured zones must not gain a WG accept for
	// the withheld value.
	for _, addr := range []string{"10.2.2.1"} {
		if fenceWGHasAcceptFor12959(t, p, addr) {
			t.Errorf("non-WG zone address %s must not gain a fence WG accept", addr)
		}
	}
}

// The coverage-gap fence must narrow the same mapping to its uncovered set:
// an address claimed by one zone via IngressDeny and by another via V4Addrs is
// ambiguous and gains no gap accept, while the same-zone claim keeps its
// scoped accept ahead of the bare uncovered drop.
func TestFenceWGIngressDenyGapNetlink12959(t *testing.T) {
	t.Run("same-zone admit", func(t *testing.T) {
		views := []HostInboundZoneView{
			{Zone: "edge", IngressDenyV4: []string{"192.0.2.1"}, IngressNetdevs: []string{"ge-0-0-0"}},
			{Zone: "edge", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.1"}, IngressNetdevs: []string{"ge-0-0-1"}},
		}
		p := newBuildPlan(t, HostInboundGapTableName, hostInboundGapPriority)
		buildHostInboundGapFenceNetlink(p, GapFenceSpec{
			Views: views, UncoveredV4: []string{"192.0.2.1"},
			WGZonePorts: map[string][]uint16{"edge": {51820}},
		})
		if p.err != nil {
			t.Fatalf("build gap fence: %v", p.err)
		}
		if !fenceWGHasAcceptFor12959(t, p, "192.0.2.1") {
			t.Fatalf("gap fence lacks same-zone WG accept for the shared uncovered value\nrules:\n%s", canonRules(p))
		}
	})

	t.Run("cross-zone ambiguity fail-closed", func(t *testing.T) {
		views := []HostInboundZoneView{
			{Zone: "denyzone", IngressDenyV4: []string{"192.0.2.1"}, IngressNetdevs: []string{"ge-0-0-0"}},
			{Zone: "admzone", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.1"}, IngressNetdevs: []string{"ge-0-0-1"}},
		}
		p := newBuildPlan(t, HostInboundGapTableName, hostInboundGapPriority)
		buildHostInboundGapFenceNetlink(p, GapFenceSpec{
			Views: views, UncoveredV4: []string{"192.0.2.1"},
			WGZonePorts: map[string][]uint16{"denyzone": {51820}, "admzone": {51820}},
		})
		if p.err != nil {
			t.Fatalf("build gap fence: %v", p.err)
		}
		if fenceWGHasAcceptFor12959(t, p, "192.0.2.1") {
			t.Fatalf("cross-zone IngressDeny claim must stay fail-closed in the gap fence\nrules:\n%s", canonRules(p))
		}
	})
}
