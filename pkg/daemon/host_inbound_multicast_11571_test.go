package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestHostInboundRoutingMulticastIsScopedByIngressZone11571(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone:           "ospf-zone",
			Protocols:      []string{"ospf"},
			V4Addrs:        []string{"192.0.2.1"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
		{
			Zone:           "closed-zone",
			V4Addrs:        []string{"198.51.100.1"},
			IngressNetdevs: []string{"ge-0-0-1"},
		},
		{
			Zone:           "vrrp6-zone",
			Protocols:      []string{"vrrp"},
			V6Addrs:        []string{"2001:db8::1"},
			IngressNetdevs: []string{"ge-0-0-2"},
		},
		{
			Zone:           "closed6-zone",
			V6Addrs:        []string{"2001:db8:1::1"},
			IngressNetdevs: []string{"ge-0-0-3"},
		},
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	lines := strings.Split(payload, "\n")

	wantScopedRule := func(iface, group, protocol string) bool {
		for _, line := range lines {
			if strings.Contains(line, iface) && strings.Contains(line, group) &&
				strings.Contains(line, protocol) && strings.Contains(line, "accept") &&
				strings.Contains(line, "iifname") {
				return true
			}
		}
		return false
	}
	wantGroupDrop := func(iface, group string) bool {
		for _, line := range lines {
			if strings.Contains(line, iface) && strings.Contains(line, group) &&
				strings.Contains(line, "drop") && strings.Contains(line, "iifname") {
				return true
			}
		}
		return false
	}

	if !wantScopedRule("ge-0-0-0", "224.0.0.5", "89") {
		t.Fatal("OSPFv2 group 224.0.0.5/proto 89 has no ingress-scoped accept for the OSPF zone")
	}
	if wantScopedRule("ge-0-0-1", "224.0.0.5", "89") {
		t.Fatal("empty host-inbound zone must not accept OSPF multicast")
	}
	if !wantGroupDrop("ge-0-0-1", "224.0.0.5") {
		t.Fatal("OSPFv2 multicast on a zone without the protocol must hit a group-scoped drop")
	}
	if !wantScopedRule("ge-0-0-2", "ff02::12", "112") {
		t.Fatal("VRRPv6 group ff02::12/proto 112 has no ingress-scoped accept for the VRRP zone")
	}
	if wantScopedRule("ge-0-0-3", "ff02::12", "112") {
		t.Fatal("empty IPv6 host-inbound zone must not accept VRRP multicast")
	}
	if !wantGroupDrop("ge-0-0-3", "ff02::12") {
		t.Fatal("VRRPv6 multicast on a zone without the protocol must hit a group-scoped drop")
	}
}
