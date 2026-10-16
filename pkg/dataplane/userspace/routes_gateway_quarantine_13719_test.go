package userspace

// #13719 (deep-review D19-06): forwardingGatewayInterface admitted
// quarantined-VRF rows and missing-link rows in its global-gateway
// branch, and false-ambiguated link-local gateways when a base row and
// its unit-0 row describe the same netdev.
//
// The producer contract these cells pin:
//   - A quarantined row carries RoutingInstance "" and
//     RoutingDomain == QuarantinedRoutingInstanceDomain (2); it is in
//     NO instance and must never qualify a forwarding-instance gateway
//     (#9956/#11060). The link-local branch already guards this under
//     its default-instance case; the global branch did not.
//   - A row with Ifindex <= 0 has no kernel link; addConnectedRoutes
//     already refuses to publish its addresses as connected routes,
//     but gateway qualification still honoured its config-merged
//     addresses.
//   - snapshotLinuxName collapses a non-VLAN unit 0 onto its base
//     netdev, so the base row and the unit-0 row are ONE egress for a
//     link-local gateway, not two ambiguous candidates.

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestForwardingGatewayInterfaceRejectsQuarantinedDefault13719(t *testing.T) {
	interfaces := []InterfaceSnapshot{{
		Name:          "reth0.80",
		LinuxName:     "reth0.80",
		Ifindex:       80,
		RoutingDomain: QuarantinedRoutingInstanceDomain,
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.1/24"},
		},
	}}
	if got := forwardingGatewayInterface("ISP-B", "inet", net.ParseIP("192.0.2.254"), interfaces); got != "" {
		t.Errorf("quarantined default-instance interface qualified a forwarding-instance gateway as %q; a RoutingDomain==%d row belongs to no VRF and must stay unresolved", got, QuarantinedRoutingInstanceDomain)
	}
}

func TestForwardingGatewayInterfaceRejectsMissingLink13719(t *testing.T) {
	global := []InterfaceSnapshot{{
		Name:      "reth0.80",
		LinuxName: "reth0.80",
		Ifindex:   0, // configured identity whose kernel netdev is gone
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.1/24"},
		},
	}}
	if got := forwardingGatewayInterface("ISP-B", "inet", net.ParseIP("192.0.2.254"), global); got != "" {
		t.Errorf("missing-link interface qualified a global gateway as %q; Ifindex<=0 rows publish no connected route and cannot egress", got)
	}

	linkLocal := []InterfaceSnapshot{{
		Name:      "reth0.80",
		LinuxName: "reth0.80",
		Ifindex:   0,
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet6", Address: "fe80::8/64"},
		},
	}}
	if got := forwardingGatewayInterface("ISP-B", "inet6", net.ParseIP("fe80::254"), linkLocal); got != "" {
		t.Errorf("missing-link interface qualified a link-local gateway as %q; Ifindex<=0 rows cannot egress", got)
	}
}

func TestForwardingGatewayInterfaceLinkLocalBaseUnitSameNetdev13719(t *testing.T) {
	// One physical default-instance interface: the base row and its
	// unit-0 row share a netdev (same LinuxName/Ifindex) and both carry
	// the live kernel link-local address. That is a single candidate,
	// so the gateway must resolve — to the unit row, the Junos
	// interface identity — instead of counting two and returning "".
	interfaces := []InterfaceSnapshot{
		{
			Name:      "ge-0/0/1",
			LinuxName: "ge-0-0-1",
			Ifindex:   12,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "fe80::1/64"},
			},
		},
		{
			Name:      "ge-0/0/1.0",
			IsUnit:    true,
			LinuxName: "ge-0-0-1",
			Ifindex:   12,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "fe80::1/64"},
			},
		},
	}
	if got := forwardingGatewayInterface("ISP-B", "inet6", net.ParseIP("fe80::2"), interfaces); got != "ge-0/0/1.0" {
		t.Errorf("base+unit-0 rows on one netdev = %q, want %q: the pair is one egress, not an ambiguity", got, "ge-0/0/1.0")
	}

	// Control: two genuinely distinct default-instance netdevs stay
	// ambiguous — deduplication must not widen into picking a winner.
	interfaces[1].Name = "ge-0/0/2.0"
	interfaces[1].LinuxName = "ge-0-0-2"
	interfaces[1].Ifindex = 13
	if got := forwardingGatewayInterface("ISP-B", "inet6", net.ParseIP("fe80::2"), interfaces); got != "" {
		t.Errorf("two distinct default-instance netdevs = %q, want unresolved (ambiguous)", got)
	}
}

func TestForwardingGatewayInterfaceAdmitsValidDefault13719(t *testing.T) {
	interfaces := []InterfaceSnapshot{{
		Name:      "reth0.80",
		LinuxName: "reth0.80",
		Ifindex:   80,
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.1/24"},
		},
	}}
	if got := forwardingGatewayInterface("ISP-B", "inet", net.ParseIP("192.0.2.254"), interfaces); got != "reth0.80" {
		t.Errorf("valid default-instance interface = %q, want %q (guard must not over-reject the default instance)", got, "reth0.80")
	}
}

// TestFBFQuarantinedGatewayStaysUnresolved13719 is the end-to-end cell:
// a forwarding-instance default route whose only covering interface is
// quarantined must not be published with a qualified next-hop.
func TestFBFQuarantinedGatewayStaysUnresolved13719(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "ISP-B",
			InstanceType: "forwarding",
			StaticRoutes: []*config.StaticRoute{{
				Destination: "0.0.0.0/0",
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.254"}},
			}},
		}},
	}
	interfaces := []InterfaceSnapshot{{
		Name:          "reth0.80",
		LinuxName:     "reth0.80",
		Ifindex:       80,
		RoutingDomain: QuarantinedRoutingInstanceDomain,
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.1/24"},
		},
	}}
	routes, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Table == "ISP-B.inet.0" && route.Destination == "0.0.0.0/0" {
			t.Fatalf("quarantined interface must not qualify the forwarding-instance gateway, got %+v", route)
		}
	}
}
