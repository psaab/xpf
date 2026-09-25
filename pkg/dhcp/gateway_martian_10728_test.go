package dhcp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// TestDHCPGatewayMartianRefused10728 is the A10b-F02 fail-on-revert guard: a
// DHCP-supplied default gateway inside a non-forwardable range must NOT become
// the next-hop (no FRR default route, no neighbor entry). Each row is a rogue
// server handing a bogus value via option 3 or the option-121 /0 entry; the
// legitimate rows pin that ordinary + private gateways still install.
func TestDHCPGatewayMartianRefused10728(t *testing.T) {
	for _, tc := range []struct {
		name   string
		router string // option-3 value; "" means option absent
		wantGW string // "" means refused (no gateway installed)
	}{
		{"legit public gateway honored", "198.51.100.1", "198.51.100.1"},
		{"legit private gateway honored", "10.0.61.1", "10.0.61.1"},
		{"loopback refused", "127.0.0.1", ""},
		{"unspecified refused", "0.0.0.0", ""},
		{"multicast refused", "224.0.0.1", ""},
		{"limited broadcast refused", "255.255.255.255", ""},
		{"this-network refused", "0.0.0.9", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []dhcpv4.Option
			if tc.router != "" {
				opts = append(opts, dhcpv4.OptRouter(net.ParseIP(tc.router)))
			}
			lease, err := leaseFromACKv4("wan0", classlessACK(t, opts...))
			if err != nil {
				t.Fatalf("leaseFromACKv4: %v", err)
			}
			if tc.wantGW == "" {
				if lease.Gateway.IsValid() {
					t.Errorf("lease.Gateway = %v, want NONE (rogue %q must not install)", lease.Gateway, tc.router)
				}
				return
			}
			if want := netip.MustParseAddr(tc.wantGW); lease.Gateway != want {
				t.Errorf("lease.Gateway = %v, want %v", lease.Gateway, want)
			}
		})
	}
}

// TestDHCPClasslessGatewayMartianRefused10728 pins the same gate on the
// option-121 path: a martian /0 gateway is refused (first VALID wins), and a
// martian per-route gateway drops its route.
func TestDHCPClasslessGatewayMartianRefused10728(t *testing.T) {
	mkclassless := func(gw string) dhcpv4.Option {
		return dhcpv4.OptClasslessStaticRoute(
			&dhcpv4.Route{Dest: mustCIDR(t, "0.0.0.0/0"), Router: net.ParseIP(gw)},
		)
	}
	for _, tc := range []struct {
		name   string
		gw     string
		wantGW string
	}{
		{"legit classless gateway honored", "192.0.2.1", "192.0.2.1"},
		{"martian classless gateway refused", "127.0.0.2", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, err := leaseFromACKv4("wan0", classlessACK(t, mkclassless(tc.gw)))
			if err != nil {
				t.Fatalf("leaseFromACKv4: %v", err)
			}
			if tc.wantGW == "" {
				if lease.Gateway.IsValid() {
					t.Errorf("lease.Gateway = %v, want NONE", lease.Gateway)
				}
				return
			}
			if want := netip.MustParseAddr(tc.wantGW); lease.Gateway != want {
				t.Errorf("lease.Gateway = %v, want %v", lease.Gateway, want)
			}
		})
	}

	// Martian per-route gateway drops the route; the legit sibling survives.
	classless := dhcpv4.OptClasslessStaticRoute(
		&dhcpv4.Route{Dest: mustCIDR(t, "10.20.0.0/16"), Router: net.ParseIP("127.0.0.9")},
		&dhcpv4.Route{Dest: mustCIDR(t, "10.30.0.0/16"), Router: net.ParseIP("192.0.2.9")},
	)
	lease, err := leaseFromACKv4("wan0", classlessACK(t, classless))
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}
	if len(lease.ClasslessRoutes) != 1 {
		t.Fatalf("ClasslessRoutes = %+v, want only the legit-gateway route", lease.ClasslessRoutes)
	}
	if got := lease.ClasslessRoutes[0].Gateway.String(); got != "192.0.2.9" {
		t.Fatalf("surviving route gateway = %v, want 192.0.2.9", got)
	}
}

// TestDHCPGatewayMartianOverrideHonored10728 pins the escape hatch: with
// XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1 a martian gateway installs anyway.
func TestDHCPGatewayMartianOverrideHonored10728(t *testing.T) {
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	lease, err := leaseFromACKv4("wan0", classlessACK(t,
		dhcpv4.OptRouter(net.ParseIP("127.0.0.1"))))
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}
	if want := netip.MustParseAddr("127.0.0.1"); lease.Gateway != want {
		t.Fatalf("lease.Gateway = %v, want %v under override", lease.Gateway, want)
	}
}
