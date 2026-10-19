package grpcapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #15694 (V37-04): the gRPC `show dhcp server detail` renderer (remote cli)
// had the same three defects as the local CLI: v4 pools omitted
// domain-name/static-binding, v6 pools printed only Subnet/Range (omitting
// dns-server/domain-name/lease-time/static-binding), and Groups iterated
// in Go map order with no Kea subnet-id beside each pool.
//
// The config is built directly (not via the config compiler) so the evil
// hostname fixture below is not normalized away before rendering: the
// static-binding HostName is rendered with termsafe.SanitizeForDisplay,
// and a raw ESC/OSC byte must never reach the remote cli's verbatim print.
//
// FAIL-ON-REVERT: restoring the pre-fix renderer drops the asserted lines,
// returns to unsorted map iteration, and removes the Subnet ID lines;
// dropping the termsafe call makes the raw escape assertion go RED.

const evilBindingHostname15694 = "pwn\x1b]52;c;YWFhYWFh\x07host"

func detail15694Config() *config.Config {
	cfg := &config.Config{}
	cfg.System.DHCPServer.DHCPLocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"zeta": {
				Name:       "zeta",
				Interfaces: []string{"ge-0-0-1.0"},
				Pools: []*config.DHCPPool{{
					Name: "zp", Subnet: "10.0.2.0/24",
					RangeLow: "10.0.2.100", RangeHigh: "10.0.2.199",
					Router: "10.0.2.1", DNSServers: []string{"10.0.2.53"},
					Domain: "zeta.example", LeaseTime: 7200,
				}},
			},
			"alpha": {
				Name:       "alpha",
				Interfaces: []string{"ge-0-0-0.0"},
				Pools: []*config.DHCPPool{{
					Name: "ap", Subnet: "10.0.1.0/24",
					RangeLow: "10.0.1.100", RangeHigh: "10.0.1.199",
					Router: "10.0.1.1", DNSServers: []string{"10.0.1.53", "10.0.1.54"},
					Domain: "alpha.example", LeaseTime: 3600,
					StaticBindings: []*config.DHCPStaticBinding{
						{MACAddress: "00:11:22:33:44:55", FixedAddress: "10.0.1.50", HostName: "printer"},
						{MACAddress: "aa:bb:cc:dd:ee:ff", FixedAddress: "10.0.1.51"},
					},
				}},
			},
		},
	}
	cfg.System.DHCPServer.DHCPv6LocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"zeta6": {
				Name:       "zeta6",
				Interfaces: []string{"ge-0-0-1.0"},
				Pools: []*config.DHCPPool{{
					Name: "zp6", Subnet: "2001:db8:2::/64",
					RangeLow: "2001:db8:2::100", RangeHigh: "2001:db8:2::199",
					DNSServers: []string{"2001:db8:2::53"},
					Domain:     "zeta6.example", LeaseTime: 7200,
				}},
			},
			"alpha6": {
				Name:       "alpha6",
				Interfaces: []string{"ge-0-0-0.0"},
				Pools: []*config.DHCPPool{{
					// Reservation-only pool: no address-range.
					Name: "ap6", Subnet: "2001:db8:1::/64",
					DNSServers: []string{"2001:db8:1::53", "2001:db8:1::54"},
					Domain:     "alpha6.example", LeaseTime: 3600,
					StaticBindings: []*config.DHCPStaticBinding{
						{MACAddress: "00:11:22:33:44:66", FixedAddress: "2001:db8:1::50", HostName: evilBindingHostname15694},
					},
				}},
			},
		},
	}
	return cfg
}

func TestShowDHCPServerDetail_RendersPoolFields_15694(t *testing.T) {
	cfg := detail15694Config()
	ids4, ids6 := dhcpserver.SubnetIDAssignments15694(&cfg.System.DHCPServer)
	if len(ids4) != 2 || len(ids6) != 2 {
		t.Fatalf("SubnetIDAssignments15694 = v4:%v v6:%v, want 2 subnets each", ids4, ids6)
	}

	s := &Server{}
	var buf strings.Builder
	s.showDHCPServerDetail(cfg, &buf)
	out := buf.String()

	if ia, iz := strings.Index(out, "Group: alpha"), strings.Index(out, "Group: zeta"); ia < 0 || iz < 0 || ia > iz {
		t.Errorf("v4 groups not in sorted order (alpha idx %d, zeta idx %d):\n%s", ia, iz, out)
	}
	if ia, iz := strings.Index(out, "Group: alpha6"), strings.Index(out, "Group: zeta6"); ia < 0 || iz < 0 || ia > iz {
		t.Errorf("v6 groups not in sorted order (alpha6 idx %d, zeta6 idx %d):\n%s", ia, iz, out)
	}

	for _, want := range []string{
		"Domain: alpha.example",
		"Static binding: 00:11:22:33:44:55 fixed-address 10.0.1.50 hostname printer",
		"Static binding: aa:bb:cc:dd:ee:ff fixed-address 10.0.1.51",
		"Domain: zeta.example",
		fmt.Sprintf("Subnet ID: %d", ids4["10.0.1.0/24"]),
		fmt.Sprintf("Subnet ID: %d", ids6["2001:db8:1::/64"]),
		"DNS: 2001:db8:1::53, 2001:db8:1::54",
		"Domain: alpha6.example",
		"Lease time: 3600s",
		"Static binding: 00:11:22:33:44:66 fixed-address 2001:db8:1::50 hostname ",
		"DNS: 2001:db8:2::53",
		"Domain: zeta6.example",
		"Lease time: 7200s",
		"Subnet: 10.0.1.0/24",
		"Range: 10.0.1.100 - 10.0.1.199",
		"Router: 10.0.1.1",
		"DNS: 10.0.1.53, 10.0.1.54",
		"Subnet: 2001:db8:1::/64",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("grpc detail output missing %q:\n%s", want, out)
		}
	}

	// The evil hostname is sanitized: no raw ESC/OSC bytes, escape visible.
	if strings.Contains(out, "\x1b") {
		t.Errorf("raw ESC byte from static-binding hostname reached output:\n%q", out)
	}
	if !strings.Contains(out, `\x1b]52`) {
		t.Errorf("sanitized hostname escape not visible in output:\n%s", out)
	}
}
