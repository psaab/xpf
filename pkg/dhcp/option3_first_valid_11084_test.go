package dhcp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// TestDHCPOption3FirstAcceptableWins11084 pins the #11084 fix: option-3 must
// scan to the first ACCEPTABLE router (option-121 first-valid parity) instead
// of testing routers[0] only. A martian head from a rogue/misconfigured
// server must not block a later valid router from installing the default
// next-hop.
func TestDHCPOption3FirstAcceptableWins11084(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routers []string
		wantGW  string // "" means refused (no gateway installed)
	}{
		{
			name:    "martian head skipped to valid",
			routers: []string{"127.0.0.1", "192.0.2.1"},
			wantGW:  "192.0.2.1",
		},
		{
			name:    "multiple martian heads skipped to valid",
			routers: []string{"127.0.0.1", "224.0.0.1", "198.51.100.1"},
			wantGW:  "198.51.100.1",
		},
		{
			name:    "valid head wins over later valid (first-wins, not last)",
			routers: []string{"192.0.2.1", "198.51.100.1"},
			wantGW:  "192.0.2.1",
		},
		{
			name:    "all-martian installs none (fails closed)",
			routers: []string{"127.0.0.1", "0.0.0.0"},
			wantGW:  "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ips := make([]net.IP, 0, len(tc.routers))
			for _, r := range tc.routers {
				ips = append(ips, net.ParseIP(r))
			}
			lease, err := leaseFromACKv4("wan0", classlessACK(t, dhcpv4.OptRouter(ips...)))
			if err != nil {
				t.Fatalf("leaseFromACKv4: %v", err)
			}
			if tc.wantGW == "" {
				if lease.Gateway.IsValid() {
					t.Errorf("lease.Gateway = %v, want NONE (all-martian %q must fail closed)", lease.Gateway, tc.routers)
				}
				return
			}
			if want := netip.MustParseAddr(tc.wantGW); lease.Gateway != want {
				t.Errorf("lease.Gateway = %v, want %v", lease.Gateway, want)
			}
		})
	}
}
