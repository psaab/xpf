package dhcp

import (
	"net"
	"testing"
)

// TestLeaseFromACKv4RejectsBroadMaskAndMartianYiaddr14183 is the #14183
// fail-on-revert guard: a rogue DHCP server must not widen the interface
// connected prefix (up to /1) or bind a martian address via yiaddr.
//
// RED on pristine master: /1 and /7 masks and martian yiaddr values are
// accepted and become Lease.Address passed to AddrReplace.
func TestLeaseFromACKv4RejectsBroadMaskAndMartianYiaddr14183(t *testing.T) {
	for _, tc := range []struct {
		name   string
		yiaddr string
		mask   net.IPMask
	}{
		{"mask /1 rejected", "192.0.2.5", net.CIDRMask(1, 32)},
		{"mask /2 rejected", "192.0.2.5", net.CIDRMask(2, 32)},
		{"mask /7 rejected", "192.0.2.5", net.CIDRMask(7, 32)},
		{"loopback yiaddr rejected", "127.0.0.2", net.CIDRMask(24, 32)},
		{"this-network yiaddr rejected", "0.0.0.9", net.CIDRMask(24, 32)},
		{"link-local yiaddr rejected", "169.254.1.1", net.CIDRMask(24, 32)},
		{"multicast yiaddr rejected", "224.0.0.1", net.CIDRMask(24, 32)},
		{"reserved yiaddr rejected", "240.0.0.1", net.CIDRMask(24, 32)},
		{"limited broadcast yiaddr rejected", "255.255.255.255", net.CIDRMask(24, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ack := mustV4ACK(t, net.ParseIP(tc.yiaddr), tc.mask)
			lease, err := leaseFromACKv4("wan0", ack)
			if err == nil {
				t.Fatalf("leaseFromACKv4 accepted %s; got lease %v, want error", tc.name, lease.Address)
			}
			if lease != nil {
				t.Errorf("lease returned alongside error = %v, want nil", lease.Address)
			}
		})
	}

	// Legitimate leases must still be accepted: the fix must not become a
	// blanket refusal of normal addressing.
	for _, tc := range []struct {
		name   string
		yiaddr string
		mask   net.IPMask
		want   string
	}{
		{"public /24 accepted", "192.0.2.5", net.CIDRMask(24, 32), "192.0.2.5/24"},
		{"private /8 accepted", "10.0.0.5", net.CIDRMask(8, 32), "10.0.0.5/8"},
		{"private /16 accepted", "192.168.1.5", net.CIDRMask(16, 32), "192.168.1.5/16"},
		{"point-to-point /31 accepted", "192.0.2.5", net.CIDRMask(31, 32), "192.0.2.5/31"},
		{"host /32 accepted", "192.0.2.5", net.CIDRMask(32, 32), "192.0.2.5/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ack := mustV4ACK(t, net.ParseIP(tc.yiaddr), tc.mask)
			lease, err := leaseFromACKv4("wan0", ack)
			if err != nil {
				t.Fatalf("leaseFromACKv4 rejected legitimate lease: %v", err)
			}
			if got := lease.Address.String(); got != tc.want {
				t.Errorf("lease.Address = %s, want %s", got, tc.want)
			}
		})
	}
}
