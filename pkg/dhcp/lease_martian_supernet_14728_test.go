package dhcp

import (
	"net"
	"net/netip"
	"testing"
)

// #14728 leg B: leaseFromACKv4 checked ClasslessRouteIsMartian only on the
// /32 yiaddr, so a /8-/15 connected prefix covering a martian range passed.
// Probe: ClasslessRouteIsMartian(169.255.0.1/15.Masked()) must be true
// (169.254.0.0/15 covers 169.254.0.0/16) while the /32 check was false.
// RED on master: such ACKs are accepted and become Lease.Address passed to
// AddrReplace, installing a connected route over martian space.
func TestLeaseFromACKv4RejectsMartianCoveringSupernet14728(t *testing.T) {
	for _, tc := range []struct {
		name   string
		yiaddr string
		mask   net.IPMask
	}{
		{"link-local covering /15", "169.255.0.1", net.CIDRMask(15, 32)},
		{"link-local covering /14", "169.252.0.1", net.CIDRMask(14, 32)},
		{"link-local covering /12", "169.240.0.1", net.CIDRMask(12, 32)},
		{"link-local covering /8", "169.0.0.1", net.CIDRMask(8, 32)},
		{"loopback covering /9", "127.128.0.1", net.CIDRMask(9, 32)},
		{"loopback covering /8", "127.0.0.1", net.CIDRMask(8, 32)},
		{"multicast covering /8", "224.0.0.1", net.CIDRMask(8, 32)},
		{"multicast covering /12", "239.240.0.1", net.CIDRMask(12, 32)},
		{"this-network covering /8", "0.1.0.1", net.CIDRMask(8, 32)},
		{"reserved covering /8", "240.0.0.1", net.CIDRMask(8, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Oracle: the masked installed prefix itself is martian.
			ones, _ := tc.mask.Size()
			addr := netip.MustParseAddr(tc.yiaddr)
			if !ClasslessRouteIsMartian(netip.PrefixFrom(addr, ones)) {
				t.Fatalf("test oracle wrong: %s/%d not martian per ClasslessRouteIsMartian", tc.yiaddr, ones)
			}
			lease, err := leaseFromACKv4("wan0", mustV4ACK(t, net.ParseIP(tc.yiaddr), tc.mask))
			if err == nil {
				t.Fatalf("leaseFromACKv4 accepted martian-covering %s; got lease %v, want error", tc.name, lease.Address)
			}
			if lease != nil {
				t.Errorf("lease returned alongside error = %v, want nil", lease.Address)
			}
		})
	}

	// Controls: non-overlapping broad-but-legit prefixes must stay accepted.
	for _, tc := range []struct {
		name   string
		yiaddr string
		mask   net.IPMask
		want   string
	}{
		{"private /8 accepted", "10.0.0.5", net.CIDRMask(8, 32), "10.0.0.5/8"},
		{"private /12 adjacent not covering link-local", "172.16.0.5", net.CIDRMask(12, 32), "172.16.0.5/12"},
		{"public /15 accepted", "192.0.2.5", net.CIDRMask(15, 32), "192.0.2.5/15"},
		{"public /24 accepted", "192.0.2.5", net.CIDRMask(24, 32), "192.0.2.5/24"},
		// Adjacent to link-local but not covering it: 168.0.0.0/8 excludes 169.254/16.
		{"adjacent /8 accepted", "168.0.0.5", net.CIDRMask(8, 32), "168.0.0.5/8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, err := leaseFromACKv4("wan0", mustV4ACK(t, net.ParseIP(tc.yiaddr), tc.mask))
			if err != nil {
				t.Fatalf("leaseFromACKv4 rejected legitimate lease: %v", err)
			}
			if got := lease.Address.String(); got != tc.want {
				t.Errorf("lease.Address = %s, want %s", got, tc.want)
			}
		})
	}
}

// #14728 leg A: no protected-prefix overlap check existed for v4. Through the
// Manager-installed set, a lease whose connected (masked) prefix overlaps a
// configured IPv4 prefix must be refused; disjoint leases stay accepted.
// RED on master: SetProtectedIPv4Prefixes does not exist / overlap accepted.
func TestLeaseFromACKv4RefusesProtectedOverlap14728(t *testing.T) {
	protected := []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")}

	m := NewManagerForTesting(nil)
	m.SetProtectedIPv4Prefixes(protected)

	for _, tc := range []struct {
		name   string
		yiaddr string
		mask   net.IPMask
	}{
		{"more-specific inside protected", "10.0.1.2", net.CIDRMask(25, 32)},
		{"equal to protected", "10.0.1.5", net.CIDRMask(24, 32)},
		{"supernet covering protected", "10.0.0.5", net.CIDRMask(16, 32)},
		{"straddling protected", "10.0.1.128", net.CIDRMask(23, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, err := m.leaseFromACKv4("wan0", mustV4ACK(t, net.ParseIP(tc.yiaddr), tc.mask))
			if err == nil {
				t.Fatalf("leaseFromACKv4 accepted protected-overlapping %s; got %v, want error", tc.name, lease.Address)
			}
			if lease != nil {
				t.Errorf("lease returned alongside error = %v, want nil", lease.Address)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		yiaddr string
		mask   net.IPMask
		want   string
	}{
		{"disjoint accepted", "10.0.2.5", net.CIDRMask(24, 32), "10.0.2.5/24"},
		{"adjacent accepted", "10.0.0.5", net.CIDRMask(25, 32), "10.0.0.5/25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease, err := m.leaseFromACKv4("wan0", mustV4ACK(t, net.ParseIP(tc.yiaddr), tc.mask))
			if err != nil {
				t.Fatalf("leaseFromACKv4 rejected disjoint lease: %v", err)
			}
			if got := lease.Address.String(); got != tc.want {
				t.Errorf("lease.Address = %s, want %s", got, tc.want)
			}
		})
	}

	// Nil protected set (standalone manager / no v4 config) refuses nothing
	// on overlap — prior behavior preserved.
	m2 := NewManagerForTesting(nil)
	lease, err := m2.leaseFromACKv4("wan0", mustV4ACK(t, net.ParseIP("10.0.1.2"), net.CIDRMask(25, 32)))
	if err != nil {
		t.Fatalf("nil protected set must not refuse: %v", err)
	}
	if got := lease.Address.String(); got != "10.0.1.2/25" {
		t.Errorf("lease.Address = %s, want 10.0.1.2/25", got)
	}

	// Free-function callers (existing tests) keep working with no protected set.
	lease, err = leaseFromACKv4("wan0", mustV4ACK(t, net.ParseIP("10.0.1.2"), net.CIDRMask(25, 32)))
	if err != nil {
		t.Fatalf("free leaseFromACKv4 rejected: %v", err)
	}
	_ = lease
}
