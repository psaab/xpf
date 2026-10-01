// lease.go holds the DHCP Lease value type, its classless-route
// helper type, and the read-only lease accessors. Split verbatim from
// dhcp.go (#6430); lease commit/diff lifecycle lives in commit.go.
package dhcp

import (
	"net/netip"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// Lease holds the result of a DHCP negotiation.
type Lease struct {
	Interface string
	Family    AddressFamily
	Address   netip.Prefix
	Gateway   netip.Addr
	DNS       []netip.Addr
	LeaseTime time.Duration
	Obtained  time.Time

	// ClasslessRoutes holds RFC 3442 routes learned from DHCPv4 option 121/249
	// and IPv6 Route Information options learned from Router Advertisements.
	// The default route, when represented here, is programmed through the same
	// DHCP route consumers as more-specific routes.
	ClasslessRoutes []LeaseRoute

	// raGatewayExpiresAt is the absolute Router Advertisement expiry for
	// Gateway. It is bounded by the current DHCP lease deadline when used.
	raGatewayExpiresAt  time.Time
	raGatewayPreference int
	raRouteExpires      map[raRouteKey]time.Time
	leaseExpiryApplies  bool

	// serverID is the DHCPv4 server-identifier (option 54) from the ACK
	// that granted this lease. It is the unicast destination for the
	// RFC 2131 §4.3.6 RENEWING DHCPREQUEST at T1. Unexported: internal
	// renewal state, not part of the public lease surface. A change is
	// included in leaseContentChanged so a rebinding server transition is
	// visible to downstream consumers.
	serverID netip.Addr

	// v6ServerDUID is the DHCPv6 Server-Identifier (DUID) from the Reply
	// that granted this lease, echoed in the RFC 8415 §18.2.4 RENEW so
	// the original server matches the binding. Unexported; a change is
	// included in leaseContentChanged for the same reason as serverID.
	v6ServerDUID dhcpv6.DUID
}

// sameDUID compares DHCPv6 DUID values without relying on interface
// comparability: DUID implementations contain byte slices.
func sameDUID(a, b dhcpv6.DUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

// LeaseRoute is one classless static route (destination prefix plus gateway)
// learned from DHCPv4 option 121/249 or an IPv6 Route Information option.
// The comparable fields are the route identity consumed by downstream code.
type LeaseRoute struct {
	Destination netip.Prefix
	Gateway     netip.Addr
}

// Leases returns a snapshot of all current DHCP leases.
func (m *Manager) Leases() []*Lease {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*Lease, 0, len(m.leases))
	for _, l := range m.leases {
		lc := *l
		result = append(result, &lc)
	}
	return result
}

// LeaseFor returns the current lease for a specific interface/family, or nil.
func (m *Manager) LeaseFor(ifaceName string, af AddressFamily) *Lease {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.leases[clientKey{iface: ifaceName, family: af}]
	if !ok {
		return nil
	}
	lc := *l
	return &lc
}

// #1715: the DHCP client no longer writes /etc/resolv.conf. DNS
// ownership moved to the daemon's single applySem-locked reconcileDNS,
// which reads DHCP-learned servers from Leases() (lease.DNS is populated
// for both families) and merges them with static `system name-server`.
// The client only stores the lease and fires the debounced
// onAddressChange callback (scheduleRecompile), which the daemon routes
// to reconcileDNSFromDHCP. The former installDNS file write — which
// wrote through the dangling resolv.conf symlink and failed silently,
// and which clobbered the other family's servers with no merge — is
// removed.
