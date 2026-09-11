package dhcp

import (
	"context"
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// Test-only helpers for pkg/dhcp.Manager. Lives in the production
// package so external packages (e.g. pkg/api tests) can use these
// without internal-export tricks. Not for production callers.

// SeedLeaseForTesting installs a lease record for tests. Callers
// must not use this from production code paths.
func (m *Manager) SeedLeaseForTesting(ifaceName string, af AddressFamily, lease *Lease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leases == nil {
		m.leases = make(map[clientKey]*Lease)
	}
	m.leases[clientKey{iface: ifaceName, family: af}] = lease
}

// SeedDelegatedPrefixesForTesting installs the IA_PD delegations recorded for
// ifaceName, replacing any already held for it. It lets a caller outside pkg/dhcp
// (the #9413 REST handler cell) drive DelegatedPrefixes() without real DHCPv6
// traffic. Callers must not use this from production code paths.
func (m *Manager) SeedDelegatedPrefixesForTesting(ifaceName string, pds []DelegatedPrefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.delegatedPDs == nil {
		m.delegatedPDs = make(map[string][]DelegatedPrefix)
	}
	m.delegatedPDs[ifaceName] = append([]DelegatedPrefix(nil), pds...)
}

// NewManagerForTesting builds a Manager without a netlink handle and
// with the per-client run goroutine replaced by runClient, so reconcile
// and registry behavior can be tested without real DHCP traffic or
// netlink access. runClient should block on ctx.Done() to model a
// long-running client, or return early to model a terminal exit.
func NewManagerForTesting(runClient func(ctx context.Context, ifaceName string, af AddressFamily)) *Manager {
	return NewManagerForTestingWithHooks(runClient, nil)
}

// NewManagerForTestingWithHooks is NewManagerForTesting with the
// gateway-change hook wired (#1844). A constructor variant — not a
// setter — so the production immutability of onGatewayChange holds in
// tests too.
func NewManagerForTestingWithHooks(runClient func(ctx context.Context, ifaceName string, af AddressFamily), onGatewayChange func()) *Manager {
	return &Manager{
		clients:          make(map[clientKey]*dhcpClient),
		leases:           make(map[clientKey]*Lease),
		delegatedPDs:     make(map[string][]DelegatedPrefix),
		duids:            make(map[string]dhcpv6.DUID),
		duidTypes:        make(map[string]string),
		v4opts:           make(map[string]*DHCPv4Options),
		v6opts:           make(map[string]*DHCPv6Options),
		runClientForTest: runClient,
		onGatewayChange:  onGatewayChange,
	}
}

// SeedDelegatedPrefixesForRATesting installs delegated prefixes under
// sourceIface (preserving the given slice order within that source) and points
// that source's DHCPv6 RA target at raIface, so DelegatedPrefixesForRA surfaces
// them. Calling it with distinct sourceIface values but the same raIface models
// several PD sources feeding one RA interface — the cross-source iteration order
// is then map-nondeterministic, exactly the #6036 hash-flap input. Test-only;
// not for production callers.
func (m *Manager) SeedDelegatedPrefixesForRATesting(sourceIface, raIface string, pds []DelegatedPrefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delegatedPDs[sourceIface] = append(m.delegatedPDs[sourceIface], pds...)
	opts := m.v6opts[sourceIface]
	if opts == nil {
		opts = &DHCPv6Options{}
		m.v6opts[sourceIface] = opts
	}
	opts.RAIface = raIface
}

// RunningClientHandlesForTesting returns an opaque handle per running
// client keyed "iface/4" or "iface/6". Handles compare equal across
// calls iff the same client goroutine is still registered — tests use
// this to assert a reconcile did (or did not) restart a client.
func (m *Manager) RunningClientHandlesForTesting() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]any, len(m.clients))
	for k, dc := range m.clients {
		out[fmt.Sprintf("%s/%d", k.iface, k.family)] = dc
	}
	return out
}

// HasOptionStateForTesting reports desired-set membership for a client
// key (the option-state map entry Reconcile installs for desired
// clients and deletes for removed ones). Tests use it to observe the
// Renew-vs-Reconcile removal window deterministically.
func (m *Manager) HasOptionStateForTesting(ifaceName string, af AddressFamily) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if af == AFInet {
		_, ok := m.v4opts[ifaceName]
		return ok
	}
	_, ok := m.v6opts[ifaceName]
	return ok
}
