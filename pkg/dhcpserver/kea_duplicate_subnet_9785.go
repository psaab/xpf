package dhcpserver

import (
	"fmt"
	"net/netip"

	"github.com/psaab/xpf/pkg/config"
)

// claimPoolSubnet records a pool's subnet as rendered and reports the pool it
// duplicates when an earlier pool already claimed the same prefix (#9785).
//
// Kea refuses a second subnet4/subnet6 entry for a prefix it already holds and
// then loads nothing, so one duplicate stops DHCP for every pool on the node.
// Commit refuses the duplicate (validateDHCPPoolSubnetsUniqueStrict in
// pkg/config); this is the belt for a config that reached the renderer anyway,
// through the tolerant load or peer-sync path. The generators walk groups and
// pools in their stable order, so the first pool in that order is kept,
// identically on every reload, and every later one is skipped. The caller
// skips BEFORE resolveSubnetID, so a skipped pool consumes no subnet id and
// the ids of the pools that render are the ones they would get without it.
//
// The key is the masked prefix, the same key the commit gate uses. A subnet
// that does not parse is not claimed; Kea reports it itself.
func claimPoolSubnet(seen map[netip.Prefix]string, group string, pool *config.DHCPPool) (string, bool) {
	p, err := netip.ParsePrefix(pool.Subnet)
	if err != nil {
		return "", false
	}
	if prev, dup := seen[p.Masked()]; dup {
		return prev, true
	}
	seen[p.Masked()] = fmt.Sprintf("group %s pool %s", group, pool.Name)
	return "", false
}
