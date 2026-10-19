package userspace

import (
	"slices"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// markConnectedRGPeerOwned returns a copy of interfaces with
// ConnectedRGPeerOwned set on each peer-owned RG>0 row (#15742). Consistent
// predicate with connectedRowPeerOwned so Go connected RouteSnapshot rows
// and Rust connected_v4/v6 rows cannot diverge. Clustered + nil provider
// fails closed (peer-owned). The copy prevents route-building from mutating
// a snapshot's retained interface rows.
func markConnectedRGPeerOwned(cfg *config.Config, interfaces []InterfaceSnapshot, provider RGPrimaryProvider) []InterfaceSnapshot {
	if len(interfaces) == 0 {
		return interfaces
	}
	marked := make([]InterfaceSnapshot, len(interfaces))
	copy(marked, interfaces)
	for i := range marked {
		marked[i].ConnectedRGPeerOwned = connectedRowPeerOwned(cfg, marked[i], provider)
	}
	return marked
}

func connectedPrefixesForInterface(iface InterfaceSnapshot) ([]string, []string) {
	if iface.AdminDisabled {
		return nil, nil
	}
	var v4 []string
	var v6 []string
	for _, addr := range iface.Addresses {
		if addr.Scope != 0 && addr.Scope != int(netlink.SCOPE_UNIVERSE) {
			continue
		}
		// Mask-to-network + skip-host + skip-link-local is factored into
		// config.ConnectedNetworkPrefix so the rib-group per-prefix leak
		// (pkg/routing, #3876) derives the identical connected-prefix set
		// from the config addresses and the ip rules it installs match the
		// connected routes this FIB carries in the source table.
		prefix, family, ok := config.ConnectedNetworkPrefix(addr.Address)
		if !ok {
			continue
		}
		switch family {
		case "inet":
			v4 = append(v4, prefix)
		case "inet6":
			v6 = append(v6, prefix)
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	return slices.Compact(v4), slices.Compact(v6)
}
