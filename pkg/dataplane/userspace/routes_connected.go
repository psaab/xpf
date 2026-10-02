package userspace

import (
	"slices"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

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
