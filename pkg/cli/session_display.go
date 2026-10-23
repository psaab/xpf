package cli

import (
	"net"

	"github.com/psaab/xpf/pkg/config"
)

// sessionIfaceKey identifies a session row's interface identity: the
// kernel ifindex of the unit's OWN device plus the wire VID the row
// carries. It is config.SessionIfaceKey under the name this package
// has always used; the derivation lives in pkg/config (#16065) so the
// CLI, gRPC, REST and daemon tables cannot drift.
type sessionIfaceKey = config.SessionIfaceKey

func buildSessionEgressIfaces(cfg *config.Config) map[sessionIfaceKey]string {
	return buildSessionEgressIfacesWithLookup(cfg, func(name string) (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return iface.Index, nil
	})
}

// buildSessionEgressIfacesWithLookup builds the {ifindex, VID} ->
// Junos unit-name table through config.SessionIfaceNames (#16065):
// each unit keys on its OWN kernel device (per-unit tunnel devices,
// VLAN children, the shared WireGuard TUN) instead of the parent
// netdev, and a key two different units share (wg0.0/wg0.1 on the one
// TUN, both VID 0) is refused rather than naming one sibling for
// both. The lookup receives KERNEL device names ("wg0",
// "gr-0-0-0u1", "ge-0-0-3.50").
func buildSessionEgressIfacesWithLookup(cfg *config.Config, lookupIfindex func(string) (int, error)) map[sessionIfaceKey]string {
	return config.SessionIfaceNames(cfg, lookupIfindex)
}
