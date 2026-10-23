package cli

import (
	"net"

	"github.com/psaab/xpf/pkg/config"
)

// sessionIfaceKey identifies a session row's interface identity: an
// ifindex (unit's own device or parent/bind device) plus the wire VID
// the row carries. It is config.SessionIfaceKey under the name this
// package has always used; the derivation lives in pkg/config (#16065)
// so the CLI, gRPC, REST and daemon tables cannot drift.
type sessionIfaceKey = config.SessionIfaceKey

func buildSessionEgressIfaces(cfg *config.Config) map[sessionIfaceKey]string {
	return buildSessionTableWithLookup(cfg, func(name string) (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return iface.Index, nil
	}).Names
}

// buildSessionTableWithLookup builds the full session table through
// config.SessionIfaceTableFor (#16065): each unit registers both
// {parent/bind ifindex, VID} (the ingress stamp) and {own-device
// ifindex, VID} (child/tunnel egress), and a key two different units
// share (wg0.0/wg0.1 on the one TUN, both VID 0) is REFUSED — absent
// from Names and present in Ambiguous, so a filter matching that
// identity does not broaden to the zone. The lookup receives KERNEL
// device names ("wg0", "gr-0-0-0u1", "ge-0-0-3.50", "ge-0-0-3").
func buildSessionTableWithLookup(cfg *config.Config, lookupIfindex func(string) (int, error)) config.SessionIfaceTable {
	return config.SessionIfaceTableFor(cfg, lookupIfindex)
}

// buildSessionEgressIfacesWithLookup is the Names-only view kept for
// display-only callers and existing tests.
func buildSessionEgressIfacesWithLookup(cfg *config.Config, lookupIfindex func(string) (int, error)) map[sessionIfaceKey]string {
	return buildSessionTableWithLookup(cfg, lookupIfindex).Names
}
