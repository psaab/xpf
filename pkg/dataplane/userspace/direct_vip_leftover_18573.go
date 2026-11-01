package userspace

import (
	"log/slog"
	"net/netip"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vipstamp"
)

// #18573: never publish a direct-mode VIP leftover.
//
// The interface rows' live addresses come from the kernel listing
// (buildLinkSnapshot), merged with the configured ones. A RETH address a
// commit renumbered away stays on the kernel until the direct-VIP reconcile
// deletes it, and the commit's snapshot is built before that reconcile runs.
// Pre-#18573 the reconcile never deleted it at all. Either way the row
// published BOTH addresses, sorted by string, and the helper's order-based
// interface-SNAT pick (pick_interface_v4: the designated primary, else the
// first non-link-local in row order) chose whichever sorted first — measured
// on udp: .11 before .43, so every new LAN flow was SNATed to the deleted
// address and blackholed.
//
// The filter drops, from the LIVE listing only, every address vipstamp
// reports as a leftover (stamped by xpf's direct-VIP path, and the config
// assigns no such address to that netdev — config.AddressIdentitiesByNetdev).
// The configured merge runs after it, so a configured address is never
// dropped; an unstamped address (DHCP lease, kernel link-local, standalone
// VRRP VIP, anything xpf cannot prove it installed) is never dropped. The
// interface-address set the helper SNATs from is therefore the configured
// ownership plus foreign addresses, never an xpf leftover.

// directVIPStampDumpFn is the seam over the ownership dump.
var directVIPStampDumpFn = vipstamp.Dump

// directVIPLeftovers is one snapshot build's view of the stamped addresses.
// A nil receiver (dump failed, or nothing stamped) filters nothing: the build
// degrades to the pre-#18573 listing, never to a smaller one.
type directVIPLeftovers struct {
	stampedByIndex map[int][]vipstamp.Row
	configured     map[string]map[string]bool
}

// sampleDirectVIPLeftovers takes the one dump a snapshot build uses.
func sampleDirectVIPLeftovers(cfg *config.Config) *directVIPLeftovers {
	rows, err := directVIPStampDumpFn()
	if err != nil {
		slog.Debug("userspace: direct-VIP ownership dump failed; snapshot keeps the unfiltered kernel listing",
			"err", err)
		return nil
	}
	var byIndex map[int][]vipstamp.Row
	for _, row := range rows {
		if !row.Stamped() {
			continue
		}
		if byIndex == nil {
			byIndex = make(map[int][]vipstamp.Row)
		}
		byIndex[row.LinkIndex] = append(byIndex[row.LinkIndex], row)
	}
	if byIndex == nil {
		return nil
	}
	return &directVIPLeftovers{stampedByIndex: byIndex, configured: cfg.AddressIdentitiesByNetdev()}
}

// filterLive removes the leftovers on (ifindex, linuxName) from a LIVE
// address listing. It returns live unchanged when nothing is dropped.
func (l *directVIPLeftovers) filterLive(ifindex int, linuxName string, live []InterfaceAddressSnapshot) []InterfaceAddressSnapshot {
	if l == nil || ifindex <= 0 || len(live) == 0 {
		return live
	}
	var drop map[string]bool
	for _, row := range l.stampedByIndex[ifindex] {
		if vipstamp.Leftover(row, linuxName, l.configured) {
			if drop == nil {
				drop = make(map[string]bool)
			}
			drop[row.Identity()] = true
		}
	}
	if drop == nil {
		return live
	}
	out := make([]InterfaceAddressSnapshot, 0, len(live))
	for _, addr := range live {
		if p, err := netip.ParsePrefix(addr.Address); err == nil {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
			if drop[config.PrefixIdentity(p)] {
				continue
			}
		}
		out = append(out, addr)
	}
	return out
}
