package dataplane

// Per-netdev desired-state planning for the zone interface reconcile
// (#8119/#8120).
//
// Split out of compiler_iface.go, which the merge would otherwise have pushed
// past the 2000 LOC [REFACTOR] floor. The seam is a real one rather than a
// convenient cut: everything here is a PURE function of the config, with no
// netlink and no CompileResult, which is exactly the "split pure planning from
// actuation" shape #4960 asks for and is what lets the decision be tested
// without root.

import (
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// physDesired is the merged desired state for ONE physical netdev: what the
// whole config wants it to look like, decided once.
//
// #8119/#8120: before this, the same netdev was reconciled once per zone
// interface reference that resolved to it, each time against THAT reference's
// own desired state, and the last writer won. Two units of one interface with
// no VLAN ID both resolve to the same untagged netdev — a shape strict
// validation deliberately accepts — so an apply deleted addresses it had just
// added, in an order Go randomises per run; and the interface-level and
// unit-level MTU writes compared against one cached netlink.Link that
// LinkSetMTU does not refresh, so they took turns on alternate applies. Both
// surfaced the same way to an operator: state that alternates on every commit.
type physDesired struct {
	// addrs is the UNION of every untagged unit's addresses. Each unit's set
	// alone was the old per-unit desired state, and reconciling to it deleted
	// the other unit's — the union is the only set that is stable under a
	// second apply AND keeps both units' addresses.
	addrs []string
	// mtu is the single value to write. A unit-level MTU overrides the
	// interface-level one, which is the pre-existing rule; when several units
	// name an MTU the LOWEST unit number wins. That tie-break is arbitrary but
	// it is DECIDED — the old behaviour was decided by map iteration order,
	// which is not the same thing as unspecified, it is different per run.
	// A TAGGED unit contributes only the interface-level value (#9761): its own
	// unit MTU belongs to its VLAN sub-interface, not to the parent.
	mtu int
	// skipAddrs suppresses address reconciliation when any unit on the netdev
	// is DHCP-managed, or the interface is a RETH member or fabric parent.
	// Conservative on purpose: those addresses are owned by the DHCP client,
	// VRRP, or the IPVLAN overlay, and a union that included them would let
	// this path fight the real owner.
	skipAddrs bool
}

// planPhysDesired merges every zone interface reference into one desired state
// per physical netdev.
//
// PURE: config in, plan out, no netlink. That is what makes the decision
// testable without root, and it is the half of #4960's "split pure planning
// from actuation" that this path was missing — the actuation below now has no
// decision left to make.
//
// Zones are walked in sorted order. Not because callers depend on it, but so
// that a plan is a function of the config alone: with a raw map range, a tie
// between two units would resolve differently per run and the bug would come
// back wearing a different shape.
func planPhysDesired(cfg *config.Config) map[string]*physDesired {
	out := map[string]*physDesired{}
	if cfg == nil {
		return out
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)

	// unit number that supplied the current mtu, per phys; -1 = interface level.
	mtuUnit := map[string]int{}
	seenAddr := map[string]map[string]bool{}
	planFor := func(physName string) *physDesired {
		pd := out[physName]
		if pd == nil {
			pd = &physDesired{}
			out[physName] = pd
			mtuUnit[physName] = -2 // nothing decided yet
			seenAddr[physName] = map[string]bool{}
		}
		return pd
	}

	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, ifaceRef := range zone.Interfaces {
			physName, cfgName, unitNum, vlanID := resolveInterfaceRef(ifaceRef, cfg)
			if physName == "" {
				continue
			}
			if vlanID != 0 {
				// A tagged unit actuates its own sub-interface: its addresses,
				// DHCP and unit MTU belong to that child, not to the parent. The
				// parent still takes the interface-level mtu (#9761). This branch
				// used to skip the whole reference, so a vlan-tagging interface
				// whose zone references were all tagged got no plan, and its
				// interface-level mtu was never written. Two tagged references
				// plan nothing, as on master, because another component owns the
				// MTU of the device they resolve to (resolveInterfaceRef): a fabric
				// interface resolves to the local fabric member, whose MTU the
				// fabric setup owns, and a per-unit tunnel resolves to its tunnel
				// device, whose MTU the tunnel manager owns, even when a WireGuard
				// unit shares the interface's own device (#6941).
				if ifCfg := cfg.Interfaces.Interfaces[cfgName]; ifCfg != nil && ifCfg.MTU > 0 && ifCfg.LocalFabricMember == "" {
					if unit := ifCfg.Units[unitNum]; unit != nil && unit.Tunnel != nil {
						continue
					}
					pd := planFor(physName)
					if mtuUnit[physName] == -2 {
						pd.mtu = ifCfg.MTU
						mtuUnit[physName] = -1
					}
				}
				continue
			}
			pd := planFor(physName)
			ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]
			if !ok || ifCfg == nil {
				continue
			}
			if ifCfg.RedundancyGroup > 0 || ifCfg.LocalFabricMember != "" {
				pd.skipAddrs = true
			}
			if ifCfg.MTU > 0 && mtuUnit[physName] == -2 {
				pd.mtu = ifCfg.MTU
				mtuUnit[physName] = -1
			}
			unit, ok := ifCfg.Units[unitNum]
			if !ok || unit == nil {
				continue
			}
			if unit.DHCP || unit.DHCPv6 {
				pd.skipAddrs = true
			}
			for _, a := range unit.Addresses {
				if seenAddr[physName][a] {
					continue
				}
				seenAddr[physName][a] = true
				pd.addrs = append(pd.addrs, a)
			}
			if unit.MTU > 0 {
				// Unit overrides interface level; lowest unit number wins
				// between units.
				if cur := mtuUnit[physName]; cur < 0 || unitNum < cur {
					pd.mtu = unit.MTU
					mtuUnit[physName] = unitNum
				}
			}
		}
	}
	return out
}
