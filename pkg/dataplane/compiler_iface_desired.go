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
	// unit MTU belongs to its VLAN sub-interface, not to the parent. When no
	// configured value exists and this netdev is not owned by another
	// component, mtu is the explicit Linux default (#9985), so deleting a
	// statement converges the live device instead of yielding.
	mtu int
	// skipAddrs suppresses address reconciliation when any unit on the netdev
	// is DHCP-managed, or the interface is a RETH member or fabric parent.
	// Conservative on purpose: those addresses are owned by the DHCP client,
	// VRRP, or the IPVLAN overlay, and a union that included them would let
	// this path fight the real owner.
	skipAddrs bool
}

const defaultPhysicalMTU9985 = 1500

// mtuOwnedNetdevs returns resolved Linux netdev names whose MTU is reconciled
// by another component. Ownership is collected once, before any reference is
// planned, so a tagged and an untagged reference cannot disagree about the
// same device (#9985).
//
// Fabric ownership is already keyed by the resolved Linux name
// (#9927). Tunnel ownership uses the same key: the compiler-assigned tunnel
// device names are the routing owner's actual netdevs, so every configured
// interface/unit tunnel is collected even when it is not itself zoned. Only a
// tunnel that passes config.TunnelHasUsableEndpoints (the routing owner's
// admission predicate) is an owner. An unusable tunnel stays planner-owned,
// rather than yielding to a device no component will create.
func mtuOwnedNetdevs(cfg *config.Config) map[string]bool {
	if cfg == nil {
		return map[string]bool{}
	}
	owned := fabricOwnedNetdevs(cfg)
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil {
			continue
		}
		if tunnel := ifCfg.Tunnel; tunnel != nil &&
			tunnel.Name != "" && config.TunnelHasUsableEndpoints(tunnel) {
			owned[config.LinuxIfName(tunnel.Name)] = true
		}
		for _, unit := range ifCfg.Units {
			if unit == nil || unit.Tunnel == nil ||
				unit.Tunnel.Name == "" ||
				!config.TunnelHasUsableEndpoints(unit.Tunnel) {
				continue
			}
			owned[config.LinuxIfName(unit.Tunnel.Name)] = true
		}
	}
	return owned
}

// fabricOwnedNetdevs returns the resolved Linux netdev names whose MTU is
// managed by fabric setup rather than by the zone-interface reconciler.
//
// A local fabric interface owns its resolved physical member: the daemon
// creates the IPVLAN on that member and sets the parent MTU. A fabric bond
// owns the bond netdev itself, but routing/bond.go passes the authored name
// directly to netlink. Therefore a bond name is included only when it is
// already a valid Linux spelling; a slash-bearing authored name resolves to a
// different Linux key and cannot be the device that bond setup creates.
func fabricOwnedNetdevs(cfg *config.Config) map[string]bool {
	owned := make(map[string]bool)
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil {
			continue
		}
		if ifCfg.LocalFabricMember != "" {
			owned[config.LinuxIfName(ifCfg.LocalFabricMember)] = true
		}
		if len(ifCfg.FabricMembers) > 0 &&
			len(ifCfg.Name) <= 15 &&
			ifCfg.Name != "" && ifCfg.Name == config.LinuxIfName(ifCfg.Name) {
			owned[config.LinuxIfName(ifCfg.Name)] = true
		}
	}
	return owned
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
	mtuOwned := mtuOwnedNetdevs(cfg)
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
				// plan nothing when their resolved netdev is fabric-owned or a
				// per-unit tunnel owns the child device. Fabric ownership is
				// decided once for the resolved netdev before this zone walk,
				// so direct references to a local fabric member cannot contest
				// the fabric interface's MTU. A canonical bond name is included
				// as an owner; a slash-bearing authored bond name is not, because
				// bond.go passes that raw name to netlink and cannot create it.
				if ifCfg := cfg.Interfaces.Interfaces[cfgName]; ifCfg != nil && !mtuOwned[physName] {
					// A tunnel owner is included in the pre-pass above, so
					// every reference to its resolved netdev yields here.
					pd := planFor(physName)
					if mtuUnit[physName] == -2 {
						pd.mtu = ifCfg.MTU
						if pd.mtu <= 0 {
							pd.mtu = defaultPhysicalMTU9985
						}
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
			if ifCfg.MTU > 0 && !mtuOwned[physName] && mtuUnit[physName] == -2 {
				pd.mtu = ifCfg.MTU
				mtuUnit[physName] = -1
			}
			if !mtuOwned[physName] && mtuUnit[physName] == -2 {
				// Materialise absence so deleting an interface-level mtu
				// converges the physical netdev to Linux's default.
				pd.mtu = defaultPhysicalMTU9985
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
			if unit.MTU > 0 && !mtuOwned[physName] {
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
