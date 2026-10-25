package config

import (
	"fmt"
	"sort"
)

// validateVRRPVIPOwnerStrict hard-rejects, at commit / commit-check, an
// explicit `vrrp-group` whose virtual-address equals an address configured
// on the SAME unit (#16764, R3-A25-01).
//
// RFC 5798 §1.6 defines that shape as the IP address owner (priority 255,
// §5.2.4) and §6.4.1 requires it to advertise immediately as MASTER from
// its real interface address. pkg/vrrp does not implement owner addressing:
// its advert source is the lowest NON-VIP address on the interface
// (resolveLocalIPv4 excludes every VIP), and every VIP is AddrDel'd on
// BACKUP, at run start, and on shutdown (removeVIPsLocked). For an owner
// whose only address IS the VIP that yields a MASTER that sends zero IPv4
// advertisements (peers time it out and also claim MASTER — duplicate
// gateway) and that deletes its own unit address at every start and stop.
//
// REJECT-ONLY, deliberately — the bounded option the issue offers. The
// alternative (owner semantics in pkg/vrrp: VIP as advert source, never
// AddrDel an owned address, straight to MASTER per §6.4.1) is a runtime
// state-machine change touching source selection, the #7334 self-frame
// set, VIP actuation and the election; a commit-time rejection fails
// loudly on a config the operator is actively editing and cannot produce
// the silent non-advertising MASTER. Owner semantics can be implemented
// later by deleting this gate; nothing here forecloses it.
//
// Scope: explicit `vrrp-group` blocks ONLY, compared against the addresses
// of their own unit (unit.Addresses — every family on the unit, not just
// the group's nesting address, matching the issue's "any address of its
// own unit"). RETH-derived instances are not checked: their VIPs ARE the
// unit addresses by construction (CollectRethInstances), they never carry
// priority 255, and rejecting them would reject every RETH config. Two
// distinct elections claiming one VIP is #14407's gate, not this one; a
// VIP merely contained in a unit subnet stays legal (#3013).
//
// The comparison is by parsed host IP (vrrpVIPHostIP), so `10.0.1.1` and
// `10.0.1.1/24` collide and prefix-length differences do not hide an
// owner. An unparseable VIP or unit address is skipped — the schema /
// prefix gates own those literals.
//
// On the tolerant load / peer-sync paths the call site downgrades this to
// a warning (opts.lenientVRRPVIPOwner) so an already-persisted or
// peer-synced config an older binary accepted still BOOTS (#1960
// no-brick); it keeps today's runtime behaviour until corrected, which is
// the point of the tolerant path.
func validateVRRPVIPOwnerStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, ifName := range names {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 || len(unit.Addresses) == 0 {
				continue
			}
			owned := make(map[string]string, len(unit.Addresses))
			for _, a := range unit.Addresses {
				if ip := vrrpVIPHostIP(a); ip != nil {
					owned[ip.String()] = a
				}
			}
			if len(owned) == 0 {
				continue
			}
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					ip := vrrpVIPHostIP(vip)
					if ip == nil {
						continue
					}
					unitAddr, isOwner := owned[ip.String()]
					if !isOwner {
						continue
					}
					return fmt.Errorf(
						"interfaces %s unit %d vrrp-group %d virtual-address %s: "+
							"equals address %s configured on the same unit — this is the "+
							"RFC 5798 IP address owner shape, which xpf does not implement: "+
							"the advert source excludes virtual addresses and every virtual "+
							"address is removed on BACKUP and shutdown, so the group would "+
							"advertise nothing while reporting MASTER and would delete the "+
							"unit's own address at every start and stop — use a distinct "+
							"virtual-address, or remove the group",
						ifName, un, vg.ID, vip, unitAddr)
				}
			}
		}
	}
	return nil
}
