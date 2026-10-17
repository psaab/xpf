package config

import (
	"fmt"
	"sort"
)

// vrrpVIPClaim is one election's claim on a canonical VIP: either an explicit
// vrrp-group or a RETH-derived instance.
type vrrpVIPClaim struct {
	label string // operator-facing identity, e.g. "vrrp-group 1"
	vrid  int    // election identity (GroupID that will be advertised)
	scope string // config location, e.g. "interfaces ge-0/0/0 unit 0"
}

// validateVRRPVIPCrossGroupStrict hard-rejects, at commit / commit-check, a
// canonical VIP claimed by two DISTINCT VRRP elections on the same resolved
// kernel interface (#14407).
//
// Each vrrp-group (and each RETH-derived instance) is an independent election:
// the manager keys instances by (interface, VRID, family), never by VIP, and
// each master independently installs its VIPs. Two groups on one unit carrying
// the same VIP therefore normally elect the same winner — until per-group,
// per-node track state diverges. If node A's tracked interface for group 1 is
// down while node B's tracked interface for group 2 is down, group 1's
// effective priority is low on A / high on B while group 2's is the reverse:
// both nodes becomeMaster for the same VIP, both install it, and both emit
// GARP/NA — dual-master duplicate-IP with ARP flapping and split traffic.
// The same applies to an explicit group whose VIP equals a RETH unit address:
// the RETH-derived instance (VRID 100+RG) elects by cluster priority while the
// explicit group elects by config priority, so the winners can differ.
//
// Scope is the same L2 domain: the resolved kernel interface (so different
// units/VLANs and different interfaces stay legal) plus the VIP's address
// family. Canonicalization reuses vrrpVIPHostIP so `10.0.0.100` and
// `10.0.0.100/24` collide. Claims with the SAME VRID on one interface+family
// are not two independent elections and are not rejected here — the manager's
// duplicate-identity / election-domain guards own that shape.
//
// RETH-derived claims are included only when RETH VRRP synthesis is active,
// mirroring CollectRethInstances' early return (no-reth-vrrp /
// private-rg-election synthesize nothing). A VLAN-tagged RETH builds one
// instance per unit on its own sub-interface; an untagged RETH builds one
// instance on the base interface carrying every unit's addresses.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientVRRPVIPCrossGroup) so an already-persisted or
// peer-synced config still boots (#1960 no-brick); the pkg/vrrp runtime
// backstop in UpdateInstances refuses the second claimant, so a
// leniently-loaded duplicate cannot seat two masters for one VIP.
func validateVRRPVIPCrossGroupStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}

	rethVRRPActive := true
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		rethVRRPActive = false
	}
	var rgOwners map[string]int
	var rethToPhys map[string]string
	if rethVRRPActive {
		rgOwners = cfg.RethRGOwners()
		rethToPhys = cfg.RethToPhysical()
	}

	type claimKey struct {
		iface  string
		family string
		host   string
	}
	claims := make(map[claimKey]vrrpVIPClaim)

	addClaim := func(key claimKey, vip string, claim vrrpVIPClaim) error {
		prev, exists := claims[key]
		if !exists {
			claims[key] = claim
			return nil
		}
		if prev.vrid == claim.vrid {
			return nil
		}
		return fmt.Errorf(
			"virtual-address %s on %s is claimed by both %s (VRID %d) and %s (VRID %d) "+
				"on interface %s: each group is an independent VRRP election, so "+
				"divergent track-interface state can elect a different master for "+
				"each group on different nodes and both nodes would install and "+
				"advertise the same virtual address (dual-master duplicate-IP) — "+
				"give each group a distinct virtual-address, or merge the groups",
			vip, claim.scope, prev.label, prev.vrid, claim.label, claim.vrid, key.iface)
	}
	addVIPs := func(iface string, claim vrrpVIPClaim, vips []string) error {
		seen := make(map[claimKey]struct{}, len(vips))
		for _, vip := range vips {
			ip := vrrpVIPHostIP(vip)
			if ip == nil {
				continue
			}
			family := "inet6"
			if ip.To4() != nil {
				family = "inet"
			}
			key := claimKey{iface: iface, family: family, host: ip.String()}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			if err := addClaim(key, vip, claim); err != nil {
				return err
			}
		}
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

		// Explicit vrrp-groups: one election per group, resolved to the
		// kernel device CollectInstances will use.
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			kernelIf := cfg.ResolveKernelIfName(fmt.Sprintf("%s.%d", ifName, un))
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
				claim := vrrpVIPClaim{
					label: fmt.Sprintf("vrrp-group %d", vg.ID),
					vrid:  vg.ID,
					scope: fmt.Sprintf("interfaces %s unit %d", ifName, un),
				}
				if err := addVIPs(kernelIf, claim, vg.VirtualAddresses); err != nil {
					return err
				}
			}
		}

		// RETH-derived instances: unit addresses become the VIP set.
		if !rethVRRPActive {
			continue
		}
		rgID, owns := rgOwners[ifName]
		if !owns || rgID <= 0 {
			continue
		}
		vrid := RethVRRPGroupIDBase + rgID
		if ifc.VlanTagging {
			for _, un := range unitNums {
				unit := ifc.Units[un]
				if unit == nil || len(unit.Addresses) == 0 {
					continue
				}
				claim := vrrpVIPClaim{
					label: fmt.Sprintf("reth redundancy-group %d VRRP", rgID),
					vrid:  vrid,
					scope: fmt.Sprintf("interfaces %s unit %d", ifName, un),
				}
				kernelIf := rethKernelIface(rethToPhys, ifName, unit)
				if err := addVIPs(kernelIf, claim, unit.Addresses); err != nil {
					return err
				}
			}
			continue
		}
		var all []string
		for _, un := range unitNums {
			if unit := ifc.Units[un]; unit != nil {
				all = append(all, unit.Addresses...)
			}
		}
		if len(all) == 0 {
			continue
		}
		claim := vrrpVIPClaim{
			label: fmt.Sprintf("reth redundancy-group %d VRRP", rgID),
			vrid:  vrid,
			scope: fmt.Sprintf("interfaces %s", ifName),
		}
		kernelIf := rethKernelIface(rethToPhys, ifName, nil)
		if err := addVIPs(kernelIf, claim, all); err != nil {
			return err
		}
	}
	return nil
}

// rethKernelIface resolves the kernel device a RETH-derived instance binds,
// mirroring CollectRethInstances: the local physical member (or the authored
// name when no member map entry exists), with the VLAN sub-interface suffix
// for a tagged unit.
func rethKernelIface(rethToPhys map[string]string, ifName string, unit *InterfaceUnit) string {
	physName := ifName
	if phys, ok := rethToPhys[ifName]; ok {
		physName = phys
	}
	linuxName := LinuxIfName(physName)
	if unit != nil && unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
	}
	return linuxName
}
