package config

import (
	"fmt"
	"sort"
	"strings"
)

// vrrpInstanceFamily derives the CollectInstances family for one explicit
// group. parseVRRPGroups keys each group "<address-CIDR>_grp<id>", so the
// address the group hangs off (the key prefix) is authoritative, mirroring
// pkg/vrrp vrrpGroupFamily without the reverse import. Hand-built Config
// values may not carry that key shape, so the first parseable VIP is the
// compatibility fallback. Defaults to "inet" only when neither parses.
func vrrpInstanceFamily(vips []string, groupKey string) string {
	if i := strings.LastIndex(groupKey, "_grp"); i > 0 {
		if fam := vrrpFamilyOfAddrs([]string{groupKey[:i]}); fam != "" {
			return fam
		}
	}
	if fam := vrrpFamilyOfAddrs(vips); fam != "" {
		return fam
	}
	return "inet"
}

func vrrpFamilyOfAddrs(addrs []string) string {
	for _, a := range addrs {
		ip := vrrpVIPHostIP(a)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return "inet"
		}
		return "inet6"
	}
	return ""
}

// validateVRRPInstanceIdentityStrict hard-rejects, at commit / commit-check,
// a duplicate (kernelInterface, VRID, family) VRRP instance identity or an
// overlapping empty-family RETH election domain (#15688).
//
// CollectInstances emits one instance per explicit vrrp-group keyed by the
// parent address ("<address>_grp<id>"), so the same VRID authored under two
// addresses of one unit+family — or under two units that resolve to the same
// kernel device — yields two instances with the identical manager identity
// (kernelIf, VRID, family). CollectRethInstances emits one empty-family
// instance per RETH at VRID 100+rgID; an explicit group with that VRID on the
// same kernel device overlaps both wire families. vrrp.Manager.UpdateInstances
// previously returned a whole-batch error for either shape, aborting every
// instance on the node on each reconcile. This gate rejects the config at
// commit so the operator sees the collision; the tolerant path downgrades to
// a warning (opts.lenientVRRPInstanceIdentity) and UpdateInstances now skips
// only the offending duplicate/overlap (#1960 no-brick).
//
// Scope mirrors the collectors exactly: explicit groups resolve via
// ResolveKernelIfName (same as CollectInstances); RETH instances are included
// only when RETH VRRP synthesis is active (no-reth-vrrp / private-rg-election
// synthesize nothing), resolve via rethKernelIface (tagged = per-unit
// sub-interface, untagged = one base instance), and use the shared
// RethRGOwners predicate. Distinct families on one (kernelIf, VRID) — a
// dual-stack group — stay legal, as do distinct kernel devices.
func validateVRRPInstanceIdentityStrict(cfg *Config) error {
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

	type identity struct {
		label string
		scope string
	}
	seen := make(map[struct {
		iface  string
		vrid   int
		family string
	}]identity)
	// domains tracks families present per (iface, vrid) so an empty-family
	// RETH instance overlapping a family-tagged one is reported, mirroring
	// pkg/vrrp electionDomains.
	domains := make(map[struct {
		iface string
		vrid  int
	}]map[string]identity)

	add := func(iface string, vrid int, family string, id identity) error {
		key := struct {
			iface  string
			vrid   int
			family string
		}{iface, vrid, family}
		if prev, exists := seen[key]; exists {
			return fmt.Errorf(
				"duplicate VRRP instance identity interface=%q VRID=%d family=%q: "+
					"%s (%s) and %s (%s) resolve to the same VRRP instance; "+
					"vrrp.Manager.UpdateInstances would refuse the duplicate and "+
					"abort reconciliation for the entire node — renumber one "+
					"vrrp-group or remove the duplicate group",
				iface, vrid, family, prev.label, prev.scope, id.label, id.scope)
		}
		ek := struct {
			iface string
			vrid  int
		}{iface, vrid}
		fams := domains[ek]
		if fams == nil {
			fams = make(map[string]identity)
			domains[ek] = fams
		}
		if family == "" {
			for _, other := range []string{"inet", "inet6"} {
				if prev, exists := fams[other]; exists {
					return fmt.Errorf(
						"overlapping VRRP election domains interface=%q VRID=%d families=%q,%q: "+
							"%s (%s) and %s (%s) share one wire VRID; the empty-family RETH "+
							"instance overlaps both wire families and UpdateInstances would "+
							"abort reconciliation for the entire node — renumber the "+
							"vrrp-group away from VRID %d (100+redundancy-group) or move it "+
							"to a different interface",
						iface, vrid, "", other, prev.label, prev.scope, id.label, id.scope, vrid)
				}
			}
		} else if prev, exists := fams[""]; exists {
			return fmt.Errorf(
				"overlapping VRRP election domains interface=%q VRID=%d families=%q,%q: "+
					"%s (%s) and %s (%s) share one wire VRID; the empty-family RETH "+
					"instance overlaps both wire families and UpdateInstances would "+
					"abort reconciliation for the entire node — renumber the "+
					"vrrp-group away from VRID %d (100+redundancy-group) or move it "+
					"to a different interface",
				iface, vrid, "", family, prev.label, prev.scope, id.label, id.scope, vrid)
		}
		seen[key] = id
		fams[family] = id
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
				id := identity{
					label: fmt.Sprintf("vrrp-group %d", vg.ID),
					scope: fmt.Sprintf("interfaces %s unit %d", ifName, un),
				}
				if err := add(kernelIf, vg.ID, vrrpInstanceFamily(vg.VirtualAddresses, gk), id); err != nil {
					return err
				}
			}
		}

		if !rethVRRPActive {
			continue
		}
		rgID, owns := rgOwners[ifName]
		if !owns || rgID <= 0 {
			continue
		}
		vrid := RethVRRPGroupIDBase + rgID
		// Mirror CollectRethInstances: an out-of-range RETH VRID is skipped
		// there (and gated by validateRethVRRPGroupIDStrict), so it emits
		// no instance to collide.
		if vrid < 1 || vrid > MaxVRRPGroupID {
			continue
		}
		if ifc.TaggingEnabled() {
			for _, un := range unitNums {
				unit := ifc.Units[un]
				if unit == nil || len(unit.Addresses) == 0 {
					continue
				}
				id := identity{
					label: fmt.Sprintf("reth redundancy-group %d VRRP", rgID),
					scope: fmt.Sprintf("interfaces %s unit %d", ifName, un),
				}
				if err := add(rethKernelIface(rethToPhys, ifName, unit), vrid, "", id); err != nil {
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
		id := identity{
			label: fmt.Sprintf("reth redundancy-group %d VRRP", rgID),
			scope: fmt.Sprintf("interfaces %s", ifName),
		}
		if err := add(rethKernelIface(rethToPhys, ifName, nil), vrid, "", id); err != nil {
			return err
		}
	}
	return nil
}
