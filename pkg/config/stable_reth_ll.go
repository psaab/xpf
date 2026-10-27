package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// StableRethLinkLocal returns a deterministic link-local IPv6 address shared
// by both cluster nodes for the same RETH redundancy group. Used as the RA
// source address so hosts see a stable IPv6 router identity across failover.
// Format: fe80::bf72:CC:RR (clusterID, rgID — no nodeID component).
// This address sorts lower than EUI-64 link-locals derived from per-node
// RethMAC, so ndp.Listen and resolveIPv6LinkLocal will prefer it.
//
// The sole definition lives here in the leaf package: pkg/cluster
// (StableRethLinkLocal delegates), pkg/daemon and pkg/dataplane/userspace all
// import pkg/config, while userspace cannot import pkg/cluster (cluster
// imports pkg/dataplane). (#17049)
func StableRethLinkLocal(clusterID, rgID int) net.IP {
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0xbf, 0x72, 0, byte(clusterID), 0, byte(rgID)}
}

// IsStableRethLinkLocal returns true if the address matches the stable RETH
// link-local pattern (fe80::bf72:...).
func IsStableRethLinkLocal(ip net.IP) bool {
	ip = ip.To16()
	return len(ip) == 16 &&
		ip[0] == 0xfe && ip[1] == 0x80 &&
		ip[8] == 0 && ip[9] == 0 &&
		ip[10] == 0xbf && ip[11] == 0x72
}

// UnitHasIPv6 reports whether a RETH unit carries IPv6: any IPv6 address, a
// `family inet6` marker, DHCPv6, or a DHCPv6 client. The DHCPv6Client term
// makes a structured `dhcpv6-client` count even before the compiler mirrors
// it into DHCPv6 (#13102) and mirrors the commit-path predicate
// (interfaceUnitHasIPv6_13936). Single definition for the daemon install/NA
// and the userspace host-inbound mirror (#17049; the copies previously
// disagreed on the DHCPv6Client term).
func UnitHasIPv6(unit *InterfaceUnit) bool {
	if unit == nil {
		return false
	}
	if unit.FamilyInet6 || unit.DHCPv6 || unit.DHCPv6Client != nil {
		return true
	}
	for _, addr := range unit.Addresses {
		if strings.Contains(addr, ":") {
			return true
		}
	}
	return false
}

// UnitConfiguredLinkLocal returns the first configured IPv6 link-local
// unicast address (CIDR-stripped) on the unit, or "" when none is configured.
// UnitHasConfiguredLinkLocal is its boolean form. One definition replaces the
// daemon and userspace copies (#17049).
func UnitConfiguredLinkLocal(unit *InterfaceUnit) string {
	if unit == nil {
		return ""
	}
	for _, addr := range unit.Addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() && ip.To4() == nil {
			return ip.String()
		}
	}
	return ""
}

// UnitHasConfiguredLinkLocal reports whether the unit carries an explicitly
// configured link-local IPv6 address (fe80::/10).
func UnitHasConfiguredLinkLocal(unit *InterfaceUnit) bool {
	return UnitConfiguredLinkLocal(unit) != ""
}

// StableLLPlacement is one unit placement of an RG's stable RETH link-local:
// IfRef is the unit-qualified Junos reference (reth0.50), Netdev the kernel
// device carrying the address (selected by unit.VlanID > 0, #16686), Unit the
// logical unit number, and Addr the stable link-local for the RG.
type StableLLPlacement struct {
	IfRef  string
	Netdev string
	Unit   int
	Addr   net.IP
}

// unitNetdev returns the kernel netdev carrying unit's addresses: the VLAN
// sub-interface when the unit is tagged (VlanID > 0), otherwise the bare
// member. This is the RethVIPsForRG/ResolveKernelIfName rule (#16686).
func unitNetdev(linuxMember string, unit *InterfaceUnit) string {
	if unit != nil && unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", linuxMember, unit.VlanID)
	}
	return linuxMember
}

// StableRethLinkLocalPlacements returns every unit of interfaces owned by
// rgID (per RethRGOwners) on which the stable RETH link-local is present
// while the RG is MASTER: IPv6-bearing units without an explicitly
// configured link-local. Disabled interfaces and disabled units are skipped
// (#13149). It is THE single placement definition consumed by the daemon
// install/remove, the router-NA leg, the RA builder and the userspace
// host-inbound mirror (#17049), so the four can no longer diverge.
//
// The result is deterministically ordered (interface name, then unit number)
// and de-duplicated by kernel netdev (two units sharing a vlan-id collapse
// onto one sub-interface). A nil config, a config without a cluster, or an RG
// with no owning interface yields nil. Interfaces disabled at the interface
// level install nothing; the removal path deliberately keeps sweeping them
// (see RemoveNetdevs).
func (c *Config) StableRethLinkLocalPlacements(rgID int) []StableLLPlacement {
	return c.stableRethLinkLocalPlacements(rgID, false)
}

// RouterLinkLocalPlacements is StableRethLinkLocalPlacements plus one entry
// per configured-link-local unit (its Addr is that unit's configured
// link-local, not the stable LL): the set the router-NA leg must announce —
// each unit announces its own configured link-local if present, otherwise the
// stable LL (#15684).
type RouterLLPlacement = StableLLPlacement

// RouterLinkLocalPlacements returns the per-unit router link-locals to
// announce for rgID, in the same deterministic order as
// StableRethLinkLocalPlacements.
func (c *Config) RouterLinkLocalPlacements(rgID int) []StableLLPlacement {
	return c.stableRethLinkLocalPlacements(rgID, true)
}

func (c *Config) stableRethLinkLocalPlacements(rgID int, includeConfigured bool) []StableLLPlacement {
	if c == nil || c.Chassis.Cluster == nil {
		return nil
	}
	owners := c.RethRGOwners()
	ifNames := make([]string, 0, len(owners))
	for ifName, owns := range owners {
		if owns == rgID {
			ifNames = append(ifNames, ifName)
		}
	}
	if len(ifNames) == 0 {
		return nil
	}
	sort.Strings(ifNames)
	stableLL := StableRethLinkLocal(c.Chassis.Cluster.ClusterID, rgID)
	rethToPhys := c.RethToPhysical()
	var out []StableLLPlacement
	for _, ifName := range ifNames {
		ifc, ok := LookupInterface(c, ifName)
		if !ok || ifc.Disable {
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := LinuxIfName(physName)
		unitNums := make([]int, 0, len(ifc.Units))
		RangeUnits(ifc, func(unitNum int, _ *InterfaceUnit) {
			unitNums = append(unitNums, unitNum)
		})
		sort.Ints(unitNums)
		seen := make(map[string]bool, len(unitNums))
		for _, unitNum := range unitNums {
			unit, _ := LookupUnit(ifc, unitNum)
			if unit == nil || unit.Disable || !UnitHasIPv6(unit) {
				continue
			}
			addr := stableLL
			if ll := UnitConfiguredLinkLocal(unit); ll != "" {
				if !includeConfigured {
					continue
				}
				addr = net.ParseIP(ll)
				if addr == nil {
					continue
				}
			}
			netdev := unitNetdev(linuxName, unit)
			if seen[netdev] {
				continue
			}
			seen[netdev] = true
			out = append(out, StableLLPlacement{
				IfRef:  fmt.Sprintf("%s.%d", ifName, unitNum),
				Netdev: netdev,
				Unit:   unitNum,
				Addr:   addr,
			})
		}
	}
	return out
}

// RemoveNetdevs returns every kernel netdev that could carry rgID's stable
// link-local and must be swept on BACKUP/demotion: every unit's
// VlanID-selected netdev plus the bare member (so a stable LL installed by
// pre-#16686 code on the parent of a tagged unit 0 is cleaned up). It has no
// IPv6/configured-link-local predicate — removal must find the address
// wherever an earlier (possibly older-rule) install put it, including on
// interfaces or units since disabled or re-purposed to IPv4. Sorted,
// de-duplicated; nil when no interface owns rgID.
func (c *Config) RemoveNetdevs(rgID int) []string {
	if c == nil || c.Chassis.Cluster == nil {
		return nil
	}
	owners := c.RethRGOwners()
	ifNames := make([]string, 0, len(owners))
	for ifName, owns := range owners {
		if owns == rgID {
			ifNames = append(ifNames, ifName)
		}
	}
	if len(ifNames) == 0 {
		return nil
	}
	sort.Strings(ifNames)
	rethToPhys := c.RethToPhysical()
	var out []string
	for _, ifName := range ifNames {
		ifc, ok := LookupInterface(c, ifName)
		if !ok {
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := LinuxIfName(physName)
		targets := map[string]bool{linuxName: true}
		RangeUnits(ifc, func(_ int, unit *InterfaceUnit) {
			targets[unitNetdev(linuxName, unit)] = true
		})
		sorted := make([]string, 0, len(targets))
		for t := range targets {
			sorted = append(sorted, t)
		}
		sort.Strings(sorted)
		out = append(out, sorted...)
	}
	return out
}
