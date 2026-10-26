package dataplane

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/psaab/xpf/pkg/config"
)

// untaggedUnitAddresses returns the addresses the netlink planner
// actually owns on a non-RETH VLAN parent device itself (#16795, #17841).
//
// It returns nil for anything else: a RETH member (its untagged unit's
// addresses are VIPs owned by VRRP, and the parent carries only the
// advert source via vlanParentVRRPSource), a disabled unit, a unit
// already holding a standalone vrrp-group (its addresses stay VIP-foreign
// exactly as on a non-VLAN row: the row keeps them via
// KeepAddresses/KeepForeignStatic but renders none of them), and any
// tagged unit (whose addresses belong to its sub-interface). Iteration
// is by ascending unit number so the rendered order is deterministic.
//
// #17841: the render MUST be gated by the planner, not by raw config.
// planPhysDesired folds an untagged unit's addresses onto the parent
// plan only when a zone references that unit (non-quarantined,
// non-excluded), and marks the whole netdev skipAddrs when any zoned
// untagged unit is DHCP/DHCPv6-managed or the interface is in a
// redundancy group / fabric. Rendering every untagged unit
// unconditionally made partially-zoned parents flap: networkd installed
// the unzoned unit's address as static and every later compile's
// reconcileInterfaceAddresses deleted it as stale. The caller passes
// the same planPhysDesired(cfg) map the reconciler consumes; when the
// plan says skipAddrs the parent renders nothing; when the device is
// absent from the plan the render falls back to the #16795 unzoned
// shape UNLESS zone refs for untagged units exist but were all
// quarantined (then the planner deliberately owns nothing). The
// standalone-VRRP exclusion stays as a local guard because the planner
// includes such a unit's real address in pd.addrs while the render
// must keep it VIP-foreign (#15061).
// untaggedUnitAddressesFor resolves the planner view for one device:
// a missing plan entry means the planner owns nothing on it.
func untaggedUnitAddressesFor(cfg *config.Config, ifName, linuxName string, ifCfg *config.InterfaceConfig, isVRRPReth bool, physPlans map[string]*physDesired, zoned map[int]bool) []string {
	pd := physPlans[linuxName]
	if pd == nil {
		if len(zoned) == 0 && anyZoneRefForUntagged(cfg, ifName, ifCfg) {
			// #17841 quarantine leg: zone refs exist for untagged
			// units but every one is quarantined/excluded, so the
			// planner planned nothing. Rendering here would install
			// an address no reconciler owns.
			return nil
		}
		// Device absent from the plan and no untagged unit is
		// zone-referenced at all: #16795's unzoned acceptance leg
		// renders unit-0 addresses (no reconciler runs on an
		// unplanned device, so nothing deletes them).
		return untaggedUnitAddresses(ifCfg, isVRRPReth, nil, false, nil)
	}
	return untaggedUnitAddresses(ifCfg, isVRRPReth, pd.addrs, pd.skipAddrs, zoned)
}

// anyZoneRefForUntagged reports whether ANY zone (before quarantine
// filtering) references an untagged unit of ifName. Together with an
// empty zoned set it identifies the quarantined-only shape.
func anyZoneRefForUntagged(cfg *config.Config, ifName string, ifCfg *config.InterfaceConfig) bool {
	if cfg == nil || ifCfg == nil {
		return false
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		for _, ref := range zone.Interfaces {
			_, unit, vlanID, ok := splitZoneRefForParent(cfg, ref, ifName)
			if !ok || vlanID != 0 {
				continue
			}
			if unit < 0 {
				return true
			}
			if u := ifCfg.Units[unit]; u != nil && u.VlanID <= 0 {
				return true
			}
		}
	}
	return false
}

// zonedUntaggedUnits returns the unit numbers of ifCfg that a zone
// references (non-quarantined, non-excluded) with vlanID == 0 — the
// units planPhysDesired folds onto this device. A unit referenced only
// via a tagged sibling never appears here.
func zonedUntaggedUnits(cfg *config.Config, ifName string, ifCfg *config.InterfaceConfig) map[int]bool {
	out := map[int]bool{}
	if cfg == nil || ifCfg == nil {
		return out
	}
	quarantined := config.QuarantinedZoneInterfaceKeys(cfg)
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		for _, ref := range zone.Interfaces {
			_, unit, vlanID, ok := splitZoneRefForParent(cfg, ref, ifName)
			if !ok || vlanID != 0 {
				continue
			}
			if zoneInterfaceQuarantined13164(cfg, ref, quarantined) {
				continue
			}
			// A bare interface ref fans out to all its units; only
			// untagged units fold onto the parent device.
			if unit < 0 {
				for n, u := range ifCfg.Units {
					if u != nil && u.VlanID <= 0 {
						out[n] = true
					}
				}
				continue
			}
			out[unit] = true
		}
	}
	return out
}

// splitZoneRefForParent resolves a zone interface ref against the
// configured interface named ifName (config name, e.g. ge-0/0/1).
// Returns unit=-1 for a bare ref.
func splitZoneRefForParent(cfg *config.Config, ref, ifName string) (base string, unit int, vlanID int, ok bool) {
	s := cfg.SplitInterfaceUnitRef(ref)
	if s.Base != ifName {
		return "", 0, 0, false
	}
	if !s.HasUnit || s.UnitTok == "" {
		return s.Base, -1, 0, true
	}
	n, err := strconv.Atoi(s.UnitTok)
	if err != nil || n < 0 {
		return "", 0, 0, false
	}
	if ifc := cfg.Interfaces.Interfaces[ifName]; ifc != nil {
		if u := ifc.Units[n]; u != nil {
			return s.Base, n, u.VlanID, true
		}
	}
	return s.Base, n, 0, true
}

func untaggedUnitAddresses(ifCfg *config.InterfaceConfig, isVRRPReth bool, planned []string, skipAddrs bool, zoned map[int]bool) []string {
	if isVRRPReth || ifCfg == nil || skipAddrs {
		return nil
	}
	// The set the planner folded onto THIS device. When the planner
	// planned this device at all, only addresses in this set may
	// render; a device with no zone-referenced untagged unit never
	// appears in the plan, and its configured unit-0 addresses render
	// exactly as #16795 required (the unzoned acceptance leg).
	plannedOnDevice := zoned != nil
	want := make(map[string]bool, len(planned))
	for _, a := range planned {
		want[a] = true
	}
	nums := make([]int, 0, len(ifCfg.Units))
	for n := range ifCfg.Units {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	var out []string
	seen := make(map[string]bool)
	for _, n := range nums {
		unit := ifCfg.Units[n]
		if unit == nil || unit.Disable || unit.VlanID > 0 || unitCarriesStandaloneVRRP(unit) {
			continue
		}
		if plannedOnDevice {
			// #17841: on a device the planner addressed via one zoned
			// untagged unit, ghost unit-0 addresses from a second,
			// unzoned-but-planned sibling must not render. The planner
			// marks the device planned (pd != nil) exactly when some
			// unit resolved to it; an untagged unit that is not
			// zone-referenced is not planner-owned here.
			if !zoned[n] {
				continue
			}
		}
		for _, a := range unit.Addresses {
			if (plannedOnDevice && !want[a]) || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// vlanParentVRRPSource returns the addresses a VLAN parent carries ITSELF
// (networkd.InterfaceConfig.VLANParentAddresses): the VRRP advert source of a
// VRRP-backed RETH that has an addressed unit with no vlan-id (#9721).
//
// A unit with no vlan-id has no sub-interface, so CollectRethInstances
// (pkg/vrrp) binds that unit's instance to the parent device. Every other device
// of a VRRP-backed RETH carries the 169.254.<rg>.<node+1>/32 source
// (buildInterfaceNetworkdModels). Without it on the parent the instance found no
// IPv4 source and sent no IPv4 advertisement, so both nodes could become MASTER
// for the unit's VIPs.
//
// It returns nil for anything else: a tagged-only parent, an untagged unit with
// no address (which builds no instance), or an interface that is not a
// VRRP-backed RETH member. isVRRPReth and clusterNodeID are the caller's, so the
// parent is rendered under the same rule as every other RETH device.
//
// Split out of compiler_iface.go, which sits at the 2000 LOC [REFACTOR] floor.
// It is a pure function of the config, like planPhysDesired.
func vlanParentVRRPSource(ifCfg *config.InterfaceConfig, isVRRPReth bool, clusterNodeID int) []string {
	if !isVRRPReth || ifCfg == nil {
		return nil
	}
	for _, unit := range ifCfg.Units {
		if unit != nil && !unit.Disable && unit.VlanID <= 0 && len(unit.Addresses) > 0 {
			return []string{fmt.Sprintf("169.254.%d.%d/32", ifCfg.RedundancyGroup, clusterNodeID+1)}
		}
	}
	return nil
}
