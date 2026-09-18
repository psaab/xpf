package config

import (
	"fmt"
	"sort"
	"strconv"
)

// appendUserspaceMgmtZoneAdvisoryLocked warns when an operator-controlled
// `mgmt`/`control` zone name contains a non-lifeline data interface. Those
// names historically selected a userspace dataplane exemption, but a zone name
// is not a reliable identity for a vrf-mgmt lifeline: the operator can put an
// ordinary data NIC there. The dataplane now keys the exemption on interface
// class, so the data NIC remains policy-adjudicated; this commit-time warning
// makes the changed contract explicit instead of silently accepting the old
// meaning (#10308).
//
// This is an advisory, not a reject. Canonical lifeline zones named `mgmt` and
// `control` must continue to compile. Tunnel, local-fabric, and config-owned
// secure-tunnel members are already excluded by other dataplane classes and
// therefore do not receive this data-NIC advisory. Tolerant load / peer-sync
// paths suppress it through the existing advisory suppression flag so a
// persisted config does not repeat the same message on every boot.
func appendUserspaceMgmtZoneAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressContestedTrunkZoneAdvisory || cfg.Security.Zones == nil {
		return
	}
	for _, zoneName := range []string{"control", "mgmt"} {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil || len(zone.Interfaces) == 0 {
			continue
		}
		seen := make(map[string]struct{}, len(zone.Interfaces))
		members := append([]string(nil), zone.Interfaces...)
		sort.Strings(members)
		for _, member := range members {
			if _, ok := seen[member]; ok {
				continue
			}
			seen[member] = struct{}{}
			if !userspaceMgmtZoneMemberIsData(cfg, member) {
				continue
			}
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
				"security zone %q member %q is a non-lifeline interface: the userspace "+
					"exemption is keyed on interface class (vrf-mgmt lifelines such as "+
					"fxp*/fab*/em*), not on the zone name; the zone name alone does not "+
					"grant a lifeline exemption (#10308)",
				zoneName, member))
		}
	}
}

// userspaceMgmtZoneMemberIsData mirrors the static, config-visible portion of
// userspaceSkipsIngressInterface. Live stale-xfrm state is only visible while
// building a dataplane snapshot, so the warning deliberately makes no claim
// about that runtime-only half; it only warns when the zone label itself would
// otherwise be the mistaken lifeline identity.
func userspaceMgmtZoneMemberIsData(cfg *Config, member string) bool {
	if cfg == nil {
		return false
	}
	split := cfg.SplitInterfaceUnitRef(member)
	base := split.Base
	if IsManagementIfName(base) || base == "lo0" {
		return false
	}
	if _, ok := cfg.SecureTunnelNetdevForRef(member); ok {
		return false
	}
	if cfg.Interfaces.Interfaces == nil {
		return true
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return true
	}
	if ifc.Tunnel != nil || ifc.LocalFabricMember != "" {
		return false
	}
	if split.HasUnit {
		if unitNum, err := strconv.Atoi(split.UnitTok); err == nil {
			if unit := ifc.Units[unitNum]; unit != nil && unit.Tunnel != nil {
				return false
			}
		}
	}
	return true
}
