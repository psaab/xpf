package config

import (
	"fmt"
	"sort"
)

// validateVRRPTrackInterfaceRefStrict hard-rejects, at commit /
// commit-check, a vrrp-group `track-interface` that names no configured
// interface or unit (#15048, A25-01).
//
// The runtime resolves the tracked name to a kernel device (now via the
// SSOT ResolveKernelIfName in pkg/vrrp CollectInstances) and seeds the
// group's trackDown from a netlink lookup by that exact name; link events
// are matched by the same name. A name the config never declares —
// `ge-0/0/9`, a typo'd unit `ge-0/0/1.7`, a malformed unit — resolves to
// no netdev, so the lookup fails for the life of the config, the group
// advertises priority minus cost forever, and real link events for the
// intended interface are never seen: HA ownership is wrong permanently
// and the intended tracking is disabled, with a clean commit throughout.
//
// Declared-ness is judged by the shared unresolvedInterfaceRef against
// the declared-interface index (both the config spelling and the Linux
// dash spelling, #8829), so a bare interface, a declared unit (including
// a VLAN unit), a reth, and a dash-spelled name all stay legal — only a
// name that denotes nothing configured is rejected. The check is purely
// structural (which interface/unit the ref denotes), independent of how
// ResolveKernelIfName would name its device, so it cannot drift from the
// set of interfaces the config actually brings up.
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientVRRPTrackRef) so an
// already-persisted or peer-synced config an older binary accepted still
// boots (#1960 no-brick); the leniently-loaded group keeps today's
// behaviour (tracked name unresolved, group held demoted) now with an
// operator-visible warning naming the bad ref.
func validateVRRPTrackInterfaceRefStrict(cfg *Config) error {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	declared := declaredInterfaceIndex(cfg)
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
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
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil || vg.TrackInterface == "" {
					continue
				}
				if reason := unresolvedInterfaceRef(declared, vg.TrackInterface); reason != "" {
					return fmt.Errorf("interfaces %s unit %d vrrp-group %d: track-interface %s %s — "+
						"it resolves to no configured device, so the tracked link state is never "+
						"seen and the group advertises its priority minus the track cost for the "+
						"life of the config; name a configured interface or unit (#15048)",
						ifName, un, vg.ID, vg.TrackInterface, reason)
				}
			}
		}
	}
	return nil
}
