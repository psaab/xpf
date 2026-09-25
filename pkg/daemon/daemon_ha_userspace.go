package daemon

import (
	"slices"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

type userspaceXSKBindingController interface {
	XSKBoundNotified() bool
	SetOnXSKBound(func())
}

// buildZoneRGMap records every positive RG represented by each zone. A zone
// can span multiple redundancy groups in active/active; keeping the complete
// set makes its ownership independent of interface ordering. Non-RETH zones
// without an RG are not included (they fall back to global IsPrimaryFn).
func buildZoneRGMap(cfg *config.Config, zoneIDs map[string]uint16) cluster.ZoneRGMap {
	result := make(cluster.ZoneRGMap)
	for zoneName, zone := range cfg.Security.Zones {
		// Tolerant/programmatic/HA-peer-sync configs can leave a nil zone
		// value in the map. Skip it rather than panicking during HA apply.
		if zone == nil {
			continue
		}
		zid, ok := zoneIDs[zoneName]
		if !ok {
			continue
		}
		for _, ifName := range zone.Interfaces {
			// #9821 D17: the split base (declared-aware), suffix ignored as
			// before — a dotted RG owner's member resolves to its declared stanza.
			baseName := cfg.SplitInterfaceUnitRef(ifName).Base
			if ifc, ok := cfg.Interfaces.Interfaces[baseName]; ok && ifc != nil {
				rg := ifc.RedundancyGroup
				if rg <= 0 && ifc.RedundantParent != "" {
					parentName := cfg.SplitInterfaceUnitRef(ifc.RedundantParent).Base
					if parent, ok := cfg.Interfaces.Interfaces[parentName]; ok && parent != nil {
						rg = parent.RedundancyGroup
					}
				}
				if rg > 0 {
					result[zid] = append(result[zid], rg)
				}
			}
		}
	}
	for zone := range result {
		rgs := result[zone]
		slices.Sort(rgs)
		result[zone] = slices.Compact(rgs)
	}
	return result
}

// buildZoneFoldRGMap maps the stable wire identity of each configured ingress
// interface to its owning RG. Ambiguous stable-ID collisions are omitted so
// per-session ownership falls back to the complete zone RG set.
func buildZoneFoldRGMap(cfg *config.Config) map[uint32]int {
	result := make(map[uint32]int)
	ambiguous := make(map[uint32]struct{})
	for _, stable := range cfg.ClusterStableIfaceNames() {
		fold := config.StableIfaceID(stable)
		if fold == 0 {
			continue
		}
		localName, ok := cfg.LocalIfaceForStableID(fold)
		if !ok {
			ambiguous[fold] = struct{}{}
			delete(result, fold)
			continue
		}
		baseName := cfg.SplitInterfaceUnitRef(localName).Base
		ifc := cfg.Interfaces.Interfaces[baseName]
		if ifc == nil || ifc.RedundancyGroup <= 0 {
			continue
		}
		if prior, ok := result[fold]; ok && prior != ifc.RedundancyGroup {
			ambiguous[fold] = struct{}{}
			delete(result, fold)
			continue
		}
		if _, bad := ambiguous[fold]; !bad {
			result[fold] = ifc.RedundancyGroup
		}
	}
	return result
}

// rgHasRETH returns whether the given redundancy group has any RETH interfaces.
func rgHasRETH(cfg *config.Config, rgID int) bool {
	if cfg == nil {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}
