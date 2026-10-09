package daemon

import (
	"context"
	"log/slog"
	"slices"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// installActiveSessionSyncZoneOwnership repairs a published session-sync object
// when config sync skips apply. It shares applySem with config applies so a
// concurrent commit cannot leave an older snapshot installed.
func (d *Daemon) installActiveSessionSyncZoneOwnership(ss *cluster.SessionSync) {
	if ss == nil || d.store == nil || ss.ZoneOwnershipInstalled() {
		return
	}
	if d.applySem != nil {
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			slog.Warn("cluster: failed to serialize zone ownership install with config apply", "err", err)
			return
		}
		defer d.applySem.Release(1)
	}
	if ss.ZoneOwnershipInstalled() {
		return
	}
	_, cfg := d.activeAppliedZoneOwnershipSnapshot()
	if cfg == nil {
		return
	}
	ss.SetZoneOwnership(buildZoneRGMap(cfg, buildZoneIDs(cfg)), buildZoneFoldRGMap(cfg), buildIngressFoldFn(cfg))
}

// seedActiveSessionSyncZoneOwnership initializes a constructor-local object
// before it is published, so the first connection cannot observe the nil-map
// safety sentinel when an applied config already exists.
func (d *Daemon) seedActiveSessionSyncZoneOwnership(ss *cluster.SessionSync) {
	if ss == nil || ss.ZoneOwnershipInstalled() {
		return
	}
	gen, cfg := d.activeAppliedZoneOwnershipSnapshot()
	if cfg == nil {
		return
	}
	zoneRG := buildZoneRGMap(cfg, buildZoneIDs(cfg))
	foldRG := buildZoneFoldRGMap(cfg)
	ingressFold := buildIngressFoldFn(cfg)
	currentGen, currentCfg := d.store.ActiveSnapshot()
	if gen != currentGen || cfg != currentCfg || !d.store.ActiveApplied() {
		return
	}
	ss.SetZoneOwnership(zoneRG, foldRG, ingressFold)
}

// activeAppliedZoneOwnershipSnapshot captures only a stable active snapshot
// that has completed apply. Constructor seeding deliberately avoids applySem:
// stopClusterComms may join the constructor while its caller still owns it.
func (d *Daemon) activeAppliedZoneOwnershipSnapshot() (uint64, *config.Config) {
	if d.store == nil {
		return 0, nil
	}
	gen, cfg := d.store.ActiveSnapshot()
	if cfg == nil || !d.store.ActiveApplied() {
		return 0, nil
	}
	currentGen, currentCfg := d.store.ActiveSnapshot()
	if gen != currentGen || cfg != currentCfg || !d.store.ActiveApplied() {
		return 0, nil
	}
	return gen, cfg
}

type userspaceXSKBindingController interface {
	XSKBoundNotified() bool
	SetOnXSKBound(func())
}

// buildZoneRGMap records every positive RG represented by each zone. A zone
// can span multiple redundancy groups in active/active; keeping the complete
// set makes its ownership independent of interface ordering. Non-RETH zones
// without an RG are not included (they fall back to global IsPrimaryFn).
// Quarantined zones (#12237) are skipped outright: the dataplane installs only
// the surviving zone, and the zone-approximation fallback sync-owns on ANY RG
// in the set — so a collision loser's RGs would wrong-owner-sync the
// survivor's unattributable sessions. ZoneQuarantineExclusions is a pure
// function of the zone-name set, so both HA nodes compute the identical
// survivor-only map from the identical config.
func buildZoneRGMap(cfg *config.Config, zoneIDs map[string]uint16) cluster.ZoneRGMap {
	result := make(cluster.ZoneRGMap)
	names := make([]string, 0, len(cfg.Security.Zones))
	for zoneName := range cfg.Security.Zones {
		names = append(names, zoneName)
	}
	excluded := config.ZoneQuarantineExclusions(names)
	for zoneName, zone := range cfg.Security.Zones {
		// Quarantined/reserved zones are absent from dataplane enforcement.
		// Do not let their RGs leak into the survivor's same-ID ownership set.
		if _, drop := excluded[zoneName]; drop {
			continue
		}
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
		rg := configuredInterfaceRG(cfg, localName)
		if rg <= 0 {
			continue
		}
		if prior, ok := result[fold]; ok && prior != rg {
			ambiguous[fold] = struct{}{}
			delete(result, fold)
			continue
		}
		if _, bad := ambiguous[fold]; !bad {
			result[fold] = rg
		}
	}
	return result
}

// configuredInterfaceRG follows the RETH membership chain from a resolved
// physical interface to the redundancy group that owns it.
func configuredInterfaceRG(cfg *config.Config, name string) int {
	if cfg == nil {
		return 0
	}
	seen := make(map[string]struct{})
	for name != "" {
		base := cfg.SplitInterfaceUnitRef(name).Base
		if _, ok := seen[base]; ok {
			return 0
		}
		seen[base] = struct{}{}
		ifc := cfg.Interfaces.Interfaces[base]
		if ifc == nil {
			return 0
		}
		if ifc.RedundancyGroup > 0 {
			return ifc.RedundancyGroup
		}
		name = ifc.RedundantParent
	}
	return 0
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
