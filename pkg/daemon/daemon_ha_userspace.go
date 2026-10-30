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
	ss.InstallZoneOwnership(d.zoneOwnershipInstall(cfg, buildZoneRGMap(cfg, buildZoneIDs(cfg)), nil))
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
	own := d.zoneOwnershipInstall(cfg, buildZoneRGMap(cfg, buildZoneIDs(cfg)), nil)
	currentGen, currentCfg := d.store.ActiveSnapshot()
	if gen != currentGen || cfg != currentCfg || !d.store.ActiveApplied() {
		return
	}
	ss.InstallZoneOwnership(own)
}

func receiverSessionTimeoutProfileFromConfig(cfg *config.Config) cluster.ReceiverSessionTimeoutProfile {
	if cfg == nil {
		return cluster.ReceiverSessionTimeoutProfile{}
	}
	flow := cfg.Security.Flow
	profile := cluster.ReceiverSessionTimeoutProfile{
		UDPSessionSeconds:  flow.UDPSessionTimeout,
		ICMPSessionSeconds: flow.ICMPSessionTimeout,
	}
	if tcp := flow.TCPSession; tcp != nil {
		profile.TCPEstablishedSeconds = tcp.EstablishedTimeout
		profile.TCPOpeningSeconds = tcp.InitialTimeout
		profile.TCPClosingSeconds = tcp.ClosingTimeout
		profile.TCPTimeWaitSeconds = tcp.TimeWaitTimeout
		if tcp.TimeWaitStateSessionTimeout > 0 {
			profile.TCPTimeWaitSeconds = tcp.TimeWaitStateSessionTimeout
		}
		profile.TCPTimeWaitSessionAgeout = tcp.TimeWaitStateSessionAgeout
		profile.TCPTimeWaitApplyToHalfClosed = tcp.TimeWaitStateApplyToHalfClosed
		profile.TCPFinInvalidateSession = tcp.FinInvalidateSession
	}
	return profile
}

func (d *Daemon) seedActiveSessionSyncTimeoutProfile(ss *cluster.SessionSync) {
	if ss == nil {
		return
	}
	rt := d.dataplane()
	cfg := policyInvalidationAppliedConfig(rt)
	if cfg == nil && rt != nil && !hasSessionTimeoutCaptureAuthority(rt) {
		// The legacy dataplane has no capture snapshot API and applies
		// synchronously; its stable applied marker is the corresponding
		// authority.
		_, cfg = d.activeAppliedZoneOwnershipSnapshot()
	}
	if cfg == nil {
		return
	}
	ss.SetReceiverSessionTimeoutProfile(receiverSessionTimeoutProfileFromConfig(cfg))
}

func (d *Daemon) updateSessionSyncTimeoutProfile(cfg *config.Config) {
	if cfg == nil {
		return
	}
	profile := receiverSessionTimeoutProfileFromConfig(cfg)
	d.sessionSyncTimeoutProfile.Store(&profile)
	if ss := d.getSessionSync(); ss != nil {
		ss.SetReceiverSessionTimeoutProfile(profile)
	}
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
// survivor's unattributable sessions. The exclusions are
// config.ZoneQuarantineExclusionsForConfig, the same runtime zone-name set the
// dataplane quarantine decides over (#12247), so both HA nodes agree on the
// survivor even when the colliders are node-scoped: a node whose only claimant
// of a shared ID is the loser maps that ID to no RG, matching a dataplane that
// installs no zone for it.
func buildZoneRGMap(cfg *config.Config, zoneIDs map[string]uint32) cluster.ZoneRGMap {
	result := make(cluster.ZoneRGMap)
	excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
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
		zid32, ok := zoneIDs[zoneName]
		if !ok || zid32 == 0 {
			continue
		}
		// #16557: session records carry the low 16 bits of the u32
		// zone id, so ownership is keyed by that truncation (the key
		// ShouldSyncZone is queried with).
		zid := uint16(zid32)
		for _, ifName := range zone.Interfaces {
			// #17086 SSOT: InterfaceRefRG's positive form — unit split,
			// RedundantParent chain, RethRGOwners membership. A stray
			// group on a non-RETH interface no longer leaks into the
			// zone's RG set.
			if rg := cfg.RefRG(ifName); rg > 0 {
				result[zid] = append(result[zid], rg)
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
		rg := cfg.RefRG(localName) // #17086 SSOT
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

// rgHasRETH returns whether rgID owns a RETH (#6781 SSoT, #15946).
// Raw RedundancyGroup==rgID swept every default-0 interface into RG0.
func rgHasRETH(cfg *config.Config, rgID int) bool {
	if cfg == nil || rgID <= 0 {
		return false
	}
	for _, ownerRG := range cfg.RethRGOwners() {
		if ownerRG == rgID {
			return true
		}
	}
	return false
}
