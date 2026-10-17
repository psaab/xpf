package cluster

import (
	"slices"

	"github.com/psaab/xpf/pkg/dataplane"
)

// ZoneRGMap maps a zone ID to EVERY redundancy group that zone's interfaces
// represent (#11012). A zone whose interfaces belong to a single RG carries a
// one-element set and behaves exactly as the old single value did; a zone
// spanning RGs carries one entry per RG, independent of the authored interface
// order that used to decide which single RG survived.
//
// Sets are built sorted and deduplicated by the daemon, but nothing here
// depends on that: equality is order-insensitive and every consumer treats the
// set as a set.
type ZoneRGMap map[uint16][]int

// zoneRGMapEqual reports whether two zone→RG maps name the same ownership.
// Set membership compares order-insensitively and duplicate-insensitively.
func zoneRGMapEqual(a, b ZoneRGMap) bool {
	if len(a) != len(b) {
		return false
	}
	for zone, ars := range a {
		brs, ok := b[zone]
		if !ok {
			return false
		}
		for _, rg := range ars {
			if !slices.Contains(brs, rg) {
				return false
			}
		}
		for _, rg := range brs {
			if !slices.Contains(ars, rg) {
				return false
			}
		}
	}
	return true
}

// resolveSessionRG maps a session's ingress identity to its owning RG. The
// stored #7095 fold answers directly for peer-synced rows (their node-local
// ifindex was scrubbed at install); local rows fold their own {ifindex, vlan}
// through the daemon-injected resolver first. ok=false means the session
// cannot be attributed — unknown/legacy identity, an unwired resolver, or a
// fold the daemon declined as ambiguous — and the caller must fall back to the
// zone approximation.
func resolveSessionRG(ifindex uint32, vlan uint16, fold uint32, foldFn func(ifindex uint32, vlan uint16) uint32, foldRG map[uint32]int) (rg int, ok bool) {
	if fold == 0 && foldFn != nil && ifindex != 0 {
		fold = foldFn(ifindex, vlan)
	}
	if fold == 0 {
		return 0, false
	}
	rg, ok = foldRG[fold]
	return rg, ok
}

// zoneRGSet returns the RG set for zoneID when the zone is mapped.
func zoneRGSet(zoneID uint16, zoneRG ZoneRGMap) ([]int, bool) {
	rgs, ok := zoneRG[zoneID]
	return rgs, ok
}

// ShouldSyncSessionV4 reports whether this node owns the given session for
// sync purposes. It resolves the session's OWN RG first and only falls back to
// the zone approximation for unattributable rows, so a zone spanning RGs
// syncs each session by its ingress RG instead of by whichever RG the zone map
// happened to keep (#11012). Rows without any ingress identity answer exactly
// as ShouldSyncZone does.
//
// Cluster-synced safety (#14357): a peer-installed row read back through the
// BPF mirror has lost both ingress identity carriers — IngressIfaceFold is
// not persisted in the on-map ABI and ScrubNodeLocal zeroed
// IngressIfindex/IngressVlanID at install — so resolveSessionRG fails. For a
// cluster-synced row in a multi-RG zone, the zone approximation (primary for
// ANY RG in the set) would claim a peer-owned RG2 row on an RG1-primary node
// as locally owned, so sweep/bulk would re-export it (echo) and bulk
// reconcile would never purge it. Such a row is therefore NOT locally owned:
// return false. Local rows (no ClusterSynced bit) keep the zone fallback,
// and so do cluster-synced rows in single-RG/unmapped zones, where the zone
// answer is unambiguous.
func (s *SessionSync) ShouldSyncSessionV4(val dataplane.SessionValue) bool {
	if s.IsPrimaryForRGFn == nil {
		if s.IsPrimaryFn != nil {
			return s.IsPrimaryFn()
		}
		return false
	}
	s.zoneRGMu.RLock()
	zoneRG := s.zoneRGMap
	foldRG := s.foldRGMap
	foldFn := s.ingressFoldFn
	isPrimaryForRG := s.IsPrimaryForRGFn
	s.zoneRGMu.RUnlock()
	if rg, ok := resolveSessionRG(val.IngressIfindex, val.IngressVlanID, val.IngressIfaceFold, foldFn, foldRG); ok {
		return isPrimaryForRG(rg)
	}
	if val.Flags&dataplane.SessFlagClusterSynced != 0 {
		if rgs, ok := zoneRGSet(val.IngressZone, zoneRG); ok && len(rgs) > 1 {
			return false
		}
	}
	return zoneSetSyncs(val.IngressZone, zoneRG, isPrimaryForRG, s.IsPrimaryFn)
}

// ShouldSyncSessionV6 is the IPv6 twin of ShouldSyncSessionV4.
func (s *SessionSync) ShouldSyncSessionV6(val dataplane.SessionValueV6) bool {
	if s.IsPrimaryForRGFn == nil {
		if s.IsPrimaryFn != nil {
			return s.IsPrimaryFn()
		}
		return false
	}
	s.zoneRGMu.RLock()
	zoneRG := s.zoneRGMap
	foldRG := s.foldRGMap
	foldFn := s.ingressFoldFn
	isPrimaryForRG := s.IsPrimaryForRGFn
	s.zoneRGMu.RUnlock()
	if rg, ok := resolveSessionRG(val.IngressIfindex, val.IngressVlanID, val.IngressIfaceFold, foldFn, foldRG); ok {
		return isPrimaryForRG(rg)
	}
	if val.Flags&dataplane.SessFlagClusterSynced != 0 {
		if rgs, ok := zoneRGSet(val.IngressZone, zoneRG); ok && len(rgs) > 1 {
			return false
		}
	}
	return zoneSetSyncs(val.IngressZone, zoneRG, isPrimaryForRG, s.IsPrimaryFn)
}

// zoneSetSyncs is the zone-approximation fallback shared by the live row
// predicates: a mapped zone syncs when this node is primary for ANY RG in its
// set, and an unmapped zone uses the RG 0 fallback, matching ShouldSyncZone.
func zoneSetSyncs(zoneID uint16, zoneRG ZoneRGMap, isPrimaryForRG func(int) bool, isPrimary func() bool) bool {
	if rgs, ok := zoneRG[zoneID]; ok {
		for _, rg := range rgs {
			if isPrimaryForRG(rg) {
				return true
			}
		}
		return false
	}
	if isPrimary != nil {
		return isPrimary()
	}
	return false
}

// zoneRGs is the RG set for the row's ingress zone in this snapshot, used by
// shouldSyncV4/V6 to apply the #14357 multi-RG cluster-synced guard.
func (z *zoneOwnershipSnapshot) zoneRGs(zoneID uint16) ([]int, bool) {
	rgs, ok := z.zoneRGsByZone[zoneID]
	return rgs, ok
}

// shouldSyncV4 judges one v4 row by the bulk-start ownership answers this
// snapshot was taken from. A resolved RG outside the bulk-start universe (a
// skew the map-generation check did not catch) keeps the row: deleting on a
// guess is the failure this reconcile can cause.
//
// Cluster-synced safety (#14357): as in ShouldSyncSessionV4, an unattributable
// cluster-synced row in a multi-RG zone must not be kept by the zone
// approximation — BulkEnd would never purge a stale peer RG row. Return
// false so ReconcileClusterBulk treats it as not-locally-owned and, when it
// was not received in this bulk, deletes it. Local unattributable rows keep
// the zone fallback (fail-closed: never delete on a guess).
func (z *zoneOwnershipSnapshot) shouldSyncV4(val dataplane.SessionValue) bool {
	if z.useRG {
		if rg, ok := resolveSessionRG(val.IngressIfindex, val.IngressVlanID, val.IngressIfaceFold, z.foldFn, z.foldRG); ok {
			if primary, ok := z.primary[rg]; ok {
				return primary
			}
			return true
		}
		if val.Flags&dataplane.SessFlagClusterSynced != 0 {
			if rgs, ok := z.zoneRGs(val.IngressZone); ok && len(rgs) > 1 {
				return false
			}
		}
	}
	return z.shouldSync(val.IngressZone)
}

// shouldSyncV6 is the IPv6 twin of shouldSyncV4.
func (z *zoneOwnershipSnapshot) shouldSyncV6(val dataplane.SessionValueV6) bool {
	if z.useRG {
		if rg, ok := resolveSessionRG(val.IngressIfindex, val.IngressVlanID, val.IngressIfaceFold, z.foldFn, z.foldRG); ok {
			if primary, ok := z.primary[rg]; ok {
				return primary
			}
			return true
		}
		if val.Flags&dataplane.SessFlagClusterSynced != 0 {
			if rgs, ok := z.zoneRGs(val.IngressZone); ok && len(rgs) > 1 {
				return false
			}
		}
	}
	return z.shouldSync(val.IngressZone)
}
