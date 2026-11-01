package cluster

// #18374: a content-equal ownership re-install must not void an in-flight
// bulk's reconcile.
//
// The bulk reconcile judges stale sessions by the ownership it captured at
// BulkStart (snapshotZoneOwnership, #9655): the zone->RG map, the
// stable-interface fold->RG map and the ingress fold resolver. It refuses to
// reconcile when zoneRGMapGen moved during the bulk, because a map installed
// mid-bulk can move a zone to this node and the bulk-start answers would then
// delete a session this node now owns. That refusal withholds the BulkAck and
// the failover release, and the only recovery is the sender's next bulk.
//
// SetZoneOwnership (#11012) advanced the generation on EVERY install, because
// the resolver is a Go func and two funcs cannot be compared. The daemon
// re-installs ownership on every config apply and on every interface-link
// refresh, so any of those landing inside a ~10 s receive window discarded the
// whole bulk. The #18374 journal census counts 113 zone-map aborts on loss
// fw0, each withholding its BulkAck; the restart prime at 2026-10-30 06:17:16
// was one, its window crossed by an em0 link-state refresh that changed
// neither the config nor the interface table.
//
// InstallZoneOwnership compares what the reconcile reads instead. The two maps
// are data and compare directly. The resolver is compared by a digest of what
// it CLOSES OVER, which only the daemon can compute (pkg/cluster holds no
// config): the compiled config's canonical text digest and the ifindex->name
// table the closure was built from. A zero digest means "unknown" and always
// advances, so every caller that cannot prove equality keeps #9655's fail-
// closed behaviour, and a genuine mid-bulk ownership move still voids the
// reconcile exactly as before.

// ResolverDigest fingerprints everything an ingress fold resolver closes
// over. The zero value is "unknown".
type ResolverDigest [32]byte

// Known reports whether the digest proves anything.
func (d ResolverDigest) Known() bool { return d != ResolverDigest{} }

// ZoneOwnership is one apply's session-sync ownership install.
type ZoneOwnership struct {
	// ZoneRG is the zone->RG set map. Nil keeps the installed map (an apply
	// with no zone-ID snapshot); a non-nil empty map is authoritative
	// (#10227).
	ZoneRG ZoneRGMap
	// FoldRG maps a cluster-stable interface fold to its RG (#11012).
	FoldRG map[uint32]int
	// IngressFold resolves a local {ifindex, vlan} to its cluster-stable fold
	// (#7095 ingress, #12075 egress). The bulk reconcile snapshot captures it.
	IngressFold func(ifindex uint32, vlan uint16) uint32
	// NatScopeFold is the #16826 send-side NAT-scope folder. Installed with
	// the rest so the two folders never come from different interface
	// tables, but it does not take part in the generation: no reconcile
	// snapshot captures it (see SetNatScopeFoldFn).
	NatScopeFold func(ifindex int32) uint32
	// ResolverDigest fingerprints what IngressFold closes over. Zero
	// (unknown) always advances the generation.
	ResolverDigest ResolverDigest
}

// InstallZoneOwnership atomically installs o and advances the ownership
// generation only when something the bulk reconcile reads changed: the zone
// map (when o.ZoneRG is non-nil), the fold->RG map, or the ingress resolver.
// The resolver counts as unchanged only when both the installed and the new
// digest are known and equal, and both resolvers are wired. It reports whether
// the generation advanced.
func (s *SessionSync) InstallZoneOwnership(o ZoneOwnership) bool {
	var zones ZoneRGMap
	if o.ZoneRG != nil {
		zones = make(ZoneRGMap, len(o.ZoneRG))
		for zone, rgs := range o.ZoneRG {
			zones[zone] = append([]int(nil), rgs...)
		}
	}
	folds := make(map[uint32]int, len(o.FoldRG))
	for fold, rg := range o.FoldRG {
		folds[fold] = rg
	}
	s.zoneRGMu.Lock()
	defer s.zoneRGMu.Unlock()
	changed := false
	if zones != nil && (s.zoneRGMap == nil || !zoneRGMapEqual(s.zoneRGMap, zones)) {
		changed = true
	}
	if !foldRGMapEqual(s.foldRGMap, folds) {
		changed = true
	}
	if !o.ResolverDigest.Known() || o.ResolverDigest != s.ingressFoldDigest ||
		o.IngressFold == nil || s.ingressFoldFn == nil {
		changed = true
	}
	if zones != nil {
		s.zoneRGMap = zones
	}
	s.foldRGMap = folds
	s.ingressFoldFn = o.IngressFold
	s.ingressFoldDigest = o.ResolverDigest
	s.natScopeFoldFn = o.NatScopeFold
	if changed {
		s.zoneRGMapGen++
	}
	return changed
}

// ZoneOwnershipGeneration returns the ownership generation a bulk snapshot
// records at BulkStart and the reconcile compares at BulkEnd (#9655).
func (s *SessionSync) ZoneOwnershipGeneration() uint64 {
	s.zoneRGMu.RLock()
	defer s.zoneRGMu.RUnlock()
	return s.zoneRGMapGen
}

// foldRGMapEqual reports whether two fold->RG maps are identical. Nil and
// empty are the same here: an empty fold map resolves nothing either way.
func foldRGMapEqual(a, b map[uint32]int) bool {
	if len(a) != len(b) {
		return false
	}
	for fold, rg := range a {
		if other, ok := b[fold]; !ok || other != rg {
			return false
		}
	}
	return true
}
