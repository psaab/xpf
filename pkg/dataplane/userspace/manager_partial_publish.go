package userspace

import (
	"time"
)

// #16153 (W2.4 P3): the partial-publisher pipeline shared by the retained-
// snapshot publishers. Each publisher used to hand-roll the same
// clone -> bump -> hash -> dedup -> publish -> adopt bookkeeping over
// `next := *m.lastSnapshot`; the copies drifted (the #15955 triple hash
// was one such drift, and the route-vs-capture dedup predicates differ
// in ways only one copy documented). The pipeline below owns the
// bookkeeping ONCE. A publisher keeps only its per-publisher prep
// (section rebuilds, capture refresh, protocol/disarm gates, dedup
// predicate) and its error wrapping — everything between the clone and
// the success tail is the shared pipeline.
//
// The pipeline deliberately does NOT unify the dedup predicates: the
// capture-authority publisher additionally requires a non-zero
// publishedSnapshot (its retained clone can be a never-published full
// build whose hash coincidentally matches), and the link refresh
// additionally requires resampled == 0. Those differences are pinned
// by characterization tests in partial_publish_16153_test.go; a
// publisher expresses its predicate explicitly at the call site rather
// than hiding it behind a shared default.
//
// Caller holds m.mu for every helper in this file.

// cloneRetainedSnapshotLocked returns the value copy of the retained
// snapshot every partial publisher starts from, applying the
// single-use-metadata strip unless the pending-full-snapshot latch says
// this partial publish may be the first accepted publication of a
// deferred or unknown-outcome full build (in which case the metadata
// must ride once; the successful publication clears the latch).
func (m *Manager) cloneRetainedSnapshotLocked() (ConfigSnapshot, bool) {
	if m == nil || m.lastSnapshot == nil {
		return ConfigSnapshot{}, false
	}
	next := *m.lastSnapshot
	if !m.pendingFullSnapshotMetadata {
		stripSingleUseCommitMetadata(&next)
	}
	return next, true
}

// bumpRetainedGenerationLocked stamps the next publish generation, the
// current FIB generation, and the wall-clock build time onto a retained
// clone. The generation is computed from m.generation (+1) and committed
// back only on publish success (adoptPublishedGenerationLocked), so a
// failed publish burns no generation.
func (m *Manager) bumpRetainedGenerationLocked(next *ConfigSnapshot) uint64 {
	nextGeneration := m.generation + 1
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	return nextGeneration
}

// prehashedPublish carries the single pre-send content hash (#15955)
// and the publishable-neighbor view of a snapshot about to be sent.
// Computing it once serves the dedup compare, the ContentDigest stamp
// inside the send, and — via postPublishHash — the lastSnapshotHash
// recorded on success, so a publisher never pays a second
// marshal+SHA-256 under m.mu.
type prehashedPublish struct {
	snap         ConfigSnapshot
	hash         [32]byte
	hashOK       bool
	preSendClear bool
}

// preparePrehashedPublish builds the publish view of next: neighbors
// filtered to the publishable set (the retained set keeps the
// unfiltered rows) and one content hash over that final struct.
func preparePrehashedPublish(next *ConfigSnapshot) prehashedPublish {
	publishSnap := *next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	hash, ok := snapshotContentHash(&publishSnap)
	return prehashedPublish{
		snap:         publishSnap,
		hash:         hash,
		hashOK:       ok,
		preSendClear: publishSnap.ClearPolicies,
	}
}

// dedupHit reports whether the prehashed publish is a duplicate of the
// content the helper already holds and may be skipped. The common arms
// are the hash match plus both unknown-outcome stand-downs (#9520,
// #9684): while an earlier apply's or partial update's outcome is
// unknown, the hash describes what Go last sent, not what the helper
// holds. Publishers with extra arms (capture-authority's
// publishedSnapshot != 0, link refresh's resampled == 0) AND them at
// the call site — see the file doc comment.
func (m *Manager) dedupHit(pub prehashedPublish) bool {
	return pub.hashOK && pub.hash == m.lastSnapshotHash &&
		!m.applySnapshotOutcomeUnknown && m.partialOutcomeUnknown == 0
}

// adoptPublishedSnapshotLocked commits a helper-accepted partial
// publish: the retained snapshot becomes next (with the generation the
// send actually carried, #9520), the neighbor/monitor indexes are
// rebuilt, the published generation and binding-plan key advance, the
// applied-snapshot identity is marked, and lastSnapshotHash records
// the post-publish hash threaded from the pre-send hash (#15955).
// path names the publisher for the WG endpoint-transition log.
func (m *Manager) adoptPublishedSnapshotLocked(next *ConfigSnapshot, pub prehashedPublish, path string, wasDebt bool, resampled partialSections) {
	m.commitPolicySchedulerActiveStateFromSnapshotLocked(next)
	m.logWgEndpointSetTransitionLocked(&pub.snap, path)
	m.adoptPublishedGenerationLocked(next, pub.snap.Generation)
	m.lastSnapshot = next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.pendingFullSnapshotMetadata = false
	m.publishedPlanKey = snapshotBindingPlanKey(&pub.snap)
	m.markAppliedSnapshotLocked()
	if h, ok := postPublishHash(&pub.snap, pub.hash, pub.hashOK, pub.preSendClear); ok {
		m.lastSnapshotHash = h
	}
	m.resolvePartialOutcomesLocked(resampled)
	m.armPendingHAStateReplayLocked(wasDebt)
}

// copyPreparedSectionsBack copies the apply-time prepared sections from
// the sent publish snapshot back into the retained clone (#15043).
// requestApplySnapshotLocked's prepareSnapshotForApply rebuilds every
// derived section (#14209) into the publish copy; retaining only the
// pre-send clone would keep stale mirror/tunnel/route rows in
// lastSnapshot while the recorded hash describes the rebuilt copy.
// Neighbors is deliberately NOT copied: the publish copy carries the
// publishable-only neighbor filter, not the retained set. Used by the
// non-prehashed publishers (scheduler, worker-arm) whose send may
// rebuild sections after any earlier hash.
func copyPreparedSectionsBack(next, publishSnap *ConfigSnapshot) {
	next.Interfaces = publishSnap.Interfaces
	next.Routes = publishSnap.Routes
	next.LearnedRouteImportCapped = publishSnap.LearnedRouteImportCapped
	next.Fabrics = publishSnap.Fabrics
	next.TunnelEndpoints = publishSnap.TunnelEndpoints
	next.MirrorConfigs = publishSnap.MirrorConfigs
	next.MirrorExclusions = publishSnap.MirrorExclusions
	next.SourceNAT = publishSnap.SourceNAT
	next.Zones = publishSnap.Zones
	next.Summary = publishSnap.Summary
	next.ZoneSetValidated = publishSnap.ZoneSetValidated
	next.zoneIDCollisions = publishSnap.zoneIDCollisions
	next.wgFanUpBaseRows = publishSnap.wgFanUpBaseRows
	next.xfrmDumpFailed = publishSnap.xfrmDumpFailed
}

// adoptPreparedPublishLocked commits a helper-accepted
// requestApplySnapshotLocked publish (scheduler, worker-arm): the
// prepared sections are copied back first (#15043), then the shared
// adopt runs. The recorded hash is recomputed over the prepared publish
// copy — the sections the helper actually received — because the send
// may have rebuilt them after any earlier hash (#15955: these
// publishers are NOT prehash-deduped). path names the publisher for
// the WG endpoint-transition log.
func (m *Manager) adoptPreparedPublishLocked(next *ConfigSnapshot, publishSnap *ConfigSnapshot, path string, wasDebt bool, resampled partialSections) {
	copyPreparedSectionsBack(next, publishSnap)
	// The hash is taken over the post-send publish copy (ClearPolicies
	// already spent by the send), so it IS the post-publish hash:
	// preSendClear=false makes adopt's postPublishHash return it as-is.
	pub := prehashedPublish{snap: *publishSnap}
	if h, ok := snapshotContentHash(publishSnap); ok {
		pub.hash, pub.hashOK = h, true
	}
	m.adoptPublishedSnapshotLocked(next, pub, path, wasDebt, resampled)
}

// captureAuthorityFields holds one capture-authority stamp: the four
// coupled fields every capture stamp writes together (#16153 P4). The
// two stamp entry points (the builder's stampCaptureAuthorityWithRoutesMode
// and the manager's refreshCaptureAuthorityLocked) used to assign these
// field-by-field and could drift; both now produce/consume this value
// through applyTo so the field set has exactly one definition. The
// slices are detached (copied) at apply time, so a caller's backing
// arrays are never aliased into the snapshot.
type captureAuthorityFields struct {
	permitEpoch              uint64
	queueEpochs              []QueueEpochSnapshot
	tunnelSnapshotGeneration uint64
	tunnelRows               []IpsecTunnelRowSnapshot
}

// captureAuthorityFromProvider invokes provider for snap's generations
// and returns the detached stamp. A nil snap or provider yields the
// zero stamp, which applyTo still writes (matching the builder stamp's
// historical nil-provider no-op is the CALLER's gate, not this one's).
func captureAuthorityFromProvider(snap *ConfigSnapshot, provider CaptureEpochProvider) captureAuthorityFields {
	if snap == nil || provider == nil {
		return captureAuthorityFields{}
	}
	permitEpoch, queueEpochs, tunnelGeneration, tunnelRows := provider(snap.Generation, snap.FIBGeneration)
	return captureAuthorityFields{
		permitEpoch:              permitEpoch,
		queueEpochs:              queueEpochs,
		tunnelSnapshotGeneration: tunnelGeneration,
		tunnelRows:               tunnelRows,
	}
}

// applyTo stamps the four capture-authority fields onto snap, detaching
// the slice fields so the snapshot never aliases the provider's
// backing arrays (the per-publisher detach list for capture authority:
// QueueEpochs and IpsecTunnelRows are copied; the scalar epochs are
// values). This is the ONLY writer of these four fields outside the
// full builder literal, so the stamp cannot drift between the builder
// and the retained-snapshot refresh.
func (f captureAuthorityFields) applyTo(snap *ConfigSnapshot) {
	if snap == nil {
		return
	}
	snap.PermitEpoch = f.permitEpoch
	snap.QueueEpochs = append([]QueueEpochSnapshot(nil), f.queueEpochs...)
	snap.IpsecTunnelSnapshotGeneration = f.tunnelSnapshotGeneration
	snap.IpsecTunnelRows = append([]IpsecTunnelRowSnapshot(nil), f.tunnelRows...)
}
