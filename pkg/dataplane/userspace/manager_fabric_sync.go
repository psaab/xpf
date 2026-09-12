package userspace

// Fabric-state publish for the userspace dataplane: pushes freshly-resolved
// fabric snapshots (peer MACs, ifindexes) to the helper and writes the
// resolved set back into m.lastSnapshot so partial-rebuild publishes do not
// revert it (#5306). The snapshots themselves are built in fabric.go.

import (
	"log/slog"
)

// SyncFabricState pushes current fabric snapshots (with fresh peer MACs)
// to the Rust helper. Called from the daemon after refreshFabricFwd succeeds
// so the helper has up-to-date fabric MAC info for cross-chassis redirect.
func (m *Manager) SyncFabricState() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		return
	}
	// #6691 round 11: the refresh carries MACs, ifindexes and link state — never
	// a device-level binding verdict. The builder re-samples the kernel, and a
	// verdict re-decided here would apply to a snapshot whose interface rows are
	// still the applied ones, on two planes that neither replan on this path.
	// alignFabricVerdicts (fabric.go) holds the reasoning.
	fabrics := m.sampleFabricsLocked()
	if len(fabrics) == 0 {
		return
	}
	var status ProcessStatus
	req := ControlRequest{
		Type:    "update_fabrics",
		Fabrics: fabrics,
	}
	if err := m.requestLocked(req, &status); err != nil {
		slog.Debug("userspace: failed to sync fabric state", "err", err)
		m.recordPartialUpdateFailureLocked(partialFabrics, err)
		return
	}
	// #5306: persist the resolved fabrics into the Go-side lastSnapshot. The
	// update_fabrics send above already handed the helper the freshly-resolved
	// peer MACs, but the partial-rebuild publish paths
	// (PublishRouteOverlaySnapshot, the policy-scheduler republish, the #5134
	// worker-arm re-apply) each start from `next := *m.lastSnapshot` and rebuild
	// ONLY Routes, re-publishing every other section — Fabrics included —
	// verbatim. Without this writeback that verbatim Fabrics is the STALE,
	// unresolved-MAC set baked in at the last full apply, so the next such
	// apply_snapshot silently reverts the helper to the unresolved fabric MAC —
	// exactly during the HA window fabric cross-chassis forwarding exists to
	// preserve. Write back only after the send succeeds (mutate-after-success),
	// so lastSnapshot.Fabrics is the last set Go saw the helper accept. A failed
	// round trip can still follow an applied update; #9684 marks that, and the
	// next publish re-samples. Mirrors RegenerateNeighborSnapshot's post-publish
	// writeback for the neighbor table.
	m.persistResolvedFabricsLocked(fabrics)
	m.resolvePartialOutcomesLocked(partialFabrics)
}

// persistResolvedFabricsLocked writes the fabric snapshots SyncFabricState just
// pushed to the helper back into m.lastSnapshot so the partial-rebuild publish
// paths (which do `next := *m.lastSnapshot` and refresh only Routes) carry the
// resolved peer MAC forward instead of reverting to the stale set (#5306).
//
// It shares RegenerateNeighborSnapshot's post-publish bookkeeping —
// advanceGenerationAfterPartialUpdateLocked — which advances the generation and,
// ONLY when the full snapshot was already published, publishedSnapshot and
// lastSnapshotHash. Advancing those unconditionally is #6986: update_fabrics is
// a PARTIAL update, so claiming "published" over a Compile-deferred snapshot
// closes the status tick's gate on content the helper never received. When
// nothing is deferred the behaviour is unchanged: the reconcile loop does not
// mistake the mutated snapshot for an unpublished generation (a redundant full
// apply_snapshot) and the content-dedup gate compares against the now-current
// content. No-op when the fabric set is
// unchanged so the daemon's post-refreshFabricFwd SyncFabricState cadence does
// not churn the generation on every steady-state call. Caller holds m.mu.
func (m *Manager) persistResolvedFabricsLocked(fabrics []FabricSnapshot) {
	if m.lastSnapshot == nil {
		return
	}
	if fabricSnapshotsEqual(m.lastSnapshot.Fabrics, fabrics) {
		return
	}
	m.lastSnapshot.Fabrics = fabrics
	// #6986: shared with RegenerateNeighborSnapshot rather than duplicated.
	// These two are the only writebacks that advance publishedSnapshot after a
	// PARTIAL update, so any divergence between them is a bug by construction —
	// one would swallow a deferred publish and the other would not, and the
	// difference would only ever show up as a lost config on a loaded box.
	m.advanceGenerationAfterPartialUpdateLocked()
}

// fabricSnapshotsEqual reports whether two fabric snapshot slices are
// element-wise identical. FabricSnapshot is a flat struct of comparable fields,
// so a direct == comparison suffices — no reflect (retirement-boundary canary,
// TestUserspaceManagerDoesNotImportReflectOrUnsafe).
func fabricSnapshotsEqual(a, b []FabricSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
