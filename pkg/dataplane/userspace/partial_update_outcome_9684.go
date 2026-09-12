package userspace

import (
	"errors"

	"github.com/psaab/xpf/pkg/config"
)

// #9684: the outcome of a partial update.
//
// update_neighbors (RegenerateNeighborSnapshot, BumpFIBGeneration) and
// update_fabrics (SyncFabricState) write their content into m.lastSnapshot only
// after a successful round trip (#1197, #5306). A failure that is not an in-band
// refusal — a deadline, EOF or response-decode error — can follow a replace the
// helper applied, exactly as it can for apply_snapshot (#9520). The helper then
// holds the new section while m.lastSnapshot still holds the old one.
//
// Every publish that starts from m.lastSnapshot re-sends that old section:
// UpdatePolicyScheduleState, PublishRouteOverlaySnapshot, the #5134 worker-arm
// re-apply (all `next := *m.lastSnapshot`) and syncSnapshotLocked's deferred
// publish. apply_snapshot replaces the helper's whole manager-neighbor key set
// and its fabric rows, so that publish rolls the helper back. For fabrics that is
// the #5306 revert: cross-chassis redirect uses the unresolved peer MAC.
//
// The uncertainty is recorded per section and resolved by sampling again. No
// publish is held, and no extra control round trip is made:
//   - A verb failure whose outcome is unknown marks its section
//     (recordPartialUpdateFailureLocked). An in-band refusal marks nothing,
//     because the helper answered and kept what it had. Neither does a #6034
//     fence the Go ACK check recognises (#9696 tracks one it cannot).
//   - Each publish that starts from m.lastSnapshot re-samples every marked
//     section into the snapshot it sends (resampleUnresolvedSectionsLocked).
//     The sample is taken after the lost update's, so it can only move the
//     helper forward.
//   - A section is unmarked once Go has recorded exactly the copy the helper
//     accepted (resolvePartialOutcomesLocked). That is one of:
//       - a verb round trip whose response proves the update applied; for
//         update_neighbors that means an ACK of exactly the generation sent, or
//         0 from a helper without the ACK. An ACK above it is a #6034 fence the
//         Go check does not yet recognise (#9696), and leaves the section marked;
//       - a successful apply_snapshot that carried a re-sampled copy.
//   - Compile builds its snapshot outside m.mu, so a partial update can run
//     between the build and the publish, and the build's older sample would roll
//     it back whether its response was lost or it landed. So can another publish
//     that re-samples a marked section and clears the mark. Both advance
//     partialUpdateEpoch: every update_neighbors / update_fabrics request, and
//     every re-sample into a publish. Compile reads it before the build; under
//     the lock it re-samples both sections if it moved, and otherwise only the
//     marked ones (resampleForCompileLocked).
//   - A kernel back at m.lastSnapshot's copy says nothing about what the helper
//     holds. So while a section is marked, the shortcuts that infer the helper's
//     content from m.lastSnapshot stand down:
//       - the verbs' neighbor equality check, so the next
//         RegenerateNeighborSnapshot or BumpFIBGeneration re-sends even an
//         unchanged set (SyncFabricState already sends on every call);
//       - PublishRouteOverlaySnapshot's content-hash dedup, and
//         syncSnapshotLocked's generation catch-up and hash dedup, so a re-sample
//         equal to m.lastSnapshot's copy is still published.
//
//     Otherwise the helper keeps the lost update's content for as long as no
//     verb and no changed publish runs.
//   - A fabric re-sample takes every field of the fresh row except the plan half,
//     so no re-sample moves the binding plan (refreshFabricRowsKeepingPlan).
//     The plan half includes ParentIfindex, which the helper also uses as live
//     forwarding identity. A lost update_fabrics that moved it, after a parent
//     netdev was re-created, is therefore still rolled back to the published
//     value by a republish, as it was before #9684. That update_fabrics carries
//     plan fields at all is #9803, where a plan-half change belongs to a full
//     apply that replans both planes.
//     syncSnapshotLocked re-samples only once its XSK-startup plan gate lets the
//     publish proceed, so a deferred tick samples nothing.
//
// Republishing the lost update's own content in place of m.lastSnapshot's
// section does not work: it stops being the latest sample as soon as the kernel
// moves, and the equality check and the daemon neighbor listener's filter then
// suppress the event that would refresh it.

// partialSections is a set of the snapshot sections a partial update replaces.
type partialSections uint8

const (
	partialNeighbors partialSections = 1 << iota
	partialFabrics
)

// recordPartialUpdateFailureLocked marks section unknown after a failed verb
// round trip. Anything but an in-band refusal qualifies, as for apply_snapshot
// (recordApplySnapshotOutcomeLocked). Caller holds m.mu.
func (m *Manager) recordPartialUpdateFailureLocked(section partialSections, err error) {
	if err == nil || errors.Is(err, errHelperRejected) {
		return
	}
	m.partialOutcomeUnknown |= section
}

// partialSectionUnknownLocked reports whether section is marked. Caller holds m.mu.
func (m *Manager) partialSectionUnknownLocked(section partialSections) bool {
	return m.partialOutcomeUnknown&section != 0
}

// resolvePartialOutcomesLocked unmarks sections once Go has recorded exactly the
// copy the helper accepted. Caller holds m.mu.
func (m *Manager) resolvePartialOutcomesLocked(sections partialSections) {
	m.partialOutcomeUnknown &^= sections
}

// resampleUnresolvedSectionsLocked re-samples every marked section of snap, the
// snapshot about to be published (resampleSectionsLocked). Caller holds m.mu.
func (m *Manager) resampleUnresolvedSectionsLocked(snap *ConfigSnapshot) partialSections {
	return m.resampleSectionsLocked(snap, m.partialOutcomeUnknown)
}

// resampleSectionsLocked refreshes sections of snap, the snapshot about to be
// published, from the kernel for snap's own config. It returns the sections it
// refreshed. The caller retains snap's sections as m.lastSnapshot's, and passes
// the result to resolvePartialOutcomesLocked once the publish lands. Caller
// holds m.mu.
//
// Neighbors are replaced wholesale. A fabric row is refreshed in part: it keeps
// its plan half and takes every other field from the sample
// (refreshFabricRowsKeepingPlan). The plan half is the parent interface and
// netdev, the netdev's ifindex and queue count, and the device verdict; the
// binding plan key on both planes and the classifier maps read those. A re-sample therefore never moves the binding
// plan. A change to that half needs the full apply that re-derives both planes
// together, as the device verdict already does (alignFabricVerdicts).
func (m *Manager) resampleSectionsLocked(snap *ConfigSnapshot, sections partialSections) partialSections {
	if sections == 0 || snap == nil || snap.Config == nil {
		// Nothing to sample for. The verbs never mark a section without a
		// config, so a mark cannot be stranded here.
		return 0
	}
	if sections&partialNeighbors != 0 {
		snap.Neighbors = m.sampleNeighborsForLocked(snap.Config)
	}
	if sections&partialFabrics != 0 {
		build := m.fabricSnapshotBuilder
		if build == nil {
			build = buildFabricSnapshots
		}
		snap.Fabrics = refreshFabricRowsKeepingPlan(snap.Fabrics, build(snap.Config))
	}
	// The publish carrying these samples can put newer section content on the
	// helper than a Compile that built its snapshot earlier, and can clear a mark
	// that Compile would otherwise re-sample. Advance the epoch so it re-samples.
	//
	// Only after the samples. Compile reads the epoch outside m.mu, before its
	// build, so a read can land while this is still sampling. That read must see
	// the old epoch. A read of the new one then comes before a build that starts
	// after these samples, and that build's kernel reads are at least as new.
	m.partialUpdateEpoch.Add(1)
	return sections
}

// resampleForCompileLocked re-samples the sections of snap, which Compile built
// outside m.mu, that the helper may hold newer copies of. That is both sections
// if partialUpdateEpoch moved after Compile read it (a partial update was sent,
// or another publish re-sampled a section), and otherwise the marked ones. It
// returns the sections it re-sampled. Caller holds m.mu.
func (m *Manager) resampleForCompileLocked(snap *ConfigSnapshot) partialSections {
	sections := m.partialOutcomeUnknown
	if m.partialUpdateEpoch.Load() != snap.partialUpdateEpoch {
		sections = partialNeighbors | partialFabrics
	}
	return m.resampleSectionsLocked(snap, sections)
}

// refreshFabricRowsKeepingPlan returns published with each row replaced by the
// fresh row of the same fabric, except for the plan half, which stays
// published's: ParentInterface, ParentLinuxName, ParentIfindex, RXQueues and
// ParentUnbindable. Everything else comes from the sample, including the overlay
// netdev the helper recognises fabric ingress by (OverlayLinux, OverlayIfindex),
// the peer address, the MACs and Up. A row with no fresh counterpart is kept,
// and a fresh row with no published counterpart is not added, because the row
// set is part of the plan too.
func refreshFabricRowsKeepingPlan(published, fresh []FabricSnapshot) []FabricSnapshot {
	byName := make(map[string]FabricSnapshot, len(fresh))
	for _, row := range fresh {
		byName[row.Name] = row
	}
	out := make([]FabricSnapshot, len(published))
	copy(out, published)
	for i, plan := range published {
		row, ok := byName[plan.Name]
		if !ok {
			continue
		}
		row.ParentInterface = plan.ParentInterface
		row.ParentLinuxName = plan.ParentLinuxName
		row.ParentIfindex = plan.ParentIfindex
		row.RXQueues = plan.RXQueues
		row.ParentUnbindable = plan.ParentUnbindable
		out[i] = row
	}
	return out
}

// sampleNeighborsLocked samples the kernel neighbor table for m.lastSnapshot's
// config. Caller holds m.mu and has checked m.lastSnapshot is non-nil.
func (m *Manager) sampleNeighborsLocked() []NeighborSnapshot {
	return m.sampleNeighborsForLocked(m.lastSnapshot.Config)
}

// sampleNeighborsForLocked samples the kernel neighbor table for cfg. Caller
// holds m.mu.
func (m *Manager) sampleNeighborsForLocked(cfg *config.Config) []NeighborSnapshot {
	if m.neighborSnapshotBuilder != nil {
		return m.neighborSnapshotBuilder(cfg)
	}
	return buildNeighborSnapshots(cfg)
}

// sampleFabricsLocked re-resolves the fabric rows for m.lastSnapshot's config,
// keeping the applied snapshot's device-level verdicts (alignFabricVerdicts).
// Caller holds m.mu and has checked m.lastSnapshot is non-nil.
func (m *Manager) sampleFabricsLocked() []FabricSnapshot {
	build := m.fabricSnapshotBuilder
	if build == nil {
		build = buildFabricSnapshots
	}
	return alignFabricVerdicts(build(m.lastSnapshot.Config), m.lastSnapshot)
}
