package userspace

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

func (m *Manager) readFIBGeneration() uint32 {
	fibGenMap := m.bpfShim.Map("fib_gen_map")
	if fibGenMap == nil {
		return 0
	}
	var (
		key uint32
		gen uint32
	)
	if err := fibGenMap.Lookup(key, &gen); err != nil {
		return 0
	}
	return gen
}

// bpfKtimeNs returns the current CLOCK_BOOTTIME in nanoseconds, matching
// the clock used by BPF's bpf_ktime_get_ns() for session Created timestamps.
func (m *Manager) bpfKtimeNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func (m *Manager) bumpGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	return m.generation
}

// BumpFIBGeneration updates the BPF FIB generation counter and sends a
// lightweight FIB generation bump to the userspace helper. If kernel neighbors
// changed since the last publish, an incremental neighbor update is sent first.
// This avoids the full buildSnapshot() + apply_snapshot round-trip that was the
// primary source of control socket contention during route convergence.
//
// Error contract (#1844): a non-nil error means the helper-side
// invalidation is NOT confirmed (shim map bump or the
// bump_fib_generation control message failed) — callers with retry
// semantics (the ip-monitoring actuator's pendingFIBBump) must retry.
// The helperless / no-snapshot early returns are SUCCESS (nil): with
// no published snapshot there are no cached flow routes to invalidate,
// and the next full apply carries its own invalidation. A failed
// incremental NEIGHBOR update is deliberately NOT an error — it has
// its own retry semantics (the cached neighbor view is only advanced
// on success, so the next bump re-diffs and re-sends).
func (m *Manager) BumpFIBGeneration() (uint32, error) {
	newGen, shimErr := m.bpfShim.BumpFIBGeneration()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return newGen, nil
	}
	if m.proc == nil || m.proc.Process == nil {
		return newGen, nil
	}

	// Update the cached snapshot's FIB generation without rebuilding.
	m.lastSnapshot.FIBGeneration = newGen
	m.generation++
	m.lastSnapshot.Generation = m.generation

	// #1197 v4 (Codex code-review v3 #1): refresh the monitored
	// ifindex cache UNCONDITIONALLY — link recreation can happen
	// without any neighbor diff (operator unplugs cable, kernel
	// rebinds a VLAN, etc.), and a stale cache silently drops
	// events on the new ifindex until the next config commit.
	m.rebuildMonitoredIfindexes()

	// Check if kernel neighbors changed — if so, push an incremental update.
	// #1197: use forwarding-effective diff so REACHABLE↔STALE aging churn
	// doesn't trigger unnecessary publishes; filter publish payload to
	// publishable-only entries (matches userspace-dp accept rules).
	newNeighbors := m.sampleNeighborsLocked()
	// #9684: an unchanged set is re-sent while an earlier replace's outcome is unknown.
	if !neighborsEqualForwarding(m.lastSnapshot.Neighbors, newNeighbors) || m.partialSectionUnknownLocked(partialNeighbors) {
		publishable := filterPublishableNeighbors(newNeighbors)
		// #6034: stamp a fresh monotonic replace generation (see
		// RegenerateNeighborSnapshot / Manager.neighborReplaceGen).
		m.neighborReplaceGen++
		gen := m.neighborReplaceGen
		var status ProcessStatus
		if err := m.requestLocked(ControlRequest{
			Type:               "update_neighbors",
			Neighbors:          publishable,
			NeighborReplace:    true,
			NeighborGeneration: gen,
		}, &status); err != nil {
			slog.Warn("userspace: failed to publish neighbor update", "err", err)
			m.recordPartialUpdateFailureLocked(partialNeighbors, err)
		} else if status.ManagerNeighborGeneration != 0 && status.ManagerNeighborGeneration < gen {
			// #6034: the helper fenced this replace as stale. Retain the
			// cached neighbor view so the next bump re-diffs and retries
			// with a strictly higher generation. An ACK of 0 = older helper
			// without ACK support, treated as applied.
			slog.Warn("userspace: neighbor update not acknowledged; retaining retry debt",
				"sent_generation", gen,
				"applied_generation", status.ManagerNeighborGeneration)
		} else {
			// Only update cached neighbors after successful publish so
			// a transient failure doesn't suppress future retries.
			m.lastSnapshot.Neighbors = newNeighbors
			m.rebuildNeighborIndex() // #1197
			// #9684: an ACK above gen is an unrecognised fence (#9696); only 0 or
			// exactly gen proves the replace applied.
			if status.ManagerNeighborGeneration == 0 || status.ManagerNeighborGeneration == gen {
				m.resolvePartialOutcomesLocked(partialNeighbors)
			}
		}
	}

	// Send lightweight FIB generation bump — no full snapshot rebuild.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type: "bump_fib_generation",
		Snapshot: &ConfigSnapshot{
			// #3767 H4: the helper now version-gates bump_fib_generation
			// exactly like apply_snapshot. Stamp the protocol version so a
			// legitimate route-only bump is accepted; an unversioned (0)
			// message is rejected as a mixed-version / corrupt client.
			Version:       ProtocolVersion,
			FIBGeneration: newGen,
		},
	}, &status); err != nil {
		slog.Warn("userspace: failed to bump FIB generation", "err", err)
		return newGen, fmt.Errorf("bump fib generation: %w", err)
	}
	return newGen, shimErr
}

// advanceGenerationAfterPartialUpdateLocked performs the post-publish
// bookkeeping shared by the two PARTIAL-update writebacks —
// RegenerateNeighborSnapshot (after `update_neighbors`) and
// persistResolvedFabricsLocked (after `update_fabrics`).
//
// Both mutate one slice of m.lastSnapshot and bump the generation so the
// partial-rebuild publish paths carry the mutation forward. Neither sends an
// apply_snapshot: the helper has the neighbor replace or the fabric update, not
// the full snapshot.
//
// #6986: that is why publishedSnapshot may only be advanced from a state where
// it was ALREADY at the high-water mark.
//
// Compile's pendingXSKStartup branch (manager_compile.go) deliberately stores
// m.lastSnapshot WITHOUT publishing it — the publish is deferred, not skipped —
// which leaves publishedSnapshot < lastSnapshot.Generation. That inequality is
// the level-triggered predicate the status tick uses to drive syncSnapshotLocked
// later. The old unconditional writeback here closed it:
//
//	before:  lastSnapshot.Generation = 10  publishedSnapshot = 7   (gen 10 never sent)
//	regen:   generation++ -> 11; lastSnapshot.Generation = 11; publishedSnapshot = 11
//	after:   publishedSnapshot == lastSnapshot.Generation -> the tick's gate is FALSE
//
// The deferred full snapshot — policies, routes, interfaces, NAT — was then
// never apply_snapshot'd, while the manager's bookkeeping said it had been.
//
// The guard makes that UNREPRESENTABLE rather than rarer: publishedSnapshot can
// only move from a value that already equals the high-water, so it can never
// leapfrog an unpublished generation, on any interleaving. It is not a narrower
// window — there is no window.
//
// lastSnapshotHash is gated by the SAME condition, and that is load-bearing
// rather than tidiness. The hash is a SECOND, independent kill: syncSnapshotLocked
// re-hashes m.lastSnapshot and returns without sending when it matches
// lastSnapshotHash (process_status.go). Refreshing it here from a snapshot that
// was never published would make the dedup gate suppress the publish even if the
// generation gate were open, so fixing only the generation half would leave the
// content swallowed anyway. Left stale, the hash correctly describes the last
// content the helper actually received, and the comparison then differs.
//
// When the full snapshot IS published, the behaviour is unchanged from the
// original Copilot-review rationale: advance both, so the status loop does not
// see the bumped generation as unpublished and force a redundant apply_snapshot,
// and so churn in filtered-out rows cannot leak through the hash dedup.
//
// Caller holds m.mu and has already verified m.lastSnapshot != nil.
func (m *Manager) advanceGenerationAfterPartialUpdateLocked() {
	// Sampled BEFORE the bump: after it, lastSnapshot.Generation has moved and
	// the comparison would be meaningless.
	fullSnapshotWasPublished := m.publishedSnapshot >= m.lastSnapshot.Generation
	m.generation++
	m.lastSnapshot.Generation = m.generation
	if !fullSnapshotWasPublished {
		// A full-snapshot publish is outstanding. Leave publishedSnapshot and
		// lastSnapshotHash alone so the status tick still sees work to do —
		// and so the publish it eventually makes carries THIS partial update
		// too, since it reads the same m.lastSnapshot.
		return
	}
	m.publishedSnapshot = m.lastSnapshot.Generation
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
}
