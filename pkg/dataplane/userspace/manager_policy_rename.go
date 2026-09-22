package userspace

// SetPolicyRenameAncestry stages the provenance and pre-publication verdicts
// for the next full snapshot build. The daemon calls this while holding its
// apply semaphore; Manager copies both slices so the daemon's own input stays
// available for a retry.
func (m *Manager) SetPolicyRenameAncestry(
	ancestry []PolicyRenameAncestry,
	rebinds []PolicySessionRebind,
) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.policyRenameAncestry = append([]PolicyRenameAncestry(nil), ancestry...)
	m.policySessionRebinds = append([]PolicySessionRebind(nil), rebinds...)
	// A newer explicit commit supersedes any deferred-MAC replay debt from an
	// older accepted snapshot. Never let that old attempt leak into this one.
	m.clearDeferredReplayMetadataLocked()
	m.mu.Unlock()
}

// takeStagedRenameMetadataLocked moves the staged single-use commit metadata
// onto the caller and clears staged, so a later full build that is not
// preceded by its own staging cannot re-ship this commit's ancestry and
// rebinds. Every production full build IS preceded by staging: the daemon
// stages before each ApplyConfig, including the same-commit
// reapplyAfterDeferredMAC re-apply. Call with m.mu held.
func (m *Manager) takeStagedRenameMetadataLocked() (ancestry []PolicyRenameAncestry, rebinds []PolicySessionRebind) {
	ancestry = m.policyRenameAncestry
	rebinds = m.policySessionRebinds
	m.policyRenameAncestry = nil
	m.policySessionRebinds = nil
	return ancestry, rebinds
}

func (m *Manager) clearDeferredReplayMetadataLocked() {
	m.deferredReplayAncestry = nil
	m.deferredReplayRebinds = nil
	m.deferredReplayReady = false
	m.deferredReplayInFlight = false
}

// rememberDeferredReplayMetadataLocked records the metadata on the exact full
// snapshot accepted while worker startup was deferred. The daemon's
// same-commit MAC replay may reuse only this tagged attempt, never whatever
// happens to be m.lastSnapshot after an unrelated partial publish.
func (m *Manager) rememberDeferredReplayMetadataLocked(snap *ConfigSnapshot) {
	if snap == nil {
		m.clearDeferredReplayMetadataLocked()
		return
	}
	m.deferredReplayAncestry = append([]PolicyRenameAncestry(nil), snap.PolicyRenameAncestry...)
	m.deferredReplayRebinds = append([]PolicySessionRebind(nil), snap.PolicySessionRebinds...)
	m.deferredReplayReady = true
	m.deferredReplayInFlight = false
}

// RestagePolicyRenameAncestryForReplay restores metadata from the exact
// worker-deferred compile attempt accepted immediately before the daemon's
// same-commit MAC replay. It intentionally does nothing when no such attempt
// is tagged; ordinary later applies must stage their own commit metadata.
func (m *Manager) RestagePolicyRenameAncestryForReplay() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.deferredReplayReady {
		return
	}
	m.policyRenameAncestry = append([]PolicyRenameAncestry(nil), m.deferredReplayAncestry...)
	m.policySessionRebinds = append([]PolicySessionRebind(nil), m.deferredReplayRebinds...)
	// Keep the exact cached attempt until Compile reports success. If snapshot
	// construction or publication fails, a retry can restage the same attempt.
	m.deferredReplayInFlight = true
}

// stripSingleUseCommitMetadata clears the single-use commit metadata from a
// partial-republish snapshot copy. PolicyRenameAncestry and PolicySessionRebinds
// describe exactly one commit's rename; the helper's rotation consumes them on
// full apply's snapshot, so every later partial republish (route overlay,
// policy scheduler, #5134 worker arm, capture-authority refresh — all
// `next := *m.lastSnapshot`) normally ships without them. Without the strip
// a re-admitted same-tuple session is rebound to a stale policy, and an
// unrelated later delete/add evaluates for extensive retention against stale
// ancestry. The explicit Manager pendingFullSnapshotMetadata latch is the
// exception: a partial path can be the first accepted publication after a
// deferred or unknown-outcome full apply and must carry that full snapshot's
// metadata once; the successful publication clears the latch.
func stripSingleUseCommitMetadata(next *ConfigSnapshot) {
	if next == nil {
		return
	}
	next.PolicyRenameAncestry = nil
	next.PolicySessionRebinds = nil
}
