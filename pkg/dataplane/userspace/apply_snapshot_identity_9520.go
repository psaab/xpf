package userspace

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
)

// #9520: apply_snapshot content identity.
//
// A generation used to be the whole identity of an applied snapshot. The helper
// admitted a same-generation apply without looking at its content, flow-cache
// entries are stamped with (generation, fib), and session policy stamps and the
// #8356 re-derivation with the generation alone. Three republish paths
// (UpdatePolicyScheduleState, PublishRouteOverlaySnapshot,
// retryDeferredWorkerArmLocked) send m.generation+1 and commit it only after a
// nil return, while the helper commits an apply before it writes a response
// byte. So a deadline error after a landed apply leaves m.generation behind the
// helper, and the retry REBUILDS its content (routes, scheduler bits) and
// re-sends the landed generation with different content. Compile never reuses a
// generation, but it can collide with that landed one, because the republish
// never advanced m.generation.
//
// The fix has two halves, and neither is enough alone:
//   - every apply_snapshot carries ContentDigest, and the helper refuses a reused
//     generation whose digest differs from the installed snapshot's, before any
//     mutation (userspace-dp/src/server/handlers/snapshot.rs);
//   - that refusal, and only that refusal, proves the helper HOLDS the
//     generation, so requestApplySnapshotLocked consumes it and republishes once
//     on the next one. Without this half the refusal is a non-converging loop:
//     every retry re-sends the same generation and is refused again.

// snapshotContentConflictPrefix is the helper's SNAPSHOT_CONTENT_CONFLICT_PREFIX
// (userspace-dp/src/protocol/control.rs).
// TestSnapshotContentConflictPrefixMatchesTheHelper9520 reads the Rust constant,
// so the two spellings cannot drift apart silently.
const snapshotContentConflictPrefix = "snapshot content conflict at reused generation:"

// isSnapshotContentConflict reports whether err is the helper's in-band refusal
// of an apply that reused its installed generation with different content. Only
// an in-band refusal qualifies: a transport error proves nothing about what the
// helper holds (errHelperRejected).
func isSnapshotContentConflict(err error) bool {
	var rejected *helperRejectedError
	return errors.As(err, &rejected) && strings.HasPrefix(rejected.msg, snapshotContentConflictPrefix)
}

// stampSnapshotContentDigest sets snap.ContentDigest from snapshotContentHash. It
// refuses rather than sending an empty digest: the request body is the JSON
// encoding of the same struct, so a hash that cannot marshal means the request
// cannot either.
func stampSnapshotContentDigest(snap *ConfigSnapshot) error {
	sum, ok := snapshotContentHash(snap)
	if !ok {
		return errors.New("userspace: cannot compute the apply_snapshot content digest")
	}
	snap.ContentDigest = hex.EncodeToString(sum[:])
	return nil
}

// requestApplySnapshotLocked is the ONLY site that sends apply_snapshot
// (TestApplySnapshotHasOneSendSite9520). It stamps the content digest over the
// exact struct being sent. On a content-conflict refusal it consumes the refused
// generation and republishes ONCE on the next one, updating snap.Generation in
// place. A caller commits its bookkeeping from snap.Generation after a nil
// return (adoptPublishedGenerationLocked). Every outcome is recorded by
// recordApplySnapshotOutcomeLocked.
//
// Any other error is returned unchanged and m.generation is left alone. #5134's
// rule that a failed apply must not burn a generation still holds for every
// failure except the one proving the helper has that generation. Only this
// refusal adds a second control round trip under m.mu, and each round trip is
// still bounded by requestDetailedLocked's #8526 deadline. Outside shutdown the
// worst-case m.mu hold on this refusal is therefore two round trips; once
// BeginControlShutdown has latched, the retry is skipped.
func (m *Manager) requestApplySnapshotLocked(snap *ConfigSnapshot, status *ProcessStatus) (err error) {
	if stampErr := stampSnapshotContentDigest(snap); stampErr != nil {
		// Nothing was sent, so the helper's state is known to be unchanged.
		return stampErr
	}
	defer func() { m.recordApplySnapshotOutcomeLocked(err) }()
	err = m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: snap}, status)
	if err == nil || !isSnapshotContentConflict(err) {
		return err
	}
	held := snap.Generation
	if m.generation < held {
		m.generation = held
	}
	if m.controlShutdownLatched() {
		// The process is stopping (#8526): a second round trip would only spend
		// the shutdown budget. The refused generation stays consumed, so nothing
		// re-sends it.
		return err
	}
	snap.Generation = m.generation + 1
	slog.Warn("userspace: helper holds this snapshot generation with different content "+
		"(an earlier publish landed without a response); republishing on the next generation",
		"held_generation", held, "generation", snap.Generation, "err", err)
	err = m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: snap}, status)
	if isSnapshotContentConflict(err) && m.generation < snap.Generation {
		// A second conflict proves the helper holds this generation too. It is not
		// chased with a third round trip, but it is consumed, so the next publish
		// does not re-send it.
		m.generation = snap.Generation
	}
	return err
}

// recordApplySnapshotOutcomeLocked tracks whether the helper may hold content
// this Manager never saw it accept. Only a failure whose outcome is UNKNOWN
// sets it (anything but an in-band refusal: a deadline after the helper applied
// the request is the #4036 case), and only a successful apply clears it. An
// in-band refusal changes nothing, because the helper kept whatever it held,
// which is exactly as known or unknown as before.
//
// While it is set, the publish shortcuts that infer the helper's content from
// Go's own bookkeeping stand down: PublishRouteOverlaySnapshot's content-hash
// dedup, and syncSnapshotLocked's hash dedup and generation-only catch-up. A
// lost response can land content B while m.lastSnapshot and m.lastSnapshotHash
// still describe A, so "unchanged from A" no longer means "what the helper
// holds", and skipping a publish of A would leave B enforced.
func (m *Manager) recordApplySnapshotOutcomeLocked(err error) {
	switch {
	case err == nil:
		m.applySnapshotOutcomeUnknown = false
	case !errors.Is(err, errHelperRejected):
		m.applySnapshotOutcomeUnknown = true
	}
}

// adoptPublishedGenerationLocked records the generation apply_snapshot actually
// carried into the snapshot the caller retains, and never lets m.generation fall
// behind it. requestApplySnapshotLocked moves a snapshot to a fresh generation
// after a content conflict, so a caller that committed the generation it BUILT
// would record one the helper refused.
func (m *Manager) adoptPublishedGenerationLocked(retained *ConfigSnapshot, published uint64) {
	retained.Generation = published
	if m.generation < published {
		m.generation = published
	}
}

// controlShutdownLatched reports whether BeginControlShutdown has run. ctrlIOMu
// is a leaf lock, so reading it while holding m.mu is safe.
func (m *Manager) controlShutdownLatched() bool {
	m.ctrlIOMu.Lock()
	defer m.ctrlIOMu.Unlock()
	return m.ctrlShutdown
}
