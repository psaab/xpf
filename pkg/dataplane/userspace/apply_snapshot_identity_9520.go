package userspace

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"
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
//     generation, so requestApplySnapshotPreparedLocked consumes it and republishes once
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

// errSnapshotDigest marks a snapshot whose content digest cannot be computed.
// The request body marshals the same content, so a snapshot that fails here
// provably never reached the helper: retry is futile and the failure must
// never adopt retry-debt authority (#9642, isKnownUnsentFailure).
var errSnapshotDigest = errors.New("userspace: cannot compute the apply_snapshot content digest")

// stampSnapshotContentDigest sets snap.ContentDigest from snapshotContentHash. It
// refuses rather than sending an empty digest: the request body is the JSON
// encoding of the same struct, so a hash that cannot marshal means the request
// cannot either.
func stampSnapshotContentDigest(snap *ConfigSnapshot) error {
	sum, ok := snapshotContentHash(snap)
	if !ok {
		return errSnapshotDigest
	}
	snap.ContentDigest = hex.EncodeToString(sum[:])
	return nil
}

// prepareSnapshotForApply detaches and revalidates interface rows before
// classification and send, then rebuilds the snapshot sections derived
// from those rows so no derived ifindex can outlive the row it came from
// (#14209).
func (m *Manager) prepareSnapshotForApply(snap *ConfigSnapshot) {
	// #11086: re-resolve interface rows against the live kernel before
	// classification, digest, and send. revalidateSnapshotIfindexes detaches
	// the interface backing array and LinkUp pointers before mutating them.
	if m != nil {
		m.revalidateChangedIfindex = false
	}
	refreshed, dropped := revalidateSnapshotIfindexes(snap)
	if refreshed+dropped > 0 {
		if m != nil {
			m.revalidateChangedIfindex = true
		}
		slog.Info("userspace: snapshot interface rows revalidated at apply",
			"refreshed", refreshed, "dropped", dropped)
		m.rebuildDerivedSectionsAfterRevalidate(snap)
	}
}

// rebuildDerivedSectionsAfterRevalidate re-derives the sections the full
// build computes FROM the interface rows — the interface rows themselves
// (#14333), Routes (connected rows and next-hop qualification read row
// ifindexes/addresses), Fabrics, TunnelEndpoints and
// MirrorConfigs/MirrorExclusions — against the revalidated rows (#14209).
//
// Before this rebuild, revalidation refreshed only Interfaces: a link
// recreated between build and apply shipped a current ingress row joined
// to tunnel/mirror egress rows carrying the OLD ifindex (Rust consumes
// the tunnel endpoint's own ifindex in forwarding_build/tunnels.rs), and
// a vanished link kept its connected route and mirror. It also shipped
// the build-time link metadata: revalidation discarded the live MTU, MAC
// and addresses, and a row built while its link was absent (Ifindex 0)
// was never stamped with an EgressZone, because stampEgressZones skips
// Ifindex<=0 rows (#14333). The link-event refresh
// (RefreshInterfaceRowsForLink) already rebuilds exactly these sections
// after revalidating; the normal apply now does the same, from the same
// builders, so the two paths cannot drift.
// The rebuild runs ONLY when revalidation actually moved a row, and only
// when the snapshot carries its Config: without a config there is nothing
// to derive from, and a hand-built snapshot's derived rows are its
// author's own. When it runs, the freshly rebuilt rows are re-quarantined
// (quarantineCollidingZones unzones tunnel endpoints of quarantined
// zones) and ZoneSetValidated is recomputed exactly as
// RefreshInterfaceRowsForLink does, so a rebuild can never resurrect a
// quarantined zone's tunnel or stale validation state. A route build
// error keeps the previously derived rows: they were built from the same
// config, and failing the apply over a transient kernel enumeration
// error would discard a snapshot whose interface rows are already
// correct — the stale-derived window stays bounded by the next apply.
//
// Fabrics use buildFabricSnapshotsFrom against the fresh xfrm sample
// taken above, NOT the plan-preserving resample: the binding plan key is
// computed AFTER prepareSnapshotForApply at every caller, so a fabric
// parent ifindex that moved with a recreated link moves the plan key
// with it and both planes replan together.
func (m *Manager) rebuildDerivedSectionsAfterRevalidate(snap *ConfigSnapshot) {
	if snap == nil || snap.Config == nil {
		return
	}
	cfg := snap.Config
	liveXfrm, xfrmDumpFailed := sampleLiveXfrmNetdevs()
	snap.xfrmDumpFailed = xfrmDumpFailed
	// #14333: rebuild the interface rows themselves, exactly as
	// RefreshInterfaceRowsForLink does. Revalidation refreshed only
	// Ifindex/ParentIfindex/LinkUp and discarded the live MTU, MAC and
	// addresses from buildLinkSnapshot, and stampEgressZones skips
	// Ifindex<=0 rows at build time — so a link that materialized
	// (0 -> N) in the build->apply window shipped with EgressZone "",
	// empty HardwareAddr, stale/empty Addresses and build-time RXQueues.
	// A full rebuild restamps every link-derived field from the same
	// builders the full build uses, so the two paths cannot drift.
	// The rebuilt rows are freshly built and not shared, so they are
	// revalidated in place once (no second detach) before deriving.
	// Only a config that actually describes interface rows may replace
	// them: a hand-built snapshot carrying rows its empty/foreign Config
	// does not describe keeps its author's rows (revalidated above).
	if snapshotHasInterfaceRows(cfg) {
		snap.Interfaces = buildInterfaceSnapshotsFrom(cfg, liveXfrm)
		snap.wgFanUpBaseRows = wgFanUpBaseRows(cfg)
		if refreshed, dropped := revalidateSnapshotIfindexesInPlace(snap); refreshed+dropped > 0 {
			if m != nil {
				m.revalidateChangedIfindex = true
			}
			slog.Info("userspace: rebuilt snapshot interface rows revalidated at apply",
				"refreshed", refreshed, "dropped", dropped)
		}
	}
	if routes, capped, err := buildRouteSnapshots(cfg, snap.Interfaces, m.routeOverlayForSnapshot(snap)); err != nil {
		slog.Warn("userspace: keeping prior routes after apply-time rebuild failure (#14209)",
			"err", err)
	} else {
		snap.Routes = routes
		snap.LearnedRouteImportCapped = capped
	}
	snap.Fabrics = buildFabricSnapshotsFrom(cfg, liveXfrm)
	snap.TunnelEndpoints = buildTunnelEndpointSnapshots(cfg, snap.Interfaces)
	snap.MirrorConfigs, snap.MirrorExclusions = buildMirrorConfigSnapshots(cfg, snap.Interfaces)
	// #14964: preserve both full-build quarantines on this snapshot rebuild.
	// Detach NAT rows before the reporter mutates only this publish copy.
	snap.SourceNAT = append([]SourceNATRuleSnapshot(nil), snap.SourceNAT...)
	publishedZonesBefore := append([]ZoneSnapshot(nil), snap.Zones...)
	priorCollisions := snap.zoneIDCollisions
	priorValidated := snap.ZoneSetValidated
	collisions := quarantineCollidingZones(snap)
	if len(collisions) > 0 {
		snap.zoneIDCollisions = collisions
		snap.Summary.ZoneCount = len(snap.Zones)
		snap.Summary.PolicyCount = len(snap.Policies)
	}
	sameZones := len(snap.Zones) == len(publishedZonesBefore)
	if sameZones {
		for i := range snap.Zones {
			if snap.Zones[i].Name != publishedZonesBefore[i].Name || snap.Zones[i].ID != publishedZonesBefore[i].ID {
				sameZones = false
				break
			}
		}
	}
	if sameZones && len(priorCollisions) > 0 {
		snap.zoneIDCollisions = priorCollisions
	}
	if sameZones {
		snap.ZoneSetValidated = priorValidated && len(snap.Zones) > 0
	} else {
		snap.ZoneSetValidated = len(snap.Zones) > 0 && len(snap.zoneIDCollisions) == 0
	}
	reportInterfaceSNATPoolOverlaps(snap)
}

// requestApplySnapshotLocked prepares interface rows before sending the snapshot.
func (m *Manager) requestApplySnapshotLocked(snap *ConfigSnapshot, status *ProcessStatus) error {
	m.prepareSnapshotForApply(snap)
	m.consumeRevalidateAttachLocked(snap)
	return m.requestApplySnapshotPreparedLocked(snap, status)
}

// consumeRevalidateAttachLocked runs the pre-publish XDP attach reconcile
// when the most recent prepareSnapshotForApply revalidation moved a row to
// a recreated/materialized ifindex, and clears the flag (#15042). Every
// publisher that sends through requestApplySnapshotLocked or
// requestApplySnapshotPreparedLocked must consume it: before this, only
// applyCompiledSnapshot did, so a non-Compile republish (route-overlay,
// policy-scheduler, capture-authority, deferred worker-arm, deferred sync)
// adopted the new ifindex into lastSnapshot+hash without attaching, and
// the later link refresh then deduped on that hash before its own attach
// reconcile — leaving the interface unshimmed (fail-closed transit loss)
// until the next full Compile. Attach failure is fail-closed and does not
// fail the publish (see reconcileInterfaceAttachmentsForRefreshLocked).
// Caller holds m.mu.
func (m *Manager) consumeRevalidateAttachLocked(snap *ConfigSnapshot) {
	if m == nil || !m.revalidateChangedIfindex {
		return
	}
	m.reconcileInterfaceAttachmentsForRefreshLocked(snap)
	m.revalidateChangedIfindex = false
}

// requestApplySnapshotPreparedLocked is the ONLY site that sends apply_snapshot
// (TestApplySnapshotHasOneSendSite9520). Its caller has already detached and
// revalidated Interfaces when plan-key classification needs that sample;
// requestApplySnapshotLocked performs that preparation for other publishers.
// This function stamps the content digest over the exact struct being sent. On
// a content-conflict refusal it consumes the refused generation and republishes
// ONCE on the next one, updating snap.Generation in place. A caller commits its
// bookkeeping from snap.Generation after a nil return
// (adoptPublishedGenerationLocked). Every outcome is recorded by
// recordApplySnapshotOutcomeLocked.
//
// Any other error is returned unchanged and m.generation is left alone. #5134's
// rule that a failed apply must not burn a generation still holds for every
// failure except the one proving the helper has that generation. Only this
// refusal adds a second control round trip under m.mu, and each round trip is
// still bounded by requestDetailedLocked's #8526 deadline. Outside shutdown the
// worst-case m.mu hold on this refusal is therefore two round trips; once
// BeginControlShutdown has latched, the retry is skipped.
func (m *Manager) requestApplySnapshotPreparedLocked(snap *ConfigSnapshot, status *ProcessStatus) (err error) {
	if stampErr := stampSnapshotContentDigest(snap); stampErr != nil {
		// Nothing was sent, so the helper's state is known to be unchanged.
		return stampErr
	}
	defer func() { m.recordApplySnapshotOutcomeLocked(err) }()
	// #15093: if this snapshot re-introduces scheduled policy after a
	// no-schedule era, send the heartbeat BEFORE the apply so the helper
	// never publishes the new snapshot against a stale lease. Best-effort:
	// an old helper rejects the verb and the snapshot still applies; the
	// post-apply seed below then runs as before.
	preHeartbeat := m.snapshotReintroducesScheduledLocked(snap)
	if preHeartbeat {
		m.sendSchedulerHeartbeatLocked()
	}
	err = m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: snap}, status)
	if err == nil {
		m.recordSchedulerSnapshotAppliedLocked(snap)
		return nil
	}
	if !isSnapshotContentConflict(err) {
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
	if err == nil {
		m.recordSchedulerSnapshotAppliedLocked(snap)
	}
	if isSnapshotContentConflict(err) && m.generation < snap.Generation {
		// A second conflict proves the helper holds this generation too. It is not
		// chased with a third round trip, but it is consumed, so the next publish
		// does not re-send it.
		m.generation = snap.Generation
	}
	return err
}

// snapshotHasScheduledPolicies reports whether the snapshot carries any
// scheduler-bound policy rule.
func snapshotHasScheduledPolicies(snap *ConfigSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, policy := range snap.Policies {
		if policy.SchedulerName != "" {
			return true
		}
	}
	return false
}

// snapshotReintroducesScheduledLocked reports whether this snapshot brings
// scheduled policy back after a no-schedule era that had heartbeats
// (#15093). The previous published snapshot's scheduled presence is
// tracked in hasScheduledPolicySnapshot, which
// recordSchedulerSnapshotAppliedLocked updates on every successful apply
// (including no-schedule applies). A zero policySchedulerVersion means no
// scheduled snapshot ever succeeded, so there is no stale stamp to rebase
// and the helper's version-zero lease never expires — no pre-send.
func (m *Manager) snapshotReintroducesScheduledLocked(snap *ConfigSnapshot) bool {
	return snapshotHasScheduledPolicies(snap) && !m.hasScheduledPolicySnapshot &&
		m.policySchedulerVersion != 0
}

// sendSchedulerHeartbeatLocked bumps the publication version and sends one
// best-effort heartbeat. A refused verb (old helper) leaves the version
// bumped — the helper ignores unknown verbs without state change, and the
// next successful heartbeat reuses the version — but does not advance the
// successful-send timestamp.
func (m *Manager) sendSchedulerHeartbeatLocked() {
	if m.policySchedulerVersion < ^uint64(0) {
		m.policySchedulerVersion++
	}
	if m.policySchedulerVersion == 0 {
		m.policySchedulerVersion = 1
	}
	if err := m.requestLocked(ControlRequest{
		Type:           "scheduler_heartbeat",
		Version:        m.policySchedulerVersion,
		SuppressStatus: true,
	}, nil); err == nil {
		m.lastSchedulerHeartbeatAt = time.Now()
	}
}

// recordSchedulerSnapshotAppliedLocked seeds a fresh dataplane lease after a
// successful scheduled-policy snapshot. The extra control verb is best-effort:
// older helpers reject it, while the accepted snapshot remains successful.
func (m *Manager) recordSchedulerSnapshotAppliedLocked(snap *ConfigSnapshot) {
	hasScheduledPolicies := snapshotHasScheduledPolicies(snap)
	m.hasScheduledPolicySnapshot = hasScheduledPolicies
	if !hasScheduledPolicies {
		return
	}
	m.sendSchedulerHeartbeatLocked()
}

// recordApplySnapshotOutcomeLocked tracks whether the helper may hold content
// this Manager never saw it accept. Only a failure whose outcome is UNKNOWN
// sets it (anything but a normal pre-teardown in-band refusal: a deadline after
// the helper applied the request is the #4036 case, and a post-teardown refusal
// is #10702), and only a successful apply clears it. Normal in-band refusals
// change nothing, because the helper kept whatever it held, which is exactly as
// known or unknown as before. A deterministic-local failure
// (isKnownUnsentFailure: digest, marshal, size, unconfigured socket) likewise
// changes nothing — the helper provably received nothing, so there is no new
// uncertainty. That distinction is load-bearing for retry debt (#9642): a
// deferred-but-unpublished snapshot plus a deterministic failure must keep
// today's revert-to-old behavior, not open a latch no transport failure backs.
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
		m.retryDebtSince = time.Time{}
		m.lastRetryDebtWarn = time.Time{}
	case errors.Is(err, errHelperRejected):
		// Helper provably kept its prior state: no new uncertainty.
	case isKnownUnsentFailure(err):
		// Helper provably received nothing: no new uncertainty. Pre-existing
		// debt (and its timestamps) survive untouched — a deterministic retry
		// failure neither settles nor refreshes unknown state.
	default:
		// Unknown outcome (parent review round 2: stamp the debt clock on
		// EVERY mark-setting transition, not just the adopt arm — a
		// direct-producer failure later converted by a partial success
		// opens the latch with no adoption in between, and its recovery
		// log must report a real age, not the zero time).
		if !m.applySnapshotOutcomeUnknown {
			m.retryDebtSince = time.Now()
		}
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
