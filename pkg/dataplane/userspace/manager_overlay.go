package userspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// routeOverlaySnapshot returns a copy of the cached ip-monitoring
// route overlay.
func (m *Manager) routeOverlaySnapshot() []config.RouteOverlayEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneRouteOverlay(m.routeOverlay)
}

// routeOverlayForSnapshot returns the route overlay this snapshot's
// Routes were built with, for the apply-time derived-section rebuild
// (#14209, #16640). The full builder records it on the snapshot
// (builtRouteOverlay), so a fresh Compile snapshot — whose Config is
// not yet the retained applied config — rebuilds with the overlay it
// was actually built with, not nil. A snapshot with no recorded build
// (hand-built, or a retained clone whose Routes a partial publisher
// rebuilt from an explicit overlay that publisher records itself)
// falls back to the retained-config identity check: only a snapshot
// whose Config is the retained applied config may re-apply the
// manager's current overlay, because m.routeOverlay may have moved
// since any other snapshot was built. Caller holds m.mu (every
// prepareSnapshotForApply caller does).
func (m *Manager) routeOverlayForSnapshot(snap *ConfigSnapshot) []config.RouteOverlayEntry {
	if snap == nil {
		return nil
	}
	if snap.builtRouteOverlay != nil {
		return cloneRouteOverlay(snap.builtRouteOverlay)
	}
	if m == nil || m.lastSnapshot == nil || snap.Config != m.lastSnapshot.Config {
		return nil
	}
	return cloneRouteOverlay(m.routeOverlay)
}

func cloneRouteOverlay(overlay []config.RouteOverlayEntry) []config.RouteOverlayEntry {
	if overlay == nil {
		return nil
	}
	out := make([]config.RouteOverlayEntry, len(overlay))
	copy(out, overlay)
	return out
}

// SetRouteOverlay caches the ip-monitoring effective-route overlay for
// the next full snapshot build WITHOUT publishing. The daemon calls
// this at the top of applyConfigLocked (holding applySem) so an
// operator commit while a policy is FAILED rebuilds routes with the
// active overlay instead of wiping the injected route (#1827, AGY
// r2-2).
func (m *Manager) SetRouteOverlay(overlay []config.RouteOverlayEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routeOverlay = cloneRouteOverlay(overlay)
}

// feedSnapshotOverlay returns a deep copy of the cached dynamic-address
// feed-prefix overlay (#2049). Read under m.mu, mirroring
// routeOverlaySnapshot, so the full snapshot build sees a stable view.
func (m *Manager) feedSnapshotOverlay() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneFeedOverlay(m.feedOverlay)
}

func cloneFeedOverlay(overlay map[string][]string) map[string][]string {
	if overlay == nil {
		return nil
	}
	out := make(map[string][]string, len(overlay))
	for name, prefixes := range overlay {
		cp := make([]string, len(prefixes))
		copy(cp, prefixes)
		out[name] = cp
	}
	return out
}

// SetFeedSnapshots caches the dynamic-address feed-prefix overlay for the
// next full snapshot build WITHOUT publishing (#2049). The daemon calls this
// at the top of applyConfigLocked (holding applySem) with the live feed
// snapshots joined to the address-name bindings, so an operator commit OR a
// feed onUpdate rebuilds the address book with the current feed prefixes.
// Mirrors SetRouteOverlay. The overlay is deep-copied so the caller may reuse
// or mutate its map afterwards.
func (m *Manager) SetFeedSnapshots(overlay map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feedOverlay = cloneFeedOverlay(overlay)
}

// PublishRouteOverlaySnapshot republishes the userspace snapshot with
// the routes section rebuilt under the given ip-monitoring overlay
// (#1827 PR-1b §4.3, modeled on the policy-scheduler partial republish
// above). It must NOT call Compile (which detaches links / restarts
// the helper): it clones lastSnapshot, refreshes Routes via
// buildRouteSnapshots with the overlay, bumps the generation, and
// reuses the apply_snapshot hash/publish bookkeeping. An overlay whose
// snapshot content is identical to the last published one is skipped
// (duplicate-publish skip) and reported as success.
//
// Ordering contract (AGY r2-1): the caller (the daemon's routes-only
// actuator) must call BumpFIBGeneration ONLY after this returns
// published=true with a nil error — bumping before the helper has the
// new routes would re-resolve flows against the OLD routes and the
// later snapshot would not re-invalidate them; bumping after a
// duplicate-skip would churn established-flow route caches for
// nothing (Codex PR #1843 MED).
//
// A non-nil schedulerState stages the desired active-state map and rebuilds
// this publish's Policies / AddressBooks from it in the SAME snapshot
// (#5328 A6-b2-F4), so the helper never enforces stale schedule bits between
// overlay publishes. The applied/show cache advances only after that snapshot
// is accepted; nil keeps the current desired state and the inherited
// (last-compiled) policy sections.
func (m *Manager) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (bool, error) {
	return m.PublishRouteOverlaySnapshotWithLatch(cfg, overlay, schedulerState, false)
}

// PublishRouteOverlaySnapshotWithLatch also carries the scheduler's
// fail-closed disposition into the policy rebuild. ActiveState is deliberately
// false while latched; without this bit a route-only republish would mark
// scheduled DENY/REJECT rules inactive and renew the helper lease around them.
func (m *Manager) PublishRouteOverlaySnapshotWithLatch(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool, failClosed bool) (published bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wasDebt := m.snapshotRetryDebtLocked()

	// #3760: do NOT advance the cached desired overlay before the publish
	// is known not to have failed. buildRouteSnapshots below builds
	// against this local copy; m.routeOverlay is committed only on a
	// non-error return (deferred commit). A failed apply_snapshot
	// therefore leaves m.routeOverlay at the last-applied baseline, so
	// the next actuator sweep rebuilds the same new routes, sees a hash
	// mismatch against the still-old lastSnapshotHash, and re-publishes
	// (#3757 dirty-retry contract). Mirrors the mutate-after-success
	// pattern (#3766/#3742/#3757): the cache never records an overlay the
	// dataplane never accepted. The nil-error early returns below
	// (no published snapshot yet, helper not running) still commit the
	// overlay so the next full apply carries it; the duplicate-skip
	// return commits a content-equivalent overlay.
	desiredOverlay := cloneRouteOverlay(overlay)
	defer func() {
		if err == nil {
			m.routeOverlay = desiredOverlay
		}
	}()

	schedulerCopy := copyPolicySchedulerActiveState(schedulerState)
	if schedulerState != nil {
		m.policySchedulerDesired = schedulerCopy
		m.policySchedulerDesiredSet = true
		m.policySchedulerDesiredFailClosed = failClosed
	}

	if cfg == nil {
		if m.lastSnapshot == nil {
			return false, nil
		}
		cfg = m.lastSnapshot.Config
	}
	if cfg == nil || m.lastSnapshot == nil {
		// No published snapshot yet: the overlay is cached (deferred
		// commit) and the next full apply will carry it.
		return false, nil
	}
	if m.proc == nil || m.proc.Process == nil {
		// #16643: the helper is down, so nothing is enforced right now —
		// but the restart path replays m.lastSnapshot verbatim
		// (syncSnapshotLocked). Returning (false, nil) here commits the
		// overlay cache (deferred commit above) while the retained
		// snapshot keeps the old routes, and daemon_ipmon treats
		// !published && !pendingFIBBump as converged — so the failover
		// route would be missing from the restarted helper's FIB until
		// the next ipmon transition or commit. Fold the desired routes
		// (and any scheduler sections this call carries) into the
		// retained snapshot, without advancing published/applied
		// bookkeeping, so the restart replay carries them. The #5680
		// hybrid guard is enforced inside the scheduler rebuild and by
		// the explicit check mirroring the helper-up path below for
		// route-only folds; a refused fold returns an error, which also
		// suppresses the deferred overlay commit so the actuator stays
		// dirty and retries.
		if schedulerState == nil && routeOnlyPublishHybrid(cfg, m.lastSnapshot.Config) {
			return false, fmt.Errorf("refusing route-only publish: cfg content differs from the applied " +
				"snapshot; publishing would ACK a config whose snapshot sections were not rebuilt (#5680)")
		}
		next, _ := m.cloneRetainedSnapshotLocked()
		next.Config = cfg
		// Stash the desired overlay for the duration of the fold only:
		// prepareSnapshotForApply may rebuild Routes via
		// routeOverlayForSnapshot (retained-config snapshots read
		// m.routeOverlay, #16606), and it must see the NEW overlay, not
		// the last-applied one. Restored before return; the deferred
		// commit above installs it for real on a nil error.
		savedOverlay := m.routeOverlay
		m.routeOverlay = desiredOverlay
		m.prepareSnapshotForApply(&next)
		m.routeOverlay = savedOverlay
		next.TunnelEndpoints = append([]TunnelEndpointSnapshot(nil), next.TunnelEndpoints...)
		for i := range next.TunnelEndpoints {
			next.TunnelEndpoints[i].LinkUp = snapshotLinkUp(next.TunnelEndpoints[i].LinuxName)
		}
		resampled := m.resampleUnresolvedSectionsLocked(&next) // #9684
		var routeErr error
		next.Routes, next.LearnedRouteImportCapped, routeErr = buildRouteSnapshotsWithRGPrimary(cfg, next.Interfaces, desiredOverlay, m.rgPrimaryNowLocked())
		if routeErr != nil {
			return false, fmt.Errorf("build route overlay snapshot: %w", routeErr)
		}
		next.builtRouteOverlay = cloneRouteOverlay(desiredOverlay)
		next.Interfaces = markConnectedRGPeerOwned(cfg, next.Interfaces, m.rgPrimaryNowLocked())
		if schedulerState != nil {
			if err := m.rebuildScheduledPolicySectionsWithLatchLocked(&next, cfg, schedulerCopy, failClosed); err != nil {
				return false, fmt.Errorf("build policy overlay snapshot for scheduler state: %w", err)
			}
			next.schedulerActiveState = copyPolicySchedulerActiveState(schedulerCopy)
			next.schedulerActiveStateSet = true
			next.schedulerFailClosed = failClosed
		}
		m.recordPolicyContentRejectionLocked(next.Capabilities.PolicyContentRejected)
		m.refreshCaptureAuthorityLocked(&next)
		// Retained-only fold: not a publication (see the scheduler fold
		// in manager_compile.go). published=false with a nil error still
		// reads "converged" to the actuator, which is now true: the
		// restart replay carries these routes, so no FIB bump is owed
		// for content the helper does not yet hold.
		_ = resampled
		m.bumpRetainedGenerationLocked(&next)
		m.adoptPublishedGenerationLocked(&next, next.Generation)
		m.lastSnapshot = &next
		m.rebuildNeighborIndex()
		m.rebuildMonitoredIfindexes()
		return false, nil
	}

	// #5680: fail-closed partial-publish guard. A route-only publish rebuilds
	// Routes and inherits the rest of m.lastSnapshot, including compiled policy
	// and secret-derived sections such as the SYN-cookie ring. Stamping
	// next.Config = cfg and calling markAppliedSnapshotLocked would advance the
	// applied identity to content the helper does NOT enforce if cfg contains a
	// helper-visible change that was not included in the retained snapshot (for
	// example, a new policy or auth key whose full apply failed). That would ACK
	// a hybrid as the newly applied config.
	//
	// This is the #5679 residual: an ordinary d.dp.ApplyConfig failure captures
	// applyErr and continues (fail-closed but complete) WITHOUT advancing
	// m.lastSnapshot, while store.Commit has already promoted the NEW cfg. The
	// tail route-leak republish (reconcileRouteLeakSnapshot) and the
	// ip-monitoring actuator then call this with the NEW cfg. Refuse the publish
	// (fail-closed) so the applied identity never advances past the snapshot the
	// dataplane actually enforces; the OLD, fully-consistent snapshot stays live
	// and the caller reconverges once a full apply republishes the config
	// (reconcileRouteLeakSnapshot warns; the ipmon actuator stays dirty and
	// retries). The deferred m.routeOverlay commit above is gated on err == nil,
	// so a refused publish also leaves the desired-overlay cache at its
	// last-applied baseline (the #3760 mutate-after-success contract).
	//
	// In EVERY legitimate route-only publish cfg IS the applied config: the
	// ip-monitoring actuator passes store.ActiveConfig() and the route-leak
	// reconcile passes the just-applied cfg, both pointer-identical to
	// m.lastSnapshot.Config (ApplyConfig stores the exact object ActiveConfig
	// returns). The pointer check short-circuits that common fast path; the
	// content fallback only rejects a genuinely divergent config, never a
	// distinct-but-equal one.
	if routeOnlyPublishHybrid(cfg, m.lastSnapshot.Config) {
		return false, fmt.Errorf("refusing route-only publish: cfg content differs from the applied " +
			"snapshot; publishing would ACK a config whose snapshot sections were not rebuilt (#5680)")
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(m.lastSnapshot); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing overlay publish",
				"protocol_err", err, "err", disarmErr)
		}
		return false, fmt.Errorf("refusing route overlay publish to incompatible helper: %w", err)
	}

	next, _ := m.cloneRetainedSnapshotLocked()
	// #16153 (P3): clone/bump/hash/dedup/adopt bookkeeping is the shared
	// partial-publisher pipeline (manager_partial_publish.go); this
	// publisher keeps only its prep (route rebuild, scheduler rebuild,
	// capture refresh) and its dedup predicate. The clone preserves the
	// single-use rename metadata when the pending-full-snapshot latch
	// says this overlay can be the first accepted publication (a FIB
	// bump advancing lastSnapshot.Generation does not consume a full
	// snapshot, so generation inequality cannot decide this).
	nextGeneration := m.bumpRetainedGenerationLocked(&next)
	_ = nextGeneration
	next.Config = cfg
	// Revalidate once before route derivation and content dedup. This isolated
	// sample is also the interface state sent if the snapshot is published.
	m.prepareSnapshotForApply(&next)
	// Tunnel endpoint link state also controls route-only ECMP liveness.
	next.TunnelEndpoints = append([]TunnelEndpointSnapshot(nil), next.TunnelEndpoints...)
	for i := range next.TunnelEndpoints {
		next.TunnelEndpoints[i].LinkUp = snapshotLinkUp(next.TunnelEndpoints[i].LinuxName)
	}
	resampled := m.resampleUnresolvedSectionsLocked(&next) // #9684
	// #3772 (M9): a transient ip-rule enumeration failure aborts the
	// overlay publish (fail-closed). The deferred commit above leaves
	// m.routeOverlay at the last-applied baseline on a non-nil err, so the
	// next actuator sweep rebuilds and re-publishes (#3757 dirty-retry).
	// #9054: recompute the cap flag on THIS build, never inherit it. `next :=
	// *m.lastSnapshot` copies the previous value, and a route-only republish is
	// exactly when the kernel table size can have crossed the cap in either
	// direction — the #7437 rtnetlink listener drives one on every route change.
	// Carrying a stale `true` keeps the helper delegating NoRoute after the
	// table shrank back under the cap; carrying a stale `false` re-opens the
	// blackhole this issue is about.
	next.Routes, next.LearnedRouteImportCapped, err = buildRouteSnapshotsWithRGPrimary(cfg, next.Interfaces, desiredOverlay, m.rgPrimaryNowLocked())
	if err != nil {
		return false, fmt.Errorf("build route overlay snapshot: %w", err)
	}
	next.builtRouteOverlay = cloneRouteOverlay(desiredOverlay)
	next.Interfaces = markConnectedRGPeerOwned(cfg, next.Interfaces, m.rgPrimaryNowLocked())

	// #5328 (A6-b2-F4): when the caller supplies a policy-scheduler active-state
	// map, refresh the policy snapshot's inactive bits from that map in THIS
	// publish — the doc contract above promised it, and daemon_ipmon.go passes
	// a live scheduler.ActiveState() here. The desired map is staged above;
	// m.policySchedulerActive remains the APPLIED/show view until this snapshot
	// succeeds. Before this fix only m.policySchedulerActive was cached (above)
	// while `next := *m.lastSnapshot` inherited the PRIOR compiled
	// Policies / AddressBooks verbatim, so the helper enforced stale schedule
	// bits while this publish reported success — until the dedicated
	// UpdatePolicyScheduleState callback next fired. Rebuild exactly as the
	// scheduler-only republish does, via the shared
	// rebuildScheduledPolicySectionsLocked (which reuses the cached feed overlay
	// AND re-applies the StableZoneID zone quarantine's policy scrub so a rebuilt
	// policy never dangles against the inherited, already-reduced next.Zones —
	// #6480). Placed BEFORE the duplicate-skip hash below so a scheduler-only
	// bit flip on unchanged routes is not falsely deduped. A nil schedulerState
	// leaves the inherited policy sections untouched (the route-apply caller that
	// never carries scheduler state).
	if schedulerState != nil {
		if err := m.rebuildScheduledPolicySectionsWithLatchLocked(&next, cfg, schedulerCopy, failClosed); err != nil {
			return false, fmt.Errorf("build policy overlay snapshot for scheduler state: %w", err)
		}
		next.schedulerActiveState = copyPolicySchedulerActiveState(schedulerCopy)
		next.schedulerActiveStateSet = true
		next.schedulerFailClosed = failClosed
	}
	// #10500: scheduler-aware overlay rebuilds recompute the diagnostic;
	// route-only republishes inherit the current caps. Record before the
	// duplicate skip so the manager stamp converges even without wire I/O.
	m.recordPolicyContentRejectionLocked(next.Capabilities.PolicyContentRejected)

	m.refreshCaptureAuthorityLocked(&next)
	// #15955/#16153: build the final publish snapshot BEFORE the dedup
	// compare and hash it once (preparePrehashedPublish). Nothing below
	// mutates the hashed content before the send:
	// disarmBeforeUnsupportedPublishLocked only reads it,
	// consumeRevalidateAttachLocked only attaches XDP programs, and the
	// send site's only mutation before the wire is the ContentDigest stamp
	// itself (zeroed inside the hash) plus, on a content conflict, the
	// Generation bump (also zeroed). The single hash therefore serves the
	// dedup compare, the digest stamp, and — via postPublishHash, because
	// the send spends ClearPolicies after stamping and that marker is NOT
	// hash-zeroed — the lastSnapshotHash recorded on success.
	pub := preparePrehashedPublish(&next)
	publishSnap := pub.snap
	// Duplicate-publish skip: identical content (e.g. the actuator ran
	// twice for the same overlay) does not need a control-socket
	// round-trip. The content hash excludes Generation/FIBGeneration.
	// Route dedup predicate = the shared dedupHit (hash match + both
	// unknown-outcome stand-downs, #9520/#9684); the capture publisher
	// below ANDs an extra publishedSnapshot arm — the predicates differ
	// deliberately and are characterization-pinned (#16153).
	if m.dedupHit(pub) {
		// #15042: even on a dedup skip, a revalidation that moved a row
		// must attach its recreated ifindex before adopting next's hash.
		m.consumeRevalidateAttachLocked(&next)
		slog.Debug("userspace: route overlay publish skipped (content unchanged)")
		// No wire change was needed; the helper already enforces content
		// equivalent to next, so commit scheduler metadata as converged.
		if schedulerState != nil {
			m.commitPolicySchedulerActiveStateFromSnapshotLocked(&next)
		}
		return false, nil
	}

	var status ProcessStatus
	// #2124: disarm before publishing an unsupported-config snapshot.
	if err := m.disarmBeforeUnsupportedPublishLocked(&next); err != nil {
		return false, err
	}
	m.consumeRevalidateAttachLocked(&publishSnap)
	if err := m.requestApplySnapshotPrehashedLocked(&publishSnap, &status, pub.hash, pub.hashOK); err != nil {
		return false, fmt.Errorf("publish route overlay snapshot: %w", err)
	}
	// The helper accepted the overlay snapshot, so commit any scheduler state
	// it carries to the applied/show cache. Error returns above leave that
	// cache at the previous enforced state. #9520: adopt commits the
	// generation apply_snapshot carried, which a content-conflict
	// republish moves past nextGeneration.
	pub.snap = publishSnap
	m.adoptPublishedSnapshotLocked(&next, pub, "route-overlay", wasDebt, resampled)
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: failed to sync helper status after route overlay publish", "err", err)
	}
	slog.Info("userspace: route overlay snapshot published",
		"generation", next.Generation, "overlay_routes", len(desiredOverlay))
	return true, nil
}

// RepublishCurrentCaptureAuthority republishes the manager's retained snapshot
// with the current capture provider result. It is the rollback-heal surface:
// it clones retained authority, updates generation/time and capture-authority
// fields, and revalidates interface rows before the content-hash dedup. It does
// not rebuild routes or policy sections; the standard #9684 unresolved-partial
// repair remains so an unknown partial update cannot be rolled back.
func (m *Manager) RepublishCurrentCaptureAuthority() (bool, error) {
	if m == nil {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil ||
		m.captureEpochProvider == nil {
		return false, nil
	}
	wasDebt := m.snapshotRetryDebtLocked()
	next, _ := m.cloneRetainedSnapshotLocked()
	// #16153 (P3): shared pipeline — see PublishRouteOverlaySnapshotWithLatch.
	m.bumpRetainedGenerationLocked(&next)
	m.refreshCaptureAuthorityLocked(&next)
	m.prepareSnapshotForApply(&next)
	resampled := m.resampleUnresolvedSectionsLocked(&next)
	// #15955/#16153: one hash over the final publish snapshot drives the
	// dedup compare, the digest stamp, and the post-publish bookkeeping;
	// see PublishRouteOverlaySnapshotWithLatch for the proof obligations.
	pub := preparePrehashedPublish(&next)
	publishSnap := pub.snap
	// Capture dedup predicate = shared dedupHit AND publishedSnapshot != 0.
	// The extra arm is the characterized route-vs-capture difference
	// (#16153): a retained clone that was never published (publishedSnapshot
	// == 0) must publish even when its hash coincides with lastSnapshotHash,
	// because the helper does not yet hold that content.
	if m.dedupHit(pub) && m.publishedSnapshot != 0 {
		m.consumeRevalidateAttachLocked(&next)
		return false, nil
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(&next); err != nil {
		return false, m.disarmSnapshotProtocolFailClosedLocked(&next, err, false)
	}
	if err := m.disarmBeforeUnsupportedPublishLocked(&next); err != nil {
		return false, err
	}
	var status ProcessStatus
	m.consumeRevalidateAttachLocked(&publishSnap)
	if err := m.requestApplySnapshotPrehashedLocked(&publishSnap, &status, pub.hash, pub.hashOK); err != nil {
		return false, fmt.Errorf("republish capture authority: %w", err)
	}

	// The helper accepted the cloned snapshot. Use the same success
	// bookkeeping as the other partial publishers, but do not pretend
	// routes or policy were rebuilt: this call changed only the capture
	// authority.
	pub.snap = publishSnap
	m.adoptPublishedSnapshotLocked(&next, pub, "capture-authority", wasDebt, resampled)
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: failed to sync helper status after capture-authority republish", "err", err)
	}
	slog.Info("userspace: capture authority snapshot published",
		"generation", next.Generation)
	return true, nil
}

// routeOnlyPublishHybrid reports whether a route-only publish for cfg would
// stamp an identity whose helper-visible content is not in the retained
// snapshot (#5680, #12236). applied is the config the snapshot's compiled and
// secret-derived sections carry (m.lastSnapshot.Config, set together at each
// full Compile-based apply). The partial publish re-derives routes from cfg but
// keeps those sections from applied, so ACK'ing cfg after any helper-visible
// config change would misreport what the helper enforces.
//
// Nil applied (no established snapshot identity — e.g. the config-less
// bootstrap snapshot) cannot violate an identity contract. Pointer identity is
// the common legitimate case and the cheap fast path; the content-equality
// fallback (configsContentEqual) ensures a distinct-but-content-equal config is
// accepted (never a false refusal) while a genuinely divergent config is
// refused.
func routeOnlyPublishHybrid(cfg, applied *config.Config) bool {
	if applied == nil {
		return false
	}
	if cfg == applied {
		return false
	}
	return !configsContentEqual(cfg, applied)
}

// configsContentEqual reports whether two configs produce the same dataplane
// snapshot, by comparing the JSON encodings the control plane already ships to
// userspace-dp: ConfigSnapshot.Config is marshaled verbatim on every
// apply_snapshot (process_control.go), and the config store persists the same
// tree as JSON. Byte-equality of those encodings therefore means "content-equal
// for the snapshot the helper receives" — exactly the notion
// routeOnlyPublishHybrid needs.
//
// This replaces a former reflect.DeepEqual so the userspace package stays free
// of reflect/unsafe (retirement-boundary canary, #5985 /
// TestUserspaceManagerDoesNotImportReflectOrUnsafe).
//
// NOTE — the JSON comparison is strictly COARSER than reflect.DeepEqual, in one
// direction only (#6037 review): DeepEqual-equal ALWAYS implies JSON-equal (Go
// sorts map keys, so the encoding is deterministic), but the converse fails for
// three classes of field:
//   - Secrets: config.Secret.MarshalJSON redacts every non-empty secret to the
//     sentinel "<redacted>", so two configs differing ONLY in a non-empty secret
//     (an IPsec PSK / auth-key / password rotation) compare EQUAL here though
//     DeepEqual would call them different.
//   - Unexported fields (e.g. SNMPCommunity.clientNets): json.Marshal omits them;
//     DeepEqual compares them. These are derived from exported fields, so the
//     coarsening is benign (arguably more correct).
//   - `json:"-"` fields: json.Marshal skips them as well.
//     Config.ZoneQuarantineNames is one of them and changes the snapshot, so
//     it is compared explicitly (#12247, below).
//
// This coarsening is SAFE for every secret the helper CANNOT see, and #9161
// found the exception.
//
// The paragraph that stood here said the helper "ALWAYS receives the redacted
// JSON encoding — it never sees raw secrets", and listed strongSwan / FRR / vrrp
// / cluster as the secret-bearing subsystems that apply on separate paths.
// **WireGuard is not on that list and does not apply on a separate path.**
// `protocol_tunnels.go` declares `WgLocalPrivkeyHex` and `WgPresharedKeyHex` as
// PLAIN strings with json tags, and `tunnels.go` fills them with `.Reveal()` —
// so the helper receives raw WireGuard key material in the very snapshot this
// guard governs. It also receives SYN-cookie ring bases derived from the
// cluster auth keys when cookie protection is active (#12236), so those bases
// are digested as well.
//
// The consequence of omitting either secret was that its rotation compared
// EQUAL here: the #5680 refusal did not fire, the snapshot was marked applied
// carrying the OLD material, and the operator was told the rotation had landed
// while the dataplane still enforced the previous material.
//
// The rest of the original reasoning stands and is deliberately preserved: the
// former DeepEqual was over-strict, and a secret-only change the helper cannot
// observe genuinely is NOT a route-overlay hybrid. So this is NOT a return to
// full semantic preservation — the redacted marshal still does the coarsening it
// was chosen for, and only the secrets that DEMONSTRABLY reach the helper are
// added back, via `helperVisibleSecretDigest9161`.
//
// Do NOT restore this to a claim of full semantic preservation on this
// fail-closed guard, and do NOT widen the digest to secrets the helper does not
// receive — either change re-creates the over-strictness this coarsening exists
// to avoid.
//
// #12247: Config.ZoneQuarantineNames is `json:"-"` compile-time metadata, so
// the marshal cannot see it, yet zone quarantine decides over it
// (config.ZoneQuarantineNamesForConfig). Moving a colliding zone from a group
// nothing applies into the peer's node group changes only that set: the two
// configs marshal equal, but the new one quarantines a zone the retained
// snapshot still installs. A partial republish would then scrub that zone's
// rules while keeping the zone live, so its traffic falls through to a later
// permit (the #6480 hybrid). The runtime name set is therefore compared too:
// the merged set every quarantine consumer reads, whose zone keys the JSON
// comparison has already pinned.
//
// A marshal error is never observed in practice — the very same object is
// marshaled to the helper on each apply — but if one occurred we cannot prove
// content-equality, so we report NOT equal and let the hybrid-ACK guard fail
// closed (refuse the publish, per #5680) rather than risk ACK'ing a hybrid.
func configsContentEqual(a, b *config.Config) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	if !bytes.Equal(ab, bb) {
		return false
	}
	// #12247: the runtime zone-name set is invisible to the marshal (above).
	if !slices.Equal(config.ZoneQuarantineNamesForConfig(a), config.ZoneQuarantineNamesForConfig(b)) {
		return false
	}
	// #16606: Address.DNSAddresses is json:"-" runtime state the helper
	// DOES enforce (address-book rows are built from UsableValues), so a
	// DNS answer change is invisible to the marshal exactly like the
	// zone-quarantine set. Compare the scoped answer snapshots through
	// the same enumeration the daemon refresher uses; any divergence
	// means a partial republish would rebuild rows from stale answers
	// and must be refused as a hybrid.
	if !dnsAnswersContentEqual16606(a, b) {
		return false
	}
	// #9161: the redacted marshal cannot see a secret the helper CAN see.
	return helperVisibleSecretDigest9161(a) == helperVisibleSecretDigest9161(b)
}

// dnsAnswersContentEqual16606 compares the runtime DNS state of two
// configs by scoped identity (#16606/#17723). Order within an entry is
// significant, matching the refresher's change detection: a reordered
// answer set or a different lookup-failed flag is a different enforced
// state.
func dnsAnswersContentEqual16606(a, b *config.Config) bool {
	sa := config.DNSAnswersSnapshot(a)
	sb := config.DNSAnswersSnapshot(b)
	if len(sa) != len(sb) {
		return false
	}
	for k, va := range sa {
		vb, ok := sb[k]
		if !ok || va.DNSLookupFailed != vb.DNSLookupFailed || !slices.Equal(va.Prefixes, vb.Prefixes) {
			return false
		}
	}
	return true
}

// helperVisibleSecretDigest9161 digests exactly the secret material that reaches
// the helper, so a rotation of it is visible to configsContentEqual.
//
// Scoped to WireGuard plus the SYN-cookie ring bases (#12236): those are the
// secrets the snapshot builder reveals into the snapshot the helper receives.
// Secrets belonging to strongSwan, FRR and vrrp apply on separate paths and stay
// invisible here, which is the coarsening this guard was designed around.
//
// WireGuard keys are enumerated through `config.EmitTunnelEndpointNames` — the
// SAME enumerator the snapshot builder uses — rather than walking the interface
// map itself, so the set it digests cannot drift from the set the helper is sent.
// Peers are sorted by public key before hashing, matching the snapshot builder's
// own sort, so two configs that differ only in authoring order digest equal.
//
// The SYN-cookie bases are the second secret this guard's original
// "separate paths" list missed. `synCookieKeyMaterial` reads
// `ControlLinkAuthKey` (+`ControlLinkAuthKeyAlt` in a #6630 window) and the
// full build installs the derived ring (`builder.go`), while partial publishers
// inherit the old ring. Digest the same bases through the same derivation
// helpers, but not the wall-clock epoch key, which is intentionally not stable
// across comparisons. When protection is inactive no ring is installed, so
// neither auth key contributes and unrelated secret changes remain coarsened.
func helperVisibleSecretDigest9161(cfg *config.Config) [sha256.Size]byte {
	h := sha256.New()
	for _, ep := range config.EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel == nil {
			continue
		}
		fmt.Fprintf(h, "t:%s:%s\n", ep.Name, ep.Tunnel.WgLocalPrivkeyHex.Reveal())
		peers := make([]config.WgPeerConfig, len(ep.Tunnel.WgPeers))
		copy(peers, ep.Tunnel.WgPeers)
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].PublicKeyHex < peers[j].PublicKeyHex
		})
		for _, p := range peers {
			fmt.Fprintf(h, "p:%s:%s\n", p.PublicKeyHex, p.PresharedKeyHex.Reveal())
		}
	}
	// Hash the exact primary and optional accept-only bases installed by the
	// full builder. Fixed-length bases follow distinct domain markers, avoiding
	// ambiguity with each other or with the tunnel rows above.
	if userspaceSynCookieProtectionActive(cfg) {
		primary, additional, identity := synCookieKeyMaterial(cfg)
		h.Write([]byte("syncookie-primary\x00"))
		h.Write(deriveSYNCookieBase(primary, identity))
		if len(additional) > 0 {
			h.Write([]byte("syncookie-additional\x00"))
			h.Write(deriveSYNCookieBase(additional, identity))
		}
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
