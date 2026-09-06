package userspace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// routeOverlaySnapshot returns a copy of the cached ip-monitoring
// route overlay.
func (m *Manager) routeOverlaySnapshot() []config.RouteOverlayEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
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
// A non-nil schedulerState both updates the manager's cached scheduler
// view AND rebuilds this publish's Policies / AddressBooks from it in the
// SAME snapshot (#5328 A6-b2-F4), so the helper never enforces stale
// schedule bits between overlay publishes; nil keeps the current view and
// the inherited (last-compiled) policy sections.
func (m *Manager) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (published bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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

	if schedulerState != nil {
		m.policySchedulerActive = copyPolicySchedulerActiveState(schedulerState)
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
		return false, nil
	}

	// #5680: fail-closed hybrid-ACK guard. A route-only publish rebuilds ONLY
	// next.Routes (below) and inherits EVERY compiled policy section
	// (Zones/Policies/NAT/Screens/AddressBooks/...) verbatim from m.lastSnapshot
	// via `next := *m.lastSnapshot`. Those sections were built by the last full,
	// Compile-based apply_snapshot from m.lastSnapshot.Config — this path never
	// re-compiles. If the caller passes a cfg whose POLICY half was never
	// compiled into that snapshot, stamping next.Config = cfg and calling
	// markAppliedSnapshotLocked would advance the applied identity
	// (appliedSnapshot.Config) to a cfg the helper's live policy does NOT match:
	// an OLD-policy/NEW-route HYBRID ACK'd as the newly applied config.
	//
	// This is the #5679 residual: an ordinary d.dp.ApplyConfig failure captures
	// applyErr and continues (fail-closed but complete) WITHOUT advancing
	// m.lastSnapshot, while store.Commit has already promoted the NEW cfg. The
	// tail route-leak republish (reconcileRouteLeakSnapshot) and the
	// ip-monitoring actuator then call this with the NEW cfg. Refuse the publish
	// (fail-closed) so the applied identity never advances past the policy the
	// dataplane actually enforces; the OLD, fully-consistent snapshot stays live
	// and the caller reconverges once a full apply republishes the policy
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
		return false, fmt.Errorf("refusing route-only publish: cfg carries an unpublished " +
			"policy delta the dataplane snapshot does not reflect; publishing would ACK an " +
			"old-policy/new-route hybrid as the applied config (#5680)")
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(m.lastSnapshot); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing overlay publish",
				"protocol_err", err, "err", disarmErr)
		}
		return false, fmt.Errorf("refusing route overlay publish to incompatible helper: %w", err)
	}

	next := *m.lastSnapshot
	nextGeneration := m.generation + 1
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	next.Config = cfg
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
	next.Routes, next.LearnedRouteImportCapped, err = buildRouteSnapshots(cfg, next.Interfaces, desiredOverlay)
	if err != nil {
		return false, fmt.Errorf("build route overlay snapshot: %w", err)
	}

	// #5328 (A6-b2-F4): when the caller supplies a policy-scheduler active-state
	// map, refresh the policy snapshot's inactive bits from that map in THIS
	// publish — the doc contract above promised it, and daemon_ipmon.go passes a
	// live scheduler.ActiveState() here. Before this fix only m.policySchedulerActive
	// was cached (above) while `next := *m.lastSnapshot` inherited the PRIOR
	// compiled Policies / AddressBooks verbatim, so the helper enforced stale
	// schedule bits while this publish reported success — until the dedicated
	// UpdatePolicyScheduleState callback next fired. Rebuild exactly as the
	// scheduler-only republish does, via the shared rebuildScheduledPolicySectionsLocked
	// (which reuses the cached feed overlay AND re-applies the StableZoneID zone
	// quarantine's policy scrub so a rebuilt policy never dangles against the
	// inherited, already-reduced next.Zones — #6480). Placed BEFORE the
	// duplicate-skip hash below so a scheduler-only bit flip on unchanged routes is
	// not falsely deduped. A nil schedulerState leaves the inherited policy sections
	// untouched (the route-apply caller that never carries scheduler state).
	if schedulerState != nil {
		if err := m.rebuildScheduledPolicySectionsLocked(&next, cfg, m.policySchedulerActive); err != nil {
			return false, fmt.Errorf("build policy overlay snapshot for scheduler state: %w", err)
		}
	}

	// Duplicate-publish skip: identical content (e.g. the actuator ran
	// twice for the same overlay) does not need a control-socket
	// round-trip. The content hash excludes Generation/FIBGeneration.
	if h, ok := snapshotContentHash(&next); ok && h == m.lastSnapshotHash {
		slog.Debug("userspace: route overlay publish skipped (content unchanged)")
		return false, nil
	}

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	// #2124: disarm before publishing an unsupported-config snapshot.
	if err := m.disarmBeforeUnsupportedPublishLocked(&next); err != nil {
		return false, err
	}
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		return false, fmt.Errorf("publish route overlay snapshot: %w", err)
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "route-overlay")
	m.generation = nextGeneration
	m.lastSnapshot = &next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.publishedPlanKey = snapshotBindingPlanKey(&next)
	// #2079: full apply_snapshot succeeded — record the applied snapshot.
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(&next); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: failed to sync helper status after route overlay publish", "err", err)
	}
	slog.Info("userspace: route overlay snapshot published",
		"generation", next.Generation, "overlay_routes", len(desiredOverlay))
	return true, nil
}

// routeOnlyPublishHybrid reports whether a route-only publish for cfg would ship
// an OLD-policy/NEW-route hybrid (#5680). applied is the config whose compiled
// policy sections the current lastSnapshot carries (m.lastSnapshot.Config, set
// together at each full Compile-based apply). The publish is a hybrid iff cfg is
// NOT that config: it re-derives routes from cfg but keeps applied's compiled
// policy, so ACK'ing cfg as applied would misreport the enforced policy.
//
// Nil applied (no established policy identity — e.g. the config-less bootstrap
// snapshot) is not a hybrid: there is no policy identity to violate. Pointer
// identity is the common legitimate case and the cheap fast path; the
// content-equality fallback (configsContentEqual) ensures a distinct-but-
// content-equal config is accepted (never a false refusal) while a genuinely
// divergent config is refused.
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
// two classes of field:
//   - Secrets: config.Secret.MarshalJSON redacts every non-empty secret to the
//     sentinel "<redacted>", so two configs differing ONLY in a non-empty secret
//     (an IPsec PSK / auth-key / password rotation) compare EQUAL here though
//     DeepEqual would call them different.
//   - Unexported fields (e.g. SNMPCommunity.clientNets): json.Marshal omits them;
//     DeepEqual compares them. These are derived from exported fields, so the
//     coarsening is benign (arguably more correct).
//
// This coarsening is SAFE and correct for THIS guard: routeOnlyPublishHybrid
// governs only what the helper's route-overlay snapshot contains, and the helper
// ALWAYS receives the redacted JSON encoding (process_control.go) — it never sees
// raw secrets. A secret-only change is therefore invisible to the snapshot the
// helper gets, so it genuinely is NOT a route-overlay hybrid (the former
// DeepEqual was over-strict, refusing a publish over a change the helper could
// not observe). Secret-bearing subsystems (strongSwan/FRR/vrrp/cluster) apply on
// separate paths, and the recorded appliedSnapshot.Config self-heals on the next
// full apply. Do NOT restore this to a claim of full semantic preservation on
// this fail-closed guard.
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
	return bytes.Equal(ab, bb)
}
