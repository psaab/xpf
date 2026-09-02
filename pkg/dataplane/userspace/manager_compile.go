package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

var ErrPolicySchedulerProtocolIncompatible = errors.New("userspace policy scheduler snapshot protocol incompatible")

var ErrPersistentSourceNATProtocolIncompatible = errors.New("userspace persistent source NAT snapshot protocol incompatible")

// ErrScopedGlobalZoneSetProtocolIncompatible is the #5488 required-protocol
// gate sentinel: the committed config carries a policy whose scoped-global zone
// context holds MORE THAN ONE zone on a side, and the running helper's accepted
// ConfigSnapshotProtocolVersion predates the v4 contract in which the plural
// match_from_zones/match_to_zones snapshot fields are AUTHORITATIVE.
//
// Such a helper reads only the singular match_from_zone/match_to_zone, which
// carry the FIRST element (config.ScopeSingular), so it NARROWS the rule to one
// zone. For a `deny`/`reject` global that is a fail-OPEN — the zones dropped
// from the scope stop being denied and fall through to lower-precedence rules.
// For a `permit` it is a fail-closed correctness break. The gate is keyed on
// the multi-zone SHAPE rather than the action so it covers both directions.
var ErrScopedGlobalZoneSetProtocolIncompatible = errors.New("userspace scoped-global zone-set snapshot protocol incompatible")

// ErrEgressZoneProtocolIncompatible is the #6722 required-protocol gate
// sentinel: the RUNNING helper advertises a ConfigSnapshotProtocolVersion that
// is not this binary's, so the two do not agree on what the interface rows mean.
//
// Unlike its siblings this gate is not keyed on a config SHAPE, because the
// change it fences is not optional for any config: every InterfaceSnapshot now
// carries the Go-decided EgressZone, and the v4 `reth_projection` field it
// replaced is gone. A field DELETION cannot ride an unchanged version — two
// binaries either side of it both advertise their number and read the same
// bytes differently.
//
// It is keyed on EQUALITY, not `>=`. The helper's own apply_snapshot and
// bump_fib_generation gates are exact-equality, so a helper at ANY other
// version refuses the snapshot outright; a `>=` gate would additionally stay
// green at exactly the colliding value, which is the shape this gate exists to
// catch.
//
// MEASURED, so the severity is not a guess: feeding the v4 Go builder's rows to
// the v5 helper on the reference cluster resolves egress zone 0 for BOTH
// ifindex 24 and ifindex 25, where origin/master and the matched v5 pair
// resolve `lan` and `wan`. Ifindex 25 loses a zone even the pre-#6722 helper
// resolved, so a mixed pairing is strictly worse than either endpoint rather
// than an intermediate state — a silent transit outage under `default-policy
// deny-all`, carrying a version number both sides agree on.
var ErrEgressZoneProtocolIncompatible = errors.New("userspace egress-zone snapshot protocol incompatible")

// ErrSecureTunnelProtocolIncompatible is the #5619/#6691 gate. The snapshot
// carries InterfaceSnapshot.SecureTunnel, and the helper's binding admission
// (include_userspace_binding_interface) is AUTHORITATIVE on it: a route-based
// IPsec xfrmi must not become an AF_XDP binding candidate.
//
// #6691 round 8: the flag is set by CONFIG ownership or by the KERNEL link
// kind, so this gate fires for a stale live xfrmi too — the case the operator
// cannot fix by editing the config. Round 9: the gate reads the flag off the
// SNAPSHOT instead of re-deriving it, so it cannot disagree with what was built.
// Round 11: it reads every CONTRIBUTOR's verdict off that snapshot
// (snapshotRequiresRefusalProtocol), because round 10's fabric-parent verdict is
// carried by no row and a row scan could not see it.
//
// A helper that predates the field ignores it and plans the candidate. That is
// not a lost optimisation — the helper's queue count is the GLOBAL MINIMUM
// across candidates (replan_bindings_from_candidates) and an xfrm interface has
// exactly ONE RX queue (numrxqueues 1; a single `rx-0` under
// /sys/class/net/<if>/queues, which is what userspaceRXQueueCount reads and
// ships). So an ignored flag re-plans EVERY physical interface on the box onto
// one queue and one worker: the #3091 single-worker regression, on a config
// this control plane has already decided is safe. Neither the version-equality
// check (same advertised version on both sides before the #5619 bumps) nor the
// snapshot content hash can see it, because nothing about the bytes is wrong —
// only the reader is.
var ErrSecureTunnelProtocolIncompatible = errors.New("userspace secure-tunnel snapshot protocol incompatible")

// requiredProtocolGateSentinels enumerates every "this config cannot be
// committed against the helper's current ConfigSnapshotProtocolVersion"
// sentinel produced by ensureRequiredSnapshotProtocolLocked. ApplyConfig
// disarms the helper (Armed=false, fail-closed) and returns one of these
// when the running helper is too old to honor the committed config. A
// commit that hits any of them MUST abort — i.e. the daemon must surface a
// failed commit to the operator rather than report success against a
// disarmed dataplane (#2138).
//
// The lenient-load doctrine (#1960) is unaffected, because abort changes
// behavior ONLY for daemon callers that surface the apply error to a human:
//   - Boot/restart of an already-persisted config goes through the void
//     applyConfig wrapper, which logs slog.Warn and swallows the error —
//     the node boots through (warn, not brick).
//   - Peer config-sync goes through syncAndApply, which DOES propagate the
//     error; its caller (handleConfigSync) logs slog.Error and returns the
//     error to configApplyLoop, which counts ConfigsApplyFailed and leaves the
//     config high-water mark UNADVANCED so the primary's re-push re-converges
//     the standby (M-2/#4151). When SyncApply already promoted the store, the
//     re-push short-circuits on the "already matches active" check and heals
//     the high-water; the node stays consistent with the peer (helper
//     disarmed, not bricked).
//
// Only the operator-facing commit path (commitAndApply /
// commitConfirmedAndApply) returns the abort to the committer.
//
// Every future ensureRequiredSnapshotProtocolLocked gate MUST add its
// sentinel here so the commit-abort policy can never silently omit it
// (the omission this list exists to prevent was exactly #2138: the
// persistent-source-NAT gate disarmed the helper but was missing from the
// daemon's abort set).
var requiredProtocolGateSentinels = []error{
	ErrPolicySchedulerProtocolIncompatible,
	ErrPersistentSourceNATProtocolIncompatible,
	ErrScopedGlobalZoneSetProtocolIncompatible,
	ErrEgressZoneProtocolIncompatible,
	ErrSecureTunnelProtocolIncompatible,
}

// IsRequiredProtocolGateError reports whether err is (or wraps) any
// required helper-protocol gate sentinel — the set that must abort a
// commit. The daemon commit policy (compileErrorMustAbortApply) delegates
// to this so the abort set has a single source of truth co-located with
// the sentinels and the ensureRequiredSnapshotProtocolLocked gate that
// emits them.
func IsRequiredProtocolGateError(err error) bool {
	for _, sentinel := range requiredProtocolGateSentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

const persistentSourceNATHAUnsupportedReason = "userspace persistent-nat source pool leases are not HA-synchronized"

// recordPolicyContentRejectionLocked tracks the #3261 diagnostic for the
// just-built snapshot: the reasons (if any) it carries unrepresentable policy
// content that the helper integrity preflight will reject. It is called at the
// snapshot-build site BEFORE the publish so it is recorded even when the
// publish is rejected (the helper keeps previous-good / default-deny while
// staying armed — never fail-open). A one-shot slog line fires only on a
// transition (per the logging rules — NOT per apply): a Warn when content
// becomes unrepresentable (the operator must see the snapshot is being
// rejected) and an Info when it becomes representable again.
func (m *Manager) recordPolicyContentRejectionLocked(reasons []string) {
	had := len(m.lastSnapshotRejectReasons) > 0
	now := len(reasons) > 0
	m.lastSnapshotRejectReasons = append([]string(nil), reasons...)
	switch {
	case now && !had:
		slog.Warn(
			"userspace: snapshot carries unrepresentable policy content; the helper integrity preflight rejects it and retains the previous-good state (fresh boot: default-deny). Helper stays armed — no kernel fail-open. Edit out the offending application/address and re-commit to restore enforcement.",
			"reasons", reasons,
		)
	case had && !now:
		slog.Info("userspace: policy content is representable again; snapshot will publish normally")
	}
}

// recordZoneIDCollisionsLocked stores the #3719 zone-id-collision diagnostic
// from the last snapshot build and fires a one-shot operator alarm on a
// transition (per the logging rules — NOT per apply). A collision reaches this
// only on the LENIENT path (a tolerant load, an HA sync from an un-upgraded
// peer, or a config a pre-#3075 binary persisted); the strict commit path
// rejects it. The builder already QUARANTINED the later-sorting colliding zone
// (dropped from the wire, its interfaces unzoned, its policies removed), so the
// dataplane is fail-closed and never merges two zones — but zone isolation is
// DEGRADED (the quarantined zone forwards nothing) until an operator renames
// one zone, so this is a loud Error naming both zones.
func (m *Manager) recordZoneIDCollisionsLocked(collisions []ZoneIDCollision) {
	had := len(m.lastZoneIDCollisions) > 0
	msgs := make([]string, 0, len(collisions))
	for _, c := range collisions {
		msgs = append(msgs, c.String())
	}
	now := len(msgs) > 0
	m.lastZoneIDCollisions = msgs
	switch {
	case now && !had:
		slog.Error(
			"userspace: security-zone id collision — two zone names fold to the same StableZoneID; the later-sorting zone is QUARANTINED (dropped from the dataplane, its interfaces unzoned and its traffic denied) so two zones never share an id. Zone isolation is DEGRADED until one zone is renamed and the config re-committed.",
			"collisions", msgs,
		)
	case had && !now:
		slog.Info("userspace: security-zone id collision cleared; all zones install with distinct ids")
	}
}

func copyPolicySchedulerActiveState(activeState map[string]bool) map[string]bool {
	if activeState == nil {
		return nil
	}
	out := make(map[string]bool, len(activeState))
	for name, active := range activeState {
		out[name] = active
	}
	return out
}

func (m *Manager) policySchedulerActiveStateSnapshot() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyPolicySchedulerActiveState(m.policySchedulerActive)
}

// PolicySchedulerActiveState returns a copy of the daemon-maintained
// per-scheduler active-state map (scheduler name -> currently active).
// Read-only show surfaces (#3062 CLI/gRPC policy detail) consult it via
// PolicyInactive to render runtime scheduler-driven policy state without
// recomputing wall-clock schedule windows. A nil result means no
// scheduler state has been published yet.
func (m *Manager) PolicySchedulerActiveState() map[string]bool {
	return m.policySchedulerActiveStateSnapshot()
}

// SetPolicySchedulerActiveState seeds the active-state map used by the next
// full snapshot build. The daemon calls this while holding applySem so config
// commits and scheduler flips cannot publish hybrid policy snapshots.
func (m *Manager) SetPolicySchedulerActiveState(activeState map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policySchedulerActive = copyPolicySchedulerActiveState(activeState)
}

func (m *Manager) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	// #7079: the XDP link-pin removal that used to be the first statement of
	// this function now lives in dataplane.Manager.CompileUserspaceShim, after
	// CompileConfig has accepted the config and immediately before the attach it
	// exists for. Here it ran ahead of the #4960 validate-before-mutate
	// pre-pass, so a config the pre-pass REJECTED still lost the host's pins for
	// an apply that never happened. Its own comment named
	// "BEFORE CompileUserspaceShim()" as the requirement, but the real
	// constraint is "before AttachXDP", and that is satisfied at the new site.
	caps := deriveUserspaceCapabilities(cfg)
	// Userspace mode always attaches the retained XDP shim. The shim
	// redirects to XSK when ctrl=1; when ctrl=0 it only passes proven
	// local/control traffic to the kernel and drops transit. Do not swap to
	// xdp_main_prog for unsupported capabilities or failed XSK liveness: the
	// userspace runtime must not require the legacy main XDP pipeline.
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	result, err := m.bpfShim.CompileUserspaceShim(cfg)
	if err != nil {
		return nil, err
	}
	ucfg := deriveUserspaceConfig(cfg)
	activeState := m.policySchedulerActiveStateSnapshot()
	// #1827: include the cached ip-monitoring route overlay so a full
	// apply (operator commit) while a policy is FAILED preserves the
	// injected route instead of reverting traffic to the dead uplink.
	// #2514: a config-shaped input (e.g. address-book content-ID
	// collision) must reject the apply with an error rather than panic
	// the daemon. buildSnapshot* returns the error up here; ApplyConfig
	// fails closed and the previously published snapshot / dataplane state
	// is retained (m.lastSnapshot is not advanced on the error path).
	snap, err := buildSnapshotWithSchedulerStateAndNATCounters(cfg, ucfg, m.bumpGeneration(), m.readFIBGeneration(), activeState, m.routeOverlaySnapshot(), m.feedSnapshotOverlay(), result.NATCounterIDs)
	if err != nil {
		return nil, fmt.Errorf("userspace: build config snapshot: %w", err)
	}
	// #1620: stamp the cold-path sample mask onto the snapshot. The
	// daemon called SetColdPathSampleMask once at startup with the
	// validated CLI flag value (or nil for "use default"). A nil
	// pointer here leaves the wire field absent (omitempty), which
	// the Rust receiver unwrap_or-s to 0xff per plan §4.3.
	m.mu.Lock()
	snap.ColdPathSampleMask = m.coldPathSampleMask
	m.mu.Unlock()
	return m.applyCompiledSnapshot(cfg, result, snap, ucfg, caps)
}

// applyCompiledSnapshot is everything Compile does after the XDP shim is
// attached and the snapshot is built: publish the snapshot to the running Rust
// helper (or defer it during XSK startup), advance the retained authority, and
// only THEN reconcile the kernel attachment set.
//
// #5485 — WHY THE DETACH LIVES HERE AND NOT AT THE TOP OF THE APPLY.
// syncInterfaceAttachments detaches XDP and TC from every ifindex the NEW
// snapshot no longer lists as an adjudicated ingress. It used to run BEFORE
// this critical section, i.e. before the helper had accepted anything, so every
// failure between it and a successful apply_snapshot left the KERNEL on the new
// interface set while m.lastSnapshot — the authority the fail-closed comments
// promise is "retained" — was still the OLD one.
//
// That divergence is a policy BYPASS, not just an outage. Both pre-publish
// failure modes drive the shim to ctrl.Enabled=0 (programBootstrapMapsLocked
// programs it disabled; publishSnapshotFailClosedLocked disables it on the
// same-plan path), and a disabled ctrl makes the shim DROP transit —
// degraded_ctrl_disabled_action runs before the ingress-map test in
// userspace-xdp/src/lib.rs, so an interface that still carries the shim is
// still fail-closed. An interface that has been DETACHED is not: it has no XDP
// program at all, so with ip_forward=1 its traffic goes straight into the Linux
// stack, unadjudicated by xpf, while the daemon reports the previous-good
// snapshot as retained.
//
// Deferring the detach to the acceptance points creates the mirror-image
// transient — attached shim, interface already gone from the applied snapshot —
// and that one is harmless in BOTH ctrl states: an ifindex absent from
// userspace_ingress_ifaces takes cpumap_or_pass (the kernel path, identical to
// having no program), and a still-disabled ctrl drops transit, which is the
// fail-closed direction. So the window this ordering opens can only be as
// permissive as the detach it replaces, never more.
//
// #8279: the first half of that sentence WAS NOT TRUE when it was written, and
// this note stays because the claim is load-bearing and its failure was not
// visible from here. "An ifindex absent from userspace_ingress_ifaces takes
// cpumap_or_pass" was true of three of the shim's four arms; the fourth, an L3
// PARSE FAILURE, took drop_degraded_transit — and it sat ABOVE the ingress-map
// test, so it applied to interfaces this dataplane does not adjudicate. That
// mattered because the attach set here is strictly LARGER than the ingress set
// (compiler_iface.go puts every zoned netdev in st.xdpIfindexes, tunnels
// included) and a tunnel netdev is raw L3 with no Ethernet header, so the
// shim's Ethernet-only parse read its IP SOURCE octets as an ethertype. The
// ordering is fixed in userspace-xdp/src/lib.rs and pinned by
// shim_ingress_test_precedes_the_l3_parse_8279, so the sentence above is now
// true of every arm.
//
// The ordering fix alone did NOT cover the ctrl-DISABLED path
// (degraded_ctrl_disabled_action), which never consults the ingress map at all
// by design — a disabled ctrl must fail closed on every attached interface — so
// on a raw-L3 netdev its local/control exemption was evaluated against the
// misparse, which is fail-OPEN. Nor did it cover a raw-L3 netdev that IS in the
// ingress set. Both are closed at the source instead: compileZones now refuses
// to put a netdev into pendingXDP unless its link-layer type is Ethernet
// (netdevCarriesEthernetFraming, pkg/dataplane/netdev_framing_8279.go), so the
// shim is never attached to one and neither path can be reached. The refusal is
// recorded as an UnarmedSurface with StillForwarding set — the netdev is UP,
// zoned and unadjudicated, and that gap is reported rather than traded away
// silently.
//
// The ATTACH half stays before the publish deliberately: the helper cannot bind
// an AF_XDP socket to an interface with no shim, so staging it later is not
// possible, and its failure mode is an extra fail-closed drop on an interface
// xpf was in the middle of claiming — not a bypass.
func (m *Manager) applyCompiledSnapshot(
	cfg *config.Config,
	result *dataplane.CompileResult,
	snap *ConfigSnapshot,
	ucfg config.UserspaceConfig,
	caps UserspaceCapabilities,
) (*dataplane.CompileResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// #3261: record whether this snapshot carries unrepresentable policy
	// content BEFORE the publish, so the diagnostic is captured even when the
	// helper rejects the snapshot (the publish path returns early on the
	// integrity error, before recordApplyResultLocked). The helper stays armed
	// for this class; the reject retains previous-good (or leaves the fresh-boot
	// default-deny), never fail-open.
	m.recordPolicyContentRejectionLocked(snap.Capabilities.PolicyContentRejected)
	// #3719: record + alarm any StableZoneID collision the builder quarantined
	// (lenient / HA-sync / pre-#3075-persisted path). The colliding zone was
	// already dropped from snap; this surfaces the degraded-isolation state.
	m.recordZoneIDCollisionsLocked(snap.zoneIDCollisions)
	m.clusterHA = cfg != nil && cfg.Chassis.Cluster != nil
	m.seedHAGroupInventoryLocked(cfg)
	prevPlanKey := snapshotBindingPlanKey(m.lastSnapshot)
	newPlanKey := snapshotBindingPlanKey(snap)
	pendingXSKStartup := m.proc != nil &&
		m.proc.Process != nil &&
		m.publishedSnapshot != 0 &&
		!m.xskLivenessProven &&
		!m.xskLivenessFailed
	samePlanRefresh := m.proc != nil &&
		m.proc.Process != nil &&
		prevPlanKey != "" &&
		prevPlanKey == newPlanKey
	publishedPlanChangedDuringStartup := pendingXSKStartup &&
		m.publishedPlanKey != "" &&
		m.publishedPlanKey != newPlanKey
	if publishedPlanChangedDuringStartup {
		slog.Info(
			"userspace: restarting helper during XSK startup for binding plan change",
			"generation", snap.Generation,
			"fib_generation", snap.FIBGeneration,
		)
		m.stopLocked()
		pendingXSKStartup = false
		samePlanRefresh = false
	}
	// #1197 v4 (Codex code-review v3 #1+#2): rebuild listener
	// caches ONLY after a successful apply_snapshot. Doing it
	// here (before publish) leaves the listener thinking
	// userspace-dp has entries it doesn't if apply_snapshot fails.
	// Moved to the post-success path below (after line 343).
	if pendingXSKStartup {
		if err := m.ensureRequiredSnapshotProtocolLocked(snap); err != nil {
			if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
				return result, errors.Join(err, disarmErr)
			}
			return result, err
		}
		if err := m.syncUserspaceClassifierMapsFailClosedLocked(snap); err != nil {
			return result, err
		}
		// #1928 (Codex review Q1): the deferred-publish resume path
		// (syncSnapshotLocked in process.go) never syncs HA state, so a
		// cluster->standalone reconfig that lands during the XSK-startup
		// deferral window would leave stale HA groups in the helper and
		// re-arm the HAInactive transit-drop gate. seedHAGroupInventoryLocked
		// already cleared m.haGroups for the non-cluster case above; clear the
		// helper side here too so the standalone state is consistent
		// regardless of which apply path runs. (Idempotent empty update.)
		if !m.clusterHA {
			if err := m.clearHelperHAStateWithDebtEnsureRetryLocked(); err != nil {
				// Debt recorded — the status poll retries the clear until it
				// succeeds; still surface the error so the apply fails closed.
				// #5873: this deferred-publish resume path returns without
				// reaching the ensureStatusLoopLocked() call on the normal apply
				// path, so the WithDebtEnsureRetry wrapper starts the loop (the
				// debt's only retry consumer) before this failure propagates —
				// otherwise the failed clear would orphan the debt with no worker
				// to retry it. The pendingXSKStartup precondition guarantees
				// m.proc != nil, so the loop can actually run.
				return result, fmt.Errorf("clear userspace HA state (deferred startup): %w", err)
			}
		}
		m.lastSnapshot = snap
		// #5485: the retained authority is now the NEW snapshot, and the
		// classifier maps above already dropped the obsolete ifindexes from
		// userspace_ingress_ifaces, so the kernel attachment set may follow.
		// The publish is deferred, not skipped — this branch still returns nil
		// and its snapshot is what every later reader enforces.
		m.syncInterfaceAttachments(result, snap)
		m.cfg = ucfg
		m.recordApplyResultLocked(dataplane.ApplyResultFromCompileResult(result), caps, snap.Generation)
		slog.Info(
			"userspace: deferring snapshot publish during XSK startup",
			"generation", snap.Generation,
			"fib_generation", snap.FIBGeneration,
			"same_plan", samePlanRefresh,
		)
		return result, nil
	}
	if samePlanRefresh {
		if err := m.syncUserspaceClassifierMapsFailClosedLocked(snap); err != nil {
			return result, err
		}
	} else {
		if err := m.programBootstrapMapsLocked(snap, ucfg); err != nil {
			return result, err
		}
	}
	if err := m.ensureProcessLocked(ucfg); err != nil {
		return result, err
	}
	if err := m.ensureRequiredSnapshotProtocolLocked(snap); err != nil {
		return result, m.disarmSnapshotProtocolFailClosedLocked(snap, err, samePlanRefresh)
	}
	if m.deferWorkers {
		snap.DeferWorkers = true
	}
	var status ProcessStatus
	if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
		return result, err
	}
	// #1197 v5 (Codex code-review v4 #2): apply_snapshot must
	// send publishable-only neighbors to match the
	// update_neighbors path. Otherwise Rust's full-snapshot
	// build accepts state="none" entries Go's predicate rejects,
	// and Go can't track removal of those entries via the index.
	publishSnap := *snap
	publishSnap.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	// #4959: on the samePlanRefresh path the classifier BPF maps were already
	// mutated IN PLACE above (syncUserspaceClassifierMapsFailClosedLocked) with
	// ctrl still enabled; publishSnapshotFailClosedLocked disables ctrl if this
	// publish is rejected so the maps can never run a generation ahead of the
	// applied Rust snapshot (fail-open). The bootstrap path already set
	// ctrl.Enabled=0, so it needs no extra fail-closed.
	if err := m.publishSnapshotFailClosedLocked(&publishSnap, &status, samePlanRefresh); err != nil {
		return result, err
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "apply")
	m.lastSnapshot = snap
	// #5485: apply_snapshot landed and the retained authority has advanced, so
	// the obsolete XDP/TC attachments may now be reconciled away. Placed
	// immediately after the acceptance rather than at the tail of this function
	// so the later status/HA/forwarding steps — every one of which can fail
	// AFTER the snapshot is already the authority — cannot strand a stale
	// attachment for an interface the applied snapshot no longer adjudicates.
	m.syncInterfaceAttachments(result, snap)
	// #1197 v4: apply_snapshot succeeded — userspace-dp has the
	// new neighbors. NOW rebuild listener caches; before this
	// point the index would shadow events for entries the
	// dataplane hadn't accepted.
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = snap.Generation
	m.publishedPlanKey = newPlanKey
	// #2079: this full apply_snapshot succeeded — record the applied
	// (config, generation) for the NAT pool-utilization-alarm monitor.
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return result, fmt.Errorf("sync helper status: %w", err)
	}
	// #1928: HA group state must only be replayed/published for chassis-cluster
	// members. The rg_active map is a fixed-size ARRAY (16 entries, keys 0-15)
	// so it is ALWAYS fully populated — even on a standalone firewall with no
	// redundancy groups, where every entry is inactive. On standalone the old
	// unconditional refreshHAStateFromMapsLocked() therefore fabricated 16
	// inactive HA groups and shipped them to the helper; the helper's per-packet
	// HA gate (enforce_ha_resolution_snapshot) then treats every transit
	// ForwardCandidate as HAInactive (owner_rg_id<=0 && !ha_state.is_empty())
	// and drops it — a total transit forwarding outage on non-cluster nodes. The
	// periodic status poll already guards the refresh with m.clusterHA (see
	// process.go); the startup path must match.
	if m.clusterHA {
		if err := m.refreshHAStateFromMapsLocked(); err != nil {
			return result, fmt.Errorf("replay userspace HA state from maps: %w", err)
		}
		if err := m.syncHAStateLocked(); err != nil {
			return result, fmt.Errorf("publish userspace HA state: %w", err)
		}
	} else if err := m.clearHelperHAStateWithDebtEnsureRetryLocked(); err != nil {
		// Non-cluster node: ensure neither the manager nor the helper retains
		// HA groups. seedHAGroupInventoryLocked already cleared m.haGroups
		// above; this also clears any groups a prior clustered apply pushed to
		// the helper (cluster->standalone live reconfig), which would otherwise
		// keep the HAInactive transit-drop gate armed (Codex review #1928 Q3).
		// On failure a retry debt is recorded (#5487) so the status poll
		// re-attempts the idempotent clear until the helper reports no groups;
		// the error is still surfaced so this apply fails closed.
		// #5873: the recorded debt's ONLY retry consumer is the periodic status
		// loop, which the success path starts below via ensureStatusLoopLocked().
		// On first startup (or any apply with no pre-existing loop) returning
		// here BEFORE that call would orphan the debt — no worker would ever
		// retry the clear, so the stale helper HA groups (and the owner-RG-0
		// transit-drop gate) would persist indefinitely. The WithDebtEnsureRetry
		// wrapper starts the loop (idempotent) before this failure propagates.
		return result, fmt.Errorf("clear userspace HA state: %w", err)
	}
	if err := m.syncDesiredForwardingStateLocked(); err != nil {
		return result, fmt.Errorf("sync userspace forwarding state: %w", err)
	}
	m.ensureStatusLoopLocked()
	m.cfg = ucfg
	m.recordApplyResultLocked(dataplane.ApplyResultFromCompileResult(result), caps, snap.Generation)
	return result, nil
}

// publishSnapshotFailClosedLocked sends apply_snapshot to the running helper and
// makes an in-place classifier-map refresh + helper publish one fail-closed
// transaction (#4959).
//
// When mapsMutatedInPlace is true the caller took the samePlanRefresh path: the
// ingress/local/interface-NAT classifier BPF maps were mutated IN PLACE to the
// new plan while the XDP shim's ctrl gate is still enabled. Returning a publish
// error while leaving ctrl enabled would run the shim against classifier maps a
// generation ahead of the snapshot the helper is actually enforcing — wrong
// kernel-pass vs XSK-redirect and wrong local-vs-interface-NAT ownership, a
// fail-OPEN security/availability mismatch instead of the intended
// previous-good retention.
//
// #7468 splits that response by ERROR CLASS, and an earlier revision of this
// comment is why it had to: it said the helper "keeps enforcing the
// previous-good snapshot" on a "helper-side validation failure, OR ANY
// TRANSPORT ERROR". The second half is false. controlRoundtripDeadline exists
// because a fixed 3s deadline "reported the apply FAILED while the dataplane
// had applied it live" — on a transport failure the helper's state is unknown,
// and it may be enforcing the NEW snapshot. The uniform ctrl-disable was
// correct precisely because it never relied on that sentence.
//
//   - IN-BAND REFUSAL (errHelperRejected): the helper decoded the request, ran
//     its non-mutating integrity preflight and answered {"ok":false}. Only here
//     does "the helper still holds m.lastSnapshot" follow. The maps are rolled
//     BACK to m.lastSnapshot, which restores the exact plan the retained
//     snapshot expects, so ctrl stays enabled and there is no window in which
//     neither snapshot forwards transit (#6707 acceptance criterion 1). If the
//     rollback itself fails the ctrl-disable is the fallback.
//   - ANY OTHER ERROR: helper state unknown, so the pre-#7468 behaviour stands
//     — disable ctrl (failClosedUserspaceCtrlMapLocked) and drop transit to the
//     kernel-only fail-closed posture until a subsequent good commit
//     re-publishes and re-enables it.
//
// When mapsMutatedInPlace is false the caller took the full bootstrap path,
// which already programmed ctrl.Enabled=0 before this publish, so a publish
// error is already fail-closed and the error is returned unchanged.
func (m *Manager) publishSnapshotFailClosedLocked(publishSnap *ConfigSnapshot, status *ProcessStatus, mapsMutatedInPlace bool) error {
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: publishSnap}, status); err != nil {
		publishErr := fmt.Errorf("publish userspace snapshot: %w", err)
		// #7468: a rejected publish must never return with the manager lacking
		// a reconcile worker. On the samePlanRefresh path the loop is already
		// running and this is a no-op; on a FIRST apply the normal
		// ensureStatusLoopLocked() call is further down applyCompiledSnapshot,
		// past this return, so without it the manager is left inert — no status
		// tick, no classifier re-sync, no retry-debt consumer — with transit
		// dropped until the operator commits again. The loop cannot re-enable
		// ctrl behind a rejected first snapshot: the helper holds no snapshot,
		// so it reports no bindings, and status.enabled is
		// `!bindings.is_empty() && ...` (userspace-dp status.rs), which
		// resolveCtrlEnableLocked requires before it will arm.
		m.ensureStatusLoopLocked()
		if mapsMutatedInPlace {
			return m.retainPreviousClassifierPlanLocked(publishSnap, publishErr)
		}
		return publishErr
	}
	// #6034: apply_snapshot returns the helper's current neighbor-replace
	// generation. Seed from that response before returning to Compile, which
	// exposes m.lastSnapshot (and therefore enables RegenerateNeighborSnapshot)
	// immediately afterward. Waiting for statusLoop's first 1s tick leaves a
	// window where a surviving helper can fence this manager's generation 1.
	if status != nil {
		m.seedNeighborReplaceGenerationLocked(status.ManagerNeighborGeneration)
	}
	return nil
}

// classifierPlanRetainable reports whether a rejected in-place publish may roll
// the classifier maps BACK to the retained snapshot instead of disabling ctrl.
//
// Pure, and separate from the action, because all three conjuncts are load
// bearing and each fails differently:
//
//   - mapsMutatedInPlace: on the bootstrap path the maps were never rewritten
//     to the new plan and ctrl is already 0, so there is nothing to roll back
//     and nothing to keep enabled.
//   - retained != nil: a first apply has no previous-good plan to restore. A
//     rollback against nil would clear the classifier maps and, with ctrl left
//     enabled, hand transit to the kernel — the fail-open this whole path
//     exists to prevent.
//   - errors.Is(cause, errHelperRejected): ONLY an in-band {"ok":false} proves
//     the helper still holds `retained`. On a transport error it may already be
//     enforcing the new snapshot, and rolling the maps back would put them a
//     generation BEHIND — the same fail-open with the sign flipped.
func classifierPlanRetainable(mapsMutatedInPlace bool, retained *ConfigSnapshot, cause error) bool {
	return mapsMutatedInPlace && retained != nil && errors.Is(cause, errHelperRejected)
}

// retainPreviousClassifierPlanLocked performs the #7468 atomic retain, or falls
// back to the #4959 ctrl-disable.
//
// cause is returned either way: the publish still failed and the caller must
// still fail the apply. What changes is whether transit keeps flowing on the
// snapshot the helper retained, or drops to kernel-only until the next tick.
func (m *Manager) retainPreviousClassifierPlanLocked(publishSnap *ConfigSnapshot, cause error) error {
	if !classifierPlanRetainable(true, m.lastSnapshot, cause) {
		return m.failClosedUserspaceCtrlMapLocked(publishSnap, cause)
	}
	if err := m.syncUserspaceClassifierMapsLocked(m.lastSnapshot); err != nil {
		// The maps are now in an unknown mix of the two plans, which is
		// strictly worse than either. Disable ctrl and surface both errors —
		// the rollback failure is the actionable one.
		return m.failClosedUserspaceCtrlMapLocked(
			publishSnap,
			errors.Join(cause, fmt.Errorf("roll classifier maps back to the retained snapshot: %w", err)),
		)
	}
	slog.Warn(
		"userspace: helper refused the snapshot; classifier maps rolled back to the retained snapshot and transit continues on it",
		"retained_generation", m.lastSnapshot.Generation,
		"refused_generation", publishSnap.Generation,
		"err", cause,
	)
	return cause
}

// rebuildScheduledPolicySectionsLocked rebuilds the policy + address-book
// sections of a partial (non-Compile) republish under a scheduler active-state
// map and re-applies the StableZoneID zone quarantine's policy scrub so the
// rebuilt next.Policies stays consistent with the inherited, already-reduced
// next.Zones (#6480). It is the SHARED core of the two republish paths that
// rebuild policies without a full Compile — PublishRouteOverlaySnapshot
// (route-overlay) and UpdatePolicyScheduleState (scheduler-only) — so the
// quarantine re-application can never drift between them. It mutates next in
// place and must be called with m.mu held.
//
// activeState is the policy-scheduler active-state map to build the inactive
// bits from (both callers set m.policySchedulerActive to it first, so it equals
// m.policySchedulerActive). #2049: the cached dynamic-address feed overlay is
// threaded through so a scheduler-state flip does not drop feed enforcement
// until the next full apply (m.mu is held, so read m.feedOverlay directly via
// cloneFeedOverlay rather than feedSnapshotOverlay(), which re-locks m.mu). A
// build error is returned wrapped; both callers retain the prior snapshot
// (fail-closed) and surface a retry.
func (m *Manager) rebuildScheduledPolicySectionsLocked(next *ConfigSnapshot, cfg *config.Config, activeState map[string]bool) error {
	// #6480 (config-skew fail-open guard): this helper rebuilds next.Policies
	// from cfg and scrubs them against cfg's StableZoneID quarantine set, but
	// next.Zones / next.Interfaces were inherited verbatim from m.lastSnapshot
	// (the APPLIED config). If cfg's zone generation differs from that applied
	// config, the scrub can drop a policy whose to/from zone is STILL a live
	// member of the inherited next.Zones — shipping a snapshot the Rust
	// UnresolvableZoneReference preflight ACCEPTS yet whose missing rule lets
	// traffic fall through to the inherited default policy (a fail-OPEN a full
	// Compile of cfg would instead render fail-closed by ALSO dropping the
	// quarantined zone and unzoning its interface). The route-overlay caller
	// already refuses this exact skew at its call site (routeOnlyPublishHybrid,
	// #5680); the scheduler-only caller (UpdatePolicyScheduleState) had no prior
	// guard, so enforce it HERE so BOTH partial-republish paths are protected.
	// routeOnlyPublishHybrid is parameterized on the applied config, so it doubles
	// as the general "cfg content-differs from applied" skew predicate. next.Config
	// was already set to cfg by both callers, so compare cfg against the INHERITED
	// snapshot's config (m.lastSnapshot.Config), NEVER next.Config (a cfg==cfg
	// tautology). On divergence retain the prior snapshot; the caller surfaces a
	// retry and the next tick reconverges once cfg's full apply lands
	// (m.lastSnapshot.Config == cfg) — the #3780 retry semantics already handle it.
	if m.lastSnapshot != nil && routeOnlyPublishHybrid(cfg, m.lastSnapshot.Config) {
		return fmt.Errorf("refusing scheduled-policy republish: cfg carries a zone/policy " +
			"generation the inherited dataplane snapshot does not reflect; rebuilding and " +
			"scrubbing against it could drop a live-zone policy and ship a fail-open snapshot (#6480)")
	}
	feedOverlay := cloneFeedOverlay(m.feedOverlay)
	// #2514: an unresolvable address-book content-ID collision must not panic the
	// daemon — surface it as an error so the caller retains the prior snapshot.
	policies, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, activeState, feedOverlay)
	if err != nil {
		return fmt.Errorf("policy snapshot rebuild for scheduler republish: %w", err)
	}
	// #6480: the raw builder re-introduces any policy referencing a
	// StableZoneID-quarantined zone (it has no knowledge of the quarantine),
	// while next.Zones was inherited already reduced by quarantineCollidingZones.
	// Re-establish the same zone-isolation invariant the full build guarantees
	// (builder.go) so no policy references a zone absent from next.Zones —
	// otherwise the Rust UnresolvableZoneReference preflight rejects the WHOLE
	// snapshot, and because the ip-monitoring actuator updates FRR BEFORE this
	// publish (daemon_ipmon.go) the kernel/FRR would sit on the new routes while
	// userspace keeps the old FIB with retries that cannot converge.
	policies = scrubPoliciesForQuarantinedZones(policies, quarantinedZoneNamesForConfig(cfg))
	next.Policies = policies
	// #3261: recompute the (feed-aware) content-rejection diagnostic from the
	// scrubbed rules' sentinels; the copied lastSnapshot value would be stale.
	next.Capabilities.PolicyContentRejected = collectPolicyContentRejections(policies)
	// Keep the operator-facing count equal to what is actually published, exactly
	// as the full build does after quarantine (builder.go): Summary.PolicyCount
	// must equal len(next.Policies).
	next.Summary.PolicyCount = len(policies)
	// #1606: refresh the address-book table alongside the policies so book IDs
	// cited by the rebuilt rules always resolve dataplane-side.
	books, _, err := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	if err != nil {
		return fmt.Errorf("address-book rebuild for scheduler republish: %w", err)
	}
	next.AddressBooks = books
	return nil
}

// UpdatePolicyScheduleState republishes the userspace policy snapshot with one
// coherent inactive-bit view. This shadows the embedded eBPF manager method;
// scheduled userspace policies must not update the policy_rules BPF map.
func (m *Manager) UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool) error {
	activeCopy := copyPolicySchedulerActiveState(activeState)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.policySchedulerActive = activeCopy
	if cfg == nil {
		if m.lastSnapshot == nil {
			// #3780: no snapshot ever published — nothing to
			// republish, and no live enforcement to go stale. The
			// next full apply publishes the initial state. Converged.
			return nil
		}
		cfg = m.lastSnapshot.Config
	}
	if cfg == nil || m.lastSnapshot == nil {
		return nil
	}
	if m.proc == nil || m.proc.Process == nil {
		// #3780: the helper is not running, so no snapshot is being
		// enforced — there is no stale permit to converge. The helper
		// restart path re-applies the last snapshot. Converged.
		return nil
	}

	if err := m.ensureRequiredSnapshotProtocolLocked(m.lastSnapshot); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing snapshot publish",
				"protocol_err", err, "err", disarmErr)
		}
		slog.Warn("userspace: refusing snapshot publish to incompatible helper", "err", err)
		// #3780: the intended new inactive-bit view was NOT applied.
		// Report failure so the daemon retries on the next scheduler
		// tick and surfaces the stale-enforcement metric.
		return fmt.Errorf("userspace: refusing snapshot publish to incompatible helper: %w", err)
	}
	next := *m.lastSnapshot
	nextGeneration := m.generation + 1
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	next.Config = cfg
	// #6480: rebuild the schedule-affected policy + address-book sections
	// (threading the cached feed overlay, #2049) and re-apply the StableZoneID
	// zone quarantine's policy scrub via the shared helper, so this scheduler-only
	// republish and the route-overlay republish stay in lockstep and neither ships
	// a policy referencing a quarantined zone absent from the inherited next.Zones.
	if err := m.rebuildScheduledPolicySectionsLocked(&next, cfg, activeCopy); err != nil {
		slog.Warn("userspace: skipping policy-scheduler republish; retaining prior snapshot", "err", err)
		// #3780: the prior snapshot is retained, which for a CLOSING window means
		// the old permit stays live. Report failure so the transition is retried
		// on the next scheduler tick until the rebuild succeeds and converges.
		return fmt.Errorf("userspace: %w", err)
	}

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	// #2124: disarm before publishing an unsupported-config snapshot (see
	// disarmBeforeUnsupportedPublishLocked). cfg is this snapshot's config.
	if err := m.disarmBeforeUnsupportedPublishLocked(&publishSnap); err != nil {
		slog.Warn("userspace: failed to disarm before unsupported-config policy scheduler publish", "err", err)
		// #3780: disarm failed and the new snapshot was not published —
		// report failure so the transition retries.
		return fmt.Errorf("userspace: disarm before unsupported-config policy scheduler publish: %w", err)
	}
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		slog.Warn("userspace: failed to publish policy scheduler state", "err", err)
		// #3780: THE fail-open path from the issue. apply_snapshot did
		// not land, so the helper keeps the OLD inactive bits — a permit
		// past its window stays live. Report failure so the daemon
		// retries autonomously on the next scheduler tick.
		return fmt.Errorf("userspace: publish policy scheduler snapshot: %w", err)
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "policy-scheduler")
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
		// #3780: the snapshot DID land (generation bumped, lastSnapshot
		// updated above) — the schedule transition converged. A status
		// re-sync failure is observability only; do NOT force a retry
		// that would churn an identical snapshot.
		slog.Warn("userspace: failed to sync helper status after policy scheduler publish", "err", err)
	}
	return nil
}

func (m *Manager) syncInterfaceAttachments(result *dataplane.CompileResult, snapshot *ConfigSnapshot) {
	if result == nil {
		return
	}
	allowed := make(map[int]bool)
	for _, ifindex := range buildUserspaceIngressIfindexes(snapshot) {
		allowed[int(ifindex)] = true
	}
	for ifindex := range m.bpfShim.XDPLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.bpfShim.DetachXDP(ifindex); err != nil {
			slog.Warn("userspace: detach XDP from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
	for ifindex := range m.bpfShim.TCLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.bpfShim.DetachTC(ifindex); err != nil {
			slog.Warn("userspace: detach TC from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
}

func configHasScheduledPolicy(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && pol.SchedulerName != "" {
				return true
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol != nil && pol.SchedulerName != "" {
			return true
		}
	}
	return false
}

// policyScopeIsMultiZone reports whether a policy's scoped-global zone context
// (#4626 M03) holds more than one zone on either side — the exact shape the
// SINGULAR MatchFromZone/MatchToZone snapshot fields cannot represent, because
// config.ScopeSingular stamps only the first element onto them.
//
// A one-element scope is bit-identical in both shapes (singular == the one
// zone), and an unscoped global has both sides empty, so neither can be
// narrowed by a reader that ignores the plural fields. Restricting the
// predicate to len > 1 keeps the #5488 disarm blast radius to exactly the
// misrepresentable population.
//
// A set that CONTAINS the "any" wildcard alongside concrete zones is included
// conservatively: whether the singular field happens to land on "any" depends
// on element order, so the shape — not a coincidence of ordering — decides.
func policyScopeIsMultiZone(pol *config.Policy) bool {
	if pol == nil {
		return false
	}
	return len(pol.Match.FromZones) > 1 || len(pol.Match.ToZones) > 1
}

// configHasMultiZoneScopedPolicy scans every policy the snapshot builder lowers
// through buildOneRuleSnapshot — the global tier AND the zone-pair tier — for a
// multi-zone scope. Only global policies carry a zone scope today (the compiler
// never populates Match.FromZones/ToZones for a zone-pair policy), but the
// emitter stamps MatchFromZone/MatchToZone from the SAME Match fields for every
// rule, so the gate covers the whole emission surface rather than assuming the
// compiler's current tier discipline.
// ConfigHasMultiZoneScopedPolicy is the exported form of
// configHasMultiZoneScopedPolicy, for the #6650 CROSS-CHASSIS gate in
// pkg/daemon.
//
// It is a thin wrapper rather than a copy on purpose. The local gate (#5488)
// and the cross-chassis gate must arm on the SAME shape: two predicates that
// drift would mean a config the local helper refuses is still pushed to the
// peer, or the reverse. TestCrossChassisGateSharesTheLocalArmingPredicate6650
// pins the sharing.
func ConfigHasMultiZoneScopedPolicy(cfg *config.Config) bool {
	return configHasMultiZoneScopedPolicy(cfg)
}

func configHasMultiZoneScopedPolicy(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if policyScopeIsMultiZone(pol) {
			return true
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if policyScopeIsMultiZone(pol) {
				return true
			}
		}
	}
	return false
}

// ensureScopedGlobalZoneSetProtocolLocked is the #5488 fail-closed half of the
// v4 protocol bump. The bump itself makes a pre-v4 helper REFUSE the snapshot
// (both apply_snapshot and bump_fib_generation gate on exact version equality),
// which stops it from misreading the scope — but a refused snapshot leaves that
// helper ARMED on its previous-good image, still forwarding, with the newly
// committed deny never installed. This gate closes that window the way the
// project's other required-protocol gates do: the caller
// (ensureRequiredSnapshotProtocolLocked) disarms the helper and the commit
// aborts with an operator-visible reason, instead of reporting success against
// a dataplane running a policy set the helper cannot represent.
func (m *Manager) ensureScopedGlobalZoneSetProtocolLocked(cfg *config.Config) error {
	if !configHasMultiZoneScopedPolicy(cfg) {
		return nil
	}
	if m.lastStatus.ConfigSnapshotProtocolVersion >= MinProtocolMultiZoneScopedPolicy {
		return nil
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
		m.recordHelperStatusLocked(&status)
		if status.ConfigSnapshotProtocolVersion >= MinProtocolMultiZoneScopedPolicy {
			return nil
		}
	}
	if m.noHelperVersionObservedLocked() {
		return nil
	}
	return fmt.Errorf(
		"%w: helper config snapshot protocol version %d < required %d for multi-zone scoped global policies "+
			"(an older helper reads only the singular match from-zone/to-zone and would NARROW the scope)",
		ErrScopedGlobalZoneSetProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		MinProtocolMultiZoneScopedPolicy,
	)
}

// ensureSecureTunnelProtocolLocked is the fail-closed half of the #5619/#6691
// protocol bumps — v5 (the SecureTunnel field), v6 (the every-owner refusal
// rule) and v7 (the fabric parent's verdict). It compares against
// MinProtocolSecureTunnelRefusal, which is the LAST of those three (7): each of
// the three changes what an older helper does with the same snapshot, so the
// first version that reads the WHOLE contract is 7, and a helper below it
// misreads at least one part.
//
// #6648 changed this from `ProtocolVersion` to that pinned floor. The old
// spelling was not "the same number written differently": it made every future
// bump for an UNRELATED wire feature retroactively re-arm this gate, and report
// the secure-tunnel reason for a helper that reads the refusal contract
// perfectly well. The pin must move only when a FOURTH change to the refusal
// contract lands — never to track the shared constant. (The 7 -> 8 bump was
// collision resolution against #6722's parallel v5, not a change to this
// contract; ProtocolVersion's own comment carries that history.)
// An older helper REFUSES the snapshot outright,
// which stops it from planning a binding for the xfrmi — but a refused snapshot
// leaves that helper ARMED on its previous-good image while the commit reports
// success. This gate closes that window the way the sibling gates do: the
// caller disarms the helper and the commit aborts with an operator-visible
// reason.
//
// Scoped by snapshotRequiresRefusalProtocol (ingress_exclusions.go), which asks
// the CONTRIBUTOR ENUMERATION whether this snapshot carries an unbindable
// verdict a pre-bump helper cannot reproduce. Three earlier scopes were narrower
// and each was wrong for the same reason — they named the evidence they knew
// about instead of asking who produces it:
//
//   - "no route-based IPsec" outlived the round-8 widening. With zero VPNs
//     configured the scope is false with no live xfrmi and TRUE with a stale
//     live `st10`, which is right: a stale xfrmi is exactly the case an operator
//     cannot fix by editing the config, so an under-version helper must not stay
//     armed for it.
//   - A hand-mirrored re-derivation (round 8) took a SECOND RTM_GETLINK dump, so
//     an xfrm device visible to the builder's dump and gone by this one left the
//     gate silent for a snapshot carrying SecureTunnel=true. Two samples of a
//     changing kernel are two answers; round 9 made it a property of the code by
//     reading the applied rows, of which there is ONE classification per
//     snapshot.
//   - Reading the rows ALONE (round 9) then went silent for round 10's fabric
//     verdict, which is carried by no row at all — the #6691 round 11 blocker,
//     and the reason the scope is now derived from the same enumeration the
//     verdict is rather than from a second list beside it.
//
// The honest statement of the scope: an operator whose snapshot contains no
// verdict the older helper would decide differently is never blocked by a
// version mismatch that cannot affect them.
//
// This does NOT eliminate every re-sample in the package —
// UserspaceBoundLinuxInterfaces still builds its own snapshot from a bare
// *config.Config, because that is the only thing its daemon call sites have.
// What it eliminates is the sample whose disagreement was UNSAFE: a silent gate
// leaves an under-version helper armed on its previous-good image. The
// allowlist's remaining sample is conservative in its own direction (see its
// degrade-to-nil path) and cannot leave a helper armed.
func (m *Manager) ensureSecureTunnelProtocolLocked(snap *ConfigSnapshot) error {
	if !snapshotRequiresRefusalProtocol(snap) {
		return nil
	}
	if m.lastStatus.ConfigSnapshotProtocolVersion >= MinProtocolSecureTunnelRefusal {
		return nil
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
		m.recordHelperStatusLocked(&status)
		if status.ConfigSnapshotProtocolVersion >= MinProtocolSecureTunnelRefusal {
			return nil
		}
	}
	// ARM ON AN OBSERVED VERSION, NEVER ON THE ABSENCE OF ONE (#6691 round 10).
	//
	// Reaching here without helperStatusObserved means no helper has ever
	// answered this Manager: lastStatus is a zero value and the live status
	// request just failed too. The version compared above was 0 because there
	// is no helper to have a version, not because a helper reported an old one
	// — so there is nothing to be incompatible WITH, and arming would disarm a
	// dataplane and abort the operator's commit on the strength of a reading
	// that never happened.
	//
	// It is reachable, not defensive. The deferred-worker arm
	// (manager_worker_arm_5134.go) calls this gate through
	// ensureRequiredSnapshotProtocolLocked BEFORE any helper liveness check, so
	// a pending-XSK re-arm attempted while the helper is down took the abort
	// path on a config that had merely acquired a live xfrm device.
	//
	// An observed 0 still arms: a helper that answers without the field IS too
	// old, and helperStatusObserved is what separates that from silence —
	// the value alone cannot (manager.go).
	//
	// SCOPE: this gate only. The three sibling required-protocol gates in this
	// file share the shape and the question of what each SHOULD do when the
	// helper has never reported is #7002, which has to weigh each one's own
	// fail-closed argument. Fixing the one this PR introduces is not a licence
	// to change three others under the same commit.
	if m.noHelperVersionObservedLocked() {
		return nil
	}
	return fmt.Errorf(
		"%w: helper config snapshot protocol version %d < required %d for a device-level AF_XDP binding refusal "+
			"(a route-based IPsec secure tunnel, or a fabric parent netdev refused with no interface stanza to "+
			"carry the flags; an older helper cannot read the verdict and plans an AF_XDP binding for that "+
			"netdev, and an xfrm device's single RX queue then becomes the global minimum and collapses every "+
			"interface to one queue and one worker)",
		ErrSecureTunnelProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		MinProtocolSecureTunnelRefusal,
	)
}

func (m *Manager) ensurePolicySchedulerProtocolLocked(cfg *config.Config) error {
	if !configHasScheduledPolicy(cfg) {
		return nil
	}
	if m.lastStatus.ConfigSnapshotProtocolVersion >= MinProtocolPolicyScheduler {
		return nil
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
		m.recordHelperStatusLocked(&status)
		if status.ConfigSnapshotProtocolVersion >= MinProtocolPolicyScheduler {
			return nil
		}
	}
	if m.noHelperVersionObservedLocked() {
		return nil
	}
	return fmt.Errorf(
		"%w: helper config snapshot protocol version %d < required %d for policy scheduler snapshots",
		ErrPolicySchedulerProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		MinProtocolPolicyScheduler,
	)
}

func (m *Manager) ensurePersistentSourceNATProtocolLocked(cfg *config.Config) error {
	if !userspaceConfigUsesPersistentSourceNAT(cfg) {
		return nil
	}
	if m.lastStatus.ConfigSnapshotProtocolVersion >= MinProtocolPersistentSourceNAT {
		return nil
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
		m.recordHelperStatusLocked(&status)
		if status.ConfigSnapshotProtocolVersion >= MinProtocolPersistentSourceNAT {
			return nil
		}
	}
	if m.noHelperVersionObservedLocked() {
		return nil
	}
	return fmt.Errorf(
		"%w: helper config snapshot protocol version %d < required %d for persistent source NAT snapshots",
		ErrPersistentSourceNATProtocolIncompatible,
		m.lastStatus.ConfigSnapshotProtocolVersion,
		MinProtocolPersistentSourceNAT,
	)
}

// noHelperVersionObservedLocked reports that NO helper has ever told this
// Manager a config-snapshot protocol version — the state every required-protocol
// gate must DEFER on rather than arm (#7002).
//
// WHY DEFER. Arming here aborts the operator's commit and DISARMS a dataplane
// that is not running, on the strength of a reading that never happened — a
// brick, not a fence (#1960). The fail-closed property is kept one step later:
// when the helper returns it gets a fresh apply, and if it is genuinely too old
// its own exact-equality gate refuses that snapshot. This is the answer #6691
// round 10 and #6722 each reached independently; #7002 exists because the other
// three gates had not been brought in line.
//
// WHY BOTH TERMS. Three states share one value. "Never observed" and "a helper
// ANSWERED reporting 0" both leave ConfigSnapshotProtocolVersion at 0, and only
// the first is not evidence of a mismatch — a helper that answers with 0 is one
// old enough not to emit the field, exactly what these gates exist to refuse.
// helperStatusObserved is what separates them, which is why manager_status.go
// maintains the two as a PAIR in one function.
//
// In production the pair is always consistent — lastStatus is written only by
// setLastStatusLocked (which sets the flag) and clearLastStatusLocked (which
// clears both) — so on every reachable state this conjunction is EXACTLY
// `!helperStatusObserved`. The version term is what makes the predicate
// well-defined on the inconsistent pair too, and it resolves that pair toward
// ARMING: a non-zero version with no recorded observation is treated as an
// observation. That is the fail-closed direction, and it is the direction a
// future producer that forgets the flag should land in.
func (m *Manager) noHelperVersionObservedLocked() bool {
	return !m.helperStatusObserved && m.lastStatus.ConfigSnapshotProtocolVersion <= 0
}

// ensureRequiredSnapshotProtocolLocked takes the SNAPSHOT, not the config
// (#6691 round 9).
//
// Three of the four gates are pure config questions and read snap.Config
// exactly as before. The fourth — the secure-tunnel gate — is not: the flag it
// arms on is stamped by the snapshot builder from a sample of the KERNEL, and
// asking the same question from a config a moment later is asking a different
// kernel. Measured before this round, with an xfrm device visible to the
// builder's dump and gone by the gate's: the built snapshot carried
// SecureTunnel=true on `st10` while the gate returned false, so an under-version helper
// stayed ARMED on its previous-good image for exactly the snapshot the gate
// exists to refuse.
//
// Passing the snapshot makes "arms iff the snapshot carries a flagged row" true
// by construction rather than by two samples agreeing. Every call site already
// had one in scope: the apply paths pass the snapshot they are about to
// publish, and the poll/status/HA paths pass m.lastSnapshot, which is the
// snapshot actually being enforced — a strictly better oracle than re-deriving
// from config on a poll tick.
func (m *Manager) ensureRequiredSnapshotProtocolLocked(snap *ConfigSnapshot) error {
	var cfg *config.Config
	if snap != nil {
		cfg = snap.Config
	}
	if err := m.ensurePolicySchedulerProtocolLocked(cfg); err != nil {
		return err
	}
	if err := m.ensurePersistentSourceNATProtocolLocked(cfg); err != nil {
		return err
	}
	if err := m.ensureScopedGlobalZoneSetProtocolLocked(cfg); err != nil {
		return err
	}
	// Secure-tunnel gate FIRST, then egress-zone. Since #6648 they no longer
	// fence the same number — the secure-tunnel gate asks "can this helper read
	// the refusal contract?" (floor 7) and the egress-zone gate asks "will this
	// helper accept our snapshot at all?" (exact equality with ProtocolVersion)
	// — so both fire only for a helper below BOTH, and the order still decides
	// which sentinel the caller sees there. The secure-tunnel gate is SCOPED
	// (snapshotRequiresRefusalProtocol — it returns nil unless the snapshot
	// actually carries a flagged row) while the egress-zone gate is
	// UNCONDITIONAL, so asking the specific one first reports the narrower,
	// more actionable reason when it applies and falls through to the general
	// one otherwise. Fail-closed either way: both sentinels are in
	// requiredProtocolGateSentinels, so the commit aborts and the helper is
	// disarmed regardless of which one is returned.
	if err := m.ensureSecureTunnelProtocolLocked(snap); err != nil {
		return err
	}
	return m.ensureEgressZoneProtocolLocked()
}

// ensureEgressZoneProtocolLocked refuses to commit against a running helper
// that does not speak this binary's snapshot contract (#6722).
//
// Takes no config: every snapshot carries EgressZone, so unlike the sibling
// gates there is no shape to test. What it IS conditional on is having actually
// OBSERVED a helper version. That conditioning is load-bearing for #1960
// no-brick: `lastStatus` is zero before the first handshake, and a gate that
// fired on "version unknown" would abort every commit made while the helper is
// down or still starting — a brick, not a fence. When no version can be learned
// this returns nil and the pre-existing behaviour stands (the helper's own
// exact-equality gate refuses the snapshot and the apply surfaces that error).
//
// The comparison is EQUALITY. `>=` would pass a helper NEWER than this binary,
// whose own gate would then refuse our snapshot anyway, and — the reason the
// shape matters — a `> N` spelling stays green at exactly the version that
// collides.
func (m *Manager) ensureEgressZoneProtocolLocked() error {
	observed := m.lastStatus.ConfigSnapshotProtocolVersion
	if observed == ProtocolVersion {
		return nil
	}
	// Re-ask before failing: `lastStatus` may predate a helper restart onto a
	// matching build, and the sibling gates take the same second look.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
		m.recordHelperStatusLocked(&status)
		observed = status.ConfigSnapshotProtocolVersion
		if observed == ProtocolVersion {
			return nil
		}
	}
	// #7002, deliberately NOT unified onto noHelperVersionObservedLocked.
	//
	// This gate is the one that keeps `observed <= 0`, and the reason is
	// measured rather than stylistic. The shared predicate resolves "a helper
	// ANSWERED reporting 0" toward ARMING, which is the stronger reading and the
	// one ensureSecureTunnelProtocolLocked argues for. But no shipping helper
	// reports 0 — lifecycle.rs sets the field unconditionally to a non-zero
	// constant — so the case this gate would newly fence does not occur, while
	// the cost is real and wide: unlike its four siblings this gate has NO shape
	// predicate, so it runs on every commit and every route-overlay publish, and
	// tightening it fences any caller whose status probe answers with a partial
	// or stub ProcessStatus (measured: TestSyncFabricStatePersistsResolvedFabrics
	// IntoLastSnapshot reds on exactly that).
	//
	// Changing a deliberate, documented #6722 design for a benefit that cannot
	// currently be reached is a revert wearing the shape of a fix. The
	// divergence is recorded in the #7002 census test instead, so a later change
	// that makes a zero-reporting helper reachable finds the note.
	if observed <= 0 {
		// No helper has told us a version. Not evidence of a mismatch.
		return nil
	}
	return fmt.Errorf(
		"%w: helper config snapshot protocol version %d != required %d. The "+
			"interface rows changed shape in #6722: the egress security zone is "+
			"now decided by the control plane and carried in `egress_zone`, and "+
			"the `reth_projection` field the older contract carried is gone. A "+
			"helper on the other side of that change resolves NO egress zone for "+
			"an interface described by several rows — measured, both RETH "+
			"ifindexes of the reference cluster — so every transit flow out of "+
			"them falls to the default policy. Restart the userspace dataplane "+
			"helper onto the build that ships with this xpfd (they are pushed "+
			"together by `make cluster-deploy` / `make test-deploy`), then commit "+
			"again",
		ErrEgressZoneProtocolIncompatible,
		observed,
		ProtocolVersion,
	)
}

// disarmSnapshotProtocolFailClosedLocked is the shared fail-closed action for a
// required-protocol gate hit on a publish path (#5488 F7). It disarms the helper
// — the fail-closed contract of requiredProtocolGateSentinels — and, when the
// disarm ITSELF fails, additionally drives the userspace_ctrl shim to Enabled=0
// on the paths whose classifier BPF maps were already mutated IN PLACE.
//
// Why the extra step. A failed disarm leaves the helper ARMED on its
// previous-good Rust snapshot. On a same-plan refresh the ingress/local/
// interface-NAT classifier maps were already rewritten to the NEW plan with
// ctrl still enabled (syncUserspaceClassifierMapsFailClosedLocked), so simply
// returning would leave the XDP shim redirecting transit to XSK against maps a
// generation AHEAD of the snapshot the helper is enforcing. That is precisely
// the "fail-OPEN security/availability mismatch" failClosedUserspaceCtrlMapLocked
// exists to prevent (#4959), and the reason publishSnapshotFailClosedLocked
// takes the same mapsMutatedInPlace flag. Driving ctrl to 0 drops transit to the
// kernel-only fail-closed posture until a later good commit re-publishes.
//
// mapsMutatedInPlace MUST mirror the flag the caller passes to
// publishSnapshotFailClosedLocked, which is the codebase's oracle for "the
// classifier maps are ahead of the applied snapshot": samePlanRefresh in Compile,
// unconditionally true in syncSnapshotLocked (its only producer of an
// unpublished lastSnapshot is Compile's pendingXSKStartup branch, which always
// mutates the maps in place). The bootstrap path already programmed
// ctrl.Enabled=0, so it needs no extra fail-closed.
//
// Every failClosedUserspaceCtrlMapLocked return path PRESERVES cause (returned
// as-is, or wrapped with errors.Join), so the gate sentinel still satisfies
// IsRequiredProtocolGateError and the commit still ABORTS. A fail-closed disarm
// must never be downgraded into a promoted commit (#2138).
func (m *Manager) disarmSnapshotProtocolFailClosedLocked(snapshot *ConfigSnapshot, protocolErr error, mapsMutatedInPlace bool) error {
	disarmErr := m.disarmSnapshotProtocolFailureLocked(protocolErr)
	if disarmErr == nil {
		return protocolErr
	}
	joined := errors.Join(protocolErr, disarmErr)
	if !mapsMutatedInPlace {
		return joined
	}
	return m.failClosedUserspaceCtrlMapLocked(snapshot, joined)
}

func (m *Manager) disarmSnapshotProtocolFailureLocked(protocolErr error) error {
	if m.proc == nil || m.proc.Process == nil {
		return nil
	}
	req := ControlRequest{
		Type: "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{
			Armed: false,
		},
	}
	var status ProcessStatus
	if err := m.requestLocked(req, &status); err != nil {
		return fmt.Errorf("userspace: disarm helper after snapshot protocol error: %w", err)
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		m.recordHelperStatusLocked(&status)
		return fmt.Errorf("userspace: sync helper status after snapshot protocol fail-closed disarm: %w", err)
	}
	slog.Warn("userspace: disarmed helper after snapshot protocol error", "err", protocolErr)
	return nil
}
