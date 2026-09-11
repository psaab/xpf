package userspace

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// This file carries the per-domain apply steps that applyHelperStatusLocked
// (maps_sync.go) drives on every helper status tick. #6429 split them out of
// that one 481-line body as PURE CODE MOTION: every block below is the
// original statement sequence, in the original order, re-indented and
// nothing else. Two mechanical adaptations were unavoidable and are called
// out at their sites: the two `goto ctrlReady` jumps became `return` (the
// label sat immediately after the block they escaped, so the jump and the
// return land on the same statement), and the binding-row loops thread the
// `newBindingIndices` accumulator through their result list.
//
// Everything here runs under m.mu on the ~1/s status-poll path, so the same
// constraint that governs maps_sync.go governs this file: no new blocking,
// no new allocation, and no promotion of a slog.Debug to slog.Info.

// helperCtrlFlagsLocked derives the userspace_ctrl feature flags and the
// WireGuard listen port from the loaded shim maps and the last applied
// snapshot. Returns (flags, wgListenPort); wgListenPort is 0 when no WG
// tunnel is configured.
func (m *Manager) helperCtrlFlagsLocked() (uint32, uint32) {
	// Preserve cpumap flag if cpumap is populated.
	var ctrlFlags uint32
	if cpuMap := m.bpfShim.Map(mapNameUserspaceCPUMap); cpuMap != nil {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(m.lastSnapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}
	wgPort := snapshotWgListenPort(m.lastSnapshot)
	if wgPort != 0 {
		ctrlFlags |= userspaceCtrlFlagWgRx
	}
	return ctrlFlags, wgPort
}

// resolveCtrlEnableLocked decides ctrl.Enabled for this status tick and
// records the readiness/liveness state the decision derives from. It is the
// former inline gate of applyHelperStatusLocked; the `ctrlReady` label the
// gate used to jump to is now simply this function's return, so a caller
// resumes at exactly the statement the goto targeted.
func (m *Manager) resolveCtrlEnableLocked(status *ProcessStatus, ctrl *userspaceCtrlValue) {
	if m.ctrlMustStayDisabledLocked(status.Enabled) {
		// rgTransitionInFlight: one or more RG transitions are in progress and
		// the helper hasn't acked the HA state update yet. Keep ctrl disabled
		// until syncHAStateLocked succeeds to avoid re-enabling ctrl during the
		// handoff (#279, #284).
		//
		// linkCycleInFlight (#6871): a RETH MAC link cycle has joined the
		// workers and is taking the NIC down, so the XSK sockets this gate
		// steers into are dead or about to be. The status tick is gated on the
		// same lease and skips its whole body, but this is not only the tick's
		// path: UpdateRGActive ends in applyHelperStatusLocked too, and it is
		// driven by VRRP/cluster events and by reconcileRGStateLoop's 2s pass
		// (daemon_ha.go, which also wakes early on dropped-event
		// notifications), NEITHER of which is serialized on the daemon's
		// applySem — so it can land in
		// the middle of a cycle and re-enable ctrl on its own. Gating at the
		// write is what makes the lease cover the producer rather than one
		// caller of it. NotifyLinkCycle releases the lease at the top of its
		// critical section, so its own post-rebind status apply is NOT gated
		// here and a completed cycle re-enables ctrl on that call.
		ctrl.Enabled = 0
	} else if status.Enabled {
		// Delay ctrl enable until AFTER VIPs are configured in HA mode.
		// The VRRP election + VIP add takes ~10-14s after restart.
		// If we enable ctrl before VIPs, the XSK path gets packets but
		// can't SNAT (no source address) -> all transit dropped. While
		// ctrl is disabled, only proven local/control traffic reaches the
		// kernel; transit remains fail-closed.
		//
		// Also delay by 3s for fill ring bootstrap: mlx5 zero-copy
		// needs NAPI to post fill ring WQEs, and NAPI only runs on
		// hardware RX events.  Background traffic (VRRP, ARP) during
		// the delay generates these events.
		m.ensureCtrlEnablePrewarmLocked()
		probeBindingsReady, allBindingsBound := m.bindingReadinessLocked(status)
		// Fire OnXSKBound callback once when all bindings are bound.
		// This lets the daemon create fabric IPVLAN overlays after XSK
		// has bound in zerocopy mode on the parent interface.
		if allBindingsBound && !m.xskBoundNotified && m.OnXSKBound != nil {
			m.xskBoundNotified = true
			go m.OnXSKBound()
		}

		neighborSyncReady := status.NeighborGeneration > 0

		// XSK receive liveness: once bindings and neighbor state are ready,
		// arm ctrl and explicitly probe the userspace shim. A working XSK
		// path must show RX progress while ctrl=1 and the shim is active.
		// Otherwise keep ctrl disabled: local/control packets may still
		// reach the kernel, but transit fails closed in both modes.
		currentRX, xskReceiveLive := m.observeXSKReceiveLivenessLocked(status)
		slog.Debug("userspace: ctrl gate check",
			"probeBindingsReady", probeBindingsReady,
			"allBindingsBound", allBindingsBound,
			"neighborSyncReady", neighborSyncReady,
			"xskReceiveLive", xskReceiveLive,
			"currentRX", currentRX,
			"lastXSKRX", m.lastXSKRX,
			"neighborsPrewarmed", m.neighborsPrewarmed,
			"xskLivenessFailed", m.xskLivenessFailed,
			"xdpEntryProg", m.bpfShim.XDPEntryProgram())
		m.applyXSKLivenessGateLocked(ctrl, probeBindingsReady, neighborSyncReady,
			xskReceiveLive, allBindingsBound, currentRX)
	}
}

// ensureCtrlEnablePrewarmLocked runs the one-shot ctrl-enable prewarm: it
// arms the hard-timeout deadline on the FIRST prewarm only, kicks the NAPI
// fill-ring bootstrap, and starts proactive neighbor resolution.
func (m *Manager) ensureCtrlEnablePrewarmLocked() {
	if !m.neighborsPrewarmed {
		m.neighborsPrewarmed = true
		// Hard timeout fallback — ctrl enables after this even if
		// readiness checks haven't passed. Prevents infinite stall
		// if a readiness condition can never be met.
		//
		// Only set ctrlEnableAt on the FIRST prewarm so that
		// subsequent rebind cycles (which reset neighborsPrewarmed)
		// don't push the hard timeout forward indefinitely.
		if m.ctrlEnableAt.IsZero() {
			delay := 3 * time.Second
			if m.clusterHA {
				delay = 15 * time.Second
			}
			m.ctrlEnableAt = time.Now().Add(delay)
			slog.Info("userspace: delaying ctrl enable for readiness",
				"hard_timeout", delay, "cluster_ha", m.clusterHA)
		}
		m.bootstrapNAPIQueuesAsyncLocked("startup-prewarm")
		m.proactiveNeighborResolveLocked()
	}
}

// bindingReadinessLocked folds the helper's per-binding flags into the two
// readiness predicates the ctrl gate consumes: probeBindingsReady (every
// binding registered and armed) and allBindingsBound (no registered binding
// still unbound).
func (m *Manager) bindingReadinessLocked(status *ProcessStatus) (bool, bool) {
	// Check readiness gates BEFORE refreshing neighbors (which
	// bumps the generation). The status reports the generation
	// from the previous refresh cycle.
	//
	// The helper can only prove RX liveness after ctrl enables the
	// shim and the userspace_bindings map exposes the binding slots.
	// Requiring Bound here deadlocks startup: ctrl stays off, the shim
	// keeps passing packets away from XSK, and Bound never flips true.
	probeBindingsReady := len(status.Bindings) > 0
	allBindingsBound := len(status.Bindings) > 0
	for _, b := range status.Bindings {
		if b.Ifindex <= 0 {
			continue
		}
		if !b.Registered || !b.Armed {
			probeBindingsReady = false
		}
		if b.Registered && !b.Bound {
			allBindingsBound = false
		}
	}
	return probeBindingsReady, allBindingsBound
}

// observeXSKReceiveLivenessLocked totals RX across the helper's bindings and
// compares it with the previous tick, returning (currentRX, xskReceiveLive).
// It advances m.lastXSKRX as a side effect, exactly where the inline code
// did — the ctrl-gate debug log downstream deliberately reports the NEW
// value.
func (m *Manager) observeXSKReceiveLivenessLocked(status *ProcessStatus) (uint64, bool) {
	var currentRX uint64
	for _, b := range status.Bindings {
		currentRX += b.RXPackets
	}
	xskReceiveLive := currentRX > m.lastXSKRX
	m.lastXSKRX = currentRX
	return currentRX, xskReceiveLive
}

// applyXSKLivenessGateLocked is the top arm of the ctrl-enable decision:
// proven-broken XSK keeps ctrl off, a ready-and-neighbor-synced helper arms
// ctrl and advances the liveness probe, an expired hard timeout enables ctrl
// regardless, and anything else leaves ctrl off.
func (m *Manager) applyXSKLivenessGateLocked(
	ctrl *userspaceCtrlValue,
	probeBindingsReady, neighborSyncReady, xskReceiveLive, allBindingsBound bool,
	currentRX uint64,
) {
	if m.xskLivenessFailed {
		// XSK proven broken: ctrl stays disabled. The shim only passes
		// proven local/control packets and drops transit.
		ctrl.Enabled = 0
	} else if probeBindingsReady && neighborSyncReady {
		ctrl.Enabled = 1
		m.advanceXSKLivenessLocked(ctrl, xskReceiveLive, allBindingsBound, currentRX)
	} else if !m.ctrlEnableAt.IsZero() && time.Now().After(m.ctrlEnableAt.Add(60*time.Second)) {
		// Hard timeout fallback: allow ctrl even if readiness has not been
		// fully proven yet. The XSK liveness probe still decides whether
		// the userspace shim starts redirecting or stays fail-closed
		// for transit.
		ctrl.Enabled = 1
	} else {
		ctrl.Enabled = 0
	}
}

// advanceXSKLivenessLocked runs the XSK liveness state machine once ctrl has
// been armed: already-proven restores the shim, fresh RX proves liveness, and
// otherwise the probe is started or handed to the timeout resolver.
func (m *Manager) advanceXSKLivenessLocked(
	ctrl *userspaceCtrlValue,
	xskReceiveLive, allBindingsBound bool,
	currentRX uint64,
) {
	if m.xskLivenessProven {
		if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
			if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
				slog.Warn("userspace: failed to restore XDP shim after liveness success", "err", err)
			}
		}
	} else if xskReceiveLive {
		m.xskLivenessProven = true
		m.xskProbeStart = time.Time{}
		if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
			if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
				slog.Warn("userspace: failed to swap XDP shim after XSK RX became live", "err", err)
			}
		}
		slog.Info("userspace: XSK liveness proven")
	} else {
		if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
			if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
				slog.Warn("userspace: failed to activate XDP shim for XSK liveness probe", "err", err)
			}
		}
		if m.xskProbeStart.IsZero() {
			m.xskProbeStart = time.Now()
			slog.Info("userspace: starting XSK liveness probe")
		} else if time.Now().After(m.xskProbeStart.Add(10 * time.Second)) {
			m.resolveXSKLivenessProbeTimeoutLocked(ctrl, allBindingsBound, currentRX)
		}
	}
}

// resolveXSKLivenessProbeTimeoutLocked decides what an expired XSK liveness
// probe means: an idle standby proves liveness, an idle-but-plausible link
// extends the probe, and anything else marks liveness failed and drops ctrl
// back to 0 (strict mode logs at error level, compat re-arms the shim).
//
// The two early returns below were `goto ctrlReady` before #6429. The label
// sat immediately after the whole ctrl-gate statement, and this block was the
// last statement inside it, so returning here resumes at the same place the
// jump landed: the caller chain unwinds with nothing left to execute in
// advanceXSKLivenessLocked, applyXSKLivenessGateLocked or
// resolveCtrlEnableLocked.
func (m *Manager) resolveXSKLivenessProbeTimeoutLocked(
	ctrl *userspaceCtrlValue,
	allBindingsBound bool,
	currentRX uint64,
) {
	if m.shouldAutoProveIdleStandbyXSKLocked(currentRX, allBindingsBound) {
		m.xskLivenessProven = true
		m.xskProbeStart = time.Time{}
		if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
			if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
				slog.Warn("userspace: failed to restore XDP shim after idle standby liveness success", "err", err)
			}
		}
		slog.Info("userspace: XSK liveness proven on idle standby")
		return
	} else if m.shouldExtendXSKLivenessIdleLocked(currentRX, allBindingsBound) {
		m.xskProbeStart = time.Now()
		slog.Info("userspace: extending XSK liveness probe while idle")
		return
	}
	m.xskLivenessFailed = true
	m.xskProbeStart = time.Time{}
	ctrl.Enabled = 0
	if m.configuredMode == ModeUserspaceStrict {
		// Strict mode: keep the shim attached with ctrl=0
		// so packets hit the fail-closed ctrl-disabled path.
		// Log at error level because this degraded state
		// needs operator attention.
		slog.Error("userspace: XSK liveness probe failed in strict mode; dataplane degraded fail-closed")
	} else {
		slog.Warn("userspace: XSK liveness probe failed; keeping shim disabled with transit fail-closed")
		if !m.bpfShim.UsingUserspaceXDPShimEntryProgram() {
			if err := m.bpfShim.SwapToUserspaceXDPShimEntryProgram(); err != nil {
				slog.Warn("userspace: failed to restore XDP shim after XSK liveness failure", "err", err)
			}
		}
	}
}

// flushStaleBPFStateOnCtrlEnableLocked flushes stale BPF session entries when
// ctrl transitions from disabled to enabled. Older legacy-fallback windows
// could create PASS_TO_KERNEL entries in the userspace session map. These
// poison the XDP shim after ctrl enables: it sees the stale entry and
// bypasses XSK instead of redirecting to the userspace helper.
//
// It also flushes BPF conntrack sessions left by earlier legacy-fallback
// windows. These sessions interfere with the userspace pipeline via TC
// egress: when the Rust helper sends packets via XSK TX, TC egress finds the
// stale BPF conntrack entries and may apply conflicting NAT or update session
// state incorrectly. The userspace helper's own session table (Rust
// SessionTable + shared_sessions) holds the authoritative synced sessions, so
// BPF conntrack must be empty when ctrl re-enables.
//
// The caller gates this on the very first ctrl enable after daemon startup.
// Snapshot generation is not a reliable proxy for "startup" on long-lived HA
// nodes because a steady appliance can stay at generation 1 indefinitely;
// later ctrl re-enables during RG moves would then retrigger the startup
// flush and destroy synced sessions. This function sets
// m.initialCtrlCleanupDone as its last act, which is what closes that gate.
func (m *Manager) flushStaleBPFStateOnCtrlEnableLocked() {
	if usMap := m.bpfShim.Map(mapNameUserspaceSessions); usMap != nil {
		var key, nextKey []byte
		key = make([]byte, usMap.KeySize())
		nextKey = make([]byte, usMap.KeySize())
		deleted := 0
		for {
			if err := usMap.NextKey(key, nextKey); err != nil {
				break
			}
			copy(key, nextKey)
			_ = usMap.Delete(key)
			deleted++
		}
		if deleted > 0 {
			slog.Info("userspace: flushed stale BPF session entries on initial ctrl enable",
				"deleted", deleted)
		}
	}
	// Flush BPF conntrack sessions left by an earlier fallback
	// transition window. Only delete
	// sessions whose Created timestamp is AFTER ctrlDisabledAt —
	// synced sessions from the cluster peer have earlier timestamps
	// and must survive for HA failover continuity.
	//
	// Why this is needed (issue #334): a previous legacy fallback
	// can leave conntrack entries in the BPF sessions map. When
	// ctrl re-enables, TC egress finds these stale BPF entries and
	// may apply conflicting NAT or update session state incorrectly;
	// the userspace helper's own session table (Rust SessionTable +
	// shared_sessions) is authoritative.
	//
	// #6816: the `Created` offset is DERIVED from the Go struct that mirrors the
	// C ABI (dataplane.SessionValueCreatedOffset), not written down here.
	//
	// It used to be the literal 16, justified by an in-comment sum
	// "State(1)+Flags(1)+TCPState(1)+IsReverse(1)+AppTimeout(4)+SessionID(8)=16"
	// that was wrong twice over: `Flags` has been a uint16 since #5460, and the
	// struct carries three explicit padding gaps (#6082) the sum omits. SessionID
	// is at 16 and Created at 24 — so this read a SESSION ID and compared it
	// against a seconds-since-boot cutoff, and the "keep synced sessions" branch
	// decided on a number that is not a timestamp.
	//
	// The value is seconds since boot (bpf_ktime_get_coarse_ns / 1e9);
	// ctrlDisabledAt is nanoseconds, so convert to seconds for comparison.
	cutoffSec := m.ctrlDisabledAt / 1_000_000_000
	for _, mapName := range []string{"sessions", "sessions_v6"} {
		if ctMap := m.bpfShim.Map(mapName); ctMap != nil {
			keySize := ctMap.KeySize()
			valSize := ctMap.ValueSize()
			var key, nextKey []byte
			key = make([]byte, keySize)
			nextKey = make([]byte, keySize)
			val := make([]byte, valSize)
			deleted, kept := 0, 0
			for {
				if err := ctMap.NextKey(key, nextKey); err != nil {
					break
				}
				copy(key, nextKey)
				// Read session value to check the Created timestamp, at the
				// offset the ABI struct actually puts it at (#6816).
				if cutoffSec > 0 {
					end := dataplane.SessionValueCreatedOffset + 8
					if err := ctMap.Lookup(key, val); err == nil && len(val) >= end {
						created := binary.NativeEndian.Uint64(
							val[dataplane.SessionValueCreatedOffset:end])
						if created > 0 && created <= cutoffSec {
							kept++
							continue // synced session — keep it
						}
					}
				}
				_ = ctMap.Delete(key)
				deleted++
			}
			if deleted > 0 || kept > 0 {
				slog.Info("userspace: flushed stale BPF conntrack on ctrl enable",
					"map", mapName, "deleted", deleted, "kept_synced", kept,
					"cutoff_sec", cutoffSec)
			}
		}
	}
	m.initialCtrlCleanupDone = true
}

// applyRuntimeModeLocked derives m.mode from the resolved ctrl state and the
// XSK liveness verdict, then stamps the strict flag into ctrl so the XDP shim
// reports strict degraded drops separately.
func (m *Manager) applyRuntimeModeLocked(ctrl *userspaceCtrlValue) {
	// Compute active runtime mode from ctrl state and liveness.
	switch {
	case ctrl.Enabled == 0 || m.xskLivenessFailed:
		// Degraded userspace mode keeps the shim attached. Compat still only
		// permits local/control kernel delivery; it is not eBPF-only transit.
		if m.configuredMode == ModeUserspaceStrict {
			m.mode = ModeUserspaceStrict
		} else {
			m.mode = ModeUserspaceCompat
		}
	case m.xskLivenessProven && m.configuredMode == ModeUserspaceStrict:
		m.mode = ModeUserspaceStrict
	case m.xskLivenessProven:
		m.mode = ModeUserspaceCompat
	default:
		// ctrl enabled but liveness not yet proven — still probing.
		m.mode = ModeUserspaceCompat
	}
	// Set strict flag in ctrl so the XDP shim reports strict degraded drops
	// separately while keeping transit fail-closed in both modes.
	if m.configuredMode == ModeUserspaceStrict {
		ctrl.Flags |= userspaceCtrlFlagStrict
	}
}

// applyPrimaryBindingRowsLocked writes one userspace_bindings row per live
// helper binding and returns the accumulated row inventory. The three error
// exits fail ctrl closed exactly as the inline loop did; they carry the
// partial inventory back only so no information is lost — the caller returns
// on a non-nil error without touching m.lastBindingIndices, which is the
// pre-#6429 behaviour.
// bindingSlotOutOfRangeError reports a helper-supplied binding slot that the
// slot-keyed shim maps cannot address.
//
// This is a DIFFERENT guard from the map-ABI drift check added with the
// plan-time cap (`validateUserspaceShimSpecWith`), and the two must not be
// conflated: that one verifies the maps are the size we believe at load, this
// one verifies a row we are about to write can actually be addressed in them.
// A correct map size does not make an out-of-range slot writable.
//
// It is also NOT redundant with the helper's own plan-time refusal
// (`MAX_BINDING_SLOTS` in userspace-dp). They are separate trust boundaries:
// during a rolling HA upgrade the two nodes run different binaries, so a peer
// helper predating that cap can hand this manager a slot at or above the map
// capacity, and without this check the manager would write it (#7497 blocker 8).
func bindingSlotOutOfRangeError(slot uint32, ifindex int, queue uint32) error {
	return fmt.Errorf(
		"update userspace_bindings: slot=%d exceeds the %d-entry userspace_heartbeat/userspace_xsk_map capacity (ifindex=%d queue=%d); the shim indexes BOTH by binding slot, so this row could never be redirected to or heartbeat-checked (#7497)",
		slot, dataplane.BindingSlotMapMaxEntries, ifindex, queue,
	)
}

func (m *Manager) applyPrimaryBindingRowsLocked(
	status *ProcessStatus,
	ctrlMap ctrlMapUpdater,
	bindingsMap ctrlMapUpdater,
	ctrl userspaceCtrlValue,
	deadWorkers map[uint32]bool,
	newBindingIndices []uint32,
	newBindingIndexSet map[uint32]struct{},
) ([]uint32, error) {
	// #7497 blocker 8: the helper's binding list is accepted on trust today.
	// These two maps are LOCAL to this call deliberately — the shared
	// newBindingIndexSet accumulator also carries the alias path's rows, and a
	// VLAN alias legitimately REUSES its parent's slot at a different index, so
	// a uniqueness check spanning both paths would reject correct configs.
	seenSlotIfindex := make(map[uint32]int, len(status.Bindings))
	seenCoordSlot := make(map[uint32]uint32, len(status.Bindings))
	for _, binding := range status.Bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		flags := uint32(0)
		if bindingForwardingLive(binding, deadWorkers) {
			// #1666: mark forwarding-ready only when the helper derives
			// the binding Ready (registered && bound && xsk_registered &&
			// heartbeat_fresh) and the worker has not panicked. The prior
			// (Registered && Armed) predicate let the XDP shim steer
			// transit to a slot whose worker had crashed or never finished
			// XSK registration (crash-blind blackhole). Ready's
			// sub-conditions are all set by worker bringup independent of
			// RX, so this does not deadlock startup (plan §4).
			flags = userspaceBindingReady
		}
		// Queue-dimension bound guard (#4894): a queue-id at or above the
		// fixed stride makes idx = ifindex*stride + queue land on
		// (ifindex+1)*stride + (queue-stride) — aliasing a slot that
		// belongs to the ADJACENT ifindex. The dense-cap guard below
		// cannot catch this (the aliased index is in range), so bound the
		// queue dimension explicitly and fail closed rather than steer an
		// interface's packets into another interface's XSK. Never
		// clamp/modulo the queue-id: that would still steer to a wrong
		// slot.
		if binding.QueueID >= bindingQueuesPerIface {
			return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
				"update userspace_bindings: queue-id=%d >= stride=%d would alias the adjacent ifindex queue-0 slot (ifindex=%d) — cap the helper queue count or raise BINDING_QUEUES_PER_IFACE in userspace-xdp/src/binding_index.rs (mirrored in pkg/dataplane/constants.go) (#4894)",
				binding.QueueID, uint32(bindingQueuesPerIface), binding.Ifindex,
			))
		}
		// Ifindex-dimension bound (#9698), BEFORE the multiply. An ifindex of
		// 2^28 or more wraps uint32(ifindex)*stride back inside the dense cap
		// (and 2^32 or more truncates in the conversion), so the #814 check
		// below passes and the row lands on another (ifindex, queue).
		if !bindingIfindexInRange(binding.Ifindex) {
			return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
				"update userspace_bindings: ifindex=%d exceeds cap MaxInterfaces=%d (queue=%d); ifindex*stride would wrap the uint32 composed index onto another interface's row — raise MAX_INTERFACES in bpf/headers/xpf_common.h if the ifindex is real (#9698)",
				binding.Ifindex, dataplane.MaxInterfaces, binding.QueueID,
			))
		}
		idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
		// Call-site cap guard (#814): the aya Array is sized to
		// dataplane.BindingArrayMaxEntries = MaxInterfaces *
		// BindingQueuesPerIface. An ifindex above MaxInterfaces would
		// overflow the flat index; fail with a legible error instead
		// of relying on the kernel's "argument list too long" E2BIG.
		if idx >= dataplane.BindingArrayMaxEntries {
			return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
				"update userspace_bindings: idx=%d exceeds cap=%d (ifindex=%d queue=%d; raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
				idx, dataplane.BindingArrayMaxEntries, binding.Ifindex, binding.QueueID,
			))
		}
		// Slot-dimension bound (#7497 blocker 8). The two guards above bound
		// the COMPOSED index into userspace_bindings; neither bounds `Slot`,
		// which is what indexes userspace_heartbeat and userspace_xsk_map —
		// maps 256x smaller than BindingArrayMaxEntries.
		if binding.Slot >= dataplane.BindingSlotMapMaxEntries {
			return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl,
				bindingSlotOutOfRangeError(binding.Slot, binding.Ifindex, binding.QueueID))
		}
		// Duplicate (ifindex, queue): two rows resolving to one composed index.
		// Without this the second Update silently overwrites the first and the
		// first row's XSK is orphaned — registered and heartbeating, but no
		// longer reachable by any redirect. Nothing counts that.
		if prevSlot, dup := seenCoordSlot[idx]; dup {
			return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
				"update userspace_bindings: duplicate (ifindex=%d queue=%d) from the helper — slot=%d would overwrite slot=%d at idx=%d and orphan the first slot's XSK (#7497)",
				binding.Ifindex, binding.QueueID, binding.Slot, prevSlot, idx,
			))
		}
		// Duplicate slot across DIFFERENT coordinates: two RX queues steering
		// into one XSK. The redirect would succeed and the packets would be
		// adjudicated, so this is invisible downstream — but one of the two
		// queues has no socket of its own and the plan is not what it claims.
		if prevIfindex, dup := seenSlotIfindex[binding.Slot]; dup {
			return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
				"update userspace_bindings: slot=%d claimed twice by the helper (ifindex=%d queue=%d and ifindex=%d) — binding slots are minted densely and must be unique per row (#7497)",
				binding.Slot, binding.Ifindex, binding.QueueID, prevIfindex,
			))
		}
		seenCoordSlot[idx] = binding.Slot
		seenSlotIfindex[binding.Slot] = binding.Ifindex
		val := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
			return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf("update userspace_bindings idx=%d (if=%d q=%d): %w", idx, binding.Ifindex, binding.QueueID, err))
		}
		if _, seen := newBindingIndexSet[idx]; !seen {
			newBindingIndexSet[idx] = struct{}{}
			newBindingIndices = append(newBindingIndices, idx)
		}
	}
	return newBindingIndices, nil
}

// applyAliasBindingRowsLocked mirrors each VLAN-alias child ifindex onto its
// parent's binding rows. Same accumulator and same fail-closed exits as
// applyPrimaryBindingRowsLocked.
func (m *Manager) applyAliasBindingRowsLocked(
	status *ProcessStatus,
	ctrlMap ctrlMapUpdater,
	bindingsMap ctrlMapUpdater,
	ctrl userspaceCtrlValue,
	deadWorkers map[uint32]bool,
	newBindingIndices []uint32,
	newBindingIndexSet map[uint32]struct{},
) ([]uint32, error) {
	for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
		for _, binding := range status.Bindings {
			if binding.Ifindex != int(parentIfindex) {
				continue
			}
			flags := uint32(0)
			if bindingForwardingLive(binding, deadWorkers) {
				// #1666: unify the VLAN-alias child with the primary gate.
				flags = userspaceBindingReady
			}
			// Queue-dimension bound guard (#4894): see primary apply above.
			// The alias child uses its own ifindex, but the queue-id comes
			// from the parent's binding, so bound it here too.
			if binding.QueueID >= bindingQueuesPerIface {
				return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
					"update aliased userspace_bindings: queue-id=%d >= stride=%d would alias the adjacent ifindex queue-0 slot (child=%d parent=%d) — cap the helper queue count or raise BINDING_QUEUES_PER_IFACE in userspace-xdp/src/binding_index.rs (mirrored in pkg/dataplane/constants.go) (#4894)",
					binding.QueueID, uint32(bindingQueuesPerIface), childIfindex, parentIfindex,
				))
			}
			idx := childIfindex*bindingQueuesPerIface + binding.QueueID
			// Call-site cap guard (#814): see primary apply above.
			// VLAN-alias children use their own ifindex here, so the
			// child (not the parent) is the overflow risk.
			if idx >= dataplane.BindingArrayMaxEntries {
				return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
					"update aliased userspace_bindings: idx=%d exceeds cap=%d (child=%d parent=%d queue=%d; raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
					idx, dataplane.BindingArrayMaxEntries, childIfindex, parentIfindex, binding.QueueID,
				))
			}
			// Slot-dimension bound (#7497 blocker 8), repeated here rather
			// than relied upon from the primary pass. Every binding this
			// loop mirrors is one the primary pass already validated, so
			// today this is unreachable — but that is a property of the
			// CALL ORDER in applyUserspaceHelperStatusLocked, not of this
			// function, and an ordering assumption is not a guard.
			if binding.Slot >= dataplane.BindingSlotMapMaxEntries {
				return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl,
					bindingSlotOutOfRangeError(binding.Slot, int(childIfindex), binding.QueueID))
			}
			val := userspaceBindingValue{
				Slot:  binding.Slot,
				Flags: flags,
			}
			if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
				return newBindingIndices, m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
					"update aliased userspace_bindings idx=%d (if=%d parent=%d q=%d): %w",
					idx,
					childIfindex,
					parentIfindex,
					binding.QueueID,
					err,
				))
			}
			if _, seen := newBindingIndexSet[idx]; !seen {
				newBindingIndexSet[idx] = struct{}{}
				newBindingIndices = append(newBindingIndices, idx)
			}
		}
	}
	return newBindingIndices, nil
}
