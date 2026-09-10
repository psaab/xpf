package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	xpfnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

type userspaceCtrlValue struct {
	Enabled         uint32
	MetadataVersion uint32
	Workers         uint32
	QueueCount      uint32
	Flags           uint32
	// WgListenPort (#1432 S2a) occupies the former Pad slot before the
	// u64 ConfigGeneration (the ABI alignment pad the Rust shim's
	// UserspaceCtrl also exposes as wg_listen_port). Low 16 bits carry
	// the WG listen port; 0 means no WG tunnel is configured (the shim's
	// per-CPU "wg_rx" gate). The shim steers local-destination UDP on
	// this port to the kernel.
	WgListenPort       uint32
	ConfigGeneration   uint64
	FIBGeneration      uint32
	HeartbeatTimeoutMS uint32
}

const userspaceMetadataVersion = 4
const userspaceCtrlFlagCPUMap = 1
const userspaceCtrlFlagTrace = 2
const userspaceCtrlFlagNativeGRE = 4
const userspaceCtrlFlagStrict = 8

// userspaceCtrlFlagWgRx (#1432 S2a) is set iff at least one WireGuard
// tunnel is configured. The shim gates its per-packet WG steering branch
// on this single bit so non-WG traffic never even loads wg_listen_port.
const userspaceCtrlFlagWgRx = 16
const bindingQueuesPerIface = 16 // must match BINDING_QUEUES_PER_IFACE in BPF

const userspaceBindingReady = 1

// deadWorkerIDSet builds the set of worker IDs whose worker_loop has
// panicked, from the helper's per-worker runtime status. On panic the
// supervisor (coordinator/supervisor.rs) sets runtime_atomics.dead which
// surfaces as WorkerRuntimeStatus.Dead (#925). Dead is set-only until
// daemon restart, so it never spuriously fires for a live worker.
func deadWorkerIDSet(runtime []WorkerRuntimeStatus) map[uint32]bool {
	if len(runtime) == 0 {
		return nil
	}
	var dead map[uint32]bool
	for _, w := range runtime {
		if w.Dead {
			if dead == nil {
				dead = make(map[uint32]bool, len(runtime))
			}
			dead[w.WorkerID] = true
		}
	}
	return dead
}

// bindingForwardingLive reports whether a binding is safe to mark READY
// (userspaceBindingReady) in the XDP userspace_bindings array.
//
// #1666: the gate keeps the historical (Registered && Armed)
// admission AND adds the helper-derived binding.Ready — which is
// (registered && bound && xsk_registered && heartbeat_fresh), computed in
// userspace-dp coordinator/refresh_bindings.rs — ANDed with the binding's
// worker not being Dead.
//
// Registered && Armed must stay in the predicate: the Rust Ready
// derivation does NOT include Armed (armed = armed_req && registered is a
// separate control-plane flag), so a Ready-but-disarmed binding must not
// forward. The Ready + !Dead legs are what newly withhold/clear READY for
// a worker that crashed or never finished XSK registration (the
// crash-blind blackhole).
//
// All of Ready's sub-conditions are flipped true by worker bringup alone
// (socket create -> set_bound, XSKMAP register -> set_xsk_registered,
// per-poll-tick heartbeat), independent of inbound traffic, so this gate
// cannot deadlock a legitimately-live binding (see
// docs/pr/1666-ready-gate/plan.md §4).
func bindingForwardingLive(b BindingStatus, deadWorkers map[uint32]bool) bool {
	return b.Registered && b.Armed && b.Ready && !deadWorkers[b.WorkerID]
}

type userspaceBindingKey struct {
	Ifindex uint32
	QueueID uint32
}

type userspaceBindingValue struct {
	Slot  uint32
	Flags uint32
}

type userspaceLocalV6Key struct {
	Addr [16]byte
}

type userspaceLocalAddressEntry struct {
	v4    bool
	v4Key uint32
	v6Key userspaceLocalV6Key
}

func (m *Manager) programBootstrapMapsLocked(snapshot *ConfigSnapshot, cfg config.UserspaceConfig) error {
	ctrlMap := m.bpfShim.Map(mapNameUserspaceCtrl)
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.bpfShim.Map(mapNameUserspaceBindings)
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}
	heartbeatMap := m.bpfShim.Map(mapNameUserspaceHeartbeat)
	if heartbeatMap == nil {
		return errors.New("userspace_heartbeat map not loaded")
	}

	// Populate userspace_cpumap so the XDP shim can use cpumap redirect
	// for IP packets that must reach the kernel on zero-copy AF_XDP paths.
	cpumapReady := m.setupUserspaceCPUMapLocked()

	zero := uint32(0)
	var ctrlFlags uint32
	if cpumapReady {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(snapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}
	wgPort := snapshotWgListenPort(snapshot)
	if wgPort != 0 {
		ctrlFlags |= userspaceCtrlFlagWgRx
	}
	// Clamp the worker count before it feeds the ctrl fields and the
	// heartbeat zero-init loop below (#4572). deriveUserspaceConfig
	// already coerces workers<=0 -> 1 (capabilities.go), so the negative
	// case is defended one layer up; this restores the line-154/179
	// consistency with the QueueCount clamp on the next line and keeps the
	// low bound local to the map programmer. The genuinely dangerous input
	// is a large POSITIVE workers: the schema leaf is min-only
	// (ValidateIntegerMin(1)) and deriveUserspaceConfig does not cap the
	// upper side, so e.g. `workers 999999999` reaches the loop below and
	// uint32(999999999)*32 wraps to ~1.9B iterations that hang the apply
	// for hours — bounded by effectiveWorkers' map-capacity clamp.
	//
	// #5718 fold F3: ONE derivation feeds every representation of this
	// quantity. cfg.Workers used to be consumed TWICE under different rules —
	// `maxInt(cfg.Workers, 1)` cast to uint32 for ctrl.Workers/ctrl.QueueCount,
	// and the RAW cfg.Workers passed to the heartbeat zero-init bound below —
	// so the two
	// descriptions of "how many workers this dataplane has" could drift, and
	// after the A6-b01-C1 narrowing fix they demonstrably DID: `workers
	// 4294967296` clamps to the full heartbeat map for the zero-init loop
	// while `uint32(maxInt(...))` narrows to 0 for the ctrl fields, telling the
	// shim there are ZERO workers and ZERO queues. planUserspaceWorkers returns
	// both numbers from a single clamp, so no call site can pair a clamped
	// count with a raw one. cfg.Workers is read exactly once, here — a property
	// worker_count_single_source_5718_test.go asserts on this function's AST.
	plan := planUserspaceWorkers(cfg.Workers, heartbeatMap.MaxEntries())
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            plan.Workers,
		QueueCount:         plan.Workers,
		Flags:              ctrlFlags,
		WgListenPort:       wgPort,
		ConfigGeneration:   0,
		FIBGeneration:      0,
		HeartbeatTimeoutMS: 30000,
	}
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl: %w", err)
	}

	// Bindings map is now an Array — zero previously-set indices.
	m.clearAllBindingRowsLocked()
	// Heartbeat map is now an Array — zero used slots instead of deleting.
	// Slots with value 0 appear as stale (bpf_ktime_get_ns() >> 0) so the
	// XDP shim correctly refuses to redirect until userspace begins updating.
	{
		var zeroHB uint64
		// The bound is the Array's OWN capacity (#6702 blocker 2), not a
		// worker-derived prefix: heartbeat slots are indexed by BINDING slot,
		// and the binding count is not a function of cfg.Workers, so a
		// worker-derived prefix left the tail slots holding the previous
		// load's timestamps — which read as FRESH and mask a helper that has
		// stopped. It still comes from the SAME plan the ctrl fields above
		// were built from (#5718 fold F3), so there is one derivation and no
		// second description to diverge from; and because it no longer reads
		// cfg.Workers, neither a negative nor an absurd value can make this
		// loop wrap uint32 or index past the map (#4572).
		//
		// #5718 fold r3: read plan.HeartbeatSlots INLINE in the loop condition
		// rather than through a local. An intermediate `slots := ...` leaves a
		// decoy an AST guard can be satisfied by while the loop counts against
		// something else entirely — `slot < plan.Workers` zeroes one entry per
		// WORKER instead of per SLOT: 1 of 32 at the default worker count
		// (capabilities.go seeds Workers: 1), and 6 of 192 on the six-worker
		// loss cluster. Every un-zeroed slot keeps whatever stale value it
		// held. The bound the loop actually uses is the only thing worth
		// pinning, so it is the only thing written.
		//
		// #6959: the Update error is PROPAGATED, matching the
		// userspace_ctrl write above which already aborts bring-up on the
		// same class of failure. A DISCARDED rejection here leaves the
		// slot holding the previous load's timestamp, which reads as
		// FRESH and lets the shim redirect to a worker that is not there
		// — the exact hazard the #6702 bound fix above closed. The bound
		// is the Array's own MaxEntries(), so no in-range write turns
		// into a spurious bring-up failure.
		for slot := uint32(0); slot < plan.HeartbeatSlots; slot++ {
			if err := heartbeatMap.Update(slot, zeroHB, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("zero userspace heartbeat slot %d: %w", slot, err)
			}
		}
	}
	return m.syncUserspaceClassifierMapsLocked(snapshot)
}

// setupUserspaceCPUMapLocked populates the userspace_cpumap BPF map with one
// entry per online CPU. This enables the XDP shim to use cpumap redirect
// instead of relying on driver-specific XDP_PASS recycling behavior for IP
// packets delivered to the kernel from zero-copy AF_XDP paths.
func (m *Manager) setupUserspaceCPUMapLocked() bool {
	cpuMap := m.bpfShim.Map(mapNameUserspaceCPUMap)
	if cpuMap == nil {
		slog.Warn("userspace_cpumap not found, zero-copy cpumap redirect disabled")
		return false
	}

	numCPUs := runtime.NumCPU()
	if numCPUs > 256 {
		numCPUs = 256
	}

	// cpumap value: struct { __u32 qsize; int bpf_prog_fd; }
	// With prog_fd=0, no cpumap program is attached — packets go to kernel.
	// TODO: attach xdp_cpumap_prog for eBPF embedded ICMP NAT reversal.
	for cpu := 0; cpu < numCPUs; cpu++ {
		val := make([]byte, 8)
		binary.NativeEndian.PutUint32(val[0:4], 2048) // qsize
		binary.NativeEndian.PutUint32(val[4:8], 0)    // no attached program
		if err := cpuMap.Update(uint32(cpu), val, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace_cpumap update failed", "cpu", cpu, "err", err)
			return false
		}
	}

	slog.Info("userspace cpumap enabled for zero-copy AF_XDP", "cpus", numCPUs)
	return true
}

func (m *Manager) failClosedUserspaceCtrlLocked(ctrlMap ctrlMapUpdater, ctrl userspaceCtrlValue, cause error) error {
	if ctrl.Enabled != 1 {
		return cause
	}
	disabled := ctrl
	disabled.Enabled = 0
	zero := uint32(0)
	if err := ctrlMap.Update(zero, disabled, ebpf.UpdateAny); err != nil {
		return errors.Join(cause, fmt.Errorf("fail closed userspace_ctrl after publication error: %w", err))
	}
	if m.ctrlWasEnabled {
		m.ctrlDisabledAt = m.bpfKtimeNs()
	}
	m.ctrlWasEnabled = false
	return cause
}

func (m *Manager) syncUserspaceClassifierMapsLocked(snapshot *ConfigSnapshot) error {
	// #7468 test seam, mirroring clearHelperHAStateHook. Unprivileged the three
	// map syncs below no-op (m.bpfShim.Map returns nil), so "the maps were
	// rolled back to the retained snapshot" and "the rollback was never
	// attempted" are indistinguishable without it — and telling those apart is
	// the whole property. Production leaves it nil.
	if m.syncClassifierMapsHook != nil {
		return m.syncClassifierMapsHook(snapshot)
	}
	if err := m.syncIngressIfaceMapLocked(snapshot); err != nil {
		return err
	}
	if err := m.syncLocalAddressMapsLocked(snapshot); err != nil {
		return err
	}
	return m.syncInterfaceNATAddressMapsLocked(snapshot)
}

type userspaceCtrlLookupHook func(ctrlMapUpdater, uint32, *userspaceCtrlValue) error

func (m *Manager) lookupUserspaceCtrlForFailClosed(ctrlMap ctrlMapUpdater, key uint32, ctrl *userspaceCtrlValue) error {
	if m.lookupUserspaceCtrlForFailClosedHook != nil {
		return m.lookupUserspaceCtrlForFailClosedHook(ctrlMap, key, ctrl)
	}
	return ctrlMap.Lookup(key, ctrl)
}

func (m *Manager) syncUserspaceClassifierMapsFailClosedLocked(snapshot *ConfigSnapshot) error {
	if err := m.syncUserspaceClassifierMapsLocked(snapshot); err != nil {
		return m.failClosedUserspaceCtrlMapLocked(snapshot, err)
	}
	return nil
}

// failClosedCtrlMap resolves the userspace_ctrl handle the fail-closed path
// writes through, preferring the test seam (#9337).
//
// It is the same map-free seam #5486 established for the disable path and #6994
// for applyHelperStatusLocked, added for the same measured reason: without it
// the ONLY way to observe "a rejected publish drove ctrl to 0" is a real BPF
// map, so every guard on this — the security property #4959 exists for — sits
// above the CAP_BPF boundary and does not execute where the suite normally
// runs. Unprivileged, m.bpfShim.Map returns nil and the whole function returns
// cause unchanged, which makes "failed closed" and "never tried" identical.
// Production leaves the hook nil.
func (m *Manager) failClosedCtrlMap() ctrlMapUpdater {
	if m.failClosedCtrlMapHook != nil {
		return m.failClosedCtrlMapHook
	}
	if shimMap := m.bpfShim.Map(mapNameUserspaceCtrl); shimMap != nil {
		return shimMap
	}
	return nil
}

// failClosedUserspaceCtrlMapLocked drives the userspace_ctrl shim to the
// fail-closed state (Enabled=0) so the XDP shim stops redirecting transit to
// XSK and only passes proven local/control traffic to the kernel. It is the
// shared fail-closed action for any error that leaves the ingress/local/
// interface-NAT classifier BPF maps mutated to a plan the running Rust snapshot
// has NOT accepted: a classifier-map write failure
// (syncUserspaceClassifierMapsFailClosedLocked) OR a rejected apply_snapshot
// after an in-place same-plan refresh (#4959). cause is returned, wrapped with
// any secondary lookup/update error. When the ctrl row is unreadable the blind
// path reconstructs a disabled row from the snapshot; a genuinely-absent row
// (fresh boot, never enabled) is already fail-closed and returns cause
// unchanged.
func (m *Manager) failClosedUserspaceCtrlMapLocked(snapshot *ConfigSnapshot, cause error) error {
	ctrlMap := m.failClosedCtrlMap()
	if ctrlMap == nil {
		return cause
	}
	var ctrl userspaceCtrlValue
	zero := uint32(0)
	if lookupErr := m.lookupUserspaceCtrlForFailClosed(ctrlMap, zero, &ctrl); lookupErr != nil {
		if errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
			return cause
		}
		return m.blindFailClosedUserspaceCtrlLocked(ctrlMap, snapshot, cause, lookupErr)
	}
	return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, cause)
}

func (m *Manager) blindFailClosedUserspaceCtrlLocked(
	ctrlMap ctrlMapUpdater,
	snapshot *ConfigSnapshot,
	cause error,
	lookupErr error,
) error {
	disabled := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: 30000,
	}
	if snapshot != nil {
		workers := maxInt(snapshot.Userspace.Workers, 1)
		disabled.Workers = uint32(workers)
		disabled.QueueCount = uint32(workers)
		disabled.ConfigGeneration = snapshot.Generation
		disabled.FIBGeneration = snapshot.FIBGeneration
		disabled.WgListenPort = snapshotWgListenPort(snapshot)
		if disabled.WgListenPort != 0 {
			disabled.Flags |= userspaceCtrlFlagWgRx
		}
		if snapshotHasNativeGRE(snapshot) {
			disabled.Flags |= userspaceCtrlFlagNativeGRE
		}
	}
	if m.configuredMode == ModeUserspaceStrict {
		disabled.Flags |= userspaceCtrlFlagStrict
	}
	if cpuMap := m.bpfShim.Map(mapNameUserspaceCPUMap); cpuMap != nil {
		disabled.Flags |= userspaceCtrlFlagCPUMap
	}

	zero := uint32(0)
	if err := ctrlMap.Update(zero, disabled, ebpf.UpdateAny); err != nil {
		return errors.Join(
			cause,
			fmt.Errorf("lookup userspace_ctrl for classifier-map fail-closed: %w", lookupErr),
			fmt.Errorf("blind fail closed userspace_ctrl after lookup failure: %w", err),
		)
	}
	if m.ctrlWasEnabled {
		m.ctrlDisabledAt = m.bpfKtimeNs()
	}
	m.ctrlWasEnabled = false
	return errors.Join(
		cause,
		fmt.Errorf("lookup userspace_ctrl for classifier-map fail-closed: %w", lookupErr),
	)
}

// ctrlMustStayDisabledLocked reports whether the ctrl gate must be held at 0
// even though the helper reports Enabled. It is the exact condition that used to
// be inline in applyHelperStatusLocked's ctrl branch; the reasoning for each
// disjunct lives at that branch.
//
// #6871 (round 9, F4): extracted so the clause is REACHABLE without privileges.
// applyHelperStatusLocked opens by resolving userspace_ctrl and userspace_bindings
// off the shim and returns "userspace_ctrl map not loaded" when either is absent,
// so every unprivileged test stops at line one and the clause behind it is bound
// by nothing CI runs — deleting `|| m.linkCycleInFlight()` left BOTH
// pkg/dataplane/userspace and pkg/daemon fully green. The three cells that do
// cover it need real BPF maps and SKIP unprivileged, and Go reports a parent as
// PASS when every subtest skipped.
//
// SCOPE OF THE REMEDY, stated rather than implied. This binds the PREDICATE, not
// the call site: a change that stopped calling it, or inlined a different
// condition, would not be caught here. The full remedy is to route
// applyHelperStatusLocked's map handles through an interface the way
// ctrlMapForDisableLocked does (process_linkcycle.go), and that is a wide change
// — the two handles are threaded through failClosedUserspaceCtrlLocked,
// clearStaleBindingRowsLocked and ~15 other call sites inside a 481-line function
// on the fail-closed path — so it is deliberately NOT bundled into this round.
// What this buys is the difference between "unbound" and "bound one level in".
func (m *Manager) ctrlMustStayDisabledLocked(statusEnabled bool) bool {
	return statusEnabled && (m.rgTransitionInFlight.Load() || m.linkCycleInFlight())
}

// applyHelperStatusLocked reconciles one helper status report into the shim's
// userspace_ctrl and userspace_bindings maps and the manager's derived state.
// It runs under m.mu on the ~1/s status-poll path (and on the UpdateRGActive
// path), so it must not block or allocate beyond what the steps below already
// do. #6429 split the per-domain steps into helper_status_apply.go; the order
// of the steps, and what each early return skips, is unchanged.
// helperStatusMapsLocked resolves the two shim maps applyHelperStatusLocked
// operates on, through a map-free seam (#6994).
//
// WHY THIS EXISTS. applyHelperStatusLocked used to open by calling
// m.bpfShim.Map twice and returning "userspace_ctrl map not loaded" when either
// was absent. On an unprivileged machine — which is every machine CI runs on —
// the shim holds no maps, so EVERY test stopped on line one and the entire body
// behind it was bound by nothing. Measured on the pre-#6994 head: deleting
// `m.resolveCtrlEnableLocked(status, &ctrl)` outright left both
// pkg/dataplane/userspace and pkg/daemon fully green, which is the ctrl gate —
// #6871's link-cycle clause included — not being reached by any test at all.
//
// #6871 round 9 extracted ctrlMustStayDisabledLocked so the PREDICATE could be
// tabled unprivileged, and that binding is real: dropping
// `|| m.linkCycleInFlight()` from it reds
// TestCtrlMustStayDisabledDuringLinkCycle_6871. What it could not bind is
// production still CONSULTING it. That is this seam's job, and the reason a
// predicate table is not a substitute for it.
//
// Nil handling matches ctrlMapForDisableLocked: a missing map returns an
// untyped nil, never a non-nil interface wrapping a nil *ebpf.Map, so the
// callers' `== nil` checks behave as they did when the values were pointers.
func (m *Manager) helperStatusMapsLocked() (ctrlMapUpdater, ctrlMapUpdater) {
	var ctrlMap, bindingsMap ctrlMapUpdater
	if m.helperStatusCtrlMapHook != nil {
		ctrlMap = m.helperStatusCtrlMapHook
	} else if cm := m.bpfShim.Map(mapNameUserspaceCtrl); cm != nil {
		ctrlMap = cm
	}
	if m.helperStatusBindingsMapHook != nil {
		bindingsMap = m.helperStatusBindingsMapHook
	} else if bm := m.bpfShim.Map(mapNameUserspaceBindings); bm != nil {
		bindingsMap = bm
	}
	return ctrlMap, bindingsMap
}

func (m *Manager) applyHelperStatusLocked(status *ProcessStatus) error {
	ctrlMap, bindingsMap := m.helperStatusMapsLocked()
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}

	var newBindingIndices []uint32
	newBindingIndexSet := make(map[uint32]struct{})

	ctrlFlags, wgPort := m.helperCtrlFlagsLocked()

	zero := uint32(0)
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            uint32(maxInt(status.Workers, 1)),
		QueueCount:         uint32(queueCountFromBindings(status.Bindings)),
		Flags:              ctrlFlags,
		WgListenPort:       wgPort,
		ConfigGeneration:   status.LastSnapshotGeneration,
		FIBGeneration:      status.LastFIBGeneration,
		HeartbeatTimeoutMS: 30000,
	}
	m.resolveCtrlEnableLocked(status, &ctrl)

	// Only flush stale BPF sessions on the very first ctrl enable after daemon
	// startup; flushStaleBPFStateOnCtrlEnableLocked documents why that gate
	// matters and closes it by setting m.initialCtrlCleanupDone.
	if ctrl.Enabled == 1 && !m.ctrlWasEnabled && !m.initialCtrlCleanupDone {
		m.flushStaleBPFStateOnCtrlEnableLocked()
	}

	m.applyRuntimeModeLocked(&ctrl)

	if ctrl.Enabled == 0 {
		if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("disable userspace_ctrl from helper status: %w", err)
		}
		if m.ctrlWasEnabled {
			m.ctrlDisabledAt = m.bpfKtimeNs()
		}
		m.ctrlWasEnabled = false
	}

	deadWorkers := deadWorkerIDSet(status.WorkerRuntime)
	newBindingIndices, err := m.applyPrimaryBindingRowsLocked(
		status, ctrlMap, bindingsMap, ctrl, deadWorkers, newBindingIndices, newBindingIndexSet)
	if err != nil {
		return err
	}
	newBindingIndices, err = m.applyAliasBindingRowsLocked(
		status, ctrlMap, bindingsMap, ctrl, deadWorkers, newBindingIndices, newBindingIndexSet)
	if err != nil {
		return err
	}
	m.lastBindingIndices = m.clearStaleBindingRowsLocked(bindingsMap, newBindingIndices, newBindingIndexSet)
	// #6994: one call through the shared classifier-sync helper instead of the
	// three inline calls this used to make. Behaviour-identical — that helper
	// runs the SAME three syncs in the SAME order and returns the first error,
	// and all three inline arms wrapped that error in the identical
	// failClosedUserspaceCtrlLocked — while bringing this path under the #7468
	// syncClassifierMapsHook seam. Without it the ingress-iface sync errors
	// "userspace_ingress_ifaces map not loaded" on any unprivileged machine and
	// applyHelperStatusLocked fail-closes before ever writing the ctrl gate, so
	// the map-free seam above would still leave the ctrl branch untestable.
	if err := m.syncUserspaceClassifierMapsLocked(m.lastSnapshot); err != nil {
		return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, err)
	}
	// Sync userspace-forwarded packet counters into BPF counter maps so
	// that ReadGlobalCounter/ReadZoneCounters/etc. return complete values
	// even for packets that bypassed the BPF pipeline (#332).
	m.syncBPFCountersLocked(status)

	if ctrl.Enabled == 1 {
		if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
			return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf("enable userspace_ctrl from helper status: %w", err))
		}
		m.ctrlWasEnabled = true
	}

	m.recordHelperStatusLocked(status)
	return nil
}

// clearStaleBindingRowsLocked zeroes userspace_bindings rows that were live on
// the previous status pass (recorded in m.lastBindingIndices) but are absent
// from the current pass (newBindingIndexSet). It returns the retry inventory
// to store back into m.lastBindingIndices.
//
// A row whose zeroing Update FAILS is RETAINED in the returned inventory so a
// later status pass re-attempts the clear (#5697, codex-review-182 M20). The
// clear loop only rescans indices recorded in m.lastBindingIndices, so if a
// failed clear dropped the row from the inventory it would never be
// rediscovered — the stale row would persist in the BPF map indefinitely and
// the XDP shim would keep steering transit to a slot no longer backed by a
// live worker. A successful clear removes the row from the inventory (it is
// not in newBindingIndexSet, so it is not carried forward).
func (m *Manager) clearStaleBindingRowsLocked(bindingsMap ctrlMapUpdater, newBindingIndices []uint32, newBindingIndexSet map[uint32]struct{}) []uint32 {
	var zeroBinding userspaceBindingValue
	for _, idx := range m.lastBindingIndices {
		if _, keep := newBindingIndexSet[idx]; keep {
			continue
		}
		if err := bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace: failed to clear stale binding entry; retaining in retry inventory",
				"idx", idx, "err", err)
			if _, seen := newBindingIndexSet[idx]; !seen {
				newBindingIndexSet[idx] = struct{}{}
				newBindingIndices = append(newBindingIndices, idx)
			}
			continue
		}
	}
	return newBindingIndices
}

// clearAllBindingRowsLocked zeroes every userspace_bindings row recorded in
// m.lastBindingIndices and forgets the inventory. It is the fail-closed
// teardown primitive (#5486): when ctrl-disable cannot be verified before
// worker/UMEM teardown, this leaves the XDP shim with no READY slot to
// redirect to, so no packet can reach a soon-dead XSK fd. It mirrors the
// bootstrap zero-all used by the initial map program. Best-effort: a per-row
// Update failure on the teardown path is not fatal (the helper is stopping),
// but the inventory is always niled so a fresh apply re-establishes rows.
func (m *Manager) clearAllBindingRowsLocked() {
	bindingsMap := m.bpfShim.Map(mapNameUserspaceBindings)
	if bindingsMap == nil {
		m.lastBindingIndices = nil
		return
	}
	var zeroBinding userspaceBindingValue
	for _, idx := range m.lastBindingIndices {
		_ = bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny)
	}
	m.lastBindingIndices = nil
}

// userspaceCounterSnapshot holds cumulative counter totals from the helper,
// used to compute deltas between status polls.

// degradedPathReasonNames maps BPF array index to a human-readable name.
// Must stay in sync with USERSPACE_FALLBACK_REASON_* in userspace-xdp/src/lib.rs.
var degradedPathReasonNames = [16]string{
	0:  "ctrl_disabled",
	1:  "parse_fail",
	2:  "binding_missing",
	3:  "binding_not_ready",
	4:  "heartbeat_missing",
	5:  "heartbeat_stale",
	6:  "icmp",
	7:  "early_filter",
	8:  "adjust_meta",
	9:  "meta_bounds",
	10: "redirect_err",
	11: "interface_nat_no_session",
	12: "no_session",
	13: "strict_drop",
	14: "pass_to_kernel",
	15: "transit_drop",
}

// readDegradedPathStatsLocked reads retained-shim degraded-path counters and
// returns a map of reason name -> cumulative count. Entries with zero count are
// omitted.
//
// The pinned BPF map name remains userspace_fallback_stats as an internal
// mixed-version compatibility exception. Operator-facing Go status, JSON, and
// docs must use degraded-path terminology instead.
func (m *Manager) readDegradedPathStatsLocked() map[string]uint64 {
	statsMap := m.bpfShim.Map(mapNameUserspaceShimDegradedStats)
	if statsMap == nil {
		return nil
	}
	result := make(map[string]uint64)
	for i := uint32(0); i < uint32(len(degradedPathReasonNames)); i++ {
		// #4113 (F13): userspace_fallback_stats is a PER-CPU array. A per-CPU
		// map lookup returns one value per possible CPU, which we sum to get
		// the cumulative count for this reason. Reading into a single uint64
		// would fail (per-CPU maps require a slice destination).
		var perCPU []uint64
		if err := statsMap.Lookup(i, &perCPU); err != nil {
			continue
		}
		var val uint64
		for _, v := range perCPU {
			val += v
		}
		if val == 0 {
			continue
		}
		name := degradedPathReasonNames[i]
		if name == "" {
			name = fmt.Sprintf("reason_%d", i)
		}
		result[name] = val
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// entryProgramsLocked returns a map of ifindex -> attached XDP program name
// by inspecting the bpfShim dataplane manager's link state.
// Note: VLAN sub-interfaces are skipped during userspace-shim swaps and may
// retain the parent's program; they are excluded from this map.
func (m *Manager) entryProgramsLocked() map[int]string {
	// #6740: ONE guarded accessor rather than three unsynchronised reads.
	//
	// This ran at 1 Hz and used to range the shim's LIVE xdpLinks map, index
	// its exported VlanSubInterfaces map and read the entry-program name
	// separately — while CompileUserspaceShim / AttachXDP / DetachXDP mutated
	// those maps underneath. A concurrent Go map read+write is a fatal
	// runtime.throw, so the status poll could kill the daemon outright.
	//
	// XDPEntryPrograms takes the shim's m.mu once and applies the VLAN skip
	// against the same instant it read the link set, so this path no longer
	// touches the manager's maps at all.
	return m.bpfShim.XDPEntryPrograms()
}

// syncIngressIfaceMapLocked reconciles userspace_ingress_ifaces to the ingress
// set the snapshot adjudicates, and maintains m.lastIngressIfaces — the delete
// inventory the reap loop below rescans.
//
// #6537: the inventory is recorded on EVERY exit, not only the all-succeeded
// one. Within a process it is the record of which rows exist in the BPF map,
// and the reap loop only ever revisits ifindexes named in it, so a row that is
// installed but never recorded is permanently unreachable: when its interface
// later drops out of the config nothing deletes it, and the XDP shim keeps
// redirecting that interface's traffic to userspace. Recording it only when no
// retry is needed wrote the debt down exactly when there was none — the same
// shape #5697 fixed for the stale userspace_bindings clears
// (clearStaleBindingRowsLocked).
//
// #6784: "within a process" is the load-bearing qualifier, and before #6784 it
// was missing — the comment claimed the inventory was the SOLE record of the
// map's rows. It is not: userspace_ingress_ifaces is PinByName-pinned at
// /sys/fs/bpf/xpf, so its rows outlive xpfd while the inventory is an ordinary
// Manager field that starts nil. A daemon restart therefore reaped nothing on
// its first pass — the loop below scanned an empty `prior` — and any ifindex
// that dropped out of the config while xpfd was down (or whose interface was
// deleted and its ifindex reused) stayed in the map with the shim still
// treating it as an ingress interface. adoptIngressInventoryLocked closes that
// by enumerating the pinned map ONCE per Manager before the inventory is read,
// so the reap has a truthful starting set. The sibling classifier maps already
// worked this way — syncLocalAddressMapsLocked and
// syncInterfaceNATAddressMapsLocked prune by iterating the MAP rather than an
// in-process list — so this makes ingress consistent with them rather than
// inventing a mechanism.
//
// On an early return the inventory becomes prior ∪ installed: the prior entries
// are kept because a failed (or not-yet-attempted) delete still has to be
// retried, and the entries installed on this pass are added because they are
// now live rows. On a clean pass it is exactly newIngress — every prior entry
// not in the new set was successfully deleted, so carrying it would make the
// reap loop rescan keys that are already gone.
func (m *Manager) syncIngressIfaceMapLocked(snapshot *ConfigSnapshot) error {
	ifaceMap := m.bpfShim.Map(mapNameUserspaceIngressIfaces)
	if ifaceMap == nil {
		return errors.New("userspace_ingress_ifaces map not loaded")
	}

	// #6784: make the delete inventory truthful about the PINNED map before
	// anything reads it. On a fresh Manager (daemon restart) this is what turns
	// the reap below from a no-op into a real reconcile; on every later pass it
	// is a single already-adopted bool test.
	if err := m.adoptIngressInventoryLocked(ifaceMap); err != nil {
		return fmt.Errorf("adopt userspace_ingress_ifaces inventory: %w", err)
	}

	newIngress := buildUserspaceIngressIfindexes(snapshot)
	prior := m.lastIngressIfaces
	// installed accumulates the rows THIS pass created, so an early return can
	// hand them to the retry inventory rather than stranding them.
	installed := make([]uint32, 0, len(newIngress))
	retainDebt := func() {
		m.lastIngressIfaces = mergeIngressInventory(prior, installed)
	}

	newIngressSet := make(map[uint32]struct{}, len(newIngress))
	for _, ifindex := range newIngress {
		newIngressSet[ifindex] = struct{}{}
		if err := ifaceMap.Update(ifindex, uint8(1), ebpf.UpdateAny); err != nil {
			retainDebt()
			return fmt.Errorf("update userspace_ingress_ifaces %d: %w", ifindex, err)
		}
		installed = append(installed, ifindex)
	}
	// HashMap: Delete removes the entry. ErrKeyNotExist is expected
	// across daemon restarts (idempotent). Any other failure must be
	// fatal — a stale entry the dataplane still treats as ingress
	// would silently redirect traffic for an interface removed from
	// the config.
	for _, k := range prior {
		if _, keep := newIngressSet[k]; keep {
			continue
		}
		if err := ifaceMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			retainDebt()
			return fmt.Errorf("delete userspace_ingress_ifaces %d: %w", k, err)
		}
	}
	m.lastIngressIfaces = newIngress
	return nil
}

// adoptIngressInventoryLocked folds the rows actually present in the pinned
// userspace_ingress_ifaces map into m.lastIngressIfaces, ONCE per Manager
// (#6784).
//
// WHY THIS IS NEEDED AT ALL. Session state is retained across a helper/daemon
// restart deliberately — that is how HA continuity survives one. The classifier
// maps are retained by the same PinByName mechanism, but NOT for the same
// reason: nothing about a classifier row is worth preserving across a config
// reload, and unlike sessions there is no code that rebuilds an inventory for
// them. So a fresh Manager inherits rows it never wrote and cannot name, and
// the reap loop — which only ever revisits ifindexes the inventory names —
// silently reaps nothing on its first pass.
//
// That matters because the row is not inert. The XDP shim reads this map on
// EVERY packet (userspace-xdp/src/lib.rs: `USERSPACE_INGRESS_IFACES.get(
// &ingress_ifindex)`) and a present non-zero row is what diverts the packet
// away from `cpumap_or_pass` into the AF_XDP redirect path. A stale row for an
// interface that dropped out of the config therefore does not merely leak — it
// keeps steering that interface's traffic, and this map is the gate every
// later binding/XSK stage sits behind.
//
// UNION, not replace. The adopted set is merged with whatever the inventory
// already holds rather than overwriting it, so adoption can never DROP a #6537
// retry debt recorded before the first sync completed. Adoption is recorded
// only after a successful enumeration, so a failed scan retries on the next
// pass instead of latching a partial view.
//
// Only rows the SHIM ACTS ON are adopted — those with a non-zero value. The
// shim's test is `USERSPACE_INGRESS_IFACES.get(&ifindex).map_or(true, |v| *v
// == 0)`, so a 0-valued row means "not ingress" and takes the same
// cpumap_or_pass path as an absent one. A 0-valued row therefore diverts no
// traffic and is not a stale classifier row in the sense this repairs; the Go
// sync is the map's sole producer (the Rust helper never touches it, the shim
// only reads it) and only ever writes 1, so in production the filter excludes
// nothing that exists.
//
// The filter also makes adoption correct independent of the map's DENSITY
// rather than by assuming a HashMap. Enumerating a dense map — an Array, where
// every index is present — would otherwise adopt every slot as a live row and
// send the reap loop into Delete calls that an Array rejects with EINVAL.
// Keying on the value the shim reads is the property that actually matters, and
// it holds for either shape.
//
// An enumeration failure is returned to the caller and is FATAL, matching the
// established treatment of a classifier-map iteration failure in
// syncLocalAddressMapsLocked / syncInterfaceNATAddressMapsLocked: if the map's
// contents cannot be established, the reap cannot be trusted, and the caller
// (syncUserspaceClassifierMapsFailClosedLocked) drives ctrl to Enabled=0 so the
// shim stops redirecting transit rather than running against a classifier no
// one can account for.
func (m *Manager) adoptIngressInventoryLocked(ifaceMap *ebpf.Map) error {
	if m.ingressInventoryAdopted {
		return nil
	}
	var (
		key uint32
		val uint8
	)
	present := make([]uint32, 0, len(m.lastIngressIfaces))
	iter := ifaceMap.Iterate()
	for iter.Next(&key, &val) {
		if val == 0 {
			// Inert: the shim reads this exactly as it reads an absent row.
			continue
		}
		present = append(present, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_ingress_ifaces: %w", err)
	}
	m.lastIngressIfaces = mergeIngressInventory(m.lastIngressIfaces, present)
	m.ingressInventoryAdopted = true
	return nil
}

// mergeIngressInventory returns the union of the prior userspace_ingress_ifaces
// delete inventory and the rows installed on an interrupted pass, preserving
// prior order and de-duplicating (#6537).
//
// It is only reached on an error path, so it allocates a fresh slice rather
// than appending into prior: prior may alias the caller's newIngress from an
// earlier successful sync, and growing it in place would mutate an inventory
// another reader still holds.
func mergeIngressInventory(prior, installed []uint32) []uint32 {
	merged := make([]uint32, 0, len(prior)+len(installed))
	seen := make(map[uint32]struct{}, len(prior)+len(installed))
	for _, src := range [][]uint32{prior, installed} {
		for _, k := range src {
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			merged = append(merged, k)
		}
	}
	return merged
}

func (m *Manager) syncLocalAddressMapsLocked(snapshot *ConfigSnapshot) error {
	localV4Map := m.bpfShim.Map(mapNameUserspaceLocalV4)
	if localV4Map == nil {
		return errors.New("userspace_local_v4 map not loaded")
	}
	localV6Map := m.bpfShim.Map(mapNameUserspaceLocalV6)
	if localV6Map == nil {
		return errors.New("userspace_local_v6 map not loaded")
	}

	desiredV4, desiredV6, enumComplete := m.buildDesiredLocalAddressSets(snapshot)
	for key := range desiredV4 {
		if err := localV4Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_local_v4 %08x: %w", key, err)
		}
	}
	for key := range desiredV6 {
		if err := localV6Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_local_v6 %+v: %w", key, err)
		}
	}

	// A transient netlink AddrList failure (or an interrupted/ENOBUFS
	// partial dump) yields a NON-AUTHORITATIVE desired set that may be
	// missing kernel-owned VIP addresses (VRRP VIPs, secondary locals).
	// Pruning against that partial set would delete live VRRP VIP / local
	// keys from userspace_local_v4/v6 and blackhole packets destined to
	// the VIP / SSH / BGP / IKE local endpoints (#3924). Treat the
	// incomplete enumeration as non-authoritative: the adds above already
	// landed (adding is always safe — it only ever widens the local set),
	// but SKIP the stale-key prune this cycle and warn. The next reconcile
	// with a complete enumeration removes any genuinely stale keys.
	if !enumComplete {
		slog.Warn("userspace local-address sync: netlink AddrList enumeration incomplete; " +
			"skipping stale-key prune to avoid removing VRRP VIP/local keys from " +
			"userspace_local_v4/v6 (will reconcile on the next complete enumeration)")
		return nil
	}

	var (
		localV4Key uint32
		localV4Val uint8
	)
	localV4Iter := localV4Map.Iterate()
	var staleLocalV4Keys []uint32
	for localV4Iter.Next(&localV4Key, &localV4Val) {
		if _, keep := desiredV4[localV4Key]; keep {
			continue
		}
		staleLocalV4Keys = append(staleLocalV4Keys, localV4Key)
	}
	if err := localV4Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_local_v4: %w", err)
	}
	for _, key := range staleLocalV4Keys {
		if err := localV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v4 %08x: %w", key, err)
		}
	}

	var (
		localV6Key userspaceLocalV6Key
		localV6Val uint8
	)
	localV6Iter := localV6Map.Iterate()
	var staleLocalV6Keys []userspaceLocalV6Key
	for localV6Iter.Next(&localV6Key, &localV6Val) {
		if _, keep := desiredV6[localV6Key]; keep {
			continue
		}
		staleLocalV6Keys = append(staleLocalV6Keys, localV6Key)
	}
	if err := localV6Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_local_v6: %w", err)
	}
	for _, key := range staleLocalV6Keys {
		if err := localV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v6 %+v: %w", key, err)
		}
	}
	return nil
}

// addrListHook mirrors netlink.AddrList so tests can inject a transient
// enumeration failure through the Manager (#3924).
type addrListHook func(link netlink.Link, family int) ([]netlink.Addr, error)

// addrListForLocalSync enumerates addresses for the local-address map
// reconcile, dispatching to the test hook when one is installed and to
// netlink.AddrList otherwise.
func (m *Manager) addrListForLocalSync(link netlink.Link, family int) ([]netlink.Addr, error) {
	if m.addrListForLocalSyncHook != nil {
		return m.addrListForLocalSyncHook(link, family)
	}
	return netlink.AddrList(link, family)
}

// buildDesiredLocalAddressSets returns the desired userspace_local_v4/v6
// key sets and reports whether the kernel-address enumeration was
// COMPLETE. enumComplete is false when any netlink AddrList family dump
// failed — in that case the returned sets are non-authoritative (they may
// be missing kernel-owned VIP addresses), so the caller MUST NOT prune
// existing map keys against them (#3924). Config-derived entries are
// always present regardless of enumeration outcome.
func (m *Manager) buildDesiredLocalAddressSets(snapshot *ConfigSnapshot) (desiredV4 map[uint32]struct{}, desiredV6 map[userspaceLocalV6Key]struct{}, enumComplete bool) {
	desiredV4 = make(map[uint32]struct{})
	desiredV6 = make(map[userspaceLocalV6Key]struct{})
	for _, entry := range buildLocalAddressEntries(snapshot) {
		if entry.v4 {
			desiredV4[entry.v4Key] = struct{}{}
			continue
		}
		desiredV6[entry.v6Key] = struct{}{}
	}
	// Also add kernel addresses (VIPs added by VRRP) that aren't in the
	// config snapshot. Without this, the XDP shim doesn't recognize VIP
	// destinations as local and redirects them to XSK instead of the kernel.
	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
	//
	// A failed family dump means the enumeration is INCOMPLETE: record it
	// via enumComplete so the caller skips the destructive prune. We still
	// accumulate whatever the surviving family dump returned (adding is
	// safe — only pruning against a partial set is dangerous).
	enumComplete = true
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		addrs, err := m.addrListForLocalSync(nil, family)
		if err != nil {
			enumComplete = false
			continue
		}
		for _, addr := range addrs {
			ip := addr.IP
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil && family == netlink.FAMILY_V4 {
				key := binary.BigEndian.Uint32(v4)
				desiredV4[key] = struct{}{}
			} else if v6 := ip.To16(); v6 != nil && family == netlink.FAMILY_V6 {
				var key [16]byte
				copy(key[:], v6)
				desiredV6[userspaceLocalV6Key{Addr: key}] = struct{}{}
			}
		}
	}
	return desiredV4, desiredV6, enumComplete
}

func (m *Manager) syncInterfaceNATAddressMapsLocked(snapshot *ConfigSnapshot) error {
	natV4Map := m.bpfShim.Map(mapNameUserspaceInterfaceNATv4)
	if natV4Map == nil {
		return errors.New("userspace_interface_nat_v4 map not loaded")
	}
	natV6Map := m.bpfShim.Map(mapNameUserspaceInterfaceNATv6)
	if natV6Map == nil {
		return errors.New("userspace_interface_nat_v6 map not loaded")
	}

	desiredV4, desiredV6, rstV4, rstV6 := buildDesiredInterfaceNATAddressSets(snapshot)
	for key := range desiredV4 {
		if err := natV4Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_interface_nat_v4 %08x: %w", key, err)
		}
	}
	for key := range desiredV6 {
		if err := natV6Map.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_interface_nat_v6 %+v: %w", key, err)
		}
	}

	var (
		natV4Key uint32
		natV4Val uint8
	)
	natV4Iter := natV4Map.Iterate()
	var staleNatV4Keys []uint32
	for natV4Iter.Next(&natV4Key, &natV4Val) {
		if _, keep := desiredV4[natV4Key]; keep {
			continue
		}
		staleNatV4Keys = append(staleNatV4Keys, natV4Key)
	}
	if err := natV4Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_interface_nat_v4: %w", err)
	}
	for _, key := range staleNatV4Keys {
		if err := natV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v4 %08x: %w", key, err)
		}
	}

	var (
		natV6Key userspaceLocalV6Key
		natV6Val uint8
	)
	natV6Iter := natV6Map.Iterate()
	var staleNatV6Keys []userspaceLocalV6Key
	for natV6Iter.Next(&natV6Key, &natV6Val) {
		if _, keep := desiredV6[natV6Key]; keep {
			continue
		}
		staleNatV6Keys = append(staleNatV6Keys, natV6Key)
	}
	if err := natV6Iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_interface_nat_v6: %w", err)
	}
	for _, key := range staleNatV6Keys {
		if err := natV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v6 %+v: %w", key, err)
		}
	}

	slices.SortFunc(rstV4, netip.Addr.Compare)
	slices.SortFunc(rstV6, netip.Addr.Compare)
	// Install RST suppression rules. Retry immediately on address changes,
	// and periodically retry unchanged failed installs so a transient
	// startup failure does not leave the node permanently unprotected.
	now := time.Now()
	if shouldAttemptRSTSuppression(
		now,
		rstV4,
		rstV6,
		m.lastRSTv4,
		m.lastRSTv6,
		m.lastRSTAttempt,
		m.lastRSTInstallOK,
	) {
		if err := xpfnft.InstallRSTSuppression(rstV4, rstV6); err != nil {
			slog.Warn("userspace: RST suppression unavailable (nftables error, non-fatal)", "err", err)
			m.lastRSTInstallOK = false
		} else {
			m.lastRSTInstallOK = true
		}
		m.lastRSTAttempt = now
		m.lastRSTv4 = slices.Clone(rstV4)
		m.lastRSTv6 = slices.Clone(rstV6)
	}
	return nil
}

func buildDesiredInterfaceNATAddressSets(snapshot *ConfigSnapshot) (map[uint32]struct{}, map[userspaceLocalV6Key]struct{}, []netip.Addr, []netip.Addr) {
	entries := buildInterfaceNATAddressEntries(snapshot)
	v4Count := 0
	for _, entry := range entries {
		if entry.v4 {
			v4Count++
		}
	}
	v6Count := len(entries) - v4Count
	desiredV4 := make(map[uint32]struct{})
	desiredV6 := make(map[userspaceLocalV6Key]struct{})
	rstV4 := make([]netip.Addr, 0, v4Count)
	rstV6 := make([]netip.Addr, 0, v6Count)
	for _, entry := range entries {
		if entry.v4 {
			desiredV4[entry.v4Key] = struct{}{}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], entry.v4Key)
			rstV4 = append(rstV4, netip.AddrFrom4(b))
			continue
		}
		desiredV6[entry.v6Key] = struct{}{}
		rstV6 = append(rstV6, netip.AddrFrom16(entry.v6Key.Addr))
	}
	return desiredV4, desiredV6, rstV4, rstV6
}

// verifyBindingsMapLocked reads the BPF userspace_bindings map and compares
// each entry against the helper's last reported binding status. If the helper
// reports a binding as Registered+Armed (meaning the XSK socket exists and the
// queue is armed for redirect) but the BPF map entry is all zeros (no slot,
// no flags), the BPF map is stale — the XDP shim has nothing to redirect to
// and all transit traffic silently drops.
//
// This can happen after a peer crash+reconnect when Compile() calls
// programBootstrapMapsLocked() which zeros the bindings map, and then either:
//   - applyHelperStatusLocked didn't run (error path)
//   - another Compile() ran concurrently and re-zeroed the map
//   - the bpfShim eBPF compile recreated the map from a fresh pin
//
// When a mismatch is detected, this method rewrites the BPF map entries from
// the helper's reported state — the same logic as applyHelperStatusLocked but
// targeted to only the stale entries. This is cheaper than a full rebind.
//
// Returns true if any stale entries were repaired.
func (m *Manager) verifyBindingsMapLocked() bool {
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	// Only check when ctrl is enabled and bindings should be active.
	// During startup (ctrl=0), the map is expected to be empty.
	if !m.ctrlWasEnabled {
		return false
	}
	bindings := m.lastStatus.Bindings
	if len(bindings) == 0 {
		return false
	}
	bindingsMap := m.bpfShim.Map(mapNameUserspaceBindings)
	if bindingsMap == nil {
		return false
	}

	deadWorkers := deadWorkerIDSet(m.lastStatus.WorkerRuntime)
	repaired := 0
	for _, binding := range bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		// #1666: only repair (re-assert READY for) slots whose worker is
		// actually forwarding-live. Repairing on (Registered && Armed)
		// would let the watchdog fight the crash-clear by rewriting
		// READY=1 for a dead worker.
		if !bindingForwardingLive(binding, deadWorkers) {
			continue
		}
		// Queue-dimension bound guard (#4894): repair-only, log-and-skip
		// (never unwind). A queue-id at/above the stride would alias the
		// adjacent ifindex queue-0 slot; the dense-cap guard below cannot
		// catch that, so skip the binding instead of repairing a wrong slot.
		if binding.QueueID >= bindingQueuesPerIface {
			slog.Warn("userspace: bindings watchdog: queue-id at/above stride would alias adjacent ifindex queue-0 slot, skipping (#4894)",
				"ifindex", binding.Ifindex, "queue", binding.QueueID,
				"stride", uint32(bindingQueuesPerIface))
			continue
		}
		idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
		// Call-site cap guard (#814): the watchdog is repair-only and
		// must not unwind. Log and skip if the ifindex would overflow
		// the BindingArrayMaxEntries dense cap.
		if idx >= dataplane.BindingArrayMaxEntries {
			slog.Warn("userspace: bindings watchdog: ifindex exceeds BindingArrayMaxEntries cap, skipping",
				"ifindex", binding.Ifindex, "queue", binding.QueueID,
				"idx", idx, "cap", dataplane.BindingArrayMaxEntries)
			continue
		}
		var val userspaceBindingValue
		if err := bindingsMap.Lookup(idx, &val); err != nil {
			slog.Debug("userspace: bindings watchdog lookup failed",
				"ifindex", binding.Ifindex, "queue", binding.QueueID, "err", err)
			continue
		}
		if val.Flags != 0 || val.Slot != 0 {
			// BPF map entry is populated — no mismatch.
			continue
		}
		// BPF map entry is all zeros but the helper says the queue is
		// forwarding-live (Registered && Armed && Ready && !Dead, gated
		// above). Rewrite the entry.
		flags := uint32(userspaceBindingReady)
		newVal := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(idx, newVal, ebpf.UpdateAny); err != nil {
			slog.Warn("userspace: bindings watchdog failed to repair entry",
				"ifindex", binding.Ifindex, "queue", binding.QueueID,
				"slot", binding.Slot, "err", err)
			continue
		}
		repaired++
	}

	// Also repair aliased bindings (VLAN children inheriting parent's XSK).
	if m.lastSnapshot != nil {
		for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
			for _, binding := range bindings {
				if binding.Ifindex != int(parentIfindex) {
					continue
				}
				// #1666: same forwarding-live gate as the primary repair.
				if !bindingForwardingLive(binding, deadWorkers) {
					continue
				}
				// Queue-dimension bound guard (#4894): repair-only,
				// log-and-skip. Same aliasing risk as the primary watchdog
				// path; the queue-id comes from the parent binding.
				if binding.QueueID >= bindingQueuesPerIface {
					slog.Warn("userspace: bindings watchdog alias: queue-id at/above stride would alias adjacent ifindex queue-0 slot, skipping (#4894)",
						"child", childIfindex, "parent", parentIfindex,
						"queue", binding.QueueID, "stride", uint32(bindingQueuesPerIface))
					continue
				}
				idx := childIfindex*bindingQueuesPerIface + binding.QueueID
				// Call-site cap guard (#814): repair-only, log-and-skip
				// instead of unwinding. VLAN child ifindex is the
				// overflow risk here.
				if idx >= dataplane.BindingArrayMaxEntries {
					slog.Warn("userspace: bindings watchdog alias: ifindex exceeds BindingArrayMaxEntries cap, skipping",
						"child", childIfindex, "parent", parentIfindex,
						"queue", binding.QueueID,
						"idx", idx, "cap", dataplane.BindingArrayMaxEntries)
					continue
				}
				var val userspaceBindingValue
				if err := bindingsMap.Lookup(idx, &val); err != nil {
					slog.Debug("userspace: bindings watchdog alias lookup failed",
						"child", childIfindex, "parent", parentIfindex, "queue", binding.QueueID, "err", err)
					continue
				}
				if val.Flags != 0 || val.Slot != 0 {
					continue
				}
				newVal := userspaceBindingValue{
					Slot:  binding.Slot,
					Flags: userspaceBindingReady,
				}
				if err := bindingsMap.Update(idx, newVal, ebpf.UpdateAny); err != nil {
					slog.Warn("userspace: bindings watchdog failed to repair alias entry",
						"child", childIfindex, "parent", parentIfindex,
						"queue", binding.QueueID, "slot", binding.Slot, "err", err)
					continue
				}
				repaired++
			}
		}
	}

	if repaired > 0 {
		slog.Warn("userspace: bindings watchdog repaired stale BPF map entries",
			"repaired", repaired, "total_bindings", len(bindings))
	}
	return repaired > 0
}
func buildLocalAddressEntries(snapshot *ConfigSnapshot) []userspaceLocalAddressEntry {
	if snapshot == nil {
		return nil
	}
	excludedV4, excludedV6 := buildNATTranslatedLocalAddressExclusions(snapshot)
	seenV4 := make(map[uint32]bool)
	seenV6 := make(map[[16]byte]bool)
	out := make([]userspaceLocalAddressEntry, 0)
	for _, iface := range snapshot.Interfaces {
		for _, addr := range iface.Addresses {
			ip, _, err := net.ParseCIDR(addr.Address)
			if err != nil || ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				key := binary.BigEndian.Uint32(v4)
				if excludedV4[key] || seenV4[key] {
					continue
				}
				seenV4[key] = true
				out = append(out, userspaceLocalAddressEntry{v4: true, v4Key: key})
				continue
			}
			v6 := ip.To16()
			if v6 == nil {
				continue
			}
			var key [16]byte
			copy(key[:], v6)
			if excludedV6[key] || seenV6[key] {
				continue
			}
			seenV6[key] = true
			out = append(out, userspaceLocalAddressEntry{v4: false, v6Key: userspaceLocalV6Key{Addr: key}})
		}
	}
	return out
}

func buildInterfaceNATAddressEntries(snapshot *ConfigSnapshot) []userspaceLocalAddressEntry {
	if snapshot == nil {
		return nil
	}
	excludedV4, excludedV6 := buildNATTranslatedLocalAddressExclusions(snapshot)
	seenV4 := make(map[uint32]bool)
	seenV6 := make(map[[16]byte]bool)
	out := make([]userspaceLocalAddressEntry, 0)
	for key := range excludedV4 {
		if seenV4[key] {
			continue
		}
		seenV4[key] = true
		out = append(out, userspaceLocalAddressEntry{v4: true, v4Key: key})
	}
	for key := range excludedV6 {
		if seenV6[key] {
			continue
		}
		seenV6[key] = true
		out = append(out, userspaceLocalAddressEntry{v6Key: userspaceLocalV6Key{Addr: key}})
	}
	return out
}

func buildUserspaceIngressIfindexes(snapshot *ConfigSnapshot) []uint32 {
	if snapshot == nil {
		return nil
	}
	seen := make(map[uint32]bool)
	out := make([]uint32, 0)
	refused := buildUserspaceRefusedNetdevs(snapshot)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.ParentIfindex > 0 {
			// #6691 round 8: the parent netdev is one a DIFFERENT row has
			// already been refused a binding for on device grounds — an xfrmi
			// under `bind-interface st10` with a zoned sibling unit is the
			// reachable case. Appending its ifindex here re-admits exactly the
			// netdev the predicate just excluded, and measured at head it did:
			// the set came back [10 11] with 11 the live xfrmi.
			//
			// WHICH ROWS THE REFUSED PARENT ACTUALLY DISQUALIFIES (#6691 round
			// 9). Round 8 dropped the WHOLE ROW here and justified it with "for
			// a VLAN child the parent IS the bind target". True — but this
			// branch is entered on `ParentIfindex > 0`, which is every UNIT
			// row, not every VLAN row. A plain unit (`st10 unit 5` with no
			// vlan-id) merely CARRIES a parent ifindex; its bind target is its
			// OWN netdev, so a refused parent says nothing about it.
			//
			// Measured before this round with secure `st10` at ifindex 11 and an
			// ordinary live `st10.5` at 12: Go ingress came back [10] — 12
			// missing — while the RSS allowlist named `st10.5` and the Rust
			// planner made it a candidate. That is the ingress/plan split in
			// the OTHER direction from the one round 8 fixed: a netdev with a
			// binding but no ingress entry takes cpumap_or_pass and leaves the
			// adjudicated path.
			//
			// So the parent key is always suppressed, and the row survives iff
			// it binds its own netdev. For a VLAN child (bind target == the
			// parent) the whole row still goes, which is what keeps an ifindex
			// out of the ingress map with no READY binding —
			// drop_degraded_transit (BINDING_MISSING) — the invariant round 8
			// was holding up and this preserves.
			// BOTH KEYS (#6691 round 16, refusesNetdev): the parent's refusal
			// can hold on the NAME alone — the parent's own base row is a
			// separate buildLinkSnapshot from this unit row's parent lookup, so
			// a base row that missed names the netdev without contributing an
			// ifindex bucket. Rust's binding_target_is_refused asks by name and
			// drops the child outright, so an ifindex-only reader here left
			// both the child and the parent key adjudicated with no binding.
			if refused.refusesNetdev(iface.ParentLinuxName, iface.ParentIfindex) {
				if !userspaceOwnsItsNetdev(iface) {
					continue
				}
				if iface.Ifindex > 0 && !iface.LogicalOnly {
					key := uint32(iface.Ifindex)
					if !seen[key] {
						seen[key] = true
						out = append(out, key)
					}
				}
				continue
			}
			if iface.Ifindex > 0 && !iface.LogicalOnly {
				key := uint32(iface.Ifindex)
				if !seen[key] {
					seen[key] = true
					out = append(out, key)
				}
			}
			key := uint32(iface.ParentIfindex)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, key)
			continue
		}
		if iface.Ifindex <= 0 {
			continue
		}
		key := uint32(iface.Ifindex)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	for _, fab := range snapshot.Fabrics {
		if fab.ParentIfindex <= 0 {
			continue
		}
		// #6691 round 9: the sibling of the allowlist's fabric guard, and the
		// same reachability — round 8's kernel-kind evidence refuses an xfrm
		// device by DEVICE KIND, so a slot-shaped `ge-0/0/0` created out of band
		// is both refused and a legal `fabric-options member-interfaces` value.
		// Measured: ingress came back [20 21] with 20 the refused member. See
		// UserspaceBoundLinuxInterfaces for why this is transparent to an
		// ordinary fabric.
		// BOTH KEYS (#6691 round 16, refusesNetdev): the fabric row and the
		// interface rows are separate netlink samples — SyncFabricState
		// refreshes the fabric rows alone — so an owning, unbindable row that
		// missed names this netdev while the fabric row carries its live
		// ifindex. The RSS allowlist's own fabric guard already asked by name.
		if refused.refusesNetdev(fab.ParentLinuxName, fab.ParentIfindex) {
			continue
		}
		key := uint32(fab.ParentIfindex)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func snapshotBindingPlanKey(snapshot *ConfigSnapshot) string {
	if snapshot == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "workers=%d;ring=%d;", snapshot.Userspace.Workers, snapshot.Userspace.RingEntries)
	// #8901: `shared_umem` is hashed by the Rust plan hash
	// (`update_snapshot_binding_plan_key`, planning.rs) and was omitted here.
	//
	// This key gates the SAME-PLAN REFRESH EXCEPTION -- the rule that lets a
	// FIB-only update publish during the pending-XSK-startup window, because
	// blocking it deadlocks (XSK liveness needs RX traffic, transit traffic
	// needs FIB data). A config changing only SharedUMEM therefore left this
	// key unchanged, was classified as a same-plan refresh, and published
	// straight through -- while the helper, whose hash DOES include it,
	// rebuilt its AF_XDP bindings. Back-to-back reconciles in the window whose
	// entire purpose is to prevent them.
	//
	// NOT the #8899 question. That one is process identity (argv, binary,
	// sockets) and correctly EXCLUDES SharedUMEM, because a SharedUMEM change
	// reaches the helper inside the snapshot rather than on the command line,
	// so it needs no process restart. This is whether the two PLAN hashes
	// agree about what constitutes a plan change.
	if su := snapshot.Userspace.SharedUMEM; su != nil {
		// #9009 D4: SORTED. Rust hashes shared_umem through
		// `update_canonical_json_hash`, which sorts array items, while this side
		// joined `su.Interfaces` in AUTHORED order — and compileSharedUMEMConfig
		// appends in authored order with no sort, so REORDERING A BRACKETED LIST
		// is a supported operator edit that moved only this key.
		//
		// Over-detection is not wasted CPU: `!samePlan` reaches
		// stopForNewGenerationLocked -> stopLocked + ensureProcessLocked, a full
		// AF_XDP teardown and rebind, and inside the XSK-startup window the
		// snapshot is not published at all. A forwarding interruption.
		//
		// Sorting a COPY — the snapshot is shared and the authored order is
		// meaningful to everything downstream of this hash.
		ifaces := append([]string(nil), su.Interfaces...)
		sort.Strings(ifaces)
		fmt.Fprintf(&b, "shared_umem=%s/%s/%s;", su.Mode, strings.Join(ifaces, ","), su.Phase0ArtifactFile)
	}
	// #9009 D3: the refusal tally, built ONCE and used by both loops. Rust
	// filters rows whose BIND TARGET the snapshot refuses — `replan_queues`
	// produces no candidate for them — while this side had the predicate
	// (buildUserspaceRefusedNetdevs, already used by the alias builder below)
	// and never applied it here. Rust's row set was a strict subset, so its key
	// moved where this one did not.
	refused := buildUserspaceRefusedNetdevs(snapshot)
	for _, iface := range snapshot.Interfaces {
		if !planKeyIncludesInterface(iface) {
			continue
		}
		resolvedLinux := planKeyResolvedLinuxName(iface)
		if planKeyBindingTargetRefused(refused, iface, resolvedLinux) {
			continue
		}
		// #8901: `vlan_id` and `parent_linux_name` were hashed by Rust and not
		// here. #3091 records why Rust hashes them: `replan_queues` dedups a
		// VLAN-child netdev onto its physical parent using exactly these two
		// fields, so a re-parent or a VLAN-tag change moves the layout. Both
		// are ordinary config edits, which makes this reachable by a far more
		// routine change than the SharedUMEM case above.
		fmt.Fprintf(
			&b,
			"iface=%s/%s/%d/%d/%d/%t/%t/%d/%s;",
			iface.Name,
			iface.LinuxName,
			iface.Ifindex,
			iface.ParentIfindex,
			// #9009 D1/D6: the EFFECTIVE count the planner will use, including
			// the orphan-VLAN-child re-key onto the PARENT's hardware queues.
			// The raw field is, for that shape, a different number tracking a
			// different device — so the two sides were not sampling one value
			// twice, they were following two values.
			planKeyRXQueues(snapshot, iface, resolvedLinux),
			// #9009 D5: Rust has no `logical_only` field at all, and the #8901
			// adjudication justified keeping it here as "Rust excludes the row
			// upstream via include_userspace_binding_interface". THAT IS FALSE:
			// that function tests zone-empty, local_fabric_member,
			// userspace_unbindable_netdev and mgmt/control; `logical_only`
			// appears nowhere in userspace-dp, and the wire value is silently
			// discarded by a serde struct that has no such field.
			//
			// The CONCLUSION survives, which is why the field stays: a
			// LogicalOnly flip also swaps the row between a real and a synthetic
			// ifindex (shouldUseLogicalOnlyParentBoundRethVLAN), and BOTH sides
			// hash the ifindex — so it cannot move this key alone. The reason on
			// record is now the true one. A false rationale that licenses a real
			// difference is worse than none: the next reader inherits it as
			// established fact and reasons from it.
			iface.LogicalOnly,
			iface.Tunnel,
			iface.VLANID,
			iface.ParentLinuxName,
		)
	}
	for _, fab := range snapshot.Fabrics {
		// #9009 D2 — the cleanest under-detect, and the loop that had NO filter
		// at all. Rust drops a fabric whose parent netdev the snapshot refuses
		// (`snapshot_refuses_parent_netdev`), so its key moves; this loop
		// carried none of the signals, so this key did not.
		//
		// The isolating case needs nothing exotic: give fab0 a member whose
		// netdev is in NO security zone — so its row is absent from the
		// interface loop above — then add a tunnel stanza to that member. On the
		// Rust side the owner row flips userspace_unbindable_netdev, the refusal
		// is unanimous and the key moves. Here ParentLinuxName comes from
		// config.LinuxIfName rather than snapshotLinuxName, so the tunnel stanza
		// does not rename it; ifindex and RXQueues are unchanged; and the member
		// row is unzoned so it is not in the loop above either. Nothing moved.
		// The same flip is reachable with NO config change at all, through
		// snapshotSecureTunnel's liveXfrmNetdevs oracle.
		if refused.refusesNetdev(fab.ParentLinuxName, fab.ParentIfindex) {
			continue
		}
		// #9009 D6: the same resolution Rust's fabric candidate loop uses —
		// effective count, then at least 1 because a fabric needs a TX queue.
		fabRX := planKeyEffectiveRXQueues(fab.RXQueues, fab.ParentLinuxName)
		if fabRX < 1 {
			fabRX = 1
		}
		fmt.Fprintf(
			&b,
			"fabric=%s/%s/%d/%d;",
			fab.Name,
			fab.ParentLinuxName,
			fab.ParentIfindex,
			fabRX,
		)
	}
	return b.String()
}

func buildUserspaceIngressBindingAliases(snapshot *ConfigSnapshot) map[uint32]uint32 {
	if snapshot == nil {
		return nil
	}
	out := make(map[uint32]uint32)
	refused := buildUserspaceRefusedNetdevs(snapshot)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.Ifindex <= 0 || iface.ParentIfindex <= 0 || iface.Ifindex == iface.ParentIfindex || iface.LogicalOnly {
			continue
		}
		// #6691 round 8: same redirect, same refusal. An alias here would tell
		// the shim to treat frames on the child as arriving on a netdev the
		// dataplane refused to bind. This site is inert on every config
		// reachable today and is guarded anyway — the reachability analysis,
		// per exclusion class, is in userspaceRefusedNetdevs
		// (ingress_exclusions.go), which owns the contract.
		// BOTH KEYS (#6691 round 16, refusesNetdev) — same sampling skew as the
		// ingress loop above. An alias installed for a name-refused parent tells
		// the shim to treat the child's frames as arriving on a netdev nothing
		// ever binds.
		if refused.refusesNetdev(iface.ParentLinuxName, iface.ParentIfindex) {
			continue
		}
		out[uint32(iface.Ifindex)] = uint32(iface.ParentIfindex)
	}
	return out
}

func snapshotHasNativeGRE(snapshot *ConfigSnapshot) bool {
	if snapshot == nil {
		return false
	}
	for _, endpoint := range snapshot.TunnelEndpoints {
		if endpoint.ID == 0 {
			continue
		}
		switch endpoint.Mode {
		case "", "gre", "ip6gre":
			return true
		}
	}
	return false
}

// snapshotWgListenPort returns the WireGuard listen port for the shim ctrl
// block (#1432 S2a): the ONE port the shim steers onto the AF_XDP WireGuard
// path. 0 means no WireGuard tunnel (the shim's WG_RX gate stays off). The shim
// packs it into the low 16 bits of UserspaceCtrl.wg_listen_port.
//
// #9521: it reads ConfigSnapshot.WgSteeredListenPort and nothing else. It used
// to return the first WireGuard row of snapshot.TunnelEndpoints, and those rows
// are the configured endpoints INTERSECTED with the live interface rows — so a
// missing netdev for the warned tunnel promoted the next tunnel's port, the one
// the commit warning had just called unsteered. The field is derived once, from
// the configuration (config.SteeredWireGuardListenPort), and the helper decides
// from the SAME field which control threads may deliver kernel-path transport
// plaintext; the shim, the helper and the warning therefore cannot name
// different ports. Do not re-derive it here from the endpoint rows.
func snapshotWgListenPort(snapshot *ConfigSnapshot) uint32 {
	if snapshot == nil {
		return 0
	}
	return uint32(snapshot.WgSteeredListenPort)
}

func buildNATTranslatedLocalAddressExclusions(snapshot *ConfigSnapshot) (map[uint32]bool, map[[16]byte]bool) {
	excludedV4 := make(map[uint32]bool)
	excludedV6 := make(map[[16]byte]bool)
	if snapshot == nil || len(snapshot.SourceNAT) == 0 || len(snapshot.Interfaces) == 0 {
		return excludedV4, excludedV6
	}
	toZones := make(map[string]bool)
	for _, nat := range snapshot.SourceNAT {
		if !nat.InterfaceMode || nat.Off || nat.ToZone == "" {
			continue
		}
		toZones[nat.ToZone] = true
	}
	if len(toZones) == 0 {
		return excludedV4, excludedV6
	}
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || !toZones[iface.Zone] {
			continue
		}
		if ip := pickInterfaceSnapshotV4(iface); ip != nil {
			excludedV4[binary.BigEndian.Uint32(ip.To4())] = true
		}
		if ip := pickInterfaceSnapshotV6(iface); ip != nil {
			var key [16]byte
			copy(key[:], ip.To16())
			excludedV6[key] = true
		}
	}
	return excludedV4, excludedV6
}

func pickInterfaceSnapshotV4(iface InterfaceSnapshot) net.IP {
	var fallback net.IP
	for _, addr := range iface.Addresses {
		if addr.Family != "inet" {
			continue
		}
		ip, _, err := net.ParseCIDR(addr.Address)
		if err != nil || ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if fallback == nil {
			fallback = append(net.IP(nil), v4...)
		}
		if !v4.IsLinkLocalUnicast() {
			return append(net.IP(nil), v4...)
		}
	}
	return fallback
}

func pickInterfaceSnapshotV6(iface InterfaceSnapshot) net.IP {
	var fallback net.IP
	for _, addr := range iface.Addresses {
		if addr.Family != "inet6" {
			continue
		}
		ip, _, err := net.ParseCIDR(addr.Address)
		if err != nil || ip == nil {
			continue
		}
		v6 := ip.To16()
		if v6 == nil || ip.To4() != nil {
			continue
		}
		if fallback == nil {
			fallback = append(net.IP(nil), v6...)
		}
		if !v6.IsLinkLocalUnicast() {
			return append(net.IP(nil), v6...)
		}
	}
	return fallback
}

// heartbeatSlotsPerWorker is the number of userspace_heartbeat Array
// slots reserved per dataplane worker (2 directions x up to 16 queues).
//
// It is NOT the zero-init loop's bound any more (#6702 blocker 2 — see
// heartbeatZeroSlotBound); it survives as the divisor `effectiveWorkers` uses
// to cap the worker count REPORTED to the shim at what the Array can carry
// slots for.
const heartbeatSlotsPerWorker = 2 * 16

// heartbeatZeroSlotBound returns how many userspace_heartbeat Array slots
// programBootstrapMapsLocked must zero-init: ALL of them.
//
// #6702 blocker 2 — WHY THIS IS NOT DERIVED FROM THE WORKER COUNT ANY MORE.
// It used to return `effectiveWorkers(workers) * heartbeatSlotsPerWorker`, and
// that bound was measuring the wrong quantity. A heartbeat slot is indexed by
// the BINDING SLOT — the XDP shim reads `USERSPACE_HEARTBEAT.get(binding.slot)`
// (userspace-xdp/src/lib.rs) and the helper writes `update_heartbeat_slot(fd,
// slot, ..)` (userspace-dp/src/afxdp/bpf_map/ha.rs) — and the binding count is
// `Σ min(rx_queues, 16)` over the binding candidates since #7497 (it was
// `min(rx_queues) * interfaces` before), which has never been a function of
// `cfg.Workers` under either rule. With the default `Workers: 1` (capabilities.go) the loop
// zeroed 32 slots, so ANY box whose binding count exceeds that — six dataplane
// interfaces at 6 queues, or three at 16 — left its tail slots holding the
// PREVIOUS load's timestamps.
//
// That fails in the direction the heartbeat exists to prevent. A zeroed slot
// reads as stale (`bpf_ktime_get_ns() >> 0`) and the shim correctly refuses to
// redirect until userspace starts updating it; a slot still holding a
// timestamp from inside the heartbeat timeout reads as FRESH, which masks a
// helper that has STOPPED for up to one timeout — on precisely the slots
// nobody zeroed.
//
// The sibling map settles what the right bound is. `userspace_xsk_map` is the
// other 4096-entry map indexed by the SAME binding slot, and it is already
// cleared over its FULL range on helper start ("Old entries point to dead
// socket fds", process.go). Two maps with one index and two different clearing
// domains: the XSK one was right.
//
// Zeroing the whole Array is safe on the path that reaches it even though that
// path is NOT bootstrap-only: programBootstrapMapsLocked runs on every
// non-same-plan apply, but it calls clearAllBindingRowsLocked() ~25 lines
// earlier — zeroing every binding row the manager wrote — and the shim gates on
// the binding row BEFORE reading the heartbeat. So a packet a zeroed heartbeat
// could blackhole is already blackholed by the zeroed binding row in the same
// function; this widens no window that call does not already open. (The binding
// half of that hazard is separately acknowledged and repaired by
// verifyBindingsMapLocked.)
//
// #6784 CORRECTION to the paragraph above: "zeroing every binding row the
// manager wrote" is true only of rows THIS Manager wrote.
// clearAllBindingRowsLocked iterates m.lastBindingIndices, which is nil on a
// freshly constructed Manager, so on the first apply after a daemon restart it
// zeroes NOTHING while userspace_bindings — PinByName-pinned like every other
// shim map — still holds the previous process's rows. The conclusion survives,
// but not for the stated reason: zeroing a heartbeat slot can only move a
// packet ONTO the stale-heartbeat branch, which is fail-closed
// (drop_degraded_transit for transit, pass_local_control for local), so the
// widening is in the safe direction regardless of what the binding rows hold.
//
// The stale binding rows themselves are left alone deliberately, and the reason
// is the gate order in the shim: userspace_ingress_ifaces is consulted BEFORE
// the binding array, so a binding row is only ever reached for an ifindex the
// ingress map still admits. Repairing the ingress map (adoptIngressInventoryLocked)
// therefore makes a stale binding row for a de-configured interface
// unreachable, and for an interface still in the config
// applyHelperStatusLocked rewrites its rows from live helper status every poll.
// A blanket zero of this Array is NOT the answer here the way it was for the
// heartbeat: BindingArrayMaxEntries is MaxInterfaces*BindingQueuesPerIface =
// 1,048,576 rows (versus the heartbeat Array's 4096), so sweeping it would put
// a million map syscalls on every non-same-plan apply.
//
// Taking the Array's own capacity also closes #4572 and #5718-A6-b01-C1 BY
// CONSTRUCTION rather than by a clamp — the bound no longer reads `workers` at
// all, so no value of it (negative, zero, 1<<32, max int) can wrap the loop
// counter or push it past the Array. `effectiveWorkers` still clamps the count
// REPORTED to the shim, which is a different question and keeps its own guard.
func heartbeatZeroSlotBound(heartbeatMapCap uint32) uint32 {
	return heartbeatMapCap
}

// userspaceWorkerPlan carries every representation of the bootstrap's worker
// count, produced by one derivation (#5718 fold F3). Returning them together
// is the contract: a caller cannot pair a clamped count with a raw one,
// because there is only one clamp and both fields come out of it.
type userspaceWorkerPlan struct {
	// Workers is the count reported to the shim in userspaceCtrlValue's
	// Workers AND QueueCount fields.
	Workers uint32
	// HeartbeatSlots is how many userspace_heartbeat Array slots the zero-init
	// loop must write: the Array's whole capacity (#6702 blocker 2). It is
	// deliberately NOT derived from Workers — a heartbeat slot is indexed by
	// BINDING slot, and the binding count is not a function of the worker
	// count. See heartbeatZeroSlotBound.
	HeartbeatSlots uint32
}

// planUserspaceWorkers clamps the configured worker count ONCE and derives
// every representation of it from that single value. See userspaceWorkerPlan.
func planUserspaceWorkers(workers int, heartbeatMapCap uint32) userspaceWorkerPlan {
	w := effectiveWorkers(workers, heartbeatMapCap)
	return userspaceWorkerPlan{
		Workers:        uint32(w),
		HeartbeatSlots: heartbeatZeroSlotBound(heartbeatMapCap),
	}
}

// effectiveWorkers is the single source of truth for "how many workers this
// dataplane has" (#5718 fold F3). Every representation of that quantity —
// userspaceCtrlValue.Workers, userspaceCtrlValue.QueueCount, and the heartbeat
// zero-init loop bound — derives from this one value, so they cannot describe
// the same number differently.
//
// The clamp runs entirely in INT space, before any uint32 cast, for the
// A6-b01-C1 reason: cfg.Workers is an int from a min-only schema leaf
// (ValidateIntegerMin(1)) with no upper bound in deriveUserspaceConfig, so a
// cast-first implementation lets a worker count above the uint32 range narrow
// into the clamp's blind spot — `1<<32` becomes 0 and `1<<32+5` becomes 5,
// both of which look like legal counts and sail through every bound. That is
// how the two representations diverged after A6-b01-C1: the zero-init loop got
// the clamped value while ctrl.Workers/ctrl.QueueCount got the narrowed one.
//
// maxW is how many workers the fixed-size userspace_heartbeat Array can carry
// slots for (4096 / 32 = 128 today), which is also the honest ceiling for the
// ctrl fields: a worker with no zero-initialised heartbeat slot has none to
// keep fresh, and the shim refuses to redirect on a stale slot.
//
// #6930: THE INT-SPACE CLAIM ABOVE IS CONDITIONAL, AND THE CONDITION IS THE
// DEGENERATE CASE. `maxW` is 0 whenever the Array holds fewer than
// heartbeatSlotsPerWorker entries, and the clamp is then SKIPPED entirely — so
// `w` leaves this function unbounded and `planUserspaceWorkers`' `uint32(w)`
// narrows it. Measured before fixing, with heartbeatMapCap = 31:
//
//	workers 1<<32    -> effectiveWorkers 4294967296 -> plan.Workers 0
//	workers 1<<32+5  -> effectiveWorkers 4294967301 -> plan.Workers 5
//
// Those are the exact two values the paragraph above names as the A6-b01-C1
// defect — reporting ZERO workers and ZERO queues to the shim, or a
// plausible-looking 5 — reproduced at the CAST rather than at the multiply that
// #6702 removed. Running the clamp in int space does not help when there is no
// clamp.
//
// The floor stays 1 even when the Array cannot hold a single worker's slots.
// The CEILING is now unconditional: clamping to MaxUint32 makes the cast in
// planUserspaceWorkers faithful for every input without changing any reachable
// answer (with maxW >= 1 the maxW clamp binds first and is far smaller), so
// this fixes the narrowing without altering the degenerate case's documented
// intent of reporting a worker count rather than zero.
//
// Bounding the OPERAND rather than checking the product is deliberate: a
// post-hoc check on a value that has already narrowed cannot tell 0-because-
// overflow from 0-because-zero, which is what made the original silent.
func effectiveWorkers(workers int, heartbeatMapCap uint32) int {
	w := maxInt(workers, 1)
	if maxW := int(heartbeatMapCap / heartbeatSlotsPerWorker); maxW >= 1 && w > maxW {
		w = maxW
	}
	// #6930: unconditional, so it also binds when the maxW clamp above was
	// skipped. int is 64-bit on every platform this builds for, so this cannot
	// itself wrap.
	if w > math.MaxUint32 {
		w = math.MaxUint32
	}
	return w
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func queueCountFromBindings(bindings []BindingStatus) int {
	maxQueueID := -1
	for _, binding := range bindings {
		if !binding.Registered || binding.Ifindex <= 0 {
			continue
		}
		if int(binding.QueueID) > maxQueueID {
			maxQueueID = int(binding.QueueID)
		}
	}
	if maxQueueID < 0 {
		return 1
	}
	return maxQueueID + 1
}
