package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
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
	Enabled            uint32
	MetadataVersion    uint32
	Workers            uint32
	QueueCount         uint32
	Flags              uint32
	Pad                uint32
	ConfigGeneration   uint64
	FIBGeneration      uint32
	HeartbeatTimeoutMS uint32
}

const userspaceMetadataVersion = 4
const userspaceCtrlFlagCPUMap = 1
const userspaceCtrlFlagTrace = 2
const userspaceCtrlFlagNativeGRE = 4
const userspaceCtrlFlagStrict = 8
const bindingQueuesPerIface = 16 // must match BINDING_QUEUES_PER_IFACE in BPF

const userspaceBindingReady = 1

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
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}
	heartbeatMap := m.inner.Map("userspace_heartbeat")
	if heartbeatMap == nil {
		return errors.New("userspace_heartbeat map not loaded")
	}
	fallbackMap := m.inner.Map("userspace_fallback_progs")
	if fallbackMap == nil {
		return errors.New("userspace_fallback_progs map not loaded")
	}
	fallbackProg := m.inner.Program("xdp_main_prog")
	if fallbackProg == nil {
		return errors.New("xdp_main_prog not loaded")
	}

	// Populate userspace_cpumap so the XDP shim can use cpumap redirect
	// instead of XDP_PASS (required for zero-copy AF_XDP).
	cpumapReady := m.setupUserspaceCPUMapLocked()

	zero := uint32(0)
	var ctrlFlags uint32
	if cpumapReady {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(snapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            uint32(cfg.Workers),
		QueueCount:         uint32(maxInt(cfg.Workers, 1)),
		Flags:              ctrlFlags,
		ConfigGeneration:   0,
		FIBGeneration:      0,
		HeartbeatTimeoutMS: 30000,
	}
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl: %w", err)
	}
	fallbackFD := uint32(fallbackProg.FD())
	if err := fallbackMap.Update(zero, fallbackFD, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_fallback_progs: %w", err)
	}

	// Bindings map is now an Array — zero previously-set indices.
	{
		var zeroBinding userspaceBindingValue
		for _, idx := range m.lastBindingIndices {
			_ = bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny)
		}
		m.lastBindingIndices = nil
	}
	// Heartbeat map is now an Array — zero used slots instead of deleting.
	// Slots with value 0 appear as stale (bpf_ktime_get_ns() >> 0) so the
	// XDP shim correctly refuses to redirect until userspace begins updating.
	{
		var zeroHB uint64
		for slot := uint32(0); slot < uint32(cfg.Workers)*2*16; slot++ {
			_ = heartbeatMap.Update(slot, zeroHB, ebpf.UpdateAny)
		}
	}
	if err := m.syncIngressIfaceMapLocked(snapshot); err != nil {
		return err
	}
	if err := m.syncLocalAddressMapsLocked(snapshot); err != nil {
		return err
	}
	return m.syncInterfaceNATAddressMapsLocked(snapshot)
}

// setupUserspaceCPUMapLocked populates the userspace_cpumap BPF map with one
// entry per online CPU. This enables the XDP shim to use cpumap redirect
// instead of XDP_PASS, which is required for zero-copy AF_XDP (XDP_PASS in
// zero-copy mode permanently leaks UMEM frames).
func (m *Manager) setupUserspaceCPUMapLocked() bool {
	cpuMap := m.inner.Map("userspace_cpumap")
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

func (m *Manager) applyHelperStatusLocked(status *ProcessStatus) error {
	ctrlMap := m.inner.Map("userspace_ctrl")
	if ctrlMap == nil {
		return errors.New("userspace_ctrl map not loaded")
	}
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return errors.New("userspace_bindings map not loaded")
	}

	var newBindingIndices []uint32
	newBindingIndexSet := make(map[uint32]struct{})

	// Preserve cpumap flag if cpumap is populated.
	var ctrlFlags uint32
	if cpuMap := m.inner.Map("userspace_cpumap"); cpuMap != nil {
		ctrlFlags |= userspaceCtrlFlagCPUMap
	}
	if snapshotHasNativeGRE(m.lastSnapshot) {
		ctrlFlags |= userspaceCtrlFlagNativeGRE
	}

	zero := uint32(0)
	ctrl := userspaceCtrlValue{
		Enabled:            0,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            uint32(maxInt(status.Workers, 1)),
		QueueCount:         uint32(queueCountFromBindings(status.Bindings)),
		Flags:              ctrlFlags,
		ConfigGeneration:   status.LastSnapshotGeneration,
		FIBGeneration:      status.LastFIBGeneration,
		HeartbeatTimeoutMS: 30000,
	}
	if status.Enabled && m.rgTransitionInFlight.Load() {
		// One or more RG transitions are in progress and the helper hasn't
		// acked the HA state update yet. Keep ctrl disabled until
		// syncHAStateLocked succeeds to avoid re-enabling ctrl during the
		// handoff (#279, #284).
		ctrl.Enabled = 0
	} else if status.Enabled {
		// Delay ctrl enable until AFTER VIPs are configured in HA mode.
		// The VRRP election + VIP add takes ~10-14s after restart.
		// If we enable ctrl before VIPs, the XSK path gets packets but
		// can't SNAT (no source address) → all transit dropped.  The
		// eBPF pipeline (XDP_PASS fallback) handles traffic correctly
		// during this window since the kernel has the same FIB state.
		//
		// Also delay by 3s for fill ring bootstrap: mlx5 zero-copy
		// needs NAPI to post fill ring WQEs, and NAPI only runs on
		// hardware RX events.  Background traffic (VRRP, ARP) during
		// the delay generates these events.
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
		// Otherwise swap back to the eBPF pipeline instead of assuming
		// the userspace AF_XDP path is healthy.
		var currentRX uint64
		for _, b := range status.Bindings {
			currentRX += b.RXPackets
		}
		xskReceiveLive := currentRX > m.lastXSKRX
		m.lastXSKRX = currentRX
		slog.Debug("userspace: ctrl gate check",
			"probeBindingsReady", probeBindingsReady,
			"allBindingsBound", allBindingsBound,
			"neighborSyncReady", neighborSyncReady,
			"xskReceiveLive", xskReceiveLive,
			"currentRX", currentRX,
			"lastXSKRX", m.lastXSKRX,
			"neighborsPrewarmed", m.neighborsPrewarmed,
			"xskLivenessFailed", m.xskLivenessFailed,
			"xdpEntryProg", m.inner.XDPEntryProg)
		if m.xskLivenessFailed {
			// XSK proven broken — ctrl disabled.
			// In compat mode, the entry program was already swapped to
			// xdp_main_prog (eBPF pipeline). In strict mode the shim
			// stays attached so packets drop rather than silently
			// falling through to eBPF.
			ctrl.Enabled = 0
		} else if probeBindingsReady && neighborSyncReady {
			ctrl.Enabled = 1
			if m.xskLivenessProven {
				if m.inner.XDPEntryProg != "xdp_userspace_prog" {
					if err := m.inner.SwapXDPEntryProg("xdp_userspace_prog"); err != nil {
						slog.Warn("userspace: failed to restore XDP shim after liveness success", "err", err)
					}
				}
			} else if xskReceiveLive {
				m.xskLivenessProven = true
				m.xskProbeStart = time.Time{}
				if m.inner.XDPEntryProg != "xdp_userspace_prog" {
					if err := m.inner.SwapXDPEntryProg("xdp_userspace_prog"); err != nil {
						slog.Warn("userspace: failed to swap XDP shim after XSK RX became live", "err", err)
					}
				}
				slog.Info("userspace: XSK liveness proven")
			} else {
				if m.inner.XDPEntryProg != "xdp_userspace_prog" {
					if err := m.inner.SwapXDPEntryProg("xdp_userspace_prog"); err != nil {
						slog.Warn("userspace: failed to activate XDP shim for XSK liveness probe", "err", err)
					}
				}
				if m.xskProbeStart.IsZero() {
					m.xskProbeStart = time.Now()
					slog.Info("userspace: starting XSK liveness probe")
				} else if time.Now().After(m.xskProbeStart.Add(10 * time.Second)) {
					if m.shouldAutoProveIdleStandbyXSKLocked(currentRX, allBindingsBound) {
						m.xskLivenessProven = true
						m.xskProbeStart = time.Time{}
						if m.inner.XDPEntryProg != "xdp_userspace_prog" {
							if err := m.inner.SwapXDPEntryProg("xdp_userspace_prog"); err != nil {
								slog.Warn("userspace: failed to restore XDP shim after idle standby liveness success", "err", err)
							}
						}
						slog.Info("userspace: XSK liveness proven on idle standby")
						goto ctrlReady
					} else if m.shouldExtendXSKLivenessIdleLocked(currentRX, allBindingsBound) {
						m.xskProbeStart = time.Now()
						slog.Info("userspace: extending XSK liveness probe while idle")
						goto ctrlReady
					}
					m.xskLivenessFailed = true
					m.xskProbeStart = time.Time{}
					ctrl.Enabled = 0
					if m.configuredMode == ModeUserspaceStrict {
						// Strict mode: do NOT swap to xdp_main_prog.
						// Keep the shim attached with ctrl=0 so packets
						// hit the shim's ctrl-disabled fallback path and
						// get counted, but never silently enter the eBPF
						// pipeline. Log at error level — this is a
						// degraded state that needs operator attention.
						slog.Error("userspace: XSK liveness probe failed in strict mode — dataplane degraded, no eBPF fallback")
					} else {
						slog.Warn("userspace: XSK liveness probe failed, falling back to eBPF pipeline")
						if err := m.inner.SwapXDPEntryProg("xdp_main_prog"); err != nil {
							slog.Warn("userspace: failed to swap to eBPF pipeline after XSK liveness failure", "err", err)
						}
					}
				}
			}
		} else if !m.ctrlEnableAt.IsZero() && time.Now().After(m.ctrlEnableAt.Add(60*time.Second)) {
			// Hard timeout fallback: allow ctrl even if readiness has not been
			// fully proven yet. The XSK liveness probe still decides whether
			// the userspace shim stays active or we fall back to xdp_main.
			ctrl.Enabled = 1
		} else {
			ctrl.Enabled = 0
		}
	}
ctrlReady:
	// Flush stale BPF session entries when ctrl transitions from
	// disabled to enabled. During ctrl-disabled, the eBPF pipeline
	// creates PASS_TO_KERNEL entries in the userspace session map.
	// These poison the XDP shim after ctrl enables — it sees the stale
	// entry and bypasses XSK, routing packets to the eBPF pipeline
	// instead of the userspace helper.
	//
	// Also flush BPF conntrack sessions created by the eBPF pipeline
	// during the ctrl-disabled window. These sessions interfere with
	// the userspace pipeline via TC egress: when the Rust helper sends
	// packets via XSK TX, TC egress finds the stale BPF conntrack
	// entries and may apply conflicting NAT or update session state
	// incorrectly. The userspace helper's own session table (Rust
	// SessionTable + shared_sessions) holds the authoritative synced
	// sessions — BPF conntrack must be empty when ctrl re-enables.
	// Only flush stale BPF sessions on the very first ctrl enable after
	// daemon startup. Snapshot generation is not a reliable proxy for
	// "startup" on long-lived HA nodes because a steady appliance can stay
	// at generation 1 indefinitely; later ctrl re-enables during RG moves
	// would then retrigger the startup flush and destroy synced sessions.
	if ctrl.Enabled == 1 && !m.ctrlWasEnabled && !m.initialCtrlCleanupDone {
		if usMap := m.inner.Map("userspace_sessions"); usMap != nil {
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
		// Flush BPF conntrack sessions created by the eBPF pipeline
		// during the ctrl-disabled transition window. Only delete
		// sessions whose Created timestamp is AFTER ctrlDisabledAt —
		// synced sessions from the cluster peer have earlier timestamps
		// and must survive for HA failover continuity.
		//
		// Why this is needed (issue #334): when ctrl=0 (startup, XSK
		// liveness probe, link cycle), the eBPF pipeline creates
		// conntrack entries in the BPF sessions map. When ctrl
		// re-enables, TC egress finds these stale BPF entries and
		// may apply conflicting NAT or update session state
		// incorrectly — the userspace helper's own session table
		// (Rust SessionTable + shared_sessions) is authoritative.
		//
		// session_value layout: State[1]+Flags[1]+TCPState[1]+
		// IsReverse[1]+AppTimeout[4]+SessionID[8]+Created[8].
		// Created is at byte offset 16. The value is seconds since
		// boot (bpf_ktime_get_coarse_ns / 1e9). ctrlDisabledAt is
		// nanoseconds, so convert to seconds for comparison.
		cutoffSec := m.ctrlDisabledAt / 1_000_000_000
		for _, mapName := range []string{"sessions", "sessions_v6"} {
			if ctMap := m.inner.Map(mapName); ctMap != nil {
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
					// Read session value to check Created timestamp.
					// Created is at byte offset 16:
					//   State(1) + Flags(1) + TCPState(1) + IsReverse(1)
					//   + AppTimeout(4) + SessionID(8) = 16
					if cutoffSec > 0 {
						if err := ctMap.Lookup(key, val); err == nil && len(val) >= 24 {
							created := binary.NativeEndian.Uint64(val[16:24])
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
	if ctrl.Enabled == 0 && m.ctrlWasEnabled {
		m.ctrlDisabledAt = m.bpfKtimeNs()
	}
	m.ctrlWasEnabled = ctrl.Enabled == 1

	// Compute active runtime mode from ctrl state and liveness.
	switch {
	case ctrl.Enabled == 0 || m.xskLivenessFailed:
		// In strict mode, a degraded userspace path still implies the strict
		// shim is attached and fail-closed, not eBPF-only forwarding.
		if m.configuredMode == ModeUserspaceStrict {
			m.mode = ModeUserspaceStrict
		} else {
			m.mode = ModeEBPFOnly
		}
	case m.xskLivenessProven && m.configuredMode == ModeUserspaceStrict:
		m.mode = ModeUserspaceStrict
	case m.xskLivenessProven:
		m.mode = ModeUserspaceCompat
	default:
		// ctrl enabled but liveness not yet proven — still probing.
		m.mode = ModeUserspaceCompat
	}
	// Set strict flag in ctrl so the XDP shim knows not to fall back.
	if m.configuredMode == ModeUserspaceStrict {
		ctrl.Flags |= userspaceCtrlFlagStrict
	}

	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update userspace_ctrl from helper status: %w", err)
	}

	for _, binding := range status.Bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		flags := uint32(0)
		if binding.Registered && binding.Armed {
			// Mark ready once registered + armed. Don't wait for Bound:
			// the Bound flag is set asynchronously by worker threads
			// after XSK socket creation. Waiting creates a chicken-and-egg
			// where the XDP shim drops packets (flags=0) preventing the
			// XSK socket from ever receiving (so Bound never becomes true).
			flags = userspaceBindingReady
		}
		idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
		// Call-site cap guard (#814): the aya Array is sized to
		// dataplane.BindingArrayMaxEntries = MaxInterfaces *
		// BindingQueuesPerIface. An ifindex above MaxInterfaces would
		// overflow the flat index; fail with a legible error instead
		// of relying on the kernel's "argument list too long" E2BIG.
		if idx >= dataplane.BindingArrayMaxEntries {
			return fmt.Errorf(
				"update userspace_bindings: idx=%d exceeds cap=%d (ifindex=%d queue=%d; raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
				idx, dataplane.BindingArrayMaxEntries, binding.Ifindex, binding.QueueID,
			)
		}
		val := userspaceBindingValue{
			Slot:  binding.Slot,
			Flags: flags,
		}
		if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_bindings idx=%d (if=%d q=%d): %w", idx, binding.Ifindex, binding.QueueID, err)
		}
		if _, seen := newBindingIndexSet[idx]; !seen {
			newBindingIndexSet[idx] = struct{}{}
			newBindingIndices = append(newBindingIndices, idx)
		}
	}
	for childIfindex, parentIfindex := range buildUserspaceIngressBindingAliases(m.lastSnapshot) {
		for _, binding := range status.Bindings {
			if binding.Ifindex != int(parentIfindex) {
				continue
			}
			flags := uint32(0)
			if binding.Registered && binding.Armed && binding.Bound {
				flags = userspaceBindingReady
			}
			idx := childIfindex*bindingQueuesPerIface + binding.QueueID
			// Call-site cap guard (#814): see primary apply above.
			// VLAN-alias children use their own ifindex here, so the
			// child (not the parent) is the overflow risk.
			if idx >= dataplane.BindingArrayMaxEntries {
				return fmt.Errorf(
					"update aliased userspace_bindings: idx=%d exceeds cap=%d (child=%d parent=%d queue=%d; raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
					idx, dataplane.BindingArrayMaxEntries, childIfindex, parentIfindex, binding.QueueID,
				)
			}
			val := userspaceBindingValue{
				Slot:  binding.Slot,
				Flags: flags,
			}
			if err := bindingsMap.Update(idx, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf(
					"update aliased userspace_bindings idx=%d (if=%d parent=%d q=%d): %w",
					idx,
					childIfindex,
					parentIfindex,
					binding.QueueID,
					err,
				)
			}
			if _, seen := newBindingIndexSet[idx]; !seen {
				newBindingIndexSet[idx] = struct{}{}
				newBindingIndices = append(newBindingIndices, idx)
			}
		}
	}
	{
		var zeroBinding userspaceBindingValue
		for _, idx := range m.lastBindingIndices {
			if _, keep := newBindingIndexSet[idx]; keep {
				continue
			}
			_ = bindingsMap.Update(idx, zeroBinding, ebpf.UpdateAny)
		}
		m.lastBindingIndices = newBindingIndices
	}
	if err := m.syncIngressIfaceMapLocked(m.lastSnapshot); err != nil {
		return err
	}
	if err := m.syncLocalAddressMapsLocked(m.lastSnapshot); err != nil {
		return err
	}
	if err := m.syncInterfaceNATAddressMapsLocked(m.lastSnapshot); err != nil {
		return err
	}
	// Sync userspace-forwarded packet counters into BPF counter maps so
	// that ReadGlobalCounter/ReadZoneCounters/etc. return complete values
	// even for packets that bypassed the BPF pipeline (#332).
	m.syncBPFCountersLocked(status)

	m.recordHelperStatusLocked(status)
	return nil
}

// userspaceCounterSnapshot holds cumulative counter totals from the helper,
// used to compute deltas between status polls.

// fallbackReasonNames maps BPF array index to a human-readable name.
// Must stay in sync with USERSPACE_FALLBACK_REASON_* in userspace-xdp/src/lib.rs.
var fallbackReasonNames = [16]string{
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
}

// readFallbackStatsLocked reads the userspace_fallback_stats BPF array map
// and returns a map of reason name -> cumulative count. Entries with zero
// count are omitted.
func (m *Manager) readFallbackStatsLocked() map[string]uint64 {
	statsMap := m.inner.Map("userspace_fallback_stats")
	if statsMap == nil {
		return nil
	}
	result := make(map[string]uint64)
	for i := uint32(0); i < uint32(len(fallbackReasonNames)); i++ {
		var val uint64
		if err := statsMap.Lookup(i, &val); err != nil {
			continue
		}
		if val == 0 {
			continue
		}
		name := fallbackReasonNames[i]
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
// by inspecting the inner dataplane manager's link state.
// Note: VLAN sub-interfaces are skipped during SwapXDPEntryProg and may
// retain the parent's program; they are excluded from this map.
func (m *Manager) entryProgramsLocked() map[int]string {
	links := m.inner.XDPLinks()
	if len(links) == 0 {
		return nil
	}
	progName := m.inner.XDPEntryProg
	result := make(map[int]string, len(links))
	for ifindex := range links {
		if m.inner.VlanSubInterfaces[ifindex] {
			continue // VLAN sub-interfaces use parent's XDP program
		}
		result[ifindex] = progName
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (m *Manager) syncIngressIfaceMapLocked(snapshot *ConfigSnapshot) error {
	ifaceMap := m.inner.Map("userspace_ingress_ifaces")
	if ifaceMap == nil {
		return errors.New("userspace_ingress_ifaces map not loaded")
	}

	newIngress := buildUserspaceIngressIfindexes(snapshot)
	newIngressSet := make(map[uint32]struct{}, len(newIngress))
	for _, ifindex := range newIngress {
		newIngressSet[ifindex] = struct{}{}
		if err := ifaceMap.Update(ifindex, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_ingress_ifaces %d: %w", ifindex, err)
		}
	}
	// HashMap: Delete removes the entry. ErrKeyNotExist is expected
	// across daemon restarts (idempotent). Any other failure must be
	// fatal — a stale entry the dataplane still treats as ingress
	// would silently redirect traffic for an interface removed from
	// the config.
	for _, k := range m.lastIngressIfaces {
		if _, keep := newIngressSet[k]; keep {
			continue
		}
		if err := ifaceMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_ingress_ifaces %d: %w", k, err)
		}
	}
	m.lastIngressIfaces = newIngress
	return nil
}

func (m *Manager) syncLocalAddressMapsLocked(snapshot *ConfigSnapshot) error {
	localV4Map := m.inner.Map("userspace_local_v4")
	if localV4Map == nil {
		return errors.New("userspace_local_v4 map not loaded")
	}
	localV6Map := m.inner.Map("userspace_local_v6")
	if localV6Map == nil {
		return errors.New("userspace_local_v6 map not loaded")
	}

	var (
		localV4Key uint32
		localV4Val uint8
	)
	localV4Iter := localV4Map.Iterate()
	var localV4Keys []uint32
	for localV4Iter.Next(&localV4Key, &localV4Val) {
		localV4Keys = append(localV4Keys, localV4Key)
	}
	for _, key := range localV4Keys {
		if err := localV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v4 %08x: %w", key, err)
		}
	}

	var (
		localV6Key userspaceLocalV6Key
		localV6Val uint8
	)
	localV6Iter := localV6Map.Iterate()
	var localV6Keys []userspaceLocalV6Key
	for localV6Iter.Next(&localV6Key, &localV6Val) {
		localV6Keys = append(localV6Keys, localV6Key)
	}
	for _, key := range localV6Keys {
		if err := localV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_local_v6 %+v: %w", key, err)
		}
	}

	for _, entry := range buildLocalAddressEntries(snapshot) {
		if entry.v4 {
			if err := localV4Map.Update(entry.v4Key, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update userspace_local_v4 %08x: %w", entry.v4Key, err)
			}
			continue
		}
		if err := localV6Map.Update(entry.v6Key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_local_v6 %+v: %w", entry.v6Key, err)
		}
	}
	// Also add kernel addresses (VIPs added by VRRP) that aren't in the
	// config snapshot. Without this, the XDP shim doesn't recognize VIP
	// destinations as local and redirects them to XSK instead of the kernel.
	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		addrs, err := netlink.AddrList(nil, family)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addr.IP
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil && family == netlink.FAMILY_V4 {
				key := binary.BigEndian.Uint32(v4)
				_ = localV4Map.Update(key, uint8(1), ebpf.UpdateAny)
			} else if v6 := ip.To16(); v6 != nil && family == netlink.FAMILY_V6 {
				var key [16]byte
				copy(key[:], v6)
				_ = localV6Map.Update(userspaceLocalV6Key{Addr: key}, uint8(1), ebpf.UpdateAny)
			}
		}
	}
	return nil
}

func (m *Manager) syncInterfaceNATAddressMapsLocked(snapshot *ConfigSnapshot) error {
	natV4Map := m.inner.Map("userspace_interface_nat_v4")
	if natV4Map == nil {
		return errors.New("userspace_interface_nat_v4 map not loaded")
	}
	natV6Map := m.inner.Map("userspace_interface_nat_v6")
	if natV6Map == nil {
		return errors.New("userspace_interface_nat_v6 map not loaded")
	}

	var (
		natV4Key uint32
		natV4Val uint8
	)
	natV4Iter := natV4Map.Iterate()
	var natV4Keys []uint32
	for natV4Iter.Next(&natV4Key, &natV4Val) {
		natV4Keys = append(natV4Keys, natV4Key)
	}
	for _, key := range natV4Keys {
		if err := natV4Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v4 %08x: %w", key, err)
		}
	}

	var (
		natV6Key userspaceLocalV6Key
		natV6Val uint8
	)
	natV6Iter := natV6Map.Iterate()
	var natV6Keys []userspaceLocalV6Key
	for natV6Iter.Next(&natV6Key, &natV6Val) {
		natV6Keys = append(natV6Keys, natV6Key)
	}
	for _, key := range natV6Keys {
		if err := natV6Map.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete userspace_interface_nat_v6 %+v: %w", key, err)
		}
	}

	var rstV4 []netip.Addr
	var rstV6 []netip.Addr
	for _, entry := range buildInterfaceNATAddressEntries(snapshot) {
		if entry.v4 {
			if err := natV4Map.Update(entry.v4Key, uint8(1), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update userspace_interface_nat_v4 %08x: %w", entry.v4Key, err)
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], entry.v4Key)
			rstV4 = append(rstV4, netip.AddrFrom4(b))
			continue
		}
		if err := natV6Map.Update(entry.v6Key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_interface_nat_v6 %+v: %w", entry.v6Key, err)
		}
		rstV6 = append(rstV6, netip.AddrFrom16(entry.v6Key.Addr))
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
//   - the inner eBPF compile recreated the map from a fresh pin
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
	bindingsMap := m.inner.Map("userspace_bindings")
	if bindingsMap == nil {
		return false
	}

	repaired := 0
	for _, binding := range bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		if !binding.Registered || !binding.Armed {
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
		// registered and armed. Rewrite the entry.
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
				if !binding.Registered || !binding.Armed || !binding.Bound {
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

func (m *Manager) hasBusyBindingsWedgeLocked(repaired bool) bool {
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	if !m.lastStatus.ForwardingArmed || m.deferWorkers {
		return false
	}
	if m.xskLivenessProven || m.xskLivenessFailed {
		return false
	}
	bindings := m.lastStatus.Bindings
	if len(bindings) == 0 {
		return false
	}
	registeredArmed := 0
	bound := 0
	ready := 0
	busyErr := false
	for _, binding := range bindings {
		if binding.Ifindex <= 0 {
			continue
		}
		if binding.Registered && binding.Armed {
			registeredArmed++
		}
		if binding.Bound {
			bound++
		}
		if binding.Ready {
			ready++
		}
		if strings.Contains(strings.ToLower(binding.LastError), "resource busy") {
			busyErr = true
		}
	}
	return registeredArmed > 0 && bound == 0 && ready == 0 && (busyErr || repaired)
}

func (m *Manager) shouldAutoRebindBusyBindingsLocked(now time.Time, repaired bool) bool {
	if !m.hasBusyBindingsWedgeLocked(repaired) {
		m.bindingsBusySince = time.Time{}
		return false
	}
	if m.bindingsBusySince.IsZero() {
		m.bindingsBusySince = now
		return false
	}
	if now.Sub(m.bindingsBusySince) < 5*time.Second {
		return false
	}
	if !m.lastBindingsAutoRebind.IsZero() && now.Sub(m.lastBindingsAutoRebind) < 15*time.Second {
		return false
	}
	m.lastBindingsAutoRebind = now
	return true
}

func (m *Manager) maybeAutoRebindBusyBindingsLocked(now time.Time, repaired bool) {
	if !m.shouldAutoRebindBusyBindingsLocked(now, repaired) {
		return
	}
	var status ProcessStatus
	m.neighborsPrewarmed = false
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	m.xskProbeStart = time.Time{}
	m.lastXSKRX = 0
	if err := m.requestLocked(ControlRequest{Type: "rebind"}, &status); err != nil {
		slog.Warn("userspace: auto-rebind for stuck XSK bindings failed", "err", err)
		return
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: auto-rebind status sync failed", "err", err)
	}
	slog.Warn("userspace: auto-rebind initiated for stuck XSK bindings",
		"bindings", len(status.Bindings),
		"forwarding_armed", status.ForwardingArmed)
	m.bootstrapNAPIQueuesAsyncLocked("busy-xsk-wedge")
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
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.ParentIfindex > 0 {
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
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		fmt.Fprintf(
			&b,
			"iface=%s/%s/%d/%d/%d/%t/%t;",
			iface.Name,
			iface.LinuxName,
			iface.Ifindex,
			iface.ParentIfindex,
			iface.RXQueues,
			iface.LogicalOnly,
			iface.Tunnel,
		)
	}
	for _, fab := range snapshot.Fabrics {
		fmt.Fprintf(
			&b,
			"fabric=%s/%s/%d/%d;",
			fab.Name,
			fab.ParentLinuxName,
			fab.ParentIfindex,
			fab.RXQueues,
		)
	}
	return b.String()
}

func buildUserspaceIngressBindingAliases(snapshot *ConfigSnapshot) map[uint32]uint32 {
	if snapshot == nil {
		return nil
	}
	out := make(map[uint32]uint32)
	for _, iface := range snapshot.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		if iface.Ifindex <= 0 || iface.ParentIfindex <= 0 || iface.Ifindex == iface.ParentIfindex || iface.LogicalOnly {
			continue
		}
		out[uint32(iface.Ifindex)] = uint32(iface.ParentIfindex)
	}
	return out
}

func userspaceSkipsIngressInterface(iface InterfaceSnapshot) bool {
	if iface.Tunnel {
		return true
	}
	base := iface.Name
	if idx := strings.IndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	switch {
	case strings.HasPrefix(base, "fxp"):
		return true
	case strings.HasPrefix(base, "em"):
		return true
	case strings.HasPrefix(base, "fab"):
		return true
	case base == "lo0":
		return true
	}
	switch iface.Zone {
	case "mgmt", "control":
		return true
	}
	if iface.LocalFabric != "" {
		return true
	}
	return false
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
