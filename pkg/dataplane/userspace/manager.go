package userspace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"net/netip"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ dataplane.DataPlane = (*Manager)(nil)

// DataplaneMode describes which packet-processing pipeline is active.
type DataplaneMode int

const (
	ModeEBPFOnly        DataplaneMode = iota // Pure eBPF pipeline, no userspace
	ModeUserspaceCompat                      // Userspace preferred, eBPF/kernel fallback allowed
	ModeUserspaceStrict                      // Strict userspace only, no transit fallback
)

func (m DataplaneMode) String() string {
	switch m {
	case ModeEBPFOnly:
		return "ebpf_only"
	case ModeUserspaceCompat:
		return "userspace_compat"
	case ModeUserspaceStrict:
		return "userspace_strict"
	default:
		return "unknown"
	}
}

func init() {
	dataplane.RegisterBackend(dataplane.TypeUserspace, func() dataplane.DataPlane {
		return New()
	})
}

type Manager struct {
	dataplane.DataPlane
	inner *dataplane.Manager

	mu                      sync.Mutex
	sessionMu               sync.Mutex // separate lock for session sync requests (Phase 3)
	proc                    *exec.Cmd
	cfg                     config.UserspaceConfig
	clusterHA               bool
	generation              uint64
	syncCancel              context.CancelFunc
	lastStatus              ProcessStatus
	lastSnapshot            *ConfigSnapshot
	haGroups                map[int]HAGroupStatus
	lastIngressIfaces       []uint32
	lastRSTv4               []netip.Addr
	lastRSTv6               []netip.Addr
	lastRSTAttempt          time.Time
	lastRSTInstallOK        bool
	lastSnapshotHash        [32]byte // content hash of last published snapshot (excludes volatile fields)
	// #1197: O(1) neighbor lookup index for the listener hot path.
	// Keyed by (ifindex, ip-string). Rebuilt whenever lastSnapshot.Neighbors
	// is replaced. Read under m.mu (existing snapshot lock).
	neighborIndex map[neighborIndexKey]*NeighborSnapshot
	// #1197: ifindex set for listener filter; rebuilt on config commit.
	monitoredIfindexes map[int]struct{}
	lastBindingIndices      []uint32
	neighborsPrewarmed      bool
	ctrlEnableAt            time.Time
	ctrlWasEnabled          bool
	initialCtrlCleanupDone  bool
	ctrlDisabledAt          uint64    // monotonic ktime_ns when ctrl was last disabled
	lastDemotionTime        time.Time // wall clock when last RG demotion occurred
	xskLivenessFailed       bool
	xskLivenessProven       bool
	xskProbeStart           time.Time
	lastXSKRX               uint64
	lastNAPIBootstrap       time.Time
	lastStandbyNeighResolve time.Time
	bindingsBusySince       time.Time
	lastBindingsAutoRebind  time.Time
	publishedSnapshot       uint64
	publishedPlanKey        string
	sessionMirrorFailed     bool
	sessionMirrorErr        string
	deferWorkers            bool // skip worker spawn until NotifyLinkCycle
	xskBoundNotified        bool // OnXSKBound fired at most once

	mode               DataplaneMode // current active runtime mode
	configuredMode     DataplaneMode // user-configured desired mode (from config)
	lastHASyncTime     time.Time     // throttle HA watchdog sync to avoid control socket contention
	lastRGActivateTime time.Time     // wall clock of last update_ha_state; statusLoop skips HA sync for 2s

	rgTransitionInFlight atomic.Bool // set before syncHAStateLocked, cleared on completion

	// Counter delta tracking: previous binding counter totals for computing
	// deltas to write into BPF counter maps (#332).
	prevBindingCounters userspaceCounterSnapshot

	eventStream       *EventStream
	eventStreamCancel context.CancelFunc

	// OnXSKBound is called once when all XSK bindings are bound.
	// Used by the daemon to defer IPVLAN creation until after XSK
	// binds in zerocopy mode on fabric parents.
	OnXSKBound func()
}

const rstSuppressionRetryBackoff = 5 * time.Second

func shouldAttemptRSTSuppression(
	now time.Time,
	desiredV4 []netip.Addr,
	desiredV6 []netip.Addr,
	appliedV4 []netip.Addr,
	appliedV6 []netip.Addr,
	lastAttempt time.Time,
	lastInstallOK bool,
) bool {
	if lastAttempt.IsZero() {
		return true
	}
	if !slices.Equal(desiredV4, appliedV4) || !slices.Equal(desiredV6, appliedV6) {
		return true
	}
	if lastInstallOK {
		return false
	}
	return now.Sub(lastAttempt) >= rstSuppressionRetryBackoff
}

func New() *Manager {
	inner := dataplane.New()
	inner.XDPEntryProg = "xdp_main_prog"
	return &Manager{
		DataPlane:      inner,
		inner:          inner,
		configuredMode: ModeUserspaceCompat,
		haGroups:       make(map[int]HAGroupStatus),
	}
}

// EventStream returns the event stream instance, or nil if not available.
func (m *Manager) EventStream() *EventStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventStream
}

// XSKBoundNotified reports whether the OnXSKBound callback has already fired.
// The daemon uses this to distinguish first applyConfig (defer IPVLAN) from
// subsequent calls (reconcile normally).
func (m *Manager) XSKBoundNotified() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.xskBoundNotified
}

// Mode returns the current active dataplane runtime mode.
func (m *Manager) Mode() DataplaneMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// SetConfiguredMode sets the user-configured desired dataplane mode.
// The active mode is computed in applyHelperStatusLocked based on runtime
// state and may differ from the configured mode.
func (m *Manager) SetConfiguredMode(mode DataplaneMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configuredMode = mode
}

func (m *Manager) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return false, 0, 0
	}
	if !m.lastStatus.Enabled || !m.lastStatus.ForwardingArmed || !m.lastStatus.Capabilities.ForwardingSupported {
		return false, 0, 0
	}
	// Userspace forwarding already streams authoritative open/close deltas.
	// Keep a periodic refresh for long-lived flows, but avoid the 1s batch walk
	// that was tuned for the eBPF session tables.
	return true, 15 * time.Second, 60 * time.Second
}

func (m *Manager) Load() error {
	return m.inner.Load()
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.inner.Close()
}

func (m *Manager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.inner.Teardown()
}

// SetDeferWorkers tells the manager to skip worker startup during the next
// Compile(). Workers will be started on the first NotifyLinkCycle() instead.
// Use this when RETH MAC programming will follow Compile() — avoids the
// double-bind that causes EBUSY on mlx5 zero-copy queues.
func (m *Manager) SetDeferWorkers(v bool) {
	m.mu.Lock()
	m.deferWorkers = v
	m.mu.Unlock()
}

func (m *Manager) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	// Delete XDP link pins BEFORE inner.Compile() so AttachXDP does
	// a fresh attach. This is critical for zero-copy: fresh attach
	// triggers mlx5 to initialize XSK buffer pool from fill ring.
	// Pinned link reuse (l.Update) only swaps the program without
	// reinitializing XSK RQs, leaving the fill ring unconsumed.
	if linkPinDir := "/sys/fs/bpf/xpf/links"; true {
		entries, _ := os.ReadDir(linkPinDir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "xdp_") {
				path := filepath.Join(linkPinDir, e.Name())
				_ = os.Remove(path)
			}
		}
	}
	caps := deriveUserspaceCapabilities(cfg)
	_ = caps // used below for helper config
	// Use the shim when forwarding is supported. The shim redirects to
	// XSK when ctrl=1; when ctrl=0 it falls through to XDP_PASS which
	// delivers to the kernel at the same throughput as xdp_main_prog.
	// XSK socket creation is deferred by the arm delay (45s) to avoid
	// segfaults from __xsk_setup_xdp_prog during link cycles.
	if m.xskLivenessFailed {
		m.inner.XDPEntryProg = "xdp_main_prog"
	} else if caps.ForwardingSupported {
		m.inner.XDPEntryProg = "xdp_userspace_prog"
	} else {
		m.inner.XDPEntryProg = "xdp_main_prog"
	}
	result, err := m.inner.Compile(cfg)
	if err != nil {
		return nil, err
	}
	ucfg := deriveUserspaceConfig(cfg)
	snap := buildSnapshot(cfg, ucfg, m.bumpGeneration(), m.readFIBGeneration())
	m.syncInterfaceAttachments(result, snap)

	m.mu.Lock()
	defer m.mu.Unlock()
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
	m.lastSnapshot = snap
	// #1197 v4 (Codex code-review v3 #1+#2): rebuild listener
	// caches ONLY after a successful apply_snapshot. Doing it
	// here (before publish) leaves the listener thinking
	// userspace-dp has entries it doesn't if apply_snapshot fails.
	// Moved to the post-success path below (after line 343).
	if pendingXSKStartup {
		if err := m.syncIngressIfaceMapLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncLocalAddressMapsLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncInterfaceNATAddressMapsLocked(snap); err != nil {
			return result, err
		}
		m.cfg = ucfg
		slog.Info(
			"userspace: deferring snapshot publish during XSK startup",
			"generation", snap.Generation,
			"fib_generation", snap.FIBGeneration,
			"same_plan", samePlanRefresh,
		)
		return result, nil
	}
	if samePlanRefresh {
		if err := m.syncIngressIfaceMapLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncLocalAddressMapsLocked(snap); err != nil {
			return result, err
		}
		if err := m.syncInterfaceNATAddressMapsLocked(snap); err != nil {
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
	if m.deferWorkers {
		snap.DeferWorkers = true
	}
	var status ProcessStatus
	// #1197 v5 (Codex code-review v4 #2): apply_snapshot must
	// send publishable-only neighbors to match the
	// update_neighbors path. Otherwise Rust's full-snapshot
	// build accepts state="none" entries Go's predicate rejects,
	// and Go can't track removal of those entries via the index.
	publishSnap := *snap
	publishSnap.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	if err := m.requestLocked(ControlRequest{Type: "apply_snapshot", Snapshot: &publishSnap}, &status); err != nil {
		return result, fmt.Errorf("publish userspace snapshot: %w", err)
	}
	// #1197 v4: apply_snapshot succeeded — userspace-dp has the
	// new neighbors. NOW rebuild listener caches; before this
	// point the index would shadow events for entries the
	// dataplane hadn't accepted.
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = snap.Generation
	m.publishedPlanKey = newPlanKey
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return result, fmt.Errorf("sync helper status: %w", err)
	}
	if err := m.refreshHAStateFromMapsLocked(); err != nil {
		return result, fmt.Errorf("replay userspace HA state from maps: %w", err)
	}
	if err := m.syncHAStateLocked(); err != nil {
		return result, fmt.Errorf("publish userspace HA state: %w", err)
	}
	if err := m.syncDesiredForwardingStateLocked(); err != nil {
		return result, fmt.Errorf("sync userspace forwarding state: %w", err)
	}
	m.ensureStatusLoopLocked()
	m.cfg = ucfg
	return result, nil
}

func (m *Manager) syncInterfaceAttachments(result *dataplane.CompileResult, snapshot *ConfigSnapshot) {
	if result == nil {
		return
	}
	allowed := make(map[int]bool)
	for _, ifindex := range buildUserspaceIngressIfindexes(snapshot) {
		allowed[int(ifindex)] = true
	}
	for ifindex := range m.inner.XDPLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.inner.DetachXDP(ifindex); err != nil {
			slog.Warn("userspace: detach XDP from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
	for ifindex := range m.inner.TCLinks() {
		if allowed[ifindex] {
			continue
		}
		if err := m.inner.DetachTC(ifindex); err != nil {
			slog.Warn("userspace: detach TC from non-data interface failed", "ifindex", ifindex, "err", err)
		}
	}
}

func (m *Manager) readFIBGeneration() uint32 {
	fibGenMap := m.inner.Map("fib_gen_map")
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
func (m *Manager) BumpFIBGeneration() uint32 {
	newGen := m.inner.BumpFIBGeneration()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return newGen
	}
	if m.proc == nil || m.proc.Process == nil {
		return newGen
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
	newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if !neighborsEqualForwarding(m.lastSnapshot.Neighbors, newNeighbors) {
		publishable := filterPublishableNeighbors(newNeighbors)
		var status ProcessStatus
		if err := m.requestLocked(ControlRequest{
			Type:            "update_neighbors",
			Neighbors:       publishable,
			NeighborReplace: true,
		}, &status); err != nil {
			slog.Warn("userspace: failed to publish neighbor update", "err", err)
		} else {
			// Only update cached neighbors after successful publish so
			// a transient failure doesn't suppress future retries.
			m.lastSnapshot.Neighbors = newNeighbors
			m.rebuildNeighborIndex() // #1197
		}
	}

	// Send lightweight FIB generation bump — no full snapshot rebuild.
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type: "bump_fib_generation",
		Snapshot: &ConfigSnapshot{
			FIBGeneration: newGen,
		},
	}, &status); err != nil {
		slog.Warn("userspace: failed to bump FIB generation", "err", err)
	}
	return newGen
}

// neighborIndexKey is the (ifindex, ip-string) key for the
// O(1) neighbor lookup index used by the daemon's listener hot
// path. ip-string is used (not net.IP) so map equality is well-
// defined for both v4 and v6 representations.
type neighborIndexKey struct {
	ifindex int
	ip      string
}

// filterPublishableNeighbors returns only the entries
// userspace-dp will accept (per neighborSnapshotPublishable).
func filterPublishableNeighbors(neighbors []NeighborSnapshot) []NeighborSnapshot {
	out := make([]NeighborSnapshot, 0, len(neighbors))
	for _, n := range neighbors {
		if neighborSnapshotPublishable(n) {
			out = append(out, n)
		}
	}
	return out
}

// rebuildNeighborIndex updates m.neighborIndex from the current
// m.lastSnapshot.Neighbors slice. Caller MUST hold m.mu. Called
// after every assignment to lastSnapshot.Neighbors.
//
// Codex code-review v2 #1: index ONLY publishable entries.
// Indexing raw entries causes a bug: a raw failed→reachable
// transition on the same MAC would return existing.MAC == new.MAC
// from LookupSnapshotNeighbor → shouldTriggerRegen returns false
// → snapshot stays out of date until 60s safety tick. By indexing
// only publishable entries, an unpublishable→publishable
// transition presents as "no existing entry" → trigger fires.
func (m *Manager) rebuildNeighborIndex() {
	if m.lastSnapshot == nil {
		m.neighborIndex = nil
		return
	}
	idx := make(map[neighborIndexKey]*NeighborSnapshot,
		len(m.lastSnapshot.Neighbors))
	for i := range m.lastSnapshot.Neighbors {
		n := &m.lastSnapshot.Neighbors[i]
		if !neighborSnapshotPublishable(*n) {
			continue
		}
		idx[neighborIndexKey{n.Ifindex, n.IP}] = n
	}
	m.neighborIndex = idx
}

// RegenerateNeighborSnapshot rebuilds the in-memory neighbor
// snapshot from current kernel ARP/NDP state and publishes any
// forwarding-relevant changes to userspace-dp.
//
// #1197: this is the event-driven entry point used by the
// daemon's RTM_NEWNEIGH/DELNEIGH listener (and the 60s safety
// reconciliation tick) to keep the userspace-dp neighbor table
// in sync with the kernel without depending on the buggy
// preinstall mechanism.
//
// Forwarding-effective diff (key, MAC, publishable-bit) decides
// whether to publish; raw NUD state (REACHABLE↔STALE) is ignored
// to avoid republish churn.
func (m *Manager) RegenerateNeighborSnapshot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// #1197 v4 (Codex code-review v3 #1): refresh monitored
	// ifindex cache unconditionally — a regen call may be
	// triggered by the safety tick precisely because a link
	// changed, and the listener filter must reflect that even
	// if neighbor entries didn't diff.
	m.rebuildMonitoredIfindexes()

	newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if neighborsEqualForwarding(m.lastSnapshot.Neighbors, newNeighbors) {
		return
	}
	publishable := filterPublishableNeighbors(newNeighbors)
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type:            "update_neighbors",
		Neighbors:       publishable,
		NeighborReplace: true,
	}, &status); err != nil {
		slog.Warn("userspace: failed to publish neighbor regeneration", "err", err)
		return
	}
	m.lastSnapshot.Neighbors = newNeighbors
	m.rebuildNeighborIndex() // #1197 (after publish success)
	m.generation++
	m.lastSnapshot.Generation = m.generation
	// Copilot review: advance publishedSnapshot + refresh
	// lastSnapshotHash. Otherwise the status loop sees the
	// bumped generation as unpublished and may force a redundant
	// apply_snapshot, AND any churn in filtered-out rows could
	// leak through hash-dedup.
	m.publishedSnapshot = m.lastSnapshot.Generation
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
}

// LookupSnapshotNeighbor returns a copy of the snapshot's
// current entry for (ifindex, ip), or nil if not present. The
// returned snapshot is a value copy — safe to read after the
// lock is released, and avoids the (currently no-op) mutation
// hazard of returning an internal pointer.
//
// Codex code-review v2 #4: previous version returned a defensive
// pointer via heap copy. Caller (shouldTriggerRegen) only reads
// the MAC immediately while still under m.mu, so a pointer is
// safe. But the API surface is cleaner as a value (caller can
// hold it across other lock-acquiring calls without aliasing
// concerns), so we keep the value-copy semantics — just skip
// the heap-allocated *NeighborSnapshot wrapping.
//
// Index covers ONLY publishable entries (#1 v2 fix), so a hit
// here means userspace-dp has been told about this entry.
func (m *Manager) LookupSnapshotNeighbor(ifindex int, ip net.IP) *NeighborSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.neighborIndex == nil {
		return nil
	}
	entry, ok := m.neighborIndex[neighborIndexKey{ifindex, ip.String()}]
	if !ok {
		return nil
	}
	out := *entry
	return &out
}

// IsMonitoredIfindex returns true if the given link index
// belongs to a configured interface that buildNeighborSnapshots
// would iterate. O(1) hash-map lookup under m.mu.
//
// Codex code-review v2 #2: previous version returned a copy of
// the whole map, which made the listener hot path O(configured-
// interfaces) plus heap churn per event. This direct lookup
// avoids both.
func (m *Manager) IsMonitoredIfindex(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.monitoredIfindexes == nil {
		return false
	}
	_, ok := m.monitoredIfindexes[ifindex]
	return ok
}

// rebuildMonitoredIfindexes updates m.monitoredIfindexes from
// the active config. Caller MUST hold m.mu.
//
// Codex code-review v2 #3: previous version was called only on
// full snapshot assignment. Neighbor-only updates (BumpFIBGeneration,
// RegenerateNeighborSnapshot) didn't refresh the cache, so a
// configured link recreated under a new ifindex could have its
// events dropped. Now called from every neighbor-related update
// path that may reflect a new ifindex.
func (m *Manager) rebuildMonitoredIfindexes() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		m.monitoredIfindexes = nil
		return
	}
	m.monitoredIfindexes = MonitoredInterfaceLinkIndexes(m.lastSnapshot.Config)
}

// ForEachSnapshotNeighbor invokes fn for every PUBLISHABLE
// neighbor entry in the current snapshot (i.e., entries
// userspace-dp accepted into its forwarding table).
//
// #1197 (Copilot review): the existing SnapshotNeighbors() walks
// raw lastSnapshot.Neighbors which can include filtered-out
// entries (FAILED/INCOMPLETE/none). For force-probe target
// collection we want only the entries the dataplane is actually
// using, so we walk neighborIndex (publishable-only).
func (m *Manager) ForEachSnapshotNeighbor(fn func(ifindex int, ip net.IP)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, n := range m.neighborIndex {
		ip := net.ParseIP(n.IP)
		if ip == nil {
			continue
		}
		fn(k.ifindex, ip)
	}
}

// SnapshotHasIfindex returns true if the current snapshot
// contains any neighbor entry on the given ifindex. Used by the
// daemon's listener filter as a fallback for runtime ifindex
// drift. O(N) scan over the neighborIndex but the listener
// already pays O(1) for the LookupSnapshotNeighbor; this fallback
// only fires when the config-derived monitored set doesn't
// contain the ifindex (rare, e.g., link disappeared).
func (m *Manager) SnapshotHasIfindex(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.neighborIndex {
		if k.ifindex == ifindex {
			return true
		}
	}
	return false
}

func deriveUserspaceConfig(cfg *config.Config) config.UserspaceConfig {
	out := config.UserspaceConfig{
		Workers:       1,
		RingEntries:   1024,
		ControlSocket: filepath.Join(os.TempDir(), "xpf-userspace-dp", "control.sock"),
		StateFile:     filepath.Join(os.TempDir(), "xpf-userspace-dp", "state.json"),
	}
	if cfg != nil && cfg.System.UserspaceDataplane != nil {
		out = *cfg.System.UserspaceDataplane
	}
	if out.Workers <= 0 {
		out.Workers = 1
	}
	if out.RingEntries <= 0 {
		out.RingEntries = 1024
	}
	if out.ControlSocket == "" {
		out.ControlSocket = filepath.Join(os.TempDir(), "xpf-userspace-dp", "control.sock")
	}
	if out.StateFile == "" {
		out.StateFile = filepath.Join(filepath.Dir(out.ControlSocket), "state.json")
	}
	if out.EventSocket == "" {
		out.EventSocket = filepath.Join(filepath.Dir(out.ControlSocket), "userspace-dp-events.sock")
	}
	return out
}

func deriveUserspaceCapabilities(cfg *config.Config) UserspaceCapabilities {
	caps := UserspaceCapabilities{ForwardingSupported: true}
	if cfg == nil {
		return caps
	}
	addReason := func(reason string) {
		caps.ForwardingSupported = false
		caps.UnsupportedReasons = append(caps.UnsupportedReasons, reason)
	}
	if !userspaceSupportsSecurityPolicies(cfg) {
		addReason("full security policy semantics are not implemented in the userspace dataplane")
	}
	// Pool-mode source NAT is now implemented in the userspace dataplane
	// (PortAllocator with round-robin address + port allocation).
	// NAT64 is supported — NATv6v4 config (no-v6-frag-header option) is fine
	// Session timeouts (TCP/UDP/ICMP) are supported — only gate on unsupported flow features
	// TCP MSS clamping is supported in the userspace dataplane
	// GRE acceleration (key extraction into session ports) is supported
	if !userspaceSupportsScreenProfiles(cfg) {
		addReason("screen features requiring SYN cookies are not implemented in the userspace dataplane")
	}
	// Firewall filters and policers are now supported in the userspace dataplane.
	// Three-color policers remain unsupported.
	if len(cfg.Firewall.ThreeColorPolicers) > 0 {
		addReason("three-color policers are not implemented in the userspace dataplane")
	}
	// IPsec: kernel XFRM handles ESP encryption/decryption; the userspace
	// dataplane passes ESP/IKE traffic to the kernel via the slow-path.
	// GRE transit is now modeled as native userspace tunnel endpoints on the
	// physical NIC path. Kernel tunnel interfaces remain only for host/control
	// plane compatibility during migration.
	if cfg.ForwardingOptions.PortMirroring != nil {
		addReason("port mirroring is not implemented in the userspace dataplane")
	}
	// Flow export (NetFlow v9) is now supported in the userspace dataplane.
	return caps
}

func userspaceSupportsSecurityPolicies(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		// SchedulerName and Count are informational — not forwarding-critical.
		// Schedulers define time windows (not DSCP), and counters are advisory.
		if !userspacePolicyAddressesSupported(cfg, pol.Match.SourceAddresses) ||
			!userspacePolicyAddressesSupported(cfg, pol.Match.DestinationAddresses) ||
			!userspacePolicyApplicationsSupported(cfg, pol.Match.Applications) {
			return false
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if !userspacePolicyAddressesSupported(cfg, pol.Match.SourceAddresses) ||
				!userspacePolicyAddressesSupported(cfg, pol.Match.DestinationAddresses) ||
				!userspacePolicyApplicationsSupported(cfg, pol.Match.Applications) {
				return false
			}
		}
	}
	return true
}

func userspacePolicyAddressesSupported(cfg *config.Config, addrs []string) bool {
	_, ok := expandUserspacePolicyAddresses(cfg, addrs)
	return ok
}

func expandUserspacePolicyAddresses(cfg *config.Config, addrs []string) ([]string, bool) {
	if len(addrs) == 0 {
		return nil, true
	}
	expanded := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	addUnique := func(value string) {
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		expanded = append(expanded, value)
	}
	for _, addr := range addrs {
		switch {
		case addr == "" || addr == "any":
			addUnique("any")
		case isUserspaceLiteralAddress(addr):
			addUnique(normalizeUserspaceLiteralAddress(addr))
		default:
			values, ok := resolveUserspaceAddressBookEntry(cfg, addr)
			if !ok || len(values) == 0 {
				return nil, false
			}
			for _, value := range values {
				if value == "" {
					return nil, false
				}
				if !isUserspaceLiteralAddress(value) {
					return nil, false
				}
				addUnique(normalizeUserspaceLiteralAddress(value))
			}
		}
	}
	sort.Strings(expanded)
	return expanded, true
}

func isUserspaceLiteralAddress(value string) bool {
	if value == "" || value == "any" {
		return true
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return net.ParseIP(value) != nil
}

func normalizeUserspaceLiteralAddress(value string) string {
	if value == "" || value == "any" {
		return value
	}
	if _, ipNet, err := net.ParseCIDR(value); err == nil && ipNet != nil {
		return ipNet.String()
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func resolveUserspaceAddressBookEntry(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || cfg.Security.AddressBook == nil || name == "" {
		return nil, false
	}
	addressBook := cfg.Security.AddressBook
	seenSets := make(map[string]bool)
	expanded := make([]string, 0, 4)
	var resolve func(string) bool
	resolve = func(ref string) bool {
		if ref == "" {
			return false
		}
		if addr := addressBook.Addresses[ref]; addr != nil {
			if addr.Value == "" {
				return false
			}
			expanded = append(expanded, addr.Value)
			return true
		}
		set := addressBook.AddressSets[ref]
		if set == nil {
			return false
		}
		if seenSets[ref] {
			return true
		}
		seenSets[ref] = true
		resolvedAny := false
		for _, member := range set.Addresses {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		for _, member := range set.AddressSets {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		return resolvedAny
	}
	if !resolve(name) {
		return nil, false
	}
	sort.Strings(expanded)
	expanded = slices.Compact(expanded)
	return expanded, true
}

func userspacePolicyApplicationsSupported(cfg *config.Config, apps []string) bool {
	_, ok := expandUserspacePolicyApplications(cfg, apps)
	return ok
}

func expandUserspacePolicyApplications(cfg *config.Config, apps []string) ([]PolicyApplicationSnapshot, bool) {
	if len(apps) == 0 {
		return nil, true
	}
	expanded := make([]PolicyApplicationSnapshot, 0, len(apps))
	seen := make(map[string]struct{}, len(apps))
	for _, appName := range apps {
		if appName == "" || appName == "any" {
			return nil, true
		}
		resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
		if !ok || len(resolved) == 0 {
			return nil, false
		}
		for _, resolvedName := range resolved {
			app, ok := config.ResolveApplication(resolvedName, cfg.Applications.Applications)
			if !ok || app == nil {
				return nil, false
			}
			proto := normalizeUserspaceApplicationProtocol(app.Protocol)
			if proto == "" {
				return nil, false
			}
			snap := PolicyApplicationSnapshot{
				Name:            resolvedName,
				Protocol:        proto,
				SourcePort:      app.SourcePort,
				DestinationPort: app.DestinationPort,
			}
			key := strings.Join([]string{snap.Name, snap.Protocol, snap.SourcePort, snap.DestinationPort}, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			expanded = append(expanded, snap)
		}
	}
	sort.Slice(expanded, func(i, j int) bool {
		if expanded[i].Name != expanded[j].Name {
			return expanded[i].Name < expanded[j].Name
		}
		if expanded[i].Protocol != expanded[j].Protocol {
			return expanded[i].Protocol < expanded[j].Protocol
		}
		if expanded[i].SourcePort != expanded[j].SourcePort {
			return expanded[i].SourcePort < expanded[j].SourcePort
		}
		return expanded[i].DestinationPort < expanded[j].DestinationPort
	})
	return expanded, true
}

func resolveUserspaceApplicationNames(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || name == "" {
		return nil, false
	}
	if _, ok := config.ResolveApplication(name, cfg.Applications.Applications); ok {
		return []string{name}, true
	}
	if _, ok := config.ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
		expanded, err := config.ExpandApplicationSet(name, &cfg.Applications)
		if err != nil || len(expanded) == 0 {
			return nil, false
		}
		sort.Strings(expanded)
		return slices.Compact(expanded), true
	}
	return nil, false
}

func normalizeUserspaceApplicationProtocol(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "icmp6":
		return "icmpv6"
	default:
		return strings.ToLower(strings.TrimSpace(proto))
	}
}

func userspaceSupportsSourceNAT(ruleSets []*config.NATRuleSet) bool {
	for _, rs := range ruleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then.Interface || rule.Then.Off {
				continue
			}
			return false
		}
	}
	return true
}

// SnapshotNeighbors returns the neighbor entries from the last published
// snapshot. Used by the daemon to pre-install kernel ARP entries on RG
// activation so failback doesn't drop packets during ARP resolution.
func (m *Manager) SnapshotNeighbors() []struct {
	Ifindex int
	IP      net.IP
	MAC     net.HardwareAddr
	Family  int
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil {
		return nil
	}
	var result []struct {
		Ifindex int
		IP      net.IP
		MAC     net.HardwareAddr
		Family  int
	}
	for _, n := range m.lastSnapshot.Neighbors {
		if n.Ifindex <= 0 || n.MAC == "" || n.IP == "" {
			continue
		}
		mac, err := net.ParseMAC(n.MAC)
		if err != nil {
			continue
		}
		ip := net.ParseIP(n.IP)
		if ip == nil {
			continue
		}
		family := netlink.FAMILY_V4
		if ip.To4() == nil {
			family = netlink.FAMILY_V6
		}
		result = append(result, struct {
			Ifindex int
			IP      net.IP
			MAC     net.HardwareAddr
			Family  int
		}{
			Ifindex: n.Ifindex,
			IP:      ip,
			MAC:     mac,
			Family:  family,
		})
	}
	return result
}

func (m *Manager) Status() (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		if m.lastStatus.PID != 0 {
			return m.lastStatus, nil
		}
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err != nil {
		if m.lastStatus.PID != 0 {
			return m.lastStatus, err
		}
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetForwardingArmed(armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	if armed && !m.lastStatus.Capabilities.ForwardingSupported {
		if len(m.lastStatus.Capabilities.UnsupportedReasons) == 0 {
			return m.lastStatus, errors.New("userspace live forwarding is not supported for the current configuration")
		}
		return m.lastStatus, fmt.Errorf(
			"userspace live forwarding is not supported: %s",
			strings.Join(m.lastStatus.Capabilities.UnsupportedReasons, "; "),
		)
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_forwarding_state",
		Forwarding: &ForwardingControlRequest{
			Armed: armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetQueueState(queueID uint32, registered, armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_queue_state",
		Queue: &QueueControlRequest{
			QueueID:    queueID,
			Registered: registered,
			Armed:      armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) SetBindingState(slot uint32, registered, armed bool) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	req := ControlRequest{
		Type: "set_binding_state",
		Binding: &BindingControlRequest{
			Slot:       slot,
			Registered: registered,
			Armed:      armed,
		},
	}
	if err := m.requestLocked(req, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) InjectPacket(req InjectPacketRequest) (ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "inject_packet", Packet: &req}, &status); err != nil {
		return ProcessStatus{}, err
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) DrainSessionDeltas(max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type: "drain_session_deltas",
		SessionDeltas: &SessionDeltaDrainRequest{
			Max: max,
		},
	})
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	var status ProcessStatus
	if resp.Status != nil {
		status = *resp.Status
		if err := m.applyHelperStatusLocked(&status); err != nil {
			return resp.SessionDeltas, status, err
		}
	}
	return resp.SessionDeltas, status, nil
}

func (m *Manager) ExportOwnerRGSessions(rgIDs []int, max uint32) ([]SessionDeltaInfo, ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type: "export_owner_rg_sessions",
		SessionExport: &SessionExportRequest{
			OwnerRGs: rgIDs,
			Max:      max,
		},
	})
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	var status ProcessStatus
	if resp.Status != nil {
		status = *resp.Status
		if err := m.applyHelperStatusLocked(&status); err != nil {
			return resp.SessionDeltas, status, err
		}
	}
	return resp.SessionDeltas, status, nil
}
