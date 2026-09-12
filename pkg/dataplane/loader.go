package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

const (
	linkPinPath            = "/sys/fs/bpf/xpf/links"
	defaultXDPEntryProg    = "xdp_main_prog"
	userspaceShimEntryProg = "xdp_userspace_prog"
)

// go:generate directives.
// After the #1476 source-removal phase of the #1373 eBPF retirement
// the only generator step here is the retained Rust AF_XDP shim.
// Run "make generate" (or "make build-userspace-xdp" which calls
// "make generate-userspace-xdp" internally) to rebuild the retained
// shim object embedded by userspace_xdp_rust.go.
//
//go:generate bash build-userspace-xdp.sh

// Manager manages the eBPF dataplane: programs, maps, and attachments.
type Manager struct {
	// armCoverage holds the most recent #7191 arm-coverage proof so the daemon
	// can gate on per-interface attach coverage instead of only logging it.
	armCoverage armCoverageCell
	// hostDivergence is the #8285 sticky per-BOX record of host state an aborted
	// apply left unconverged; hostdivergence_8285.go owns the rationale.
	hostDivergence hostDivergenceCell
	// loaded is the #2114 A3 armed-admission bit: atomic so the
	// pre-registry loaded checks (AttachXDP/AttachTC/CompileConfig) and
	// the externally visible IsLoaded() surface never race the shim
	// publication batch or Close. Store(true) is the FINAL step inside
	// publishShimRegistryLocked's whole-batch m.mu hold; Store(false)
	// runs at Close()'s ENTRY. It is an admission bit, NOT a lease — it
	// cannot drain an operation that already observed true.
	loaded   atomic.Bool
	programs map[string]*ebpf.Program
	maps     map[string]*ebpf.Map
	// xdpLinks / tcLinks / vlanSubInterfaces are ALL guarded by m.mu (#6740).
	// The 1 Hz userspace status path ranges them while CompileUserspaceShim /
	// AttachXDP / DetachXDP mutate them, and a concurrent Go map read+write is
	// a fatal runtime.throw, not a torn value. Every accessor below returns a
	// SNAPSHOT rather than the live map: handing out the map by reference put
	// the range loop outside any lock the accessor could take, which is how the
	// race survived the #2114 A3 registry rule.
	xdpLinks        map[int]link.Link
	tcLinks         map[int]link.Link
	lastCompile     *CompileResult
	applyMu         sync.Mutex
	applyGeneration uint64
	// registryGeneration counts REGISTRY publications (#6741). It is bumped
	// inside publishShimRegistryLocked's m.mu hold, so it and the m.maps /
	// m.programs contents always move together.
	//
	// registryObsoleteFrom records the generation that Teardown superseded.
	// Teardown's Cleanup destroys the pinned kernel objects, so every handle
	// still sitting in the registry at that moment refers to an obsolete
	// forwarding generation — Close does NOT set this, because Close
	// deliberately keeps its pinned handles live for hitless-restart reuse.
	//
	// obsoleteRegistryAccesses counts lookups REFUSED for that reason (#6741
	// AC1). It used to count lookups that SERVED such a handle and was
	// explicitly "not a guard"; the lookup now declines, so this is the
	// observability half of a real guard. See obsoleteRegistryLocked for what
	// it still does not cover — a handle obtained BEFORE the Teardown and held
	// across it is never re-checked.
	registryGeneration       uint64
	registryObsoleteFrom     uint64
	obsoleteRegistryAccesses uint64
	obsoleteEpochLogged      bool
	lastApply                *ApplyResult
	PersistentNAT            *PersistentNATTable
	EnableCPUMap             bool // Enable cpumap multi-CPU distribution (adds startup overhead)
	xdpEntryProg             string
	vlanSubInterfaces        map[int]bool      // VLAN sub-interface ifindexes (skip XDP swap for these); guarded by m.mu (#6740)
	mu                       sync.Mutex        // protects userspaceCounterOffsets + natRuleCounterOffsets + zone/flood offsets; #2114 A3: also the uniform m.maps/m.programs registry rule (every access goes through the lookupMapLocked/lookupProgramLocked scoped helpers, classification + handle selection atomic inside) and the xdpEntryProg field
	userspaceCounterOffsets  map[uint32]uint64 // userspace counter deltas merged in ReadGlobalCounter
	// natRuleCounterOffsets holds per-rule NAT translation hit totals reported
	// by the Rust userspace dataplane (keyed by compiler-assigned counter ID),
	// merged into ReadNATRuleCounter. The Rust forwarder never writes the
	// nat_rule_counters BPF map (#2218: the #1476 eBPF retirement dropped the
	// legacy XDP increments), so these mirror the live helper totals into the
	// existing operator read path. Values are absolute cumulative totals, not
	// deltas (SetNATRuleCounterOffset overwrites).
	natRuleCounterOffsets map[uint32]CounterValue

	// zoneCounterOffsets / floodCounterOffsets hold userspace-reported per-zone
	// traffic + flood counters keyed by the STABLE-HASH zone id (#3075: zone
	// ids are a name-derived FNV fold in [1,65533], NOT a dense [1,MaxZones]
	// index). #3643: the legacy dense zone_counters / flood_counters BPF arrays
	// hold only MaxZones*2 / MaxZones entries, so indexing them by a stable-hash
	// id >= MaxZones OOBs the bounded Lookup (ErrKeyNotExist). The read surfaces
	// mis-reported that structural OOB as a hard failure (REST 500, false
	// Prometheus xpf_counter_read_errors_total alerts, CLI/gRPC error rows).
	// Read{Zone,Flood}Counters now key these sparse maps and NEVER index the
	// dense arrays -- the same treatment #2255 gave nat_rule_counters.
	//
	// #6843: the two maps are no longer symmetric and must not be described as
	// one. zoneCounterOffsets IS populated -- #3651 shipped the traffic POPULATE
	// path, and syncBPFCountersLocked REPLACES this map from every helper status
	// poll (ReplaceZoneCounterOffsets), so a zone the helper stops publishing is
	// dropped rather than left serving a frozen total. floodCounterOffsets stays
	// empty IN A RUNNING FIREWALL: the flood POPULATE path is still deferred
	// (docs/research/3643-dead-counters/plan.md §5A, leaning on the #3343
	// aggregate), so those reads report ErrCounterNotPopulated. That is a claim
	// about production, not an API-wide absolute -- SetFloodCounterOffset is
	// exported and tests do write it. Surfaces render "not available", never a
	// misleading 0.
	zoneCounterOffsets  map[uint16][2]CounterValue // [zoneID] -> {ingress, egress}
	floodCounterOffsets map[uint16]FloodState      // [zoneID]

	// #863: refcount of XDP-attached ifindexes that "claim" the
	// IFACE_FLAG_XDP_ATTACHED bit on each iface_zone_map entry.
	// Compiler.go allows BOTH parent (native) and sub-iface (generic)
	// XDP simultaneously; both AttachXDP calls flag the same
	// {parent, vlan_id} entry, and the first DetachXDP must NOT
	// clear the bit while the other link is still live. Refcount
	// makes the flag state correct under overlap: bit set when
	// claimants > 0, cleared on the last drop. Mutated only under
	// the implicit single-threaded compile path; no separate lock.
	xdpFlagClaims map[IfaceZoneKey]map[int]bool
}

// New creates a new dataplane Manager.
func New() *Manager {
	return &Manager{
		programs:          make(map[string]*ebpf.Program),
		maps:              make(map[string]*ebpf.Map),
		xdpLinks:          make(map[int]link.Link),
		tcLinks:           make(map[int]link.Link),
		PersistentNAT:     NewPersistentNATTable(),
		xdpEntryProg:      defaultXDPEntryProg,
		vlanSubInterfaces: make(map[int]bool),
		xdpFlagClaims:     make(map[IfaceZoneKey]map[int]bool),
	}
}

// XDPEntryProgram returns the entry program selected for future XDP
// attachments and non-VLAN-subinterface link swaps. #2114 A3: the field
// is m.mu-protected; each public accessor takes the lock ONCE and
// delegates to the raw helper (sync.Mutex is non-reentrant, so the
// predicate must NOT call the public getter).
func (m *Manager) XDPEntryProgram() string {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("XDPEntryProgram")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if xdpEntryProgSelectorHook != nil {
		xdpEntryProgSelectorHook()
	}
	return m.xdpEntryProgramLocked()
}

// xdpEntryProgramLocked returns the selected entry program with no
// locking of its own; callers hold m.mu.
func (m *Manager) xdpEntryProgramLocked() string {
	if m.xdpEntryProg == "" {
		return defaultXDPEntryProg
	}
	return m.xdpEntryProg
}

// SelectUserspaceXDPShimEntryProgram selects the retained userspace shim for
// future XDP attachments without touching already attached links.
func (m *Manager) SelectUserspaceXDPShimEntryProgram() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if xdpEntryProgSelectorHook != nil {
		xdpEntryProgSelectorHook()
	}
	m.xdpEntryProg = userspaceShimEntryProg
}

// UsingUserspaceXDPShimEntryProgram reports whether the retained userspace
// shim is selected for XDP attachments and swapped links.
func (m *Manager) UsingUserspaceXDPShimEntryProgram() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.xdpEntryProgramLocked() == userspaceShimEntryProg
}

// Load is a retirement stub after the #1476 mechanical source removal.
// The legacy XDP/TC dataplane source, generated bpf2go bindings, and
// the loadAllObjects() loader graph are all gone. The method stays in
// tree because the DataPlane interface (pkg/dataplane/dataplane.go:209)
// requires Load() and Manager.Start() at apply.go calls m.Load() —
// deleting the method would break the compile-time interface
// assertion at dataplane.go:30 and any test that constructs a
// Manager directly.
//
// Production callers reach Load() only through the explicit
// "dataplane-type ebpf" rollback path, which is now itself retired:
// NewDataPlane(TypeEBPF) and NewRuntimeDataPlane(TypeEBPF) return
// ErrEBPFBackendRetired directly, and daemon_run.go's soft-fallback
// branch catches it. The Store.Load() / Store.SyncApply() rewrite
// helpers rewrite persisted `dataplane-type ebpf` to empty before
// compile, so the daemon never reaches this method on a normal
// rolling upgrade.
//
// The Manager's userspace shim path uses LoadUserspaceShim() instead;
// see CompileUserspaceShim for the production attachment flow.
func (m *Manager) Load() error {
	return ErrEBPFBackendRetired
}

// LoadUserspaceShim loads only the retained AF_XDP userspace XDP shim and the
// explicit shared maps that the userspace runtime still exchanges with Go.
// It intentionally bypasses loadAllObjects, xdp_main, XDP tail-call objects,
// and TC objects.
func (m *Manager) LoadUserspaceShim() error {
	slog.Info("loading userspace XDP shim")
	m.SelectUserspaceXDPShimEntryProgram()
	if err := shimPrePublishLoad(m); err != nil {
		return err
	}
	// #2114 A3: the armed Store(true) lives INSIDE the shim registry
	// publication batch (publishShimRegistryLocked, called from the load
	// above), so the flag and a fully populated registry publish
	// atomically.
	slog.Info("userspace XDP shim loaded successfully")
	return nil
}

// shimPrePublishLoad runs the privileged load leg of LoadUserspaceShim:
// the legacy TC-link/map-pin cleanups and the object acquisition +
// publication. It is a package var ONLY as the #2114 A3 armed-gate test
// seam — the blocked-Start legs substitute a synthetic loader that still
// routes the registry writes through the production
// publishShimRegistryLocked, so the whole-batch hold and the in-hold
// Store(true) are exercised for real. Production never reassigns it; at
// most ONE test arms it at a time (the same single-hook discipline as the
// other A3 seams).
var shimPrePublishLoad = func(m *Manager) error {
	if err := cleanupUserspaceShimLegacyTCLinks(); err != nil {
		return err
	}
	if err := cleanupUserspaceShimLegacyOnlyMapPins(); err != nil {
		return err
	}
	return m.loadUserspaceShimObjects()
}

// CompileUserspaceShim runs the shared config compiler for its Linux interface
// setup and metadata, but suppresses writes to legacy eBPF dataplane maps and
// attaches only the retained userspace XDP shim. This keeps normal AF_XDP
// startup independent from xdp_main and TC program objects.
func (m *Manager) CompileUserspaceShim(cfg *config.Config) (*CompileResult, error) {
	m.SelectUserspaceXDPShimEntryProgram()
	compilerDP := userspaceShimCompileDataplane{Manager: m}
	result, err := CompileConfig(compilerDP, cfg, m.lastCompile != nil)
	if err != nil {
		return nil, err
	}
	// Scoped ifindex-cap early-warning (#5836): reject only when an
	// interface XPF actually attaches AF_XDP to (result.pendingXDP) has an
	// ifindex >= MaxInterfaces — an unrelated high-ifindex host link must
	// not fail the compile. The compiler's shim dataplane methods are
	// no-ops, so CompileConfig writes no ifindex-keyed map before this runs;
	// the userspace_bindings ARRAY cap in maps_sync.go stays the real
	// fail-closed guardrail.
	//
	// #4960: both of the steps below land AFTER CompileConfig's Phase 2 has
	// already mutated the host, and there is no undo. Neither can be hoisted
	// above it — preflightCheckIfindexCaps consumes result.pendingXDP, which
	// only compileZones populates, and the attach is the actuation itself. They
	// are therefore grouped into runPostMutationSteps, which names that region
	// and annotates any failure with what already moved.
	// Both steps are written as CALLS inside closures rather than as method
	// values (`m.attachUserspaceShimXDP`). The #5275 arm-proof canary
	// (TestArmProofIsInvokedFromCompileUserspaceShim) locates the attach by
	// walking this function for a CallExpr and asserts the proof runs after it;
	// a method value is a SelectorExpr and would silently give that canary
	// nothing to anchor to. Keeping the call shape keeps the existing guard
	// intact instead of loosening it to fit this refactor.
	// #7079: the three bpffs cleanups run HERE — after CompileConfig has accepted
	// the config, and immediately before the attach they exist for. They used to
	// run ahead of CompileConfig, so a config the #4960 pre-pass REJECTED still
	// lost the host's XDP link pins, legacy TC link pins and legacy-only map pins
	// for an apply that never happened.
	//
	// The ordering they must respect is narrower than where they used to sit: the
	// XDP removal's constraint is "before AttachXDP", not "before
	// CompileUserspaceShim" as its old comment said. Nothing between CompileConfig
	// and here touches pins — CompileConfig runs against
	// userspaceShimCompileDataplane, whose dataplane methods are no-ops.
	//
	// Blast radius, and why this MOVES rather than becoming recoverable:
	// docs/log/7079.md. Bound by TestPinCleanupsRunAfterCompileConfig_7079.
	// #8285: stamp a PREVIOUS abort's unconverged divergence onto this result.
	// Placement is load-bearing: after CompileConfig, before the first abort.
	m.inheritHostDivergence(result)
	//
	// #7289 R1: each of the three aborts below returns AFTER Phase 2 has
	// mutated the host and BEFORE the arm-coverage proof at the tail, so each
	// one used to leave the published #7191 verdict describing a DIFFERENT
	// apply — absent on the first, stale-and-affirmative on every later one —
	// and the daemon's gate disarmed nothing either way. Routing them through
	// abortAfterHostMutation publishes a LIVE proof first, so the gate decides
	// from this apply's real kernel state. Note removeUserspaceShimXDPLinkPins
	// below runs BEFORE the attach: after it, a failed attach can leave the
	// interface with no XDP program at all, which is exactly the surface the
	// proof has to adjudicate.
	if err := cleanupUserspaceShimLegacyTCLinks(); err != nil {
		return nil, m.abortAfterHostMutation(result, err)
	}
	if err := cleanupUserspaceShimLegacyOnlyMapPins(); err != nil {
		return nil, m.abortAfterHostMutation(result, err)
	}
	removeUserspaceShimXDPLinkPins()

	if err := runPostMutationSteps(result,
		func(r *CompileResult) error {
			return m.preflightCheckIfindexCaps(ifindexSet(r.pendingXDP))
		},
		func(r *CompileResult) error {
			return m.attachUserspaceShimXDP(r)
		},
	); err != nil {
		return nil, m.abortAfterHostMutation(result, err)
	}
	// #5275 PR1: OBSERVE-ONLY arm-coverage proof. Runs after the attach so it
	// sees real link state, reports what a gating build would have decided,
	// and gates NOTHING — the return value is deliberately discarded. It reads
	// `result` directly and publishes nothing: hoisting the m.lastCompile
	// assignment to feed it would expose a half-observed CompileResult through
	// the exported LastCompileResult() for a diagnostic's benefit.
	//
	// #7191: the report is no longer only logged — ProveArmCoverage now also
	// PUBLISHES it so the daemon can gate on it (ArmCoverageSummary). The call
	// shape here is unchanged, which keeps the #5275 canary's guarantee that the
	// logged report is a LIVE proof rather than a stashed one.
	m.ProveArmCoverage(result).LogArmCoverage("post-attach", m.nextApplyGeneration())

	// #8285: ONLY the success tail may clear this (see hostdivergence_8285.go).
	m.clearHostDivergence()
	m.markVLANSubInterfaces(result)
	m.lastCompile = result
	m.recordApplyResult(ApplyResultFromCompileResult(result))
	return result, nil
}

func (m *Manager) attachUserspaceShimXDP(result *CompileResult) error {
	if result == nil || len(result.pendingXDP) == 0 {
		return nil
	}

	failedNativeXDP := make(map[int]bool)
	for _, ifidx := range result.pendingXDP {
		if result.tunnelIfindexes[ifidx] || result.genericXDPIfindexes[ifidx] {
			continue
		}
		if err := m.AttachXDP(ifidx, false); err != nil {
			if strings.Contains(err.Error(), "already attached") {
				continue
			}
			slog.Warn("native XDP unavailable for userspace shim; falling back to generic (skb-mode)",
				"ifindex", ifidx, "err", err,
				"impact", "higher CPU, ~6 Gbps cap; fix driver/firmware to restore driver-mode XDP")
			m.DetachXDP(ifidx)
			failedNativeXDP[ifidx] = true
		}
	}
	if len(failedNativeXDP) > 0 {
		failed := make([]int, 0, len(failedNativeXDP))
		for ifidx := range failedNativeXDP {
			failed = append(failed, ifidx)
		}
		m.clearNativeXDPFlagsForIfindexes(failed)
	}
	for _, ifidx := range result.pendingXDP {
		forceGeneric := failedNativeXDP[ifidx] || result.tunnelIfindexes[ifidx] || result.genericXDPIfindexes[ifidx]
		if !forceGeneric {
			continue
		}
		if result.genericXDPIfindexes[ifidx] && !result.tunnelIfindexes[ifidx] {
			continue
		}
		if err := m.AttachXDP(ifidx, true); err != nil {
			if !strings.Contains(err.Error(), "already attached") {
				return fmt.Errorf("attach userspace XDP shim generic to ifindex %d: %w", ifidx, err)
			}
		}
	}
	return nil
}

// removeUserspaceShimXDPLinkPins deletes every `xdp_*` link pin so the attach is
// a FRESH attach rather than a pinned-link reuse — reuse (`existing.Update`)
// swaps the program without reinitializing the mlx5 XSK RQs, leaving the fill
// ring unconsumed, which breaks zero-copy.
//
// Relocated here from userspace.Manager.Compile by #7079: it must precede
// AttachXDP and must NOT precede CompileConfig. Best-effort — a pin already gone
// is the desired end state, as at the original site.
func removeUserspaceShimXDPLinkPins() {
	entries, _ := os.ReadDir(linkPinPath)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "xdp_") {
			_ = os.Remove(filepath.Join(linkPinPath, e.Name()))
		}
	}
}

type pinnedTCLink interface {
	Unpin() error
	Close() error
}

var userspaceShimLegacyOnlyMapPins = []string{
	"xdp_progs",
	"tc_progs",
	"policer_states",
}

func cleanupUserspaceShimLegacyOnlyMapPins() error {
	return cleanupUserspaceShimLegacyOnlyMapPinsIn(bpfPinPath, userspaceShimLegacyOnlyMapPins)
}

func cleanupUserspaceShimLegacyOnlyMapPinsIn(pinDir string, names []string) error {
	var cleanupErrs []error
	for _, name := range names {
		pinFile := filepath.Join(pinDir, name)
		if err := os.Remove(pinFile); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			cleanupErrs = append(cleanupErrs,
				fmt.Errorf("remove legacy-only userspace shim map pin %s: %w", pinFile, err))
			continue
		}
		slog.Info("removed legacy-only BPF map pin before userspace shim attach", "pin", pinFile)
	}
	return errors.Join(cleanupErrs...)
}

func cleanupUserspaceShimLegacyTCLinks() error {
	return cleanupUserspaceShimLegacyTCLinksIn(linkPinPath, func(path string) (pinnedTCLink, error) {
		return link.LoadPinnedLink(path, nil)
	})
}

func cleanupUserspaceShimLegacyTCLinksIn(
	linkDir string,
	load func(string) (pinnedTCLink, error),
) error {
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read userspace shim link pins: %w", err)
	}
	var cleanupErrs []error
	for _, entry := range entries {
		if !isLegacyTCPinName(entry.Name()) {
			continue
		}
		pinFile := filepath.Join(linkDir, entry.Name())
		pinned, err := load(pinFile)
		if err != nil {
			if rmErr := os.Remove(pinFile); rmErr != nil && !os.IsNotExist(rmErr) {
				cleanupErrs = append(cleanupErrs,
					fmt.Errorf("remove unreadable legacy TC pin %s: load: %v; remove: %w", pinFile, err, rmErr))
				continue
			}
			slog.Warn("removed unreadable legacy TC link pin", "pin", pinFile, "err", err)
			continue
		}
		pinErrs := 0
		if err := pinned.Unpin(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("unpin %s: %w", pinFile, err))
			pinErrs++
		}
		if err := pinned.Close(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close %s: %w", pinFile, err))
			pinErrs++
		}
		if pinErrs == 0 {
			slog.Info("detached stale legacy TC link before userspace shim attach", "pin", pinFile)
		}
	}
	return errors.Join(cleanupErrs...)
}

func isLegacyTCPinName(name string) bool {
	if !strings.HasPrefix(name, "tc_") {
		return false
	}
	if len(name) == len("tc_") {
		return false
	}
	for _, r := range name[len("tc_"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type userspaceShimCompileDataplane struct {
	*Manager
}

func (d userspaceShimCompileDataplane) AddTxPort(int) error { return nil }

func (d userspaceShimCompileDataplane) SetZone(int, uint16, uint16, uint32, uint8, uint8, uint32) error {
	return nil
}

func (d userspaceShimCompileDataplane) SetVlanIfaceInfo(int, int, uint16) error { return nil }
func (d userspaceShimCompileDataplane) SetZoneConfig(uint16, ZoneConfig) error  { return nil }
func (d userspaceShimCompileDataplane) ClearAddressBookV4() error               { return nil }
func (d userspaceShimCompileDataplane) ClearAddressBookV6() error               { return nil }
func (d userspaceShimCompileDataplane) ClearAddressMembership() error           { return nil }
func (d userspaceShimCompileDataplane) SetAddressBookEntry(string, uint32) error {
	return nil
}
func (d userspaceShimCompileDataplane) SetAddressMembership(uint32, uint32) error {
	return nil
}
func (d userspaceShimCompileDataplane) ClearApplications() error { return nil }
func (d userspaceShimCompileDataplane) ClearAppRanges() error    { return nil }
func (d userspaceShimCompileDataplane) SetAppRange(uint32, AppRangeEntry) error {
	return nil
}
func (d userspaceShimCompileDataplane) SetApplication(uint8, uint16, uint32, uint32, uint8, uint16, uint16) error {
	return nil
}
func (d userspaceShimCompileDataplane) ClearZonePairPolicies() error { return nil }
func (d userspaceShimCompileDataplane) SetZonePairPolicy(uint16, uint16, PolicySet) error {
	return nil
}
func (d userspaceShimCompileDataplane) SetPolicyRule(uint32, uint32, PolicyRule) error {
	return nil
}
func (d userspaceShimCompileDataplane) SetDefaultPolicy(uint8) error { return nil }

func (d userspaceShimCompileDataplane) SetDNATEntry(DNATKey, DNATValue) error       { return nil }
func (d userspaceShimCompileDataplane) SetDNATEntryV6(DNATKeyV6, DNATValueV6) error { return nil }

func (d userspaceShimCompileDataplane) SetScreenConfig(uint32, ScreenConfig) error {
	return nil
}
func (d userspaceShimCompileDataplane) SetFlowTimeout(uint32, uint32) error    { return nil }
func (d userspaceShimCompileDataplane) SetFlowConfig(FlowConfigValue) error    { return nil }
func (d userspaceShimCompileDataplane) SetMirrorConfig(int, int, uint32) error { return nil }
func (d userspaceShimCompileDataplane) ClearMirrorConfigs() error              { return nil }
func (d userspaceShimCompileDataplane) SetPolicerConfig(uint32, PolicerConfig) error {
	return nil
}
func (d userspaceShimCompileDataplane) SetIfaceFilter(IfaceFilterKey, uint32) error { return nil }
func (d userspaceShimCompileDataplane) SetFilterConfig(uint32, FilterConfig) error  { return nil }
func (d userspaceShimCompileDataplane) SetFilterRule(uint32, FilterRule) error      { return nil }

func (d userspaceShimCompileDataplane) DeleteStaleIfaceZone(map[IfaceZoneKey]bool) {}
func (d userspaceShimCompileDataplane) DeleteStaleVlanIface(map[uint32]bool)       {}
func (d userspaceShimCompileDataplane) DeleteStaleZonePairPolicies(map[ZonePairKey]bool) {
}
func (d userspaceShimCompileDataplane) DeleteStaleApplications(map[AppKey]bool) {}

func (d userspaceShimCompileDataplane) DeleteStaleDNATStatic(map[DNATKey]bool) {}
func (d userspaceShimCompileDataplane) DeleteStaleDNATStaticV6(map[DNATKeyV6]bool) {
}
func (d userspaceShimCompileDataplane) DeleteStaleStaticNAT(map[StaticNATKeyV4]bool, map[StaticNATKeyV6]bool) {
}

func (d userspaceShimCompileDataplane) ZeroStaleScreenConfigs(uint32) {}
func (d userspaceShimCompileDataplane) DeleteStaleIfaceFilter(map[IfaceFilterKey]bool) {
}
func (d userspaceShimCompileDataplane) ZeroStaleFilterConfigs(uint32) {}

// IsLoaded returns true if eBPF programs are loaded.
func (m *Manager) IsLoaded() bool {
	return m.loaded.Load()
}

// xdpAttachModeMatches reports whether the kernel's current XDP attach mode
// on ifindex matches what AttachXDP is about to request.  Returns true on
// "probe failed" so we fall through to the existing Update() path rather
// than punishing transient netlink hiccups.
//
// Kernel XDP attach modes (nl/link_linux.go):
//
//	XDP_ATTACHED_NONE = 0 — no prog attached
//	XDP_ATTACHED_DRV  = 1 — driver (native) mode
//	XDP_ATTACHED_SKB  = 2 — generic (skb) mode
//	XDP_ATTACHED_HW   = 3 — hw offload
func xdpAttachModeMatches(ifindex int, wantGeneric bool) bool {
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil || l == nil {
		return true
	}
	xdp := l.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return true
	}
	isGeneric := xdp.AttachMode == xdpAttachedSKB
	return isGeneric == wantGeneric
}

// AttachXDP attaches the XDP main program to the given interface.
// If forceGeneric is true, uses generic (SKB) mode instead of native driver mode.
// When forceGeneric is false, tries native driver mode only (no automatic fallback).
// On restart, reuses a previously pinned link and atomically replaces the program.
func (m *Manager) AttachXDP(ifindex int, forceGeneric bool) error {
	// #2114 A3 carve-out: the attach family keeps its own pre-registry
	// loaded rejection on BOTH unarmed states; the typed ErrDataplaneNotArmed
	// never fires here.
	if !m.loaded.Load() {
		return fmt.Errorf("eBPF programs not loaded")
	}

	entryProg := m.XDPEntryProgram()
	prog, present, _ := m.lookupProgramLocked(entryProg)
	if !present {
		return fmt.Errorf("%s not found", entryProg)
	}

	if _, exists := m.xdpLinkFor(ifindex); exists {
		return fmt.Errorf("XDP already attached to ifindex %d", ifindex)
	}

	// #863: defer setting IFACE_FLAG_XDP_ATTACHED on iface_zone_map
	// entries for this ifindex until AFTER a successful attach. The
	// flag is the tc_main tunnel-egress bypass's positive proof; if
	// attach fails, the flag must NOT be set. A flag-set failure on
	// the success path is logged at WARN — the attach itself
	// succeeded so we don't unwind, but tc_main's bypass won't fire
	// for this surface until the next config push runs SetZone
	// (which re-claims the surface based on m.xdpLinks[ifindex] and
	// sets the bit accordingly).
	defer func() {
		if _, ok := m.xdpLinkFor(ifindex); ok {
			if err := m.setXDPAttachedFlag(ifindex, true); err != nil {
				slog.Warn("AttachXDP: failed to set IFACE_FLAG_XDP_ATTACHED — tunnel-egress bypass will deny until next SetZone",
					"ifindex", ifindex, "err", err)
			}
		}
	}()

	// Try to load a previously pinned link and update it atomically.
	//
	// #864: before reusing, verify the pinned link's attach mode matches
	// what the caller requested.  If a previous boot fell back to generic
	// (skb-mode) and pinned a generic-mode link, we would otherwise keep
	// running in generic forever — losing native-XDP performance even
	// after the driver/firmware issue that forced the fallback is resolved,
	// and leaving IFACE_FLAG_NATIVE_XDP stale in the BPF maps.
	pinFile := filepath.Join(linkPinPath, xdpLinkPinName(ifindex))
	if existing, err := link.LoadPinnedLink(pinFile, nil); err == nil {
		if xdpAttachModeMatches(ifindex, forceGeneric) {
			if err := existing.Update(prog); err == nil {
				m.setXDPLink(ifindex, existing)
				slog.Info("updated pinned XDP link", "ifindex", ifindex)
				return nil
			}
			// Update failed (e.g. program type mismatch) — detach + re-attach.
			existing.Close()
			os.Remove(pinFile)
		} else {
			// Attach mode mismatch — existing pin is generic but we want
			// driver (or vice versa).  Drop the pin and attach fresh so the
			// mode picks up correctly and IFACE_FLAG_NATIVE_XDP stays true.
			slog.Warn("pinned XDP link has wrong attach mode; re-attaching",
				"ifindex", ifindex, "forceGeneric", forceGeneric)
			existing.Close()
			os.Remove(pinFile)
		}
	}

	// Fresh attachment (first boot or pin was removed/incompatible).
	opts := link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	}
	if forceGeneric {
		opts.Flags = link.XDPGenericMode
	} else {
		opts.Flags = link.XDPDriverMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		return fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
	}

	// Pin the link for future restarts.
	if err := os.MkdirAll(linkPinPath, 0700); err != nil {
		slog.Warn("failed to create link pin dir", "err", err)
	} else if err := l.Pin(pinFile); err != nil {
		slog.Warn("failed to pin XDP link", "ifindex", ifindex, "err", err)
	}

	m.setXDPLink(ifindex, l)
	m.seedInterfaceCounter(ifindex)
	mode := "native"
	if forceGeneric {
		mode = "generic"
	}
	slog.Info("attached XDP program", "ifindex", ifindex, "mode", mode)
	return nil
}

// seedInterfaceCounter pre-populates the PERCPU_HASH interface_counters
// entry for ifindex. Called from control-plane interface registration
// (AttachXDP, AddTxPort) so the BPF hot path stays lookup-only and
// never allocates in softirq context (#759). Idempotent: UpdateNoExist
// races safely across repeated registrations.
func (m *Manager) seedInterfaceCounter(ifindex int) {
	ic, _, _ := m.lookupMapLocked("interface_counters")
	if ic == nil {
		return
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]InterfaceCounterValue, numCPUs)
	_ = ic.Update(uint32(ifindex), zero, ebpf.UpdateNoExist)
}

// SwapToUserspaceXDPShimEntryProgram atomically replaces the XDP entry
// program on all attached interfaces with the retained userspace XDP shim.
// Userspace mode keeps this shim attached for normal operation and degraded
// local/control handling.
func (m *Manager) SwapToUserspaceXDPShimEntryProgram() error {
	return m.swapXDPEntryProg(userspaceShimEntryProg)
}

func (m *Manager) swapXDPEntryProg(name string) error {
	// #2114 A3 class 1: the program registry read is a REQUIRED access —
	// the fresh state returns the typed gate error, an armed/retained miss
	// keeps master's "not found".
	prog, present, st := m.lookupProgramLocked(name)
	if st == registryFresh {
		return fmt.Errorf("%w: XDP program %s", ErrDataplaneNotArmed, name)
	}
	if !present {
		return fmt.Errorf("XDP program %q not found", name)
	}
	m.mu.Lock()
	currentEntry := m.xdpEntryProgramLocked()
	m.mu.Unlock()
	if currentEntry == name {
		return nil // already using this program
	}
	// #6740: take the swap targets as ONE snapshot under m.mu — both maps
	// together, so the VLAN skip is decided against the same instant the link
	// set was read — then run the BPF updates on that snapshot with the lock
	// RELEASED. Holding m.mu across l.Update() would put a BPF syscall inside
	// the same lock the 1 Hz status path needs, which is the thing this section
	// exists to avoid.
	//
	// Skipping VLAN sub-interfaces: the parent's XDP handles VLAN-tagged
	// traffic. Swapping the shim onto VLAN sub-interfaces breaks NDP because
	// generic XDP + XDP_PASS doesn't properly deliver to the kernel's IPv6 NDP
	// stack on VLAN devices.
	targets := m.xdpSwapTargets()
	var errs []error
	for _, t := range targets {
		if err := t.link.Update(prog); err != nil {
			errs = append(errs, fmt.Errorf("swap XDP on ifindex %d: %w", t.ifindex, err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	// #2114 A3: scoped section around the field write only — never
	// whole-method locking (the xdpLinks loop above is serialized by the
	// outer userspace-manager lock at the liveness-restore call site).
	m.mu.Lock()
	if swapXDPEntryProgHook != nil {
		swapXDPEntryProgHook()
	}
	m.xdpEntryProg = name
	m.mu.Unlock()
	slog.Info("swapped XDP entry program", "program", name, "interfaces", len(targets))
	return nil
}

// DetachXDP detaches the XDP program from the given interface and
// removes its pin file.
func (m *Manager) DetachXDP(ifindex int) error {
	l, exists := m.xdpLinkFor(ifindex)
	if !exists {
		return nil
	}
	// #863: clear IFACE_FLAG_XDP_ATTACHED claims FIRST, before
	// closing/unpinning the link. If clear fails, the link stays in
	// m.xdpLinks and a retry of DetachXDP picks up where this one
	// left off. Doing it the other way around (close then clear)
	// leaves stale claims with no retry path — the next DetachXDP
	// early-returns at !exists.
	if err := m.setXDPAttachedFlag(ifindex, false); err != nil {
		slog.Error("DetachXDP: failed to clear IFACE_FLAG_XDP_ATTACHED — tc_main bypass may stay enabled until next config push",
			"ifindex", ifindex, "err", err)
		return fmt.Errorf("detach XDP from ifindex %d: clear flag: %w", ifindex, err)
	}
	l.Unpin()
	closeErr := l.Close()
	// Claim cleanup succeeded; the link is conceptually gone whether
	// or not Close errored. Remove from m.xdpLinks so a retry doesn't
	// infinite-loop on a stuck-close link, but surface the close
	// error.
	m.deleteXDPLink(ifindex)
	if closeErr != nil {
		return fmt.Errorf("detach XDP from ifindex %d: %w", ifindex, closeErr)
	}
	slog.Info("detached XDP program", "ifindex", ifindex)
	return nil
}

// setXDPAttachedFlag sets or clears IFACE_FLAG_XDP_ATTACHED on every
// iface_zone_map entry that represents the same ingress surface as
// the XDP attachment described by ifindex.
//
// xpf attaches XDP to two kinds of ifindexes (sometimes BOTH for the
// same {parent, vlan_id} surface — compiler.go allows native XDP on
// the parent AND generic XDP on a VLAN sub-iface):
//   - Physical ifindexes (PFs, virtio NICs). The compiler writes
//     iface_zone_map entries keyed by {phys_ifindex, vlan_id} for
//     every VLAN of that parent. Iterating by
//     `key.Ifindex == phys_ifindex` covers the native-VLAN entry
//     plus every VLAN sub-iface entry.
//   - VLAN sub-iface ifindexes. The sub-iface itself has no
//     iface_zone_map entry; the entry is keyed under the PARENT
//     ifindex plus the VLAN ID. Resolve sub→parent via
//     vlan_iface_map and flag that {parent, vlan_id} entry.
//
// Refcount semantics: m.xdpFlagClaims[entry] tracks the SET of
// ifindexes currently flagging each iface_zone_map entry. The bit
// is OR'd in when the set transitions empty → non-empty, cleared
// when it transitions non-empty → empty. Without refcount the
// first DetachXDP on a parent+sub-iface overlap would clear the bit
// while the other link is still live, reintroducing the
// enforcement-bypass #863 is fixing.
//
// Iterator and Update errors are logged AND returned. DetachXDP
// propagates the error so a stale flag is operator-visible.
// AttachXDP's deferred set logs at WARN but doesn't unwind — the
// attach succeeded; the next SetZone re-applies the bit per the
// claim set.
func (m *Manager) setXDPAttachedFlag(ifindex int, attached bool) error {
	// #2114 A3: OPTIONAL access — the absent-iface_zone_map early-boot
	// no-op is master's preserved outcome in every state (no gate; the
	// DetachXDP claim cleanup must always run on the retained registry).
	zm, present, _ := m.lookupMapLocked("iface_zone_map")
	if !present {
		// No iface_zone_map yet (early boot before Compile) — nothing
		// to flag. Caller treats this as a no-op success.
		return nil
	}

	// Collect the set of {ifindex, vlan_id} keys this XDP attachment
	// represents.
	targets := make(map[IfaceZoneKey]struct{})

	// On DETACH, also include every entry m.xdpFlagClaims says this
	// ifindex previously claimed. Without this, a Clear/recreate
	// cycle in the compile path (ClearIfaceZoneMap deletes BPF
	// entries before DetachXDP fires) would leave stale claims in
	// the in-memory map; a later SetZone on the same {ifindex,
	// vlan_id} would see a non-empty claim set and spuriously
	// re-flag the entry.
	if !attached {
		for k, claims := range m.xdpFlagClaims {
			if claims[ifindex] {
				targets[k] = struct{}{}
			}
		}
	}

	// Sub→parent resolution. Distinguish "not a sub-iface" (ENOENT
	// is the legitimate fast path: lookup returns ErrKeyNotExist
	// for any non-VLAN ifindex) from a real lookup error (which we
	// propagate so the caller can retry).
	if vmap, present, _ := m.lookupMapLocked("vlan_iface_map"); present {
		var vinfo VlanIfaceInfo
		switch err := vmap.Lookup(uint32(ifindex), &vinfo); {
		case err == nil:
			targets[IfaceZoneKey{Ifindex: vinfo.ParentIfindex, VlanID: vinfo.VlanID}] = struct{}{}
		case errors.Is(err, ebpf.ErrKeyNotExist):
			// Not a sub-iface — fine, fall through to physical-ifindex iter.
		default:
			slog.Warn("setXDPAttachedFlag: vlan_iface_map lookup failed",
				"ifindex", ifindex, "attached", attached, "err", err)
			return fmt.Errorf("vlan_iface_map lookup: %w", err)
		}
	}

	// Physical-ifindex iter: collect every {ifindex, *} entry.
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if key.Ifindex == uint32(ifindex) {
			targets[key] = struct{}{}
		}
	}
	if err := iter.Err(); err != nil {
		slog.Warn("setXDPAttachedFlag: iface_zone_map iterate failed",
			"ifindex", ifindex, "attached", attached, "err", err)
		return fmt.Errorf("iface_zone_map iterate: %w", err)
	}

	// Apply refcount semantics per target. For each entry: update
	// the claim set; if the set transitions across the empty
	// boundary, write the bit change to the BPF map.
	var firstUpdateErr error
	for tk := range targets {
		claims, exists := m.xdpFlagClaims[tk]
		if !exists {
			claims = make(map[int]bool)
		}

		var wantSet bool // bit value AFTER this op
		if attached {
			claims[ifindex] = true
			wantSet = true // we just added a claimant; bit must be set
			if !exists {
				// First claimant at this entry — store the new map.
				m.xdpFlagClaims[tk] = claims
			}
		} else {
			delete(claims, ifindex)
			if len(claims) == 0 {
				delete(m.xdpFlagClaims, tk)
				wantSet = false
			} else {
				m.xdpFlagClaims[tk] = claims
				wantSet = true // others still hold; leave the bit set
			}
		}

		// Read current entry, decide whether the bit needs to flip.
		var cur IfaceZoneValue
		if err := zm.Lookup(tk, &cur); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				// Entry not present yet (race with compiler's SetZone, or
				// already deleted). The claim set has been updated above;
				// SetZone will pick it up via m.xdpFlagClaims when it
				// re-creates the entry.
				continue
			}
			slog.Warn("setXDPAttachedFlag: iface_zone_map lookup failed",
				"ifindex", ifindex, "key", tk, "attached", attached, "err", err)
			if firstUpdateErr == nil {
				firstUpdateErr = err
			}
			continue
		}
		newFlags := cur.Flags
		if wantSet {
			newFlags |= IfaceFlagXDPAttached
		} else {
			newFlags &^= IfaceFlagXDPAttached
		}
		if newFlags == cur.Flags {
			continue
		}
		cur.Flags = newFlags
		if err := zm.Update(tk, cur, ebpf.UpdateAny); err != nil {
			slog.Warn("setXDPAttachedFlag: iface_zone_map update failed",
				"ifindex", ifindex, "key", tk, "attached", attached, "err", err)
			if firstUpdateErr == nil {
				firstUpdateErr = err
			}
		}
	}
	if firstUpdateErr != nil {
		return fmt.Errorf("iface_zone_map update: %w", firstUpdateErr)
	}
	return nil
}

// SetZone maps an {ifindex, vlanID} to a security zone and routing table in the BPF map.
func (m *Manager) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32, flags uint8, rgID uint8, screenFlags uint32) error {
	zm, present, st := m.lookupMapLocked("iface_zone_map")
	if st == registryFresh {
		return fmt.Errorf("%w: iface_zone_map", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("iface_zone_map not found")
	}
	// #863: preserve / establish IFACE_FLAG_XDP_ATTACHED.
	//
	// The bit is owned by AttachXDP/DetachXDP via the xdpFlagClaims
	// refcount, but SetZone has TWO jobs:
	//   (a) Re-rewriting an existing entry: keep the bit if any XDP
	//       attachment still claims this surface (consult
	//       m.xdpFlagClaims[key]).
	//   (b) Creating a NEW {ifindex, vlanID} entry while XDP is
	//       already attached to the physical parent: claim the
	//       surface NOW so the bit gets set, and so a later
	//       DetachXDP(parent) cleans it up correctly via the claim
	//       sweep in setXDPAttachedFlag(false).
	// Without (b), a new VLAN unit added after AttachXDP would land
	// without the flag and tc_main's bypass would never fire for
	// it even though parent XDP runs on the surface.
	key := IfaceZoneKey{Ifindex: uint32(ifindex), VlanID: vlanID}
	claims := m.xdpFlagClaims[key]
	if _, parentAttached := m.xdpLinkFor(ifindex); parentAttached {
		if claims == nil {
			claims = make(map[int]bool)
			m.xdpFlagClaims[key] = claims
		}
		claims[ifindex] = true
	}
	// Note: a sub-iface-only XDP attachment under the same surface
	// won't be discovered by SetZone (would require iterating
	// vlan_iface_map for every SetZone call). In practice this is
	// rare — sub-iface generic XDP only fires when the parent has
	// already attached its XDP (see compiler.go); the parent's claim
	// covers the surface. Filed as a follow-up if it ever bites.
	if len(claims) > 0 {
		flags |= IfaceFlagXDPAttached
	}
	val := IfaceZoneValue{
		ZoneID:       zoneID,
		Flags:        flags,
		RGID:         rgID,
		RoutingTable: routingTable,
		ScreenFlags:  screenFlags,
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// SetVlanIfaceInfo maps a VLAN sub-interface ifindex to its parent info.
func (m *Manager) SetVlanIfaceInfo(subIfindex int, parentIfindex int, vlanID uint16) error {
	zm, present, st := m.lookupMapLocked("vlan_iface_map")
	if st == registryFresh {
		return fmt.Errorf("%w: vlan_iface_map", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("vlan_iface_map not found")
	}
	val := VlanIfaceInfo{ParentIfindex: uint32(parentIfindex), VlanID: vlanID}
	return zm.Update(uint32(subIfindex), val, ebpf.UpdateAny)
}

// ClearIfaceZoneMap deletes all iface_zone_map entries.
func (m *Manager) ClearIfaceZoneMap() error {
	zm, present, st := m.lookupMapLocked("iface_zone_map")
	if st == registryFresh {
		return fmt.Errorf("%w: iface_zone_map", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("iface_zone_map not found")
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	var keys []IfaceZoneKey
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// clearNativeXDPFlags removes IfaceFlagNativeXDP from all iface_zone_map
// entries.  Called when falling back from native to generic XDP mode.
func (m *Manager) clearNativeXDPFlags() {
	zm, present, _ := m.lookupMapLocked("iface_zone_map")
	if !present {
		return
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if val.Flags&IfaceFlagNativeXDP != 0 {
			val.Flags &^= IfaceFlagNativeXDP
			zm.Update(key, val, ebpf.UpdateAny)
		}
	}
}

// clearNativeXDPFlagsForIfindexes removes IfaceFlagNativeXDP from iface_zone_map
// entries that belong to the specified physical interfaces.
func (m *Manager) clearNativeXDPFlagsForIfindexes(ifindexes []int) {
	zm, present, _ := m.lookupMapLocked("iface_zone_map")
	if !present || len(ifindexes) == 0 {
		return
	}
	targets := make(map[uint32]struct{}, len(ifindexes))
	for _, ifindex := range ifindexes {
		if ifindex > 0 {
			targets[uint32(ifindex)] = struct{}{}
		}
	}
	if len(targets) == 0 {
		return
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if _, ok := targets[key.Ifindex]; !ok {
			continue
		}
		if val.Flags&IfaceFlagNativeXDP != 0 {
			val.Flags &^= IfaceFlagNativeXDP
			zm.Update(key, val, ebpf.UpdateAny)
		}
	}
}

// ClearVlanIfaceMap deletes all vlan_iface_map entries.
func (m *Manager) ClearVlanIfaceMap() error {
	zm, present, st := m.lookupMapLocked("vlan_iface_map")
	if st == registryFresh {
		return fmt.Errorf("%w: vlan_iface_map", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("vlan_iface_map not found")
	}
	var key uint32
	var vval VlanIfaceInfo
	iter := zm.Iterate()
	var keys []uint32
	for iter.Next(&key, &vval) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// AddTxPort adds an interface to the devmap for XDP_REDIRECT.
//
// tx_ports is a DEVMAP sized MaxInterfaces; kernel ifindex is used as
// the dense key. If ifindex >= MaxInterfaces the bpf_map_update_elem
// would return E2BIG, which bubbles up as "key too big for map" and
// aborts dataplane compile before ever_ok flips. Guard at the call
// site so the error names the interface rather than needing journalctl
// archaeology. See issue #814.
func (m *Manager) AddTxPort(ifindex int) error {
	if ifindex < 0 || uint32(ifindex) >= MaxInterfaces {
		return fmt.Errorf(
			"AddTxPort: ifindex %d exceeds tx_ports cap %d (raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
			ifindex, MaxInterfaces,
		)
	}
	tm, present, st := m.lookupMapLocked("tx_ports")
	if st == registryFresh {
		return fmt.Errorf("%w: tx_ports", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("tx_ports not found")
	}
	val := struct {
		Ifindex uint32
		ProgFD  uint32
	}{Ifindex: uint32(ifindex)}
	if err := tm.Update(uint32(ifindex), val, ebpf.UpdateAny); err != nil {
		return err
	}
	m.seedInterfaceCounter(ifindex)
	return nil
}

// linkLister is the netlink enumeration surface used by
// preflightCheckIfindexCaps. Exposed as a package variable so tests
// can inject a fake without spinning up a netns.
var linkLister = netlink.LinkList

// ifindexSet builds a lookup set from a slice of interface indexes. It
// returns nil for an empty input so preflightCheckIfindexCaps can cheaply
// short-circuit a config that references no interfaces.
func ifindexSet(ifindexes []int) map[int]bool {
	if len(ifindexes) == 0 {
		return nil
	}
	s := make(map[int]bool, len(ifindexes))
	for _, idx := range ifindexes {
		s[idx] = true
	}
	return s
}

// preflightCheckIfindexCaps scans kernel links and returns a descriptive
// error if an interface XPF actually references (attaches AF_XDP to /
// inserts into a dense per-interface dataplane map) has an ifindex outside
// [0, MaxInterfaces). Callers pass `referenced` — the compiled port set
// (result.pendingXDP) — so the check is SCOPED to XPF's own interfaces.
//
// #5836: an UNRELATED host link (a bridge, veth, container link, or an
// abandoned operator netdev) with a high ifindex must NOT fail the compile.
// Only a link whose ifindex would key a dense dataplane map can overflow it,
// so only those links are candidates for rejection. Long-lived namespaces
// reach ifindex >= 65536 through interface churn even when XPF's managed
// ports stay low; the previous whole-namespace enumeration rejected every
// subsequent compile in that state.
//
// This remains a best-effort early-warning gate; the call-site cap checks in
// AddTxPort (tx_ports DEVMAP) and userspace/maps_sync.go (userspace_bindings
// ARRAY, idx = ifindex*BindingQueuesPerIface + queue) are the real
// fail-closed guardrails. Both layers exist because interfaces can appear via
// netlink events at any time (HA reconcile, link hotplug), not only at
// compile. Called after CompileConfig so `referenced` reflects the exact set
// of interfaces the compile resolved.
func (m *Manager) preflightCheckIfindexCaps(referenced map[int]bool) error {
	if len(referenced) == 0 {
		// No XPF-referenced interfaces resolved (e.g. empty config): nothing
		// can overflow a per-interface map, so there is nothing to pre-check.
		return nil
	}
	links, err := linkLister()
	if err != nil {
		// Non-fatal: a transient netlink error on preflight should not
		// abort compile. The call-site checks will still fire if any
		// offending interface is actually touched.
		slog.Warn("preflightCheckIfindexCaps: netlink.LinkList failed, skipping preflight", "err", err)
		return nil
	}
	for _, l := range links {
		attrs := l.Attrs()
		if attrs == nil {
			continue
		}
		if !referenced[attrs.Index] {
			// Not an interface XPF attaches/maps — an unrelated bridge, veth,
			// container link, or operator netdev with a high ifindex must not
			// fail the compile (#5836).
			continue
		}
		if attrs.Index < 0 || uint32(attrs.Index) >= MaxInterfaces {
			return fmt.Errorf(
				"preflightCheckIfindexCaps: interface %q ifindex %d exceeds MAX_INTERFACES cap %d (raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
				attrs.Name, attrs.Index, MaxInterfaces,
			)
		}
	}
	return nil
}

// AttachTC attaches the TC main program to the egress path of the given interface.
// On restart, reuses a previously pinned link and atomically replaces the program.
func (m *Manager) AttachTC(ifindex int) error {
	if !m.loaded.Load() {
		return fmt.Errorf("eBPF programs not loaded")
	}

	prog, present, _ := m.lookupProgramLocked("tc_main_prog")
	if !present {
		return fmt.Errorf("tc_main_prog not found")
	}

	if _, exists := m.tcLinkFor(ifindex); exists {
		return fmt.Errorf("TC already attached to ifindex %d", ifindex)
	}

	// Try to load a previously pinned link and update it atomically.
	pinFile := filepath.Join(linkPinPath, fmt.Sprintf("tc_%d", ifindex))
	if existing, err := link.LoadPinnedLink(pinFile, nil); err == nil {
		if err := existing.Update(prog); err == nil {
			m.setTCLink(ifindex, existing)
			slog.Info("updated pinned TC link", "ifindex", ifindex)
			return nil
		}
		existing.Close()
		os.Remove(pinFile)
	}

	// Fresh attachment (first boot or pin was removed/incompatible).
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
		Interface: ifindex,
	})
	if err != nil {
		return fmt.Errorf("attach TC to ifindex %d: %w", ifindex, err)
	}

	// Pin the link for future restarts.
	if err := os.MkdirAll(linkPinPath, 0700); err != nil {
		slog.Warn("failed to create link pin dir", "err", err)
	} else if err := l.Pin(pinFile); err != nil {
		slog.Warn("failed to pin TC link", "ifindex", ifindex, "err", err)
	}

	m.setTCLink(ifindex, l)
	slog.Info("attached TC egress program", "ifindex", ifindex)
	return nil
}

// DetachTC detaches the TC program from the given interface and
// removes its pin file.
func (m *Manager) DetachTC(ifindex int) error {
	l, exists := m.tcLinkFor(ifindex)
	if !exists {
		return nil
	}
	l.Unpin()
	if err := l.Close(); err != nil {
		return fmt.Errorf("detach TC from ifindex %d: %w", ifindex, err)
	}
	m.deleteTCLink(ifindex)
	slog.Info("detached TC egress program", "ifindex", ifindex)
	return nil
}

// GetPersistentNAT returns the persistent NAT table.
func (m *Manager) GetPersistentNAT() *PersistentNATTable {
	return m.PersistentNAT
}

// Map returns a named eBPF map, or nil if not found. #2114 A3 class 4:
// the handle copy happens inside the scoped registry lookup; nil covers
// the fresh and absent outcomes exactly as master.
func (m *Manager) Map(name string) *ebpf.Map {
	h, _, _ := m.lookupMapLocked(name)
	return h
}

// Program returns a named eBPF program, or nil if not found (#2114 A3
// class 4 — see Map).
func (m *Manager) Program(name string) *ebpf.Program {
	p, _, _ := m.lookupProgramLocked(name)
	return p
}

// NewEventSource creates an EventSource that reads from the eBPF events ring buffer.
func (m *Manager) NewEventSource() (EventSource, error) {
	// #2114 A3 class 4 with an error signature: the fresh state returns
	// the typed gate error; an armed/retained miss keeps master's text.
	evMap, _, st := m.lookupMapLocked("events")
	if st == registryFresh {
		return nil, fmt.Errorf("%w: events", ErrDataplaneNotArmed)
	}
	if evMap == nil {
		return nil, fmt.Errorf("events map not loaded")
	}
	rd, err := ringbuf.NewReader(evMap)
	if err != nil {
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}
	return &ebpfEventSource{reader: rd}, nil
}

// ebpfEventSource reads events from a cilium/ebpf ring buffer.
type ebpfEventSource struct {
	reader *ringbuf.Reader
}

func (s *ebpfEventSource) ReadEvent() ([]byte, error) {
	rec, err := s.reader.Read()
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

func (s *ebpfEventSource) Close() error {
	return s.reader.Close()
}

// LastCompileResult returns the result from the most recent Compile call.
func (m *Manager) LastCompileResult() *CompileResult {
	return m.lastCompile
}

// Close releases Go handles for eBPF resources but leaves pinned maps
// and links in the kernel for the next daemon to reuse. This enables
// hitless restarts — sessions survive and XDP/TC programs keep running.
func (m *Manager) Close() error {
	// #2114 A3: publish the unarmed transition at ENTRY so the
	// loaded-check set (AttachXDP/AttachTC/CompileConfig) stops admitting
	// new work BEFORE the link handles close, and the externally visible
	// IsLoaded() surface (REST/gRPC DataplaneLoaded) flips at the start
	// of the close window rather than its end. The registry is
	// deliberately NOT cleared: hitless restart keeps the pinned-map
	// handles live (the retained-unarmed state), so ordinary methods
	// still classify retained and proceed.
	m.loaded.Store(false)
	if closeWindowHook != nil {
		closeWindowHook()
	}
	// #6740: snapshot both maps under m.mu, then Close() the handles with the
	// lock released — l.Close() is a syscall and must not run under the lock
	// the 1 Hz status path needs. Close deliberately does NOT clear the
	// membership maps (see Teardown), so a snapshot is the whole interaction.
	for ifindex, l := range m.XDPLinks() {
		if err := l.Close(); err != nil {
			slog.Error("failed to close XDP link handle", "ifindex", ifindex, "err", err)
		}
	}
	for ifindex, l := range m.TCLinks() {
		if err := l.Close(); err != nil {
			slog.Error("failed to close TC link handle", "ifindex", ifindex, "err", err)
		}
	}
	return nil
}

// Teardown performs a full teardown: closes handles then removes all
// pinned BPF state. Use when switching dataplanes or decommissioning.
//
// #2114 (Codex PR #6743 r3-1): once Close has closed the Go link handles
// and Cleanup has unpinned+destroyed the kernel links, the xdpLinks /
// tcLinks membership entries point at dead handles for links that no
// longer exist. Clear them so a same-process re-Start (the
// commit-confirmed rollback → bootstrap-exit re-arm) actually
// re-attaches: AttachXDP's membership short-circuit would otherwise
// return "already attached" for a link Cleanup destroyed, and
// attachUserspaceShimXDP deliberately swallows that exact error — the
// corrected commit would report success with no AF_XDP ingress. Close
// alone deliberately does NOT clear: its pinned links stay live in the
// kernel for hitless-restart reuse, so the membership stays truthful
// there. The link maps are lifecycle-serialized (Start/Close/Teardown
// run under the daemon's applySem), matching DetachXDP's delete.
func (m *Manager) Teardown() error {
	m.Close()
	err := teardownCleanupFn()
	// #6741: Cleanup has just destroyed the pinned kernel objects, so every
	// handle still in m.maps / m.programs now refers to an obsolete forwarding
	// generation. Record the boundary so a lookup that serves one is refused
	// and counted.
	//
	// The registry is deliberately NOT cleared, and #7755 CLOSES the orphaned
	// FDs without clearing it. Why closing is not clearing, why the original
	// justification for not clearing was hollowed out by the change that cited
	// it, and why publishing the boundary BEFORE the snapshot is what closes the
	// window (order, not atomicity -- takeRegistryHandles takes its own hold):
	// see "Teardown closes the orphaned FDs" in README.md.
	m.mu.Lock()
	m.registryObsoleteFrom = m.registryGeneration
	m.obsoleteEpochLogged = false
	m.mu.Unlock()
	staleMaps, stalePrograms := m.takeRegistryHandles()

	// #6740: these Close() calls are syscalls and run with m.mu RELEASED, using
	// the same snapshot-then-close idiom Close() uses for the link handles.
	for _, h := range staleMaps {
		if err := h.Close(); err != nil {
			slog.Warn("teardown: closing orphaned shim map handle", "err", err)
		}
	}
	for _, p := range stalePrograms {
		if err := p.Close(); err != nil {
			slog.Warn("teardown: closing orphaned shim program handle", "err", err)
		}
	}
	// #6740: scoped section around the clears. teardownCleanupFn's unpin/remove
	// sweep runs BEFORE it, never under the lock.
	m.mu.Lock()
	clear(m.xdpLinks)
	clear(m.tcLinks)
	clear(m.vlanSubInterfaces)
	m.mu.Unlock()
	return err
}

// teardownCleanupFn is Teardown's pinned-state sweep (#2114 test seam:
// the unit test drives the REAL Teardown with the filesystem sweep
// neutralized — Cleanup unpins and removes the production
// /sys/fs/bpf/xpf tree). Production leaves it pointing at Cleanup.
var teardownCleanupFn = Cleanup

// Cleanup removes all pinned BPF maps and links. This fully tears down
// the dataplane — use when decommissioning, not during normal restarts.
func Cleanup() error {
	// Unpin and close any pinned links first.
	if entries, err := os.ReadDir(linkPinPath); err == nil {
		for _, e := range entries {
			pinFile := filepath.Join(linkPinPath, e.Name())
			if l, err := link.LoadPinnedLink(pinFile, nil); err == nil {
				l.Unpin()
				l.Close()
			} else {
				// If we can't load it, just remove the file.
				os.Remove(pinFile)
			}
		}
	}
	// Remove the entire pin directory tree.
	if err := os.RemoveAll(bpfPinPath); err != nil {
		return fmt.Errorf("remove %s: %w", bpfPinPath, err)
	}
	slog.Info("removed all pinned BPF state", "path", bpfPinPath)
	return nil
}
