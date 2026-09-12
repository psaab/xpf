package dataplane

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/netname"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
)

// runEthtool runs `ethtool <args...>` bounded by a 15s timeout. Every
// caller in this file executes during dp.ApplyConfig under the daemon's
// applySem, so an unbounded ethtool wedged in NIC driver/firmware ioctls
// (offload toggles, ring resizes, RSS key writes on mlx5) would hang every
// commit and HA config sync (#1794/#1800 U3, AGY r2). WaitDelay caps the
// post-SIGKILL pipe-drain window.
// A package var (not a plain func) so the #5268 fail-closed activation gate can
// be unit-tested by substituting a fake ethtool without a real NIC.
var runEthtool = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ethtool", args...)
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// CompileResult holds the result of a config compilation for reference.
type CompileResult struct {
	ZoneIDs     map[string]uint16 // zone name -> zone ID
	ScreenIDs   map[string]uint16 // screen profile name -> profile ID (1-based)
	AddrIDs     map[string]uint32 // address name -> address ID
	AppIDs      map[string]uint32 // application name -> app ID
	PoolIDs     map[string]uint8  // NAT pool name -> pool ID (0-based)
	NextPoolID  uint8             // next available pool ID (after SNAT assignment)
	PolicyNames map[uint32]string // rule_id -> "from-zone/to-zone/policy-name" (or "global/policy-name")
	AppNames    map[uint16]string // app_id -> application name (for structured logging)
	PolicySets  int               // number of policy sets created
	FilterIDs   map[string]uint32 // "inet:name" or "inet6:name" -> filter_id
	FilterSpans map[string]FilterCounterSpan

	PolicyScheduleRuleSlots []PolicyScheduleRuleSlot

	Lo0FilterV4 uint32 // lo0 inet filter ID (0=none), set by compileFirewallFilters
	Lo0FilterV6 uint32 // lo0 inet6 filter ID (0=none), set by compileFirewallFilters

	// hostMutations records the CLASSES of live host state this compile
	// actually changed (#4960), so an abort after the Phase-2 mutation point can
	// tell the operator the host has moved. Keyed by action rather than counted,
	// so N reconciled interfaces produce one entry. Set only on a real change —
	// a converged re-apply records nothing. See compiler_hostmutation_4960.go.
	hostMutations map[string]bool

	nextAddrID   uint32            // next available address ID (after address book)
	implicitSets map[string]uint32 // cache of implicit set key -> set ID
	// NATCounterIDs maps a type-namespaced NAT rule key (NATCounterKey →
	// "natType/rulesetName/ruleName") to its per-rule translation hit counter
	// ID. The ID is DERIVED from the key by a stable hash (assignNATCounterID),
	// not a sequential position counter, so a rule keeps the same ID across a
	// config reorder/removal — the cumulative helper counter store stays
	// correctly attributed by construction (#2255). A rare distinct-key hash
	// collision is resolved by finalizeNATCounterIDs in a stable sorted order
	// after all NAT phases, so the assignment is independent of compile order
	// even on a collision (#5099). 0 = no counter.
	NATCounterIDs map[string]uint32

	// pendingXDP/TC collect interface indexes for deferred program attachment.
	// Attachment happens AFTER all compilation phases so that link.Update()
	// atomically switches to programs with fully-populated maps.
	pendingXDP          []int
	pendingTC           []int
	tunnelIfindexes     map[int]bool // tunnel interfaces: XDP ingress only, no redirect
	genericXDPIfindexes map[int]bool // interfaces that must use generic XDP only

	// unarmedSurfaces records attach points the CONFIG required but the
	// compiler DECLINED to arm while still returning success (#5275) — the
	// three soft skips in compiler_iface.go (interface not found, VLAN child
	// create failed, administratively disabled). They are absent from
	// pendingXDP, so without this record the observe-only arm-coverage proof
	// (armproof.go) cannot tell a declined surface from one armed
	// successfully. Appended lazily; nil is a valid empty state.
	unarmedSurfaces []UnarmedSurface
	// unappliedFilterBindings records firewall-filter bindings the config
	// declared but the compiler could not assign (#6893). The CAUSE of such a
	// miss is already an unarmedSurfaces entry; this is its consequence.
	unappliedFilterBindings []UnappliedFilterBinding

	// ManagedInterfaces describes all interfaces managed by the firewall,
	// used by the networkd manager to generate .link and .network files.
	ManagedInterfaces []networkd.InterfaceConfig

	// ifCache avoids redundant net.InterfaceByName and netlink.LinkByName
	// syscalls across compile phases. Lazily populated on first access.
	ifCache    map[string]*net.Interface
	linkCache  map[string]netlink.Link // by name
	linkIdxMap map[int]netlink.Link    // by ifindex

	// rxVlanOffCache caches per-interface rxvlan state to avoid redundant
	// ethtool -k subprocess calls. Key is interface name, value is true
	// when rxvlan is confirmed off.
	rxVlanOffCache map[string]bool
	// ethtoolApplied tracks which interfaces have already had speed/duplex
	// settings applied via ethtool -s, keyed by "iface:speed:duplex".
	ethtoolApplied map[string]bool
}

// PolicyScheduleRuleSlot records the exact compiled policy_rules map slot for a
// scheduled policy. A single policy can compile into multiple dense app-term
// slots; runtime scheduler updates must toggle those compiled slots rather than
// recomputing indexes from the original config policy position.
type PolicyScheduleRuleSlot struct {
	PolicySetID   uint32
	RuleIndex     uint32
	RuleID        uint32
	PolicyName    string
	SchedulerName string
}

// cachedInterfaceByName returns a cached *net.Interface, performing the
// syscall only on the first lookup for each name.
func (r *CompileResult) cachedInterfaceByName(name string) (*net.Interface, error) {
	if iface, ok := r.ifCache[name]; ok {
		return iface, nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	r.ifCache[name] = iface
	return iface, nil
}

// cachedLinkByName returns a cached netlink.Link, performing the
// RTM_GETLINK syscall only on the first lookup for each name.
func (r *CompileResult) cachedLinkByName(name string) (netlink.Link, error) {
	if link, ok := r.linkCache[name]; ok {
		return link, nil
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	r.linkCache[name] = link
	r.linkIdxMap[link.Attrs().Index] = link
	return link, nil
}

// cachedLinkByIndex returns a cached netlink.Link, performing the
// RTM_GETLINK syscall only on the first lookup for each index.
func (r *CompileResult) cachedLinkByIndex(idx int) (netlink.Link, error) {
	if link, ok := r.linkIdxMap[idx]; ok {
		return link, nil
	}
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return nil, err
	}
	r.linkIdxMap[idx] = link
	if name := link.Attrs().Name; name != "" {
		r.linkCache[name] = link
	}
	return link, nil
}

// skipGenericAttachForVLANChild reports whether the generic-attach loop should
// SKIP ifidx entirely because the VLAN parent it delegates to already fell back
// to generic XDP. Attaching generic XDP to the child as well can raise EEXIST on
// the parent, since the parent's generic hook already sees the tagged frames
// (netif_receive_generic_xdp runs before kernel VLAN demuxing in
// __netif_receive_skb_core).
//
// #6917: the parent is read from LinkAttrs.ParentIndex, which is only a VLAN
// delegation once the KIND and the NAMESPACE are proven — see
// vlanDelegationDefect. vishvananda/netlink folds IFLA_LINK into that field for
// every link kind, so on an unproven device it can be a veth's peer or an
// ifindex belonging to another namespace, free to alias a local interface
// numerically. Read blind, an aliased value that happens to name a locally
// failed interface returns true here and the interface gets NO XDP attach at
// all: a live forwarding surface with no program on it.
//
// So an unproven device NEVER skips. Falling through to the generic attach is
// the direction that cannot hide a surface, and the WARN names why.
//
// SECOND BELT, and labelled as one. The only production writer of
// genericXDPIfindexes is the VLAN-child append in compiler_iface.go, whose
// ifindex now comes from an adoption that refuses a wrong-kind or foreign
// device (#6916) — so this is not independently reachable in first-order
// production and is not claimed to be. What it covers is the distance between
// check and use: the adoption runs in compile phase 2 through
// netlink.LinkByName, this runs in the attach loop after program load through
// cachedLinkByIndex, and the cache holds this child only when a unit MTU
// happened to be configured. The two are not guaranteed to be looking at the
// same device.
func (r *CompileResult) skipGenericAttachForVLANChild(ifidx int, failedNativeXDP map[int]bool) bool {
	link, err := r.cachedLinkByIndex(ifidx)
	if err != nil {
		return false
	}
	if why := vlanDelegationDefect(link); why != "" {
		slog.Warn("VLAN child is not a local 802.1Q delegation; not skipping its "+
			"XDP attach on an unverifiable parent", "ifindex", ifidx, "why", why)
		return false
	}
	parentIfindex := link.Attrs().ParentIndex
	return parentIfindex > 0 && failedNativeXDP[parentIfindex]
}

// peekLinkByIndex resolves idx WITHOUT writing to the result's link caches.
//
// cachedLinkByIndex memoises into linkIdxMap and linkCache. The observe-only
// arm-coverage proof (armproof.go) must not mutate the CompileResult it is
// proving: a diagnostic that writes into the object it observes cannot honestly
// call itself observe-only, and a CompileResult reachable by another goroutine
// would take a concurrent map write for a measurement nobody asked to persist.
func (r *CompileResult) peekLinkByIndex(idx int) (netlink.Link, error) {
	if r == nil {
		return nil, fmt.Errorf("nil compile result")
	}
	if link, ok := r.linkIdxMap[idx]; ok {
		return link, nil
	}
	return netlink.LinkByIndex(idx)
}

// recordUnarmedSurface notes an attach point the compiler declined to arm while
// still returning success (#5275). See UnarmedSurface.
//
// One record per surface. mapZoneInterface runs once per ZONE REFERENCE, and
// the per-phys dedup (st.attached) sits far below the soft skips, so an
// interface named by two zones reaches the skip twice — and the count is the
// deliverable of this phase, so a double count is a wrong number rather than a
// cosmetic wart. A repeat sighting never downgrades the classification: if
// either one could not prove the netdev down, the surface keeps the
// conservative reading.
// recordUnappliedFilterBinding records a filter binding the compiler could not
// assign (#6893). Deduped on (Interface, Reason) so one unresolvable interface
// with several units does not fan out into near-identical rows.
func (r *CompileResult) recordUnappliedFilterBinding(b UnappliedFilterBinding) {
	if r == nil || len(b.Filters) == 0 {
		return
	}
	for i := range r.unappliedFilterBindings {
		if r.unappliedFilterBindings[i].Interface != b.Interface ||
			r.unappliedFilterBindings[i].Reason != b.Reason {
			continue
		}
		r.unappliedFilterBindings[i].Filters = append(r.unappliedFilterBindings[i].Filters, b.Filters...)
		return
	}
	r.unappliedFilterBindings = append(r.unappliedFilterBindings, b)
}

// UnappliedFilterBindings reports the filter bindings this compile declined to
// assign (#6893). See UnappliedFilterBinding for what a non-empty slice means.
func (r *CompileResult) UnappliedFilterBindings() []UnappliedFilterBinding {
	if r == nil {
		return nil
	}
	return r.unappliedFilterBindings
}

func (r *CompileResult) recordUnarmedSurface(u UnarmedSurface) {
	if r == nil {
		return
	}
	for i := range r.unarmedSurfaces {
		if r.unarmedSurfaces[i].Name != u.Name || r.unarmedSurfaces[i].Ifindex != u.Ifindex {
			continue
		}
		if u.StillForwarding && !r.unarmedSurfaces[i].StillForwarding {
			r.unarmedSurfaces[i] = u
		}
		return
	}
	r.unarmedSurfaces = append(r.unarmedSurfaces, u)
}

// assignZoneIDs populates result.ZoneIDs with a STABLE, name-derived id for
// every configured security zone (#3075). The id is config.StableZoneID(name)
// — a pure FNV-1a fold of the zone NAME into [1, ZoneIDReservedMin-1], never a
// function of the zone set or compile order — so adding, renaming, or removing
// a zone can never renumber another zone. This replaces the legacy sorted
// 1..N positional assignment, whose ids shifted whenever an earlier-sorting
// zone was added/removed and mis-mapped in-flight session/HA/status metadata
// carrying an old numeric id (#3075). Both HA nodes and a cold-booting node
// compute identical ids by construction with zero synced/persisted state, and
// pkg/daemon/daemon_ha_userspace.go:buildZoneIDs MUST stay byte-identical to
// this (enforced by an HA-symmetry test).
func assignZoneIDs(result *CompileResult, cfg *config.Config) {
	for name := range cfg.Security.Zones {
		result.ZoneIDs[name] = config.StableZoneID(name)
	}
}

// assignScreenIDs populates result.ScreenIDs with 1-based ids for every
// configured screen profile, in sorted-name order so the assignment is
// deterministic. Id 0 is reserved for "no profile", which is why the counter
// starts at 1.
//
// This is a single site DELIBERATELY. Three verbatim copies of this loop used
// to exist — here, in validateBeforeMutateWithResult, and in the ID-stability
// probe's own driver (compiler_idprobe_4960_test.go) — and the third copy is
// what made TestPrePassDoesNotPerturbIDAssignment_4960's ScreenIDs column
// unable to observe a CROSS-PASS drift: the probe re-implemented the
// assignment instead of calling it, so that column compared the test's own
// loop against itself. Measured at the time: seeding this assignment from a
// package-level counter, at EITHER production site, left the whole package
// green. Keep every caller on this function; a fourth copy re-opens the hole.
//
// Note the limit of what that column can bind, which is narrower than "the ids
// are right" — see compileIDsOnce's doc. The probe compares two passes, so a
// change applied identically to both (a different seed, a different sort key)
// leaves pass 1 == pass 2 and stays green by construction. What it detects is
// state outliving a CompileResult. Correctness of the assignment itself is not
// measured here.
func assignScreenIDs(result *CompileResult, cfg *config.Config) {
	screenID := uint16(1)
	screenNames := make([]string, 0, len(cfg.Security.Screen))
	for name := range cfg.Security.Screen {
		screenNames = append(screenNames, name)
	}
	sort.Strings(screenNames)
	for _, name := range screenNames {
		result.ScreenIDs[name] = screenID
		screenID++
	}
}

// CompileConfig translates a typed Config into dataplane table entries.
// It works with any DataPlane backend (eBPF or DPDK) via the interface.
// The isRecompile flag triggers FIB generation bump for hitless restarts.
func CompileConfig(dp DataPlane, cfg *config.Config, isRecompile bool) (*CompileResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if !dp.IsLoaded() {
		return nil, fmt.Errorf("dataplane not loaded")
	}

	result := newValidationResult()

	// Phase 1: Assign STABLE zone IDs (#3075).
	assignZoneIDs(result, cfg)

	// Phase 1.5: Assign screen profile IDs (1-based; 0 = no profile).
	assignScreenIDs(result, cfg)

	// #4960: validate every fallible HOST-PURE phase against a discarding
	// dataplane BEFORE Phase 2 touches the host. compileZones below is the
	// first and only destructive netlink mutation in this function -- VLAN
	// create/link-up and address delete/add, AND netlink.LinkDel /
	// LinkSetDown on unmanaged interfaces via stripUnmanagedInterfaces
	// (compiler_iface.go, stripUnmanagedInterfaces' netlink.LinkDel / LinkSetDown), plus ethtool and /proc/sys writes
	// (#6894 r1 F5: the earlier parenthetical understated this) -- and
	// nothing after it has an undo path, so a config that trips a later phase must be rejected here rather
	// than half-applied. See compiler_validate_4960.go for what is and is not
	// covered, and why this is additive rather than a reordering.
	if err := validateBeforeMutate(cfg); err != nil {
		return nil, err
	}

	// Phase 2: Compile zones — FIRST HOST MUTATION. Everything above this line
	// must be non-destructive.
	if err := compileZones(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile zones: %w", err)
	}

	// Phase 3: Compile address book
	if err := compileAddressBook(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile address book: %w", err)
	}

	// Phase 4: Compile applications
	if err := compileApplications(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile applications: %w", err)
	}

	// Phase 5: Compile policies
	if err := compilePolicies(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}

	// Phase 6: Compile NAT
	if err := compileNAT(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile nat: %w", err)
	}

	// Phase 6.5: Compile static NAT
	if err := compileStaticNAT(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile static nat: %w", err)
	}

	// SNAT, DNAT, and static NAT have now recorded every per-rule counter key.
	// Re-derive the authoritative counter IDs in a stable order so a distinct-
	// key hash collision resolves the same way regardless of the order the rules
	// compiled in — the streaming assignment alone is compile-order dependent
	// on a collision (#5099).
	finalizeNATCounterIDs(result)

	// Phase 6.6: Compile NAT64 prefixes
	if err := compileNAT64(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile nat64: %w", err)
	}

	// Phase 6.7: Compile NPTv6 (RFC 6296) prefix translation rules
	if err := compileNPTv6(dp, cfg); err != nil {
		return nil, fmt.Errorf("compile nptv6: %w", err)
	}

	// Phase 7: Compile screen profiles
	if err := compileScreenProfiles(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile screen profiles: %w", err)
	}

	// Phase 8: Compile default policy
	if err := compileDefaultPolicy(dp, cfg); err != nil {
		return nil, fmt.Errorf("compile default policy: %w", err)
	}

	// Phase 9: Compile flow timeouts
	if err := compileFlowTimeouts(dp, cfg); err != nil {
		return nil, fmt.Errorf("compile flow timeouts: %w", err)
	}

	// Phase 10: Compile firewall filters (before flow config so lo0 IDs are available)
	if err := compileFirewallFilters(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile firewall filters: %w", err)
	}

	// Phase 10b: Compile flow config (TCP MSS clamp, lo0 filter IDs, etc.)
	if err := compileFlowConfig(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile flow config: %w", err)
	}

	// Phase 11: Compile port mirroring
	if err := compilePortMirroring(dp, cfg, result); err != nil {
		return nil, fmt.Errorf("compile port mirroring: %w", err)
	}

	// Bump FIB generation counter on recompile so sessions re-run
	// bpf_fib_lookup with potentially changed interface indices or MAC
	// addresses. BPF checks session.fib_gen != fib_gen_map[0] and
	// treats cached entries as stale — no session write-back needed.
	//
	// #7149 (split from #4960): this was a bare `dp.BumpFIBGeneration()`,
	// dropping both results. On the live userspace path it is the only
	// compiler dataplane call that is NOT a shim no-op, so it is the only one
	// that can really fail, and a failure silently leaves the snapshot the
	// helper is about to receive on the previous generation. See
	// compiler_fibgen.go for why the error is reported rather than returned.
	if isRecompile {
		bumpFIBGenerationAfterRecompile(dp)
	}

	slog.Info("config compiled to dataplane",
		"zones", len(result.ZoneIDs),
		"addresses", len(result.AddrIDs),
		"applications", len(result.AppIDs),
		"policy_sets", result.PolicySets)

	return result, nil
}

// Compile translates a typed Config into eBPF map entries and attaches programs.
func (m *Manager) Compile(cfg *config.Config) (*CompileResult, error) {
	result, err := CompileConfig(m, cfg, m.lastCompile != nil)
	if err != nil {
		return nil, err
	}

	// Scoped early-warning gate (#5836): if an interface XPF actually
	// references (result.pendingXDP) exceeds MaxInterfaces, fail with a
	// named-interface error. Scoping to the compiled port set means an
	// unrelated high-ifindex host link no longer aborts every compile. See
	// issue #814 — the call-site cap checks in loader.go's AddTxPort and
	// userspace/maps_sync.go remain the real fail-closed guardrails since
	// interfaces can appear via netlink at any time; this preflight just
	// makes the first-compile failure legible.
	if err := m.preflightCheckIfindexCaps(ifindexSet(result.pendingXDP)); err != nil {
		return nil, err
	}

	// eBPF-specific: attach XDP/TC programs AFTER all maps are populated.
	// link.Update() atomically switches to programs with complete config.
	for _, ifidx := range result.pendingTC {
		// Skip TC egress for tunnel interfaces — kernel forwards the
		// inner packet to the tunnel device before encapsulation, and
		// TC egress would see it with ingress_ifindex != 0 and drop it.
		if result.tunnelIfindexes[ifidx] {
			m.DetachTC(ifidx)
			slog.Info("skipping TC for tunnel interface", "ifindex", ifidx)
			continue
		}
		if err := m.AttachTC(ifidx); err != nil {
			if !strings.Contains(err.Error(), "already attached") {
				return nil, fmt.Errorf("attach TC to ifindex %d: %w", ifidx, err)
			}
		}
	}

	if len(result.pendingXDP) > 0 {
		// #2114 A3: OPTIONAL access — an absent redirect_capable SKIPS the
		// redirect-map population and CONTINUES into the attachment work
		// (master's exact outcome; this path is CompileConfig-gated to the
		// armed state upstream).
		rcMap, _, _ := m.lookupMapLocked("redirect_capable")

		// Populate redirect_capable BEFORE link.Update() swaps programs.
		// Skip tunnel interfaces — bpf_redirect_map sends Ethernet frames
		// but POINTOPOINT tunnels (GRE, ip6gre, XFRM) expect raw IP.
		// Those interfaces still get XDP for ingress decapsulated traffic.
		if rcMap != nil {
			for _, ifidx := range result.pendingXDP {
				if result.tunnelIfindexes[ifidx] {
					continue
				}
				// #6959 DELIBERATE DISCARD (allowlisted in
				// discarded_map_update_6959_test.go). redirect_capable is
				// a per-interface OPTIMISATION HINT, not policy: an unset
				// flag makes xdp_forward take XDP_PASS and hand the packet
				// to the kernel forwarding path instead of
				// bpf_redirect_map, which is slower but forwards
				// correctly. The default is unset, so a rejected write
				// fails SAFE. This is also the config-commit path, not an
				// operator clear — a hard error here aborts a commit over
				// a lost performance hint. The absent-map skip above is
				// the matching #2114 A3 optional-access contract.
				rcMap.Update(uint32(ifidx), uint8(1), ebpf.UpdateAny)
			}
		}

		// Try native XDP first on non-tunnel interfaces.
		// Tunnel interfaces (GRE, ip6gre, XFRM) lack native XDP support
		// and must always use generic mode. A native attach failure on one
		// interface should not force unrelated interfaces into generic mode.
		failedNativeXDP := make(map[int]bool)
		for _, ifidx := range result.pendingXDP {
			if result.tunnelIfindexes[ifidx] || result.genericXDPIfindexes[ifidx] {
				continue // tunnels always get generic below
			}
			if err := m.AttachXDP(ifidx, false); err != nil {
				if strings.Contains(err.Error(), "already attached") {
					continue
				}
				// #864: raise to WARN so operators at default log level
				// see the demotion.  Generic XDP runs in skb-mode with
				// significantly higher CPU cost and a ~6 Gbps cap.
				slog.Warn("native XDP unavailable; falling back to generic (skb-mode)",
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
			// Clear IFACE_FLAG_NATIVE_XDP only for interfaces that actually
			// fell back to generic mode.
			m.clearNativeXDPFlagsForIfindexes(failed)
		}
		// Attach remaining interfaces: generic-only for tunnels,
		// VLAN child subinterfaces, or interfaces whose native attach failed.
		// Skip VLAN sub-interfaces when the userspace shim is active or when
		// their parent physical interface already fell back to generic mode.
		// In that case the parent's generic XDP sees VLAN-tagged frames before
		// kernel VLAN demuxing (netif_receive_generic_xdp runs first in
		// __netif_receive_skb_core), and attaching generic XDP to the child
		// can create a kernel-level conflict on the parent (EEXIST).
		// Also skip with the userspace XDP shim — XDP_PASS on generic mode
		// doesn't properly deliver NDP to kernel on VLAN devices.
		isUserspaceShim := m.UsingUserspaceXDPShimEntryProgram()
		for _, ifidx := range result.pendingXDP {
			forceGeneric := failedNativeXDP[ifidx] || result.tunnelIfindexes[ifidx] || result.genericXDPIfindexes[ifidx]
			if !forceGeneric {
				continue // already attached native above
			}
			if result.genericXDPIfindexes[ifidx] && !result.tunnelIfindexes[ifidx] {
				if isUserspaceShim {
					continue // skip VLAN sub-interfaces — parent handles VLAN traffic
				}
				if result.skipGenericAttachForVLANChild(ifidx, failedNativeXDP) {
					continue
				}
			}
			if err := m.AttachXDP(ifidx, true); err != nil {
				if !strings.Contains(err.Error(), "already attached") {
					return nil, fmt.Errorf("attach XDP generic to ifindex %d: %w", ifidx, err)
				}
			}
		}
	}

	// Record VLAN sub-interfaces so userspace-shim swaps can skip them.
	// The shim on VLAN sub-interfaces breaks NDP because generic XDP
	// + XDP_PASS doesn't deliver properly to kernel NDP on VLAN devices.
	m.markVLANSubInterfaces(result)
	m.lastCompile = result
	m.recordApplyResult(ApplyResultFromCompileResult(result))
	return result, nil
}

// resolveInterfaceRef parses an interface reference like "enp6s0" or "enp6s0.100"
// and returns the physical interface name, unit number, and VLAN ID from config.
// For RETH interfaces, configName stays as "reth0" (for config lookups) while
// physName resolves to the local physical member's Linux name.

func compileAddressBook(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Clear stale address book entries before repopulating.
	if err := dp.ClearAddressBookV4(); err != nil {
		return fmt.Errorf("clear address_book_v4: %w", err)
	}
	if err := dp.ClearAddressBookV6(); err != nil {
		return fmt.Errorf("clear address_book_v6: %w", err)
	}
	if err := dp.ClearAddressMembership(); err != nil {
		return fmt.Errorf("clear address_membership: %w", err)
	}

	ab := cfg.Security.AddressBook
	if ab == nil {
		result.nextAddrID = 1 // start from 1 for implicit entries
		return nil
	}

	// Assign address IDs (1-based; 0 = "any")
	addrID := uint32(1)

	// Process individual addresses (sorted for deterministic IDs across restarts)
	addrNames := make([]string, 0, len(ab.Addresses))
	for name := range ab.Addresses {
		addrNames = append(addrNames, name)
	}
	sort.Strings(addrNames)
	for _, name := range addrNames {
		addr := ab.Addresses[name]
		result.AddrIDs[name] = addrID

		cidr := addr.Value
		// Ensure CIDR notation
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr = cidr + "/128" // IPv6
			} else {
				cidr = cidr + "/32" // IPv4
			}
		}

		if err := dp.SetAddressBookEntry(cidr, addrID); err != nil {
			return fmt.Errorf("set address %s (%s): %w", name, cidr, err)
		}

		// Write self-membership: (addrID, addrID) -> 1
		if err := dp.SetAddressMembership(addrID, addrID); err != nil {
			return fmt.Errorf("set self-membership for %s: %w", name, err)
		}

		slog.Debug("address compiled", "name", name, "cidr", cidr, "id", addrID)
		addrID++
	}

	// Process address sets (sorted for deterministic IDs)
	setNames := make([]string, 0, len(ab.AddressSets))
	for name := range ab.AddressSets {
		setNames = append(setNames, name)
	}
	sort.Strings(setNames)
	for _, setName := range setNames {
		setID := addrID
		result.AddrIDs[setName] = setID
		addrID++

		// Recursively expand nested sets to flat address list
		allAddresses, err := config.ExpandAddressSet(setName, ab)
		if err != nil {
			return fmt.Errorf("address set %q: %w", setName, err)
		}

		// Write membership entries for each resolved address
		for _, memberName := range allAddresses {
			memberID, ok := result.AddrIDs[memberName]
			if !ok {
				return fmt.Errorf("address set %q: member %q not found",
					setName, memberName)
			}
			if err := dp.SetAddressMembership(memberID, setID); err != nil {
				return fmt.Errorf("set membership %s in %s: %w",
					memberName, setName, err)
			}
		}

		slog.Debug("address set compiled", "name", setName, "id", setID,
			"members", len(allAddresses))
	}

	result.nextAddrID = addrID
	return nil
}

func compileApplications(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenApps := make(map[AppKey]bool)
	result.AppNames = make(map[uint16]string)
	var rangeIdx uint32 // next free slot in app_ranges ARRAY

	userApps := cfg.Applications.Applications

	refNames, err := appid.CatalogNames(cfg, cfg.Services.ApplicationIdentification)
	if err != nil {
		return err
	}
	// #5296: assign a STABLE, name-derived app_id to every catalog name through
	// the shared config.AssignStableAppIDs SSOT — the SAME helper appid.Build
	// Catalog uses, so the two AppNames maps stay byte-identical (appid_catalog_
	// parity_test.go). This replaces the legacy sorted 1..N positional counter,
	// whose ids shifted on an ordinary catalog edit and mis-resolved a retained
	// session's frozen app_id. The #3438 H4 uint16-overflow fail-closed boundary
	// (a config needing more than 65535 ids aborts the apply so the daemon keeps
	// the previous-good snapshot) now lives inside AssignStableAppIDs.
	idByName, err := config.AssignStableAppIDs(refNames)
	if err != nil {
		return err
	}
	for _, appName := range refNames {
		appID := uint32(idByName[appName])

		app, found := config.ResolveApplication(appName, userApps)
		if !found {
			return fmt.Errorf("application %q not found", appName)
		}

		// #4887: honor ProtocolNumber's ok bit so an EXPLICIT but unrepresentable
		// protocol token (surviving a tolerant/HA-sync load) does not record a
		// stampable AppNames name. protocolNumber (still used for the retired eBPF
		// port writes and by compiler_nat.go) drops ok; read it here to gate the
		// AppNames row identically to appid.BuildCatalog and keep the two AppNames
		// maps byte-identical (appid_catalog_parity_test.go).
		proto, protoOK := appid.ProtocolNumber(app.Protocol)

		result.AppIDs[appName] = appID

		// Parse destination port range boundaries.
		dstLow, dstHigh, err := parsePortRange(app.DestinationPort)
		if err != nil {
			compileWarn(dp, "bad port for application",
				"name", appName, "port", app.DestinationPort, "err", err)
			continue
		}
		// #5194 A3-b1-F2: sanitize an EXPLICIT destination port so a literal
		// 0/0-0 (the (0,0) "no constraint" sentinel) does not record a
		// stampable AppNames row for an over-matching app. Mirrors
		// appid.BuildCatalog exactly to keep the two AppNames maps
		// byte-identical (appid_catalog_parity_test.go).
		dstOK := true
		if app.DestinationPort != "" {
			dstLow, dstHigh, dstOK = appid.NormalizeExplicitPortRange(dstLow, dstHigh)
		}

		// Parse source port range (stored in BPF app_value, not expanded)
		srcOK := true
		var srcLow, srcHigh uint16
		if app.SourcePort != "" {
			var srcErr error
			srcLow, srcHigh, srcErr = parsePortRange(app.SourcePort)
			if srcErr != nil {
				compileWarn(dp, "bad source-port for application",
					"name", appName, "port", app.SourcePort, "err", srcErr)
				srcOK = false
			} else {
				// #5194 A3-b1-F2: same sanitization for an explicit source port.
				srcLow, srcHigh, srcOK = appid.NormalizeExplicitPortRange(srcLow, srcHigh)
			}
		}

		// #3725 M04: record the app_id -> name mapping — the LIVE map the show
		// path (appid.ResolveSessionName) resolves a stamped app_id through —
		// ONLY for an EMITTABLE application. Recording it BEFORE the port parse
		// (the old placement) left AppNames holding a name at an id no session
		// can legitimately carry when the malformed app sorted last (no later
		// good app overwrote the id), so a skewed/stale app_id from a helper
		// catalog skew resolved to the malformed name instead of UNKNOWN.
		// "Emittable" mirrors appid.BuildCatalog exactly (non-inverted dst
		// range, parseable source-port, non-inverted src range) so the two
		// AppNames maps stay byte-identical (appid_catalog_parity_test.go). The
		// id is still consumed (loop-tail appID++) because BuildCatalog also
		// consumes it here; only the dest-port `continue` above skips the id.
		// #4887: an OMITTED protocol (empty spec) fans out to TCP+UDP below and
		// stays emittable even though ProtocolNumber("") reports ok=false; an
		// EXPLICIT but unrepresentable protocol records no AppNames name (gated
		// identically to appid.BuildCatalog for parity).
		protoEmittable := protoOK || strings.TrimSpace(app.Protocol) == ""
		if protoEmittable && srcOK && dstOK && dstLow <= dstHigh && srcLow <= srcHigh {
			result.AppNames[uint16(appID)] = appName
		}

		var appTimeout uint32
		if app.InactivityTimeout > 0 {
			appTimeout = uint32(app.InactivityTimeout)
		}

		algType := algTypeFromString(app.ALG)

		// When no protocol is specified, install entries for both TCP and UDP
		// (matching Junos behavior where omitted protocol means any L4). An
		// EXPLICIT protocol — including `protocol 0` (HOPOPT) — matches that
		// single protocol only. #4008: keying the fan-out on the resolved number
		// being 0 conflated an explicit `protocol 0` (and an unrepresentable
		// token) with the omitted case, fanning a single-protocol app out to
		// TCP+UDP → over-broad match. Key on the protocol being ABSENT instead.
		// This mirrors appid.BuildCatalog (the LIVE catalog shipped to the
		// helper); the SetApplication / SetAppRange writes below are the retired
		// eBPF path (#1476), so this parity keeps the documented invariant true.
		protos := []uint8{proto}
		if strings.TrimSpace(app.Protocol) == "" {
			protos = []uint8{6, 17} // TCP + UDP
		}

		// Large ranges (>256 ports) go into app_ranges ARRAY to avoid
		// expanding thousands of per-port HASH entries.
		rangeSize := int(dstHigh) - int(dstLow) + 1
		if rangeSize > 256 && rangeIdx < MaxAppRanges {
			for _, p := range protos {
				if rangeIdx >= MaxAppRanges {
					compileWarn(dp, "app_ranges full, falling back to HASH expansion",
						"name", appName)
					break
				}
				entry := AppRangeEntry{
					Protocol:    p,
					ALGType:     algType,
					PortLow:     dstLow,
					PortHigh:    dstHigh,
					SrcPortLow:  srcLow,
					SrcPortHigh: srcHigh,
					AppID:       appID,
					Timeout:     appTimeout,
				}
				if err := dp.SetAppRange(rangeIdx, entry); err != nil {
					return fmt.Errorf("set app range %s: %w", appName, err)
				}
				rangeIdx++
			}
		} else {
			// Small range or single port — expand into per-port HASH entries.
			for _, p := range protos {
				for port := dstLow; port <= dstHigh; port++ {
					if err := dp.SetApplication(p, port, appID, appTimeout, algType, srcLow, srcHigh); err != nil {
						return fmt.Errorf("set application %s port %d: %w",
							appName, port, err)
					}
					writtenApps[AppKey{Protocol: p, DstPort: htons(port)}] = true
					if port == 65535 {
						break // prevent uint16 overflow
					}
				}
			}
		}

		slog.Debug("application compiled", "name", appName, "id", appID,
			"proto", proto, "dstPort", app.DestinationPort, "srcPort", app.SourcePort, "timeout", appTimeout)
	}

	// Zero remaining app_ranges slots (sentinel for BPF iteration).
	zeroRange := AppRangeEntry{}
	for i := rangeIdx; i < MaxAppRanges; i++ {
		dp.SetAppRange(i, zeroRange)
	}

	// Delete stale application entries no longer referenced.
	dp.DeleteStaleApplications(writtenApps)

	return nil
}

// resolveAddrList resolves a list of address names to a single address ID.
// If the list has one entry, returns that entry's ID directly.
// If the list has multiple entries, creates an implicit address-set containing
// all referenced addresses and returns the set's ID.
func resolveAddrList(dp DataPlane, names []string, result *CompileResult) (uint32, error) {
	if len(names) == 0 {
		return 0, nil
	}

	// Filter out "any" entries
	var filtered []string
	for _, n := range names {
		if n != "any" {
			filtered = append(filtered, n)
		}
	}
	if len(filtered) == 0 {
		return 0, nil // all "any"
	}

	// Single address: return its ID directly
	if len(filtered) == 1 {
		id, ok := result.AddrIDs[filtered[0]]
		if !ok {
			return 0, fmt.Errorf("address %q not found", filtered[0])
		}
		return id, nil
	}

	// Multiple addresses: build implicit address-set
	sorted := make([]string, len(filtered))
	copy(sorted, filtered)
	sort.Strings(sorted)
	cacheKey := strings.Join(sorted, ",")

	if setID, ok := result.implicitSets[cacheKey]; ok {
		return setID, nil
	}

	setID := result.nextAddrID
	result.nextAddrID++

	for _, name := range sorted {
		memberID, ok := result.AddrIDs[name]
		if !ok {
			return 0, fmt.Errorf("address %q not found", name)
		}
		if err := dp.SetAddressMembership(memberID, setID); err != nil {
			return 0, fmt.Errorf("set implicit membership %s in set %d: %w", name, setID, err)
		}
	}

	result.implicitSets[cacheKey] = setID
	slog.Debug("implicit address-set created", "id", setID, "members", sorted)
	return setID, nil
}

func compilePolicies(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenPolicySets := make(map[ZonePairKey]bool)
	result.PolicyNames = make(map[uint32]string)
	// #3057: seed the reserved implicit default-policy sentinel so a
	// default-deny/reject RT_FLOW event (policy_id = DefaultPolicySentinelID,
	// emitted by the Rust dataplane when no configured policy matched) resolves
	// to "default-policy" instead of mis-attributing to the first configured
	// policy (real ID 0). Seeded unconditionally — the implicit default fires
	// even when zero policies are configured.
	result.PolicyNames[DefaultPolicySentinelID] = DefaultPolicyName

	policySetID := uint32(0)

	for _, zpp := range cfg.Security.Policies {
		fromZone, ok := result.ZoneIDs[zpp.FromZone]
		if !ok {
			return fmt.Errorf("policy from-zone %q not found", zpp.FromZone)
		}
		toZone, ok := result.ZoneIDs[zpp.ToZone]
		if !ok {
			return fmt.Errorf("policy to-zone %q not found", zpp.ToZone)
		}

		// Expand rules: each config rule with N applications becomes N BPF rules.
		// Collect expanded rules first to know the total count.
		type expandedRule struct {
			pol   *config.Policy
			appID uint32
		}
		var expanded []expandedRule

		for _, pol := range zpp.Policies {
			// Resolve application list, expanding application-sets
			var appIDs []uint32
			hasAny := false
			for _, appName := range pol.Match.Applications {
				if appName == "any" {
					hasAny = true
					break
				}
			}
			if hasAny || len(pol.Match.Applications) == 0 {
				appIDs = []uint32{0} // single rule with app_id=0 (any)
			} else {
				seen := make(map[uint32]bool)
				for _, appName := range pol.Match.Applications {
					// Expand application-sets
					if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
						expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
						if err != nil {
							return fmt.Errorf("policy %s expand app-set %q: %w", pol.Name, appName, err)
						}
						for _, a := range expanded {
							if id, ok := result.AppIDs[a]; ok && !seen[id] {
								seen[id] = true
								appIDs = append(appIDs, id)
							}
						}
					} else if id, ok := result.AppIDs[appName]; ok && !seen[id] {
						seen[id] = true
						appIDs = append(appIDs, id)
					}
				}
				if len(appIDs) == 0 {
					appIDs = []uint32{0}
				}
			}

			for _, aid := range appIDs {
				expanded = append(expanded, expandedRule{pol: pol, appID: aid})
			}
		}

		if len(expanded) > MaxRulesPerPolicy {
			return fmt.Errorf("policy %s->%s: %d expanded rules exceeds MaxRulesPerPolicy (%d)",
				zpp.FromZone, zpp.ToZone, len(expanded), MaxRulesPerPolicy)
		}

		ps := PolicySet{
			PolicySetID:   policySetID,
			NumRules:      uint16(len(expanded)),
			DefaultAction: ActionDeny,
		}
		zpKey := ZonePairKey{FromZone: fromZone, ToZone: toZone}
		if err := dp.SetZonePairPolicy(fromZone, toZone, ps); err != nil {
			return fmt.Errorf("set zone pair policy %s->%s: %w",
				zpp.FromZone, zpp.ToZone, err)
		}
		writtenPolicySets[zpKey] = true

		for i, er := range expanded {
			pol := er.pol
			rule := PolicyRule{
				RuleID:      uint32(policySetID*MaxRulesPerPolicy + uint32(i)),
				PolicySetID: policySetID,
				Sequence:    uint16(i),
				AppID:       er.appID,
				Active:      1, // default active; scheduler may toggle to 0
			}

			// Map action
			switch pol.Action {
			case config.PolicyPermit:
				rule.Action = ActionPermit
			case config.PolicyDeny:
				rule.Action = ActionDeny
			case config.PolicyReject:
				rule.Action = ActionReject
			}

			// Logging
			if pol.Log != nil {
				if pol.Log.SessionInit {
					rule.Log |= LogFlagSessionInit
				}
				if pol.Log.SessionClose {
					rule.Log |= LogFlagSessionClose
				}
			}

			// Source address (supports multiple via implicit address-set)
			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
			if err != nil {
				return fmt.Errorf("policy %s source address: %w", pol.Name, err)
			}
			rule.SrcAddrID = srcID

			// Destination address (supports multiple via implicit address-set)
			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
			if err != nil {
				return fmt.Errorf("policy %s destination address: %w", pol.Name, err)
			}
			rule.DstAddrID = dstID

			if err := dp.SetPolicyRule(policySetID, uint32(i), rule); err != nil {
				return fmt.Errorf("set policy rule %s[%d]: %w",
					pol.Name, i, err)
			}

			result.PolicyNames[rule.RuleID] = pol.Name
			if pol.SchedulerName != "" {
				result.PolicyScheduleRuleSlots = append(result.PolicyScheduleRuleSlots, PolicyScheduleRuleSlot{
					PolicySetID:   policySetID,
					RuleIndex:     uint32(i),
					RuleID:        rule.RuleID,
					PolicyName:    pol.Name,
					SchedulerName: pol.SchedulerName,
				})
			}

			slog.Debug("policy rule compiled",
				"from", zpp.FromZone, "to", zpp.ToZone,
				"policy", pol.Name, "action", rule.Action,
				"index", i, "app_id", er.appID)
		}

		result.PolicySets++
		policySetID++
	}

	// Global policies (apply to all zone pairs, evaluated as fallback).
	// Uses special key {0, 0} which BPF checks when no zone-pair-specific match.
	if len(cfg.Security.GlobalPolicies) > 0 {
		type expandedRule struct {
			pol   *config.Policy
			appID uint32
		}
		var expanded []expandedRule

		for _, pol := range cfg.Security.GlobalPolicies {
			var appIDs []uint32
			hasAny := false
			for _, appName := range pol.Match.Applications {
				if appName == "any" {
					hasAny = true
					break
				}
			}
			if hasAny || len(pol.Match.Applications) == 0 {
				appIDs = []uint32{0}
			} else {
				seen := make(map[uint32]bool)
				for _, appName := range pol.Match.Applications {
					if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
						exp, err := config.ExpandApplicationSet(appName, &cfg.Applications)
						if err != nil {
							return fmt.Errorf("global policy expand app-set %q: %w", appName, err)
						}
						for _, a := range exp {
							if id, ok := result.AppIDs[a]; ok && !seen[id] {
								seen[id] = true
								appIDs = append(appIDs, id)
							}
						}
					} else if id, ok := result.AppIDs[appName]; ok && !seen[id] {
						seen[id] = true
						appIDs = append(appIDs, id)
					}
				}
				if len(appIDs) == 0 {
					appIDs = []uint32{0}
				}
			}

			for _, aid := range appIDs {
				expanded = append(expanded, expandedRule{pol: pol, appID: aid})
			}
		}

		if len(expanded) > MaxRulesPerPolicy {
			return fmt.Errorf("global policy: %d expanded rules exceeds MaxRulesPerPolicy (%d)",
				len(expanded), MaxRulesPerPolicy)
		}

		ps := PolicySet{
			PolicySetID:   policySetID,
			NumRules:      uint16(len(expanded)),
			DefaultAction: ActionDeny,
		}
		// Global policy key: from_zone=0, to_zone=0
		if err := dp.SetZonePairPolicy(0, 0, ps); err != nil {
			return fmt.Errorf("set global policy: %w", err)
		}
		writtenPolicySets[ZonePairKey{FromZone: 0, ToZone: 0}] = true

		for i, er := range expanded {
			pol := er.pol
			rule := PolicyRule{
				RuleID:      uint32(policySetID*MaxRulesPerPolicy + uint32(i)),
				PolicySetID: policySetID,
				Sequence:    uint16(i),
				AppID:       er.appID,
				Active:      1,
			}

			switch pol.Action {
			case config.PolicyPermit:
				rule.Action = ActionPermit
			case config.PolicyDeny:
				rule.Action = ActionDeny
			case config.PolicyReject:
				rule.Action = ActionReject
			}

			if pol.Log != nil {
				if pol.Log.SessionInit {
					rule.Log |= LogFlagSessionInit
				}
				if pol.Log.SessionClose {
					rule.Log |= LogFlagSessionClose
				}
			}

			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
			if err != nil {
				return fmt.Errorf("global policy %s source address: %w", pol.Name, err)
			}
			rule.SrcAddrID = srcID

			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
			if err != nil {
				return fmt.Errorf("global policy %s destination address: %w", pol.Name, err)
			}
			rule.DstAddrID = dstID

			if err := dp.SetPolicyRule(policySetID, uint32(i), rule); err != nil {
				return fmt.Errorf("set global policy rule %s[%d]: %w", pol.Name, i, err)
			}

			result.PolicyNames[rule.RuleID] = pol.Name
			if pol.SchedulerName != "" {
				result.PolicyScheduleRuleSlots = append(result.PolicyScheduleRuleSlots, PolicyScheduleRuleSlot{
					PolicySetID:   policySetID,
					RuleIndex:     uint32(i),
					RuleID:        rule.RuleID,
					PolicyName:    pol.Name,
					SchedulerName: pol.SchedulerName,
				})
			}

			slog.Debug("global policy rule compiled",
				"policy", pol.Name, "action", rule.Action,
				"index", i, "app_id", er.appID)
		}

		result.PolicySets++
		policySetID++
	}

	// Delete stale zone-pair policy entries no longer in the config.
	dp.DeleteStaleZonePairPolicies(writtenPolicySets)

	return nil
}

func compileDefaultPolicy(dp DataPlane, cfg *config.Config) error {
	action := uint8(ActionDeny) // default deny
	if cfg.Security.DefaultPolicy == config.PolicyPermit {
		action = ActionPermit
	}
	if err := dp.SetDefaultPolicy(action); err != nil {
		return fmt.Errorf("set default policy: %w", err)
	}
	if action == ActionPermit {
		compileInfo(dp, "default policy compiled", "action", "permit-all")
	} else {
		compileInfo(dp, "default policy compiled", "action", "deny-all")
	}
	return nil
}

func compileFlowTimeouts(dp DataPlane, cfg *config.Config) error {
	flow := &cfg.Security.Flow

	// Write all timeout slots; 0 means "use BPF default".
	timeouts := [FlowTimeoutMax]uint32{}

	if flow.TCPSession != nil {
		timeouts[FlowTimeoutTCPEstablished] = uint32(flow.TCPSession.EstablishedTimeout)
		timeouts[FlowTimeoutTCPInitial] = uint32(flow.TCPSession.InitialTimeout)
		timeouts[FlowTimeoutTCPClosing] = uint32(flow.TCPSession.ClosingTimeout)
		timeouts[FlowTimeoutTCPTimeWait] = uint32(flow.TCPSession.TimeWaitTimeout)
	}
	timeouts[FlowTimeoutUDP] = uint32(flow.UDPSessionTimeout)
	timeouts[FlowTimeoutICMP] = uint32(flow.ICMPSessionTimeout)

	for idx := uint32(0); idx < FlowTimeoutMax; idx++ {
		if err := dp.SetFlowTimeout(idx, timeouts[idx]); err != nil {
			return fmt.Errorf("set flow timeout %d: %w", idx, err)
		}
	}

	// Log only if any non-default value was set, and only on the REAL pass:
	// the pre-pass's SetFlowTimeout is a no-op, so logging here records
	// "compiled" for a write that never happened and an operator reading the
	// journal of a FAILED apply sees success followed by failure, for a
	// compile whose result was thrown away (#6894 r8 F6).
	for _, v := range timeouts {
		if v > 0 {
			compileInfo(dp, "flow timeouts compiled",
				"tcp_established", timeouts[FlowTimeoutTCPEstablished],
				"tcp_initial", timeouts[FlowTimeoutTCPInitial],
				"tcp_closing", timeouts[FlowTimeoutTCPClosing],
				"tcp_time_wait", timeouts[FlowTimeoutTCPTimeWait],
				"udp", timeouts[FlowTimeoutUDP],
				"icmp", timeouts[FlowTimeoutICMP])
			break
		}
	}

	return nil
}

func compileFlowConfig(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	flow := &cfg.Security.Flow
	fc := FlowConfigValue{
		TCPMSSIPsec:  uint16(flow.TCPMSSIPsecVPN),
		TCPMSSGreIn:  uint16(flow.TCPMSSGreIn),
		TCPMSSGreOut: uint16(flow.TCPMSSGreOut),
	}
	if flow.AllowDNSReply {
		fc.AllowDNSReply = 1
	}
	if flow.AllowEmbeddedICMP {
		fc.AllowEmbeddedICMP = 1
	}
	if flow.GREPerformanceAcceleration {
		fc.GREAccel = 1
	}

	// ALG disable flags (bitfield)
	alg := &cfg.Security.ALG
	if alg.DNSDisable {
		fc.ALGFlags |= 0x01
	}
	if alg.FTPDisable {
		fc.ALGFlags |= 0x02
	}
	if alg.SIPDisable {
		fc.ALGFlags |= 0x04
	}
	if alg.TFTPDisable {
		fc.ALGFlags |= 0x08
	}

	// #2078: the `security flow tcp-session` presence flags (no-syn-check /
	// rst-invalidate-session / no-syn-check-in-tunnel) used to be packed into
	// FlowConfigValue.TCPFlags here and written to the legacy flow_config_map
	// eBPF map. That map and its reader were retired with the eBPF dataplane
	// (#1373/#1476); on the userspace path SetFlowConfig is a no-op stub
	// (pkg/dataplane/loader.go userspaceShimCompileDataplane.SetFlowConfig).
	// The packing was therefore a dead write to a retired map. The knobs are
	// accepted-but-not-enforced on the userspace dataplane (config-only
	// parity); the operator is warned at commit time (pkg/config/compiler.go,
	// #2078). The TCPFlags field is retained on FlowConfigValue to keep the
	// struct mirroring xpf_common.h, but it is no longer populated.

	if cfg.Services.ApplicationIdentification {
		fc.AppFlags |= 0x01
	}
	if cfg.Security.PreIDDefaultPolicy != nil {
		if cfg.Security.PreIDDefaultPolicy.LogSessionInit {
			fc.AppFlags |= 0x02
		}
		if cfg.Security.PreIDDefaultPolicy.LogSessionClose {
			fc.AppFlags |= 0x04
		}
	}

	// Lo0 filter IDs for host-bound traffic filtering (0xFFFF = none)
	if result.Lo0FilterV4 != 0xFFFFFFFF {
		fc.Lo0FilterV4 = uint16(result.Lo0FilterV4)
	} else {
		fc.Lo0FilterV4 = Lo0FilterNone
	}
	if result.Lo0FilterV6 != 0xFFFFFFFF {
		fc.Lo0FilterV6 = uint16(result.Lo0FilterV6)
	} else {
		fc.Lo0FilterV6 = Lo0FilterNone
	}

	if err := dp.SetFlowConfig(fc); err != nil {
		return err
	}

	compileInfo(dp, "flow config compiled",
		"tcp_mss_ipsec", fc.TCPMSSIPsec,
		"tcp_mss_gre_in", fc.TCPMSSGreIn,
		"tcp_mss_gre_out", fc.TCPMSSGreOut,
		"allow_dns_reply", fc.AllowDNSReply,
		"allow_embedded_icmp", fc.AllowEmbeddedICMP,
		"app_flags", fc.AppFlags,
		"lo0_filter_v4", fc.Lo0FilterV4,
		"lo0_filter_v6", fc.Lo0FilterV6)

	return nil
}

// getInterfaceIP returns the first IPv4 address of a network interface.
// Uses the compile-pass cache to avoid redundant syscalls.
func getInterfaceIP(ifaceName string, result *CompileResult) (net.IP, error) {
	name := config.LinuxIfName(ifaceName)
	iface, err := result.cachedInterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s addrs: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", ifaceName)
}

// getInterfaceIPv6 returns the first global unicast IPv6 address of a network interface.
// Uses the compile-pass cache to avoid redundant syscalls.
func getInterfaceIPv6(ifaceName string, result *CompileResult) (net.IP, error) {
	name := config.LinuxIfName(ifaceName)
	iface, err := result.cachedInterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s addrs: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			continue // skip IPv4
		}
		if ipNet.IP.IsGlobalUnicast() {
			return ipNet.IP, nil
		}
	}
	return nil, fmt.Errorf("no global unicast IPv6 address on interface %s", ifaceName)
}

// rethConfigAddrs extracts IPv4 and IPv6 addresses from a RETH interface's config
// units. Used for interface-mode SNAT when the VIP may not be on this node.
func rethConfigAddrs(ifCfg *config.InterfaceConfig) (v4, v6 []net.IP) {
	for _, unit := range ifCfg.Units {
		for _, addr := range unit.Addresses {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				v4 = append(v4, ip4)
			} else if ip.IsGlobalUnicast() {
				v6 = append(v6, ip)
			}
		}
	}
	return
}

// protocolNumber converts a protocol name to its IANA number.
// Handles standard names (tcp, udp, icmp), Junos predefined protocol
// aliases (junos-icmp-all, junos-tcp-any, etc.), and numeric values.
//
// #2124: delegates to the centralized appid.ProtocolNumber so the legacy
// compiler, the app-identification catalog, and the userspace policy
// capability gate share one source of truth. Returns 0 for an
// unrepresentable token (the legacy "unknown -> 0" behavior).
func protocolNumber(name string) uint8 {
	n, _ := appid.ProtocolNumber(name)
	return n
}

// algTypeFromString maps an ALG name to its BPF constant (0=none, 1=FTP, 2=SIP, 3=DNS).
func algTypeFromString(alg string) uint8 {
	switch strings.ToLower(alg) {
	case "ftp":
		return 1
	case "sip":
		return 2
	case "dns":
		return 3
	default:
		return 0
	}
}

// parsePorts parses a port specification like "80", "8080-8090", or "".
// Returns a list of individual ports. For ranges, returns all ports in range.
func parsePorts(spec string) ([]uint16, error) {
	if spec == "" {
		return []uint16{0}, nil
	}

	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		low, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, err
		}
		high, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, err
		}
		var ports []uint16
		for p := low; p <= high; p++ {
			ports = append(ports, uint16(p))
		}
		return ports, nil
	}

	port, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return nil, err
	}
	return []uint16{uint16(port)}, nil
}

// parsePortRange parses a port spec like "80", "1024-65535", or "" into (low, high).
// Unlike parsePorts, it does NOT expand ranges — returns the range boundaries.
//
// The bounds are uint16, so they MUST NOT be used directly as an ascending loop
// counter to expand the range: at high == 65535 the counter wraps to 0 after the
// final iteration, `p <= high` is true again, and the loop never terminates
// (#6783). Callers that expand must widen to int/uint64 first, or carry an
// explicit ceiling break the way the per-port application writer above does
// ("prevent uint16 overflow"). Every current caller keeps the bounds AS bounds;
// the one expander that did not was `appPortsFromSpec`, removed in #6783 after
// ad31711e3 dropped its last production caller. pkg/dataplane/userspace owns the
// surviving port-expansion helpers and parses into uint64 for exactly this
// reason.
func parsePortRange(spec string) (uint16, uint16, error) {
	if spec == "" {
		return 0, 0, nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		low, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		high, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		return uint16(low), uint16(high), nil
	}
	port, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return 0, 0, err
	}
	return uint16(port), uint16(port), nil
}

// ensureRxVlanOff disables rx-vlan-offload on iface so the XDP parser sees the
// 802.1Q tag in packet data (a NIC that strips the tag into skb->vlan_tci,
// which XDP cannot read, would make every tagged frame parse as vlan_id=0).
// Results are cached to avoid redundant ethtool subprocess calls. Toggling
// rxvlan on iavf VFs causes a driver reset that drops in-flight packets, so we
// check current state before changing.
//
// #5268: returns an error when the offload is ACTIVE and could NOT be turned
// off (or the state cannot be determined and disabling failed). A NIC whose
// query reports the feature ABSENT, or already `off`/`off [fixed]` (e.g.
// virtio), never strips tags, so it returns nil without touching `-K`. The
// caller (compiler_iface.go) uses `rxVlanOffloadActivationError` to fail the
// compile CLOSED on a returned error ONLY when the parent carries configured
// VLAN subinterfaces (see the security rationale there) — a plain parent with
// no 802.1Q units is unaffected.
func (r *CompileResult) ensureRxVlanOff(iface string) error {
	if r.rxVlanOffCache[iface] {
		return nil
	}
	// Check current state via ethtool -k. The classification — including why a
	// NIC that lists no such feature must NOT be probed with `-K`, and why a
	// failed query counts as "needs disable" rather than "safe" — lives in
	// ClassifyRxVlanOffload, shared with the post-link-cycle re-disable in
	// pkg/daemon so the two cannot drift (#9946).
	switch ClassifyRxVlanOffload(runEthtool("-k", iface)) {
	case RxVlanOffloadOff, RxVlanOffloadAbsent:
		// Already off (includes "off [fixed]"), or the NIC has no such offload
		// at all: no tags stripped either way.
		r.rxVlanOffCache[iface] = true
		return nil
	}
	// Either the offload is ON, or the query failed (state unknown): attempt to
	// disable. Success => off; failure => the caller may fail closed.
	if out, err := runEthtool("-K", iface, "rxvlan", "off"); err != nil {
		slog.Warn("failed to disable rxvlan offload (HW-stripped tags cannot be parsed by XDP)",
			"interface", iface, "err", err, "output", strings.TrimSpace(string(out)))
		return fmt.Errorf("disable rx-vlan-offload on %s: %w (output: %s)",
			iface, err, strings.TrimSpace(string(out)))
	}
	r.rxVlanOffCache[iface] = true
	slog.Info("disabled VLAN RX offload for XDP", "interface", iface)
	return nil
}

// parentHasVlanSubinterface resolves cfgName in cfg and asks
// config.InterfaceHasVlanSubinterface about it. #5268 gates the fail-closed
// RX-VLAN-offload activation check on this.
//
// The predicate itself moved to pkg/config in #9946 because the post-link-cycle
// re-disable in pkg/daemon must use the SAME scope — it holds an
// *config.InterfaceConfig directly (the RETH's) and has no cfg/cfgName pair to
// look up, so the shared half is the one that takes the interface.
func parentHasVlanSubinterface(cfg *config.Config, cfgName string) bool {
	if cfg == nil {
		return false
	}
	ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]
	if !ok {
		return false
	}
	return config.InterfaceHasVlanSubinterface(ifCfg)
}

// rxVlanOffloadActivationError decides whether a failure to disable RX-VLAN
// hardware offload on physName must FAIL ACTIVATION CLOSED (#5268). It returns
// a non-nil error ONLY when `ensureErr != nil` AND the parent config interface
// cfgName carries ≥1 configured 802.1Q VLAN subinterface.
//
// Security rationale: the XDP dataplane derives VLAN (security-domain) identity
// SOLELY from the in-frame 802.1Q tag. If a NIC's RX-VLAN offload strips the tag
// into skb->vlan_tci (which XDP cannot read) and xpf cannot disable it, every
// tagged frame parses as vlan_id=0 and `resolve_ingress_logical_ifindex` falls
// back to the PHYSICAL parent ifindex, which maps to the parent's / first
// subinterface's zone — so untrusted VLAN traffic is classified into a TRUSTED
// zone (a screen/policy bypass). Pre-#5268 this degraded to a single warning and
// activation continued into shim attachment. Now it is an activation
// precondition. A parent with no VLAN subinterfaces does not classify by tag, so
// the offload state is irrelevant and the failure is tolerated (nil) — plain-
// interface deploys and NICs that legitimately lack the offload knob are
// unaffected.
func rxVlanOffloadActivationError(cfg *config.Config, cfgName, physName string, ensureErr error) error {
	if ensureErr == nil {
		return nil
	}
	if !parentHasVlanSubinterface(cfg, cfgName) {
		return nil
	}
	return fmt.Errorf(
		"interface %s carries configured VLAN subinterface(s) but RX-VLAN hardware "+
			"offload could not be disabled (%w): XDP reads 802.1Q identity only from "+
			"in-frame tags, so HW-stripped tagged traffic would fall back to the parent "+
			"ifindex and be classified into the parent's zone (cross-zone security "+
			"bypass) — failing activation closed",
		physName, ensureErr)
}

// applyEthtool applies speed and duplex settings via ethtool if configured.
// Results are cached to skip redundant calls for the same settings.
// Errors are logged as warnings since virtual interfaces (virtio-net) don't
// support ethtool speed/duplex changes.
func (r *CompileResult) applyEthtool(ifaceName string, ifCfg *config.InterfaceConfig) {
	speed := parseSpeed(ifCfg.Speed)
	duplex := parseDuplex(ifCfg.Duplex)
	if speed == "" && duplex == "" {
		return
	}
	cacheKey := ifaceName + ":" + speed + ":" + duplex
	if r.ethtoolApplied[cacheKey] {
		return
	}
	args := []string{"-s", ifaceName}
	if speed != "" {
		args = append(args, "speed", speed)
	}
	if duplex != "" {
		args = append(args, "duplex", duplex)
	}
	if out, err := runEthtool(args...); err != nil {
		slog.Warn("failed to apply ethtool settings",
			"name", ifaceName, "speed", ifCfg.Speed, "duplex", ifCfg.Duplex,
			"err", fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out))))
	} else {
		r.ethtoolApplied[cacheKey] = true
		slog.Info("applied ethtool settings", "name", ifaceName,
			"speed", ifCfg.Speed, "duplex", ifCfg.Duplex)
	}
}

// parseSpeed converts Junos speed values (e.g. "1g", "10g", "100m") to
// ethtool speed in Mbps. Returns "" for unknown/auto/empty values.
func parseSpeed(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "auto":
		return ""
	case "10m":
		return "10"
	case "100m":
		return "100"
	case "1g":
		return "1000"
	case "2.5g":
		return "2500"
	case "5g":
		return "5000"
	case "10g":
		return "10000"
	case "25g":
		return "25000"
	case "40g":
		return "40000"
	case "100g":
		return "100000"
	default:
		// Try to parse as raw Mbps number
		if _, err := strconv.Atoi(s); err == nil {
			return s
		}
		return ""
	}
}

// parseDuplex converts Junos duplex values to ethtool duplex values.
func parseDuplex(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "full":
		return "full"
	case "half":
		return "half"
	default:
		return ""
	}
}

// tuneInterfaceBuffers increases txqueuelen and TX/RX ring buffer sizes on
// data-plane interfaces to reduce packet drops from XDP redirect overflow.
// Must be called BEFORE XDP attachment since ethtool -G can reset the NIC.
// Results are cached to skip redundant calls across recompilations.
func (r *CompileResult) tuneInterfaceBuffers(link netlink.Link) {
	name := link.Attrs().Name
	if r.ethtoolApplied["buffers:"+name] {
		return
	}

	const desiredTxQLen = 10000
	if link.Attrs().TxQLen < desiredTxQLen {
		if err := netlink.LinkSetTxQLen(link, desiredTxQLen); err != nil {
			slog.Debug("failed to set txqueuelen", "interface", name, "err", err)
		}
	}

	// Increase ring buffers via ethtool -G. Query current/max first.
	out, err := runEthtool("-g", name)
	if err != nil {
		r.ethtoolApplied["buffers:"+name] = true
		return
	}

	maxTX, curTX := parseRingParams(string(out))
	if maxTX > 0 && curTX < maxTX {
		if out, err := runEthtool("-G", name,
			"tx", strconv.Itoa(maxTX),
			"rx", strconv.Itoa(maxTX),
		); err != nil {
			slog.Debug("failed to increase ring buffers",
				"interface", name, "err", fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out))))
		} else {
			slog.Info("increased ring buffers",
				"interface", name, "tx", maxTX)
		}
	}

	// Enable RPS on all RX queues to spread softirq processing across CPUs.
	// Without this, generic XDP redirect concentrates TX on whichever CPU
	// received the packet, causing ksoftirqd imbalance.
	numCPU := runtime.NumCPU()
	cpuMask := allCPUMask(numCPU)
	// Global RFS flow table (set once, idempotent).
	os.WriteFile("/proc/sys/net/core/rps_sock_flow_entries", []byte("32768"), 0644)
	rxQueues, _ := filepath.Glob(fmt.Sprintf("/sys/class/net/%s/queues/rx-*/rps_cpus", name))
	for _, path := range rxQueues {
		os.WriteFile(path, []byte(cpuMask), 0644)
	}
	// Set per-queue flow count for RFS (Receive Flow Steering) consistent hashing.
	flowCnt := 32768 / max(len(rxQueues), 1)
	for _, path := range rxQueues {
		fcPath := strings.Replace(path, "rps_cpus", "rps_flow_cnt", 1)
		os.WriteFile(fcPath, []byte(strconv.Itoa(flowCnt)), 0644)
	}

	// Enable XPS: pin each TX queue to its corresponding CPU for locality.
	txQueues, _ := filepath.Glob(fmt.Sprintf("/sys/class/net/%s/queues/tx-*/xps_cpus", name))
	for i, path := range txQueues {
		cpu := i % numCPU
		os.WriteFile(path, []byte(singleCPUMask(cpu)), 0644)
	}

	// Set RSS hash key for better queue distribution with AF_XDP.
	// The default Toeplitz hash key can concentrate flows with similar
	// 5-tuples onto the same queues. This key provides better spread.
	configureRSSHashKey(name)

	r.ethtoolApplied["buffers:"+name] = true
}

// configureRSSHashKey sets a well-distributed RSS hash key via ethtool -X.
// This improves AF_XDP queue utilization when traffic has limited source
// diversity (e.g. few clients with same src IP, varying only src port).
func configureRSSHashKey(name string) {
	key := "6d:5a:56:da:25:5b:0e:c2:41:67:25:3d:43:a3:8f:b0:" +
		"d0:ca:2b:cb:ae:7b:30:b4:77:cb:2d:a3:80:30:f2:0c:" +
		"8c:da:5b:6a:25:30:17:9a"
	out, err := runEthtool("-X", name, "hkey", key)
	if err != nil {
		slog.Debug("failed to set RSS hash key",
			"interface", name, "err", fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out))))
	}
}

// parseRingParams extracts max and current TX ring sizes from ethtool -g output.
func parseRingParams(output string) (maxTX, curTX int) {
	lines := strings.Split(output, "\n")
	inMax := false
	inCur := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Pre-set maximums:") {
			inMax = true
			inCur = false
			continue
		}
		if strings.HasPrefix(line, "Current hardware settings:") {
			inCur = true
			inMax = false
			continue
		}
		if strings.HasPrefix(line, "TX:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.Atoi(parts[1])
				if inMax {
					maxTX = val
				} else if inCur {
					curTX = val
				}
			}
		}
	}
	return
}

// compilePortMirroring populates the mirror_config BPF map from
// forwarding-options { port-mirroring { instance ... } }.
func compilePortMirroring(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	dp.ClearMirrorConfigs()

	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) == 0 {
		return nil
	}

	for name, inst := range pm.Instances {
		if inst.Output == "" {
			slog.Warn("port-mirroring instance has no output interface", "name", name)
			continue
		}

		outIface, err := result.cachedInterfaceByName(config.LinuxIfName(inst.Output))
		if err != nil {
			slog.Warn("port-mirroring output interface not found",
				"name", name, "interface", inst.Output, "err", err)
			continue
		}

		rate := uint32(inst.InputRate)

		for _, inputIface := range inst.Input {
			inIface, err := result.cachedInterfaceByName(config.LinuxIfName(inputIface))
			if err != nil {
				slog.Warn("port-mirroring input interface not found",
					"name", name, "interface", inputIface, "err", err)
				continue
			}

			if err := dp.SetMirrorConfig(inIface.Index, outIface.Index, rate); err != nil {
				return fmt.Errorf("set mirror config for %s: %w", inputIface, err)
			}

			slog.Info("port-mirroring compiled",
				"instance", name,
				"input", inputIface,
				"output", inst.Output,
				"rate", rate)
		}
	}

	return nil
}

// isVirtualRethMAC returns true if the MAC matches the virtual RETH pattern (02:bf:72:...).
func isVirtualRethMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0] == 0x02 && mac[1] == 0xbf && mac[2] == 0x72
}

// getPermAddr returns the permanent (factory) MAC address for an interface
// via netlink IFLA_PERM_ADDRESS. Uses the compile-pass cache when available.
func getPermAddr(ifName string, result *CompileResult) string {
	var link netlink.Link
	var err error
	if result != nil {
		link, err = result.cachedLinkByName(ifName)
	} else {
		link, err = netlink.LinkByName(ifName)
	}
	if err != nil {
		return ""
	}
	perm := link.Attrs().PermHWAddr
	if len(perm) == 0 {
		return ""
	}
	return perm.String()
}

// findInterfaceByMAC searches all system interfaces for one matching the
// given MAC address. Used to locate RETH members that weren't renamed.
func findInterfaceByMAC(mac net.HardwareAddr) *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifaces {
		if bytes.Equal(ifaces[i].HardwareAddr, mac) {
			return &ifaces[i]
		}
	}
	return nil
}

// readOriginalNameFromLink reads the OriginalName= value from an existing
// .link file for the given interface. Preserves previously-written kernel
// names across DHCP recompiles.
func readOriginalNameFromLink(ifName string) string {
	path := fmt.Sprintf("/etc/systemd/network/10-xpf-%s.link", ifName)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "OriginalName=") {
			return strings.TrimPrefix(line, "OriginalName=")
		}
	}
	return ""
}

// getOriginalKernelName returns the predictable kernel name (e.g. enp9s0f0)
// for a renamed interface. Tries altnames first, then derives from PCI sysfs.
// Uses the compile-pass cache when available.
// originalKernelNameFn is the seam for getOriginalKernelName. It exists so a
// test can bind the PRODUCTION CALL SITE (compiler_iface.go's networkd
// `.link` generation) rather than only the helper: a test that exercises the
// helper while production bypasses it proves nothing, and #7420's own merge
// gate used exactly this shape — bypassing the production call while leaving
// the callee intact must RED (#7426).
var originalKernelNameFn = getOriginalKernelName

func getOriginalKernelName(ifName string, result *CompileResult) string {
	var link netlink.Link
	var err error
	if result != nil {
		link, err = result.cachedLinkByName(ifName)
	} else {
		link, err = netlink.LinkByName(ifName)
	}
	if err != nil {
		return ""
	}
	// #7426: the altname ORDER and the PCI derivation both come from
	// pkg/netname now. This copy took the first altname matching any of four
	// prefixes, in whatever order the kernel listed them — a coin flip on a NIC
	// carrying several at once — and its PCI fallback had no domain handling
	// and parsed the function base 10. The daemon copy had the ordering and the
	// domain but under-emitted the `f0` suffix this copy got right in #4795.
	// Two copies wrong in opposite directions on the same field is what makes
	// this single-source rather than agreement-test material.
	if name := netname.FromAltNames(link.Attrs().AltNames); name != "" {
		return name
	}
	// Derive from PCI device path via sysfs.
	// /sys/class/net/<name>/device -> .../0000:09:00.0
	devPath, err := os.Readlink(fmt.Sprintf("/sys/class/net/%s/device", ifName))
	if err != nil {
		return ""
	}
	pciAddr := devPath[strings.LastIndex(devPath, "/")+1:]
	return netname.FromPCIAddr(pciAddr, netname.Multifunction(pciAddr))
}
