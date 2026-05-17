package dataplane

import (
	"bytes"
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

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
)

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

	nextAddrID       uint32            // next available address ID (after address book)
	implicitSets     map[string]uint32 // cache of implicit set key -> set ID
	nextNATCounterID uint16            // next available NAT rule counter ID (1-based, 0 = no counter)
	NATCounterIDs    map[string]uint16 // "rulesetName/ruleName" -> counter ID

	// pendingXDP/TC collect interface indexes for deferred program attachment.
	// Attachment happens AFTER all compilation phases so that link.Update()
	// atomically switches to programs with fully-populated maps.
	pendingXDP          []int
	pendingTC           []int
	tunnelIfindexes     map[int]bool // tunnel interfaces: XDP ingress only, no redirect
	genericXDPIfindexes map[int]bool // interfaces that must use generic XDP only

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

	result := &CompileResult{
		ZoneIDs:             make(map[string]uint16),
		ScreenIDs:           make(map[string]uint16),
		AddrIDs:             make(map[string]uint32),
		AppIDs:              make(map[string]uint32),
		PoolIDs:             make(map[string]uint8),
		implicitSets:        make(map[string]uint32),
		nextNATCounterID:    1, // 0 = no counter
		NATCounterIDs:       make(map[string]uint16),
		FilterSpans:         make(map[string]FilterCounterSpan),
		Lo0FilterV4:         0xFFFFFFFF, // sentinel: no lo0 filter
		Lo0FilterV6:         0xFFFFFFFF,
		ifCache:             make(map[string]*net.Interface),
		linkCache:           make(map[string]netlink.Link),
		linkIdxMap:          make(map[int]netlink.Link),
		rxVlanOffCache:      make(map[string]bool),
		ethtoolApplied:      make(map[string]bool),
		genericXDPIfindexes: make(map[int]bool),
	}

	// Phase 1: Assign zone IDs (1-based; 0 = unassigned).
	// Sort names for deterministic IDs across restarts — existing sessions
	// store zone IDs, so changing them breaks session→policy lookups.
	zoneID := uint16(1)
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, name := range zoneNames {
		result.ZoneIDs[name] = zoneID
		zoneID++
	}

	// Phase 1.5: Assign screen profile IDs (1-based; 0 = no profile).
	// Sorted for deterministic IDs.
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

	// Phase 2: Compile zones
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
	if isRecompile {
		dp.BumpFIBGeneration()
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
	// Bonus early-warning gate: if any kernel ifindex already exceeds
	// MaxInterfaces, fail now with a named-interface error rather than
	// deep inside zone apply (AddTxPort returning E2BIG as "key too big
	// for map"). See issue #814 — the call-site cap checks in
	// loader.go's AddTxPort and userspace/maps_sync.go are the real
	// guardrails since interfaces can appear via netlink at any time;
	// this preflight just makes the first-compile failure legible.
	if err := m.preflightCheckIfindexCaps(); err != nil {
		return nil, err
	}

	result, err := CompileConfig(m, cfg, m.lastCompile != nil)
	if err != nil {
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
		rcMap := m.maps["redirect_capable"]

		// Populate redirect_capable BEFORE link.Update() swaps programs.
		// Skip tunnel interfaces — bpf_redirect_map sends Ethernet frames
		// but POINTOPOINT tunnels (GRE, ip6gre, XFRM) expect raw IP.
		// Those interfaces still get XDP for ingress decapsulated traffic.
		if rcMap != nil {
			for _, ifidx := range result.pendingXDP {
				if result.tunnelIfindexes[ifidx] {
					continue
				}
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
		isUserspaceShim := m.XDPEntryProg == "xdp_userspace_prog"
		for _, ifidx := range result.pendingXDP {
			forceGeneric := failedNativeXDP[ifidx] || result.tunnelIfindexes[ifidx] || result.genericXDPIfindexes[ifidx]
			if !forceGeneric {
				continue // already attached native above
			}
			if result.genericXDPIfindexes[ifidx] && !result.tunnelIfindexes[ifidx] {
				if isUserspaceShim {
					continue // skip VLAN sub-interfaces — parent handles VLAN traffic
				}
				if link, err := result.cachedLinkByIndex(ifidx); err == nil {
					parentIfindex := link.Attrs().ParentIndex
					if parentIfindex > 0 && failedNativeXDP[parentIfindex] {
						continue
					}
				}
			}
			if err := m.AttachXDP(ifidx, true); err != nil {
				if !strings.Contains(err.Error(), "already attached") {
					return nil, fmt.Errorf("attach XDP generic to ifindex %d: %w", ifidx, err)
				}
			}
		}
	}

	// Record VLAN sub-interfaces so SwapXDPEntryProg can skip them.
	// The shim on VLAN sub-interfaces breaks NDP because generic XDP
	// + XDP_PASS doesn't deliver properly to kernel NDP on VLAN devices.
	for ifidx := range result.genericXDPIfindexes {
		if !result.tunnelIfindexes[ifidx] {
			m.VlanSubInterfaces[ifidx] = true
		}
	}
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

	appID := uint32(1)
	userApps := cfg.Applications.Applications

	refNames, err := appid.CatalogNames(cfg, cfg.Services.ApplicationIdentification)
	if err != nil {
		return err
	}
	for _, appName := range refNames {
		app, found := config.ResolveApplication(appName, userApps)
		if !found {
			return fmt.Errorf("application %q not found", appName)
		}

		proto := protocolNumber(app.Protocol)

		result.AppIDs[appName] = appID
		result.AppNames[uint16(appID)] = appName

		// Parse destination port range boundaries.
		dstLow, dstHigh, err := parsePortRange(app.DestinationPort)
		if err != nil {
			slog.Warn("bad port for application",
				"name", appName, "port", app.DestinationPort, "err", err)
			continue
		}

		// Parse source port range (stored in BPF app_value, not expanded)
		var srcLow, srcHigh uint16
		if app.SourcePort != "" {
			srcLow, srcHigh, err = parsePortRange(app.SourcePort)
			if err != nil {
				slog.Warn("bad source-port for application",
					"name", appName, "port", app.SourcePort, "err", err)
			}
		}

		var appTimeout uint32
		if app.InactivityTimeout > 0 {
			appTimeout = uint32(app.InactivityTimeout)
		}

		algType := algTypeFromString(app.ALG)

		// When no protocol is specified, install entries for both TCP and UDP
		// (matching Junos behavior where omitted protocol means any L4).
		protos := []uint8{proto}
		if proto == 0 && app.Protocol != "icmp" {
			protos = []uint8{6, 17} // TCP + UDP
		}

		// Large ranges (>256 ports) go into app_ranges ARRAY to avoid
		// expanding thousands of per-port HASH entries.
		rangeSize := int(dstHigh) - int(dstLow) + 1
		if rangeSize > 256 && rangeIdx < MaxAppRanges {
			for _, p := range protos {
				if rangeIdx >= MaxAppRanges {
					slog.Warn("app_ranges full, falling back to HASH expansion",
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
		appID++
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

		if len(expanded) >= MaxRulesPerPolicy {
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

		if len(expanded) >= MaxRulesPerPolicy {
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
		slog.Info("default policy compiled", "action", "permit-all")
	} else {
		slog.Info("default policy compiled", "action", "deny-all")
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

	// Log only if any non-default value was set.
	for _, v := range timeouts {
		if v > 0 {
			slog.Info("flow timeouts compiled",
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

	// TCP session flags
	if flow.TCPSession != nil {
		if flow.TCPSession.NoSynCheck {
			fc.TCPFlags |= 0x01
		}
		if flow.TCPSession.RstInvalidateSession {
			fc.TCPFlags |= 0x02
		}
		if flow.TCPSession.NoSynCheckInTunnel {
			fc.TCPFlags |= 0x04
		}
	}

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

	slog.Info("flow config compiled",
		"tcp_mss_ipsec", fc.TCPMSSIPsec,
		"tcp_mss_gre_in", fc.TCPMSSGreIn,
		"tcp_mss_gre_out", fc.TCPMSSGreOut,
		"allow_dns_reply", fc.AllowDNSReply,
		"allow_embedded_icmp", fc.AllowEmbeddedICMP,
		"tcp_flags", fc.TCPFlags,
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
func protocolNumber(name string) uint8 {
	switch strings.ToLower(name) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp", "junos-icmp-all", "junos-ping":
		return 1
	case "icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6":
		return 58
	case "gre", "junos-gre":
		return 47
	case "ospf", "junos-ospf":
		return 89
	case "junos-tcp-any":
		return 6
	case "junos-udp-any":
		return 17
	case "junos-ip-in-ip", "junos-ipip", "ipip":
		return 4
	case "egp":
		return 8
	case "igmp":
		return 2
	case "pim":
		return 103
	case "ah":
		return 51
	case "esp":
		return 50
	case "sctp":
		return 132
	case "vrrp":
		return 112
	default:
		// Try numeric protocol number
		if n, err := strconv.Atoi(name); err == nil && n > 0 && n < 256 {
			return uint8(n)
		}
		return 0
	}
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

// appPortsFromSpec parses an application's DestinationPort spec (e.g. "80", "8080-8090")
// into a slice of individual port ints. Returns nil for empty spec.
func appPortsFromSpec(spec string) []int {
	if spec == "" {
		return nil
	}
	lo, hi, err := parsePortRange(spec)
	if err != nil {
		return nil
	}
	if hi > lo {
		var ports []int
		for p := lo; p <= hi; p++ {
			ports = append(ports, int(p))
		}
		return ports
	}
	return []int{int(lo)}
}

// parsePortRange parses a port spec like "80", "1024-65535", or "" into (low, high).
// Unlike parsePorts, it does NOT expand ranges — returns the range boundaries.
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

// ensureRxVlanOff disables rx-vlan-offload on iface if not already off.
// Results are cached to avoid redundant ethtool subprocess calls.
// Toggling rxvlan on iavf VFs causes a driver reset that drops in-flight
// packets, so we check current state before changing.
func (r *CompileResult) ensureRxVlanOff(iface string) {
	if r.rxVlanOffCache[iface] {
		return
	}
	// Check current state via ethtool -k.
	out, err := exec.Command("ethtool", "-k", iface).CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "rx-vlan-offload:") {
				if strings.Contains(line, "off") {
					r.rxVlanOffCache[iface] = true
					return
				}
				break
			}
		}
	}
	// Not off yet — disable it.
	if out, err := exec.Command("ethtool", "-K", iface, "rxvlan", "off").CombinedOutput(); err != nil {
		slog.Warn("failed to disable rxvlan offload (VLAN parsing may fail)",
			"interface", iface, "err", err, "output", strings.TrimSpace(string(out)))
	} else {
		r.rxVlanOffCache[iface] = true
		slog.Info("disabled VLAN RX offload for XDP", "interface", iface)
	}
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
	if out, err := exec.Command("ethtool", args...).CombinedOutput(); err != nil {
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
	out, err := exec.Command("ethtool", "-g", name).CombinedOutput()
	if err != nil {
		r.ethtoolApplied["buffers:"+name] = true
		return
	}

	maxTX, curTX := parseRingParams(string(out))
	if maxTX > 0 && curTX < maxTX {
		if out, err := exec.Command("ethtool", "-G", name,
			"tx", strconv.Itoa(maxTX),
			"rx", strconv.Itoa(maxTX),
		).CombinedOutput(); err != nil {
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
	out, err := exec.Command("ethtool", "-X", name, "hkey", key).CombinedOutput()
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
	for _, alt := range link.Attrs().AltNames {
		if strings.HasPrefix(alt, "enp") || strings.HasPrefix(alt, "eno") ||
			strings.HasPrefix(alt, "ens") || strings.HasPrefix(alt, "eth") {
			return alt
		}
	}
	// Derive from PCI device path via sysfs.
	// /sys/class/net/<name>/device -> .../0000:09:00.0
	devPath, err := os.Readlink(fmt.Sprintf("/sys/class/net/%s/device", ifName))
	if err != nil {
		return ""
	}
	pciAddr := devPath[strings.LastIndex(devPath, "/")+1:]
	// Parse "domain:bus:slot.function" e.g. "0000:09:00.0"
	parts := strings.SplitN(pciAddr, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	bus, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return ""
	}
	sf := strings.SplitN(parts[2], ".", 2)
	if len(sf) != 2 {
		return ""
	}
	slot, err := strconv.ParseUint(sf[0], 16, 16)
	if err != nil {
		return ""
	}
	fn, err := strconv.ParseUint(sf[1], 10, 8)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("enp%ds%df%d", bus, slot, fn)
}
