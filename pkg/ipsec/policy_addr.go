package ipsec

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// PrepareConfig resolves runtime-only IPsec values from the full config.
// The returned config is a deep copy that can be safely mutated by the IPsec
// runtime without affecting the active config tree.
func PrepareConfig(cfg *config.Config) *config.IPsecConfig {
	if cfg == nil {
		return nil
	}
	// A dynamic-hostname gateway resolves its remote family hint via a DNS
	// lookup bounded by resolveHostFamilyTimeout (#2757). Resolving those
	// hints CONCURRENTLY (bounded pool) keeps a multi-gateway commit at
	// ~one timeout of wall-clock rather than N×timeout under DNS failure
	// (#4547). The hint is per-gateway and order-independent, so the result
	// per gateway is identical to the former sequential resolution.
	familyHints := resolveGatewayFamilyHints(cfg.Security.IPsec.Gateways)
	return prepareConfig(cfg, func(name string, gw *config.IPsecGateway) string {
		return resolveInterfaceAddress(cfg, gw.ExternalIface, familyHints[name])
	})
}

// prepareConfig is PrepareConfig's deep copy. localAddr supplies the local address of
// every gateway that sets external-interface and no local-address; nothing else is
// resolved.
func prepareConfig(cfg *config.Config, localAddr func(name string, gw *config.IPsecGateway) string) *config.IPsecConfig {
	src := &cfg.Security.IPsec
	out := &config.IPsecConfig{
		IKEProposals: make(map[string]*config.IKEProposal, len(src.IKEProposals)),
		IKEPolicies:  make(map[string]*config.IKEPolicy, len(src.IKEPolicies)),
		Gateways:     make(map[string]*config.IPsecGateway, len(src.Gateways)),
		Proposals:    make(map[string]*config.IPsecProposal, len(src.Proposals)),
		Policies:     make(map[string]*config.IPsecPolicyDef, len(src.Policies)),
		VPNs:         make(map[string]*config.IPsecVPN, len(src.VPNs)),
	}

	for name, prop := range src.IKEProposals {
		cp := *prop
		out.IKEProposals[name] = &cp
	}
	for name, pol := range src.IKEPolicies {
		cp := *pol
		out.IKEPolicies[name] = &cp
	}
	for name, gw := range src.Gateways {
		cp := *gw
		if cp.LocalAddress == "" && cp.ExternalIface != "" {
			cp.LocalAddress = localAddr(name, gw)
		}
		out.Gateways[name] = &cp
	}
	for name, prop := range src.Proposals {
		cp := *prop
		out.Proposals[name] = &cp
	}
	for name, pol := range src.Policies {
		cp := *pol
		out.Policies[name] = &cp
	}
	for name, vpn := range src.VPNs {
		cp := *vpn
		if vpn.TrafficSelectors != nil {
			cp.TrafficSelectors = make(map[string]*config.IPsecTrafficSelector, len(vpn.TrafficSelectors))
			for tsName, ts := range vpn.TrafficSelectors {
				tsCopy := *ts
				cp.TrafficSelectors[tsName] = &tsCopy
			}
		}
		out.VPNs[name] = &cp
	}

	return out
}

// HasDHCPBoundGateway reports whether any IPsec gateway resolves its
// local bind address DYNAMICALLY from a DHCP-managed interface — i.e.
// the gateway sets external-interface, carries no explicit
// local-address (so PrepareConfig resolves local_addrs at apply time),
// and the referenced interface unit is DHCP/DHCPv6-managed. Such a
// gateway's swanctl local_addrs tracks the lease, so a runtime lease
// change (DHCP renew to a new address) must trigger a swanctl
// re-render; otherwise strongSwan keeps binding to the stale IP and the
// tunnel cannot re-establish (#2884).
//
// It returns false when no gateway is lease-dependent, letting the
// daemon skip the swanctl re-render on unrelated DHCP lease refreshes
// (e.g. a management-only interface no IPsec gateway uses) and avoid an
// SA-resetting reload storm.
func HasDHCPBoundGateway(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, gw := range cfg.Security.IPsec.Gateways {
		if gw == nil || gw.ExternalIface == "" || gw.LocalAddress != "" {
			continue
		}
		if interfaceRefIsDHCP(cfg, gw.ExternalIface) {
			return true
		}
	}
	return false
}

// interfaceRefIsDHCP reports whether the interface reference (e.g.
// "ge-0/0/0" or "ge-0/0/0.0") names a unit configured for DHCPv4 or
// DHCPv6. A bare reference (no unit) matches if ANY of the interface's
// units is DHCP-managed. Mirrors resolveConfiguredInterfaceAddress's
// base/unit parsing so the two derivations cannot drift.
func interfaceRefIsDHCP(cfg *config.Config, ifaceRef string) bool {
	parts := strings.SplitN(ifaceRef, ".", 2)
	ifc, ok := cfg.Interfaces.Interfaces[parts[0]]
	if !ok || ifc == nil {
		return false
	}
	if len(parts) == 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			unit, ok := ifc.Units[n]
			return ok && unit != nil && (unit.DHCP || unit.DHCPv6)
		}
		return false
	}
	for _, unit := range ifc.Units {
		if unit != nil && (unit.DHCP || unit.DHCPv6) {
			return true
		}
	}
	return false
}

// resolveInterfaceAddress selects the local-address to bind for an IKE SA
// from the external interface, constrained to the remote gateway's address
// family. family is the resolved remote family hint (4, 6, or 0 for
// "either" — see gatewayRemoteFamilyHint). Constraining by family is what
// keeps a dual-stack appliance from sourcing the SA out of the wrong family
// vs the resolved peer (#2757): if the remote is/resolves to IPv6, the IPv6
// local-address is chosen, and vice versa.
//
// When the constrained family yields no local-address on the interface (the
// interface is single-stack in the other family), we fall back to a
// family-agnostic selection so a misconfiguration degrades to the legacy
// behavior rather than emitting no local_addrs line at all.
func resolveInterfaceAddress(cfg *config.Config, ifaceRef string, family int) string {
	if addr := resolveInterfaceAddressFamily(cfg, ifaceRef, family); addr != "" {
		return addr
	}
	if family != 0 {
		// The remote family has no matching local-address on this
		// interface — fall back to whatever the interface offers rather
		// than rendering an empty local_addrs.
		return resolveInterfaceAddressFamily(cfg, ifaceRef, 0)
	}
	return ""
}

func resolveInterfaceAddressFamily(cfg *config.Config, ifaceRef string, family int) string {
	if addr := resolveConfiguredInterfaceAddress(cfg, ifaceRef, family); addr != "" {
		return addr
	}

	resolvedRef := cfg.ResolveReth(ifaceRef)
	for _, name := range []string{
		config.LinuxIfName(resolvedRef),
		config.LinuxIfName(ifaceRef),
	} {
		if addr := resolveKernelInterfaceAddress(name, family); addr != "" {
			return addr
		}
	}

	return ""
}

// resolveHostFamilyTimeout bounds the default dynamic-hostname DNS lookup.
// PrepareConfig runs SYNCHRONOUSLY in the daemon's ordered apply sequence
// (pkg/daemon/daemon_apply.go) and the CLI commit path (pkg/cli/apply.go),
// neither of which did any DNS before #2757. This lookup is only a *family
// hint* (strongSwan does the authoritative resolution at IKE time), so it
// must never stall commit/apply for the full glibc resolver timeout. 2s is
// ample for a hint; on timeout/error the default returns family 0 and the
// interface-decides fallback applies — graceful degradation, never a hang.
const resolveHostFamilyTimeout = 2 * time.Second

// resolveHostFamily is the hook used to resolve a dynamic-hostname gateway to
// an address family for local-address selection. It is a package var so tests
// can make resolution deterministic without real DNS (tests inject a fake; no
// real DNS in the test suite). It returns 4 if the host resolves to (or
// prefers) IPv4, 6 for IPv6, and 0 if it cannot resolve, times out, or the
// host is dual-stack with no clear preference (let the local interface
// decide). The default uses the system resolver bounded by
// resolveHostFamilyTimeout.
var resolveHostFamily = defaultResolveHostFamily

func defaultResolveHostFamily(host string) int {
	ctx, cancel := context.WithTimeout(
		context.Background(), resolveHostFamilyTimeout)
	defer cancel()

	var r net.Resolver
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		// Timeout / NXDOMAIN / SERVFAIL: fall back to family-agnostic so a
		// slow or unreachable resolver degrades to interface-decides rather
		// than stalling commit/apply or guessing the family.
		return 0
	}
	var has4, has6 bool
	for _, addr := range ips {
		if addr.IP.To4() != nil {
			has4 = true
		} else {
			has6 = true
		}
	}
	switch {
	case has4 && has6:
		// Dual-stack peer: no explicit preference is configured, so let
		// the local interface's available family decide (family-agnostic).
		return 0
	case has6:
		return 6
	case has4:
		return 4
	default:
		return 0
	}
}

// resolveFamilyHintConcurrency bounds how many gateway family-hint lookups run
// at once inside resolveGatewayFamilyHints. Each dynamic-hostname lookup can
// block for up to resolveHostFamilyTimeout under DNS failure, so the cap keeps
// wall-clock cost at ~one timeout while bounding concurrent resolver goroutines
// (and file descriptors) for a pathologically large gateway set.
const resolveFamilyHintConcurrency = 8

// resolveGatewayFamilyHints computes the remote address-family hint for every
// gateway that needs an external-interface local-address resolution
// (LocalAddress unset, ExternalIface set) CONCURRENTLY, keyed by gateway name.
//
// gatewayRemoteFamilyHint performs a bounded (resolveHostFamilyTimeout) DNS
// lookup per dynamic-hostname gateway (#2757). PrepareConfig runs
// synchronously in the ordered commit apply, so resolving the hints
// sequentially stalled a multi-gateway commit up to N×timeout under DNS
// failure (#4547). The hint is per-gateway and order-independent, so a bounded
// worker pool that collects results by name is safe and yields the identical
// per-gateway result as the former inline sequential lookup — only the
// scheduling changes.
//
// Only gateways whose LocalAddress is resolved from ExternalIface are looked up
// here; gateways with an explicit LocalAddress never consult the hint, so
// skipping them avoids needless DNS traffic. Gateways with a literal remote
// Address (or a bare-IP hostname) resolve their hint without touching DNS, so
// the concurrency cap only matters for genuine dynamic-hostname sets.
func resolveGatewayFamilyHints(gateways map[string]*config.IPsecGateway) map[string]int {
	names := make([]string, 0, len(gateways))
	for name, gw := range gateways {
		if gw == nil {
			continue
		}
		if gw.LocalAddress == "" && gw.ExternalIface != "" {
			names = append(names, name)
		}
	}

	hints := make(map[string]int, len(names))
	if len(names) == 0 {
		return hints
	}

	// Results land in a per-index slice so no goroutine writes the shared
	// map — the map is assembled single-threaded after the pool drains.
	results := make([]int, len(names))
	sem := make(chan struct{}, resolveFamilyHintConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		sem <- struct{}{} // block until a worker slot frees — bounds concurrency
		go func(i int, gw *config.IPsecGateway) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = gatewayRemoteFamilyHint(gw)
		}(i, gateways[name])
	}
	wg.Wait()

	for i, name := range names {
		hints[name] = results[i]
	}
	return hints
}

// gatewayRemoteFamilyHint determines the address family (4, 6, or 0 for
// either) that the local-address for this gateway must match. A gateway with
// a literal remote Address takes the family of that IP. A dynamic-hostname
// gateway (Address empty, DynamicHostname set) is resolved via
// resolveHostFamily so the chosen local-address matches the family the peer
// actually resolves to (#2757) — previously the empty Address yielded a
// family-agnostic hint and the wrong-family local-address could win on a
// dual-stack appliance.
func gatewayRemoteFamilyHint(gw *config.IPsecGateway) int {
	if gw == nil {
		return 0
	}
	if gw.Address != "" {
		return addressFamilyHint(gw.Address)
	}
	if gw.DynamicHostname != "" {
		// A bare IP in the hostname slot still classifies directly.
		if f := addressFamilyHint(gw.DynamicHostname); f != 0 {
			return f
		}
		return resolveHostFamily(gw.DynamicHostname)
	}
	return 0
}

// prepareConfigFromConfig is PrepareConfig resolved from the configuration ALONE (#9641).
// It replays a stored generation's render without the kernel or DNS, neither of which can
// be replayed for the past. runtime names every gateway whose production local address
// could have come from either, and that gateway's LocalAddress is left empty here.
//
// It mirrors resolveInterfaceAddress. Production takes the configured unit address for
// the remote family hint when there is one, and asks the kernel only when there is not.
// So a configured address found here is exactly production's answer, and a miss is
// runtime. The hint mirrors gatewayRemoteFamilyHint without its DNS lookup, so a dynamic
// hostname that is not an IP literal is runtime too.
func prepareConfigFromConfig(cfg *config.Config) (*config.IPsecConfig, map[string]bool) {
	runtime := map[string]bool{}
	if cfg == nil {
		return nil, runtime
	}
	out := prepareConfig(cfg, func(name string, gw *config.IPsecGateway) string {
		family, ok := configuredGatewayFamilyHint(gw)
		if !ok {
			runtime[name] = true
			return ""
		}
		addr := resolveConfiguredInterfaceAddress(cfg, gw.ExternalIface, family)
		if addr == "" {
			runtime[name] = true
		}
		return addr
	})
	return out, runtime
}

// configuredGatewayFamilyHint is gatewayRemoteFamilyHint without the DNS lookup. ok is
// false for exactly the case gatewayRemoteFamilyHint resolves through DNS.
func configuredGatewayFamilyHint(gw *config.IPsecGateway) (family int, ok bool) {
	if gw == nil {
		return 0, true
	}
	if gw.Address != "" {
		return addressFamilyHint(gw.Address), true
	}
	if gw.DynamicHostname != "" {
		if f := addressFamilyHint(gw.DynamicHostname); f != 0 {
			return f, true
		}
		return 0, false
	}
	return 0, true
}

func resolveConfiguredInterfaceAddress(cfg *config.Config, ifaceRef string, family int) string {
	parts := strings.SplitN(ifaceRef, ".", 2)
	base := parts[0]
	unitNum := 0
	if len(parts) == 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			unitNum = n
		}
	}

	ifc, ok := cfg.Interfaces.Interfaces[base]
	if !ok {
		return ""
	}

	// Zone identifier for a link-local result is the KERNEL interface name of
	// the configured ifaceRef base (#2885) — the vSRX name xpfd renames to.
	//
	// #9137: resolve reth first. `reth<N>` is not a kernel netdev under
	// bondless RETH, which is the shipped HA model: xpfd programs the VRRP VIP
	// and virtual MAC on the PHYSICAL member and creates no reth device (the
	// dataplane's compiler_iface.go skips reth for the same reason). An
	// `external-interface reth0.0` therefore produced `fe80::1%reth0`, charon
	// could not if_nametoindex("reth0"), and the IKE SA never bound — from a
	// config that commits clean. This also makes the function agree with its
	// own sibling: the kernel-lookup fallback in resolveInterfaceAddressFamily
	// has resolved reth since it was written, so the asymmetry lived inside one
	// function pair. Both the unit branch and the bare-ref fallback below read
	// this variable, so one assignment covers both.
	//
	// ResolveReth returns the ref unchanged when the name is not a reth, so a
	// non-reth base is byte-identical to before. The empty guard covers the
	// degenerate binding where a member carries RedundantParent but no Name:
	// RethToPhysical then maps reth0 to "", and an EMPTY zone is strictly
	// WORSE than the wrong one — zoneQualify returns the address unqualified,
	// losing the #2885 disambiguation that is the whole point of the zone.
	zone := config.LinuxIfName(base)
	if resolved := config.LinuxIfName(cfg.ResolveReth(base)); resolved != "" {
		zone = resolved
	}

	if unit, ok := ifc.Units[unitNum]; ok {
		if addr := selectUnitAddress(unit, family); addr != "" {
			return zoneQualify(addr, zone)
		}
	}

	if len(parts) == 1 && len(ifc.Units) > 0 {
		unitIDs := make([]int, 0, len(ifc.Units))
		for id := range ifc.Units {
			unitIDs = append(unitIDs, id)
		}
		sort.Ints(unitIDs)
		for _, id := range unitIDs {
			if addr := selectUnitAddress(ifc.Units[id], family); addr != "" {
				return zoneQualify(addr, zone)
			}
		}
	}

	return ""
}

func selectUnitAddress(unit *config.InterfaceUnit, family int) string {
	if unit == nil {
		return ""
	}

	candidates := make([]string, 0, 2+len(unit.Addresses))
	candidates = append(candidates, unit.PrimaryAddress, unit.PreferredAddress)
	candidates = append(candidates, unit.Addresses...)
	// Global-wins is order-independent (#2885): selectFamilyAddress scans
	// family-6 candidates for a global address before admitting link-local.
	return selectFamilyAddress(candidates, family)
}

func resolveKernelInterfaceAddress(ifaceName string, family int) string {
	if ifaceName == "" {
		return ""
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	candidates := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		candidates = append(candidates, addr.String())
	}
	// A global address always wins over a link-local one regardless of
	// kernel enumeration order (#2885); zone-qualify a link-local result with
	// the interface name so strongSwan can disambiguate fe80:: on a
	// multi-interface box.
	if addr := selectFamilyAddress(candidates, family); addr != "" {
		return zoneQualify(addr, ifaceName)
	}
	return ""
}

// selectFamilyAddress chooses one address from candidates for the requested
// family. For family 6 it scans twice: the first pass admits only
// global-unicast addresses, and a link-local (fe80::/10) candidate is accepted
// only if no global address is present. This makes "global wins" independent of
// candidate enumeration order (config order or kernel order) — without it a
// link-local enumerated before the global IPv6 would be selected first (#2885).
// For family 4 and family-agnostic (0) selection, link-local is never admitted
// by matchFamily, so a single pass is sufficient.
func selectFamilyAddress(candidates []string, family int) string {
	if family == 6 {
		for _, c := range candidates {
			if ip := bareIPGlobalOnly(c); ip != "" {
				return ip
			}
		}
	}
	for _, c := range candidates {
		if ip := bareIP(c, family); ip != "" {
			return ip
		}
	}
	return ""
}

func bareIP(addr string, family int) string {
	ip := parseBareIP(addr)
	if ip == nil {
		return ""
	}
	return matchFamily(ip, family)
}

// bareIPGlobalOnly is bareIP restricted to global-unicast IPv6 — the first pass
// of the family-6 global-wins scan in selectFamilyAddress (#2885).
func bareIPGlobalOnly(addr string) string {
	ip := parseBareIP(addr)
	if ip == nil || !ip.IsGlobalUnicast() || ip.To4() != nil {
		return ""
	}
	return matchFamily(ip, 6)
}

func parseBareIP(addr string) net.IP {
	if addr == "" {
		return nil
	}
	if ip, _, err := net.ParseCIDR(addr); err == nil {
		return ip
	}
	return net.ParseIP(addr)
}

// zoneQualify appends the IPv6 zone (%<iface>) to a link-local source address
// so strongSwan/the kernel can pick the right interface when more than one
// interface carries an fe80:: address (#2885). Non-link-local addresses, an
// empty iface name, and addresses already carrying a zone are returned
// unchanged.
func zoneQualify(addr, ifaceName string) string {
	if ifaceName == "" || strings.Contains(addr, "%") {
		return addr
	}
	if ip := net.ParseIP(addr); ip != nil && ip.IsLinkLocalUnicast() && ip.To4() == nil {
		return addr + "%" + ifaceName
	}
	return addr
}

func addressFamilyHint(addr string) int {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func matchFamily(ip net.IP, family int) string {
	if ip == nil {
		return ""
	}
	// Global unicast covers the common case. IPv6 link-local unicast
	// (fe80::/10) is also a valid IPsec local-bind source on point-to-point
	// / link-local IPv6 links (#2885); IsGlobalUnicast() rejects it, so admit
	// it explicitly here. Multicast, unspecified, and loopback stay excluded.
	if !ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
		return ""
	}
	switch family {
	case 4:
		// IPv4 link-local (169.254.0.0/16) is not a usable IPsec source.
		if ip.IsLinkLocalUnicast() {
			return ""
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	case 6:
		if ip.To4() == nil {
			return ip.String()
		}
	default:
		// Family-agnostic selection: never surface a link-local address
		// implicitly — only an explicit family-6 hint may bind link-local.
		if ip.IsLinkLocalUnicast() {
			return ""
		}
		return ip.String()
	}
	return ""
}
