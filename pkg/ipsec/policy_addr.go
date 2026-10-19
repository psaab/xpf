package ipsec

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// PrepareConfig resolves runtime-only IPsec values from the full config.
// The returned config is a deep copy that can be safely mutated by the IPsec
// runtime without affecting the active config tree.
func PrepareConfig(cfg *config.Config) *config.IPsecConfig {
	if cfg == nil {
		return nil
	}
	// Family hints are pure: a literal remote address classifies directly
	// and a dynamic-hostname gateway is responder-only (#14590), so no DNS
	// lookup ever runs on the synchronous commit/apply path.
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
func interfaceRefUnit(cfg *config.Config, ifaceRef string) (*config.InterfaceConfig, int, bool) {
	if cfg == nil {
		return nil, 0, false
	}
	ref := cfg.SplitInterfaceUnitRef(ifaceRef)
	ifc := cfg.Interfaces.Interfaces[ref.Base]
	if ifc == nil {
		return nil, 0, false
	}
	if !ref.HasUnit {
		return ifc, 0, true
	}
	unitNum, err := strconv.Atoi(ref.UnitTok)
	if err != nil {
		return nil, 0, false
	}
	return ifc, unitNum, true
}

func interfaceRefIsDHCP(cfg *config.Config, ifaceRef string) bool {
	// RETH gateway references resolve to a physical member on bondless
	// clusters; check both the logical RETH unit and its active member.
	refs := []string{ifaceRef}
	if cfg != nil {
		if resolved := cfg.ResolveReth(ifaceRef); resolved != ifaceRef {
			refs = append(refs, resolved)
		}
	}
	for _, ref := range refs {
		ifc, unitNum, ok := interfaceRefUnit(cfg, ref)
		if !ok {
			continue
		}
		split := cfg.SplitInterfaceUnitRef(ref)
		if split.HasUnit {
			unit := ifc.Units[unitNum]
			if unit != nil && (unit.DHCP || unit.DHCPv6) {
				return true
			}
			continue
		}
		for _, unit := range ifc.Units {
			if unit != nil && (unit.DHCP || unit.DHCPv6) {
				return true
			}
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
// If the constrained family yields no local-address on the interface (the
// interface is single-stack in the other family), we fall back to a
// family-agnostic selection. A complete miss still returns ""; renderConfig
// treats that as an unresolved external-interface and skips the VPN rather
// than omitting local_addrs and allowing a bind to every local interface.
func resolveInterfaceAddress(cfg *config.Config, ifaceRef string, family int) string {
	if addr := resolveInterfaceAddressFamily(cfg, ifaceRef, family); addr != "" {
		return addr
	}
	if family != 0 {
		// The remote family has no matching local-address on this
		// interface — fall back to whatever the interface offers, then
		// report an empty result if neither family has an address.
		return resolveInterfaceAddressFamily(cfg, ifaceRef, 0)
	}
	return ""
}

func resolveInterfaceAddressFamily(cfg *config.Config, ifaceRef string, family int) string {
	if addr := resolveConfiguredInterfaceAddress(cfg, ifaceRef, family); addr != "" {
		return addr
	}

	resolvedRef := cfg.ResolveReth(ifaceRef)
	// ResolveKernelIfName maps Junos unit refs to the netdev actually
	// created by the kernel (unit-0 collapse, VLAN ID, IRB bridge, and
	// tunnel mapping). LinuxIfName only rewrites slashes and therefore
	// leaves unit suffixes that net.InterfaceByName cannot resolve.
	for _, name := range []string{
		cfg.ResolveKernelIfName(ifaceRef),
		cfg.ResolveKernelIfName(resolvedRef),
		config.LinuxIfName(resolvedRef),
		config.LinuxIfName(ifaceRef),
	} {
		if addr := resolveKernelInterfaceAddress(name, family); addr != "" {
			return addr
		}
	}

	return ""
}

// resolveGatewayFamilyHints computes the remote address-family hint for every
// gateway that needs an external-interface local-address resolution
// (LocalAddress unset, ExternalIface set), keyed by gateway name. The hint
// is pure — a literal address classifies directly and a dynamic-hostname
// gateway is responder-only with no remote family (#14590) — so no DNS
// lookup and no worker pool are involved.
func resolveGatewayFamilyHints(gateways map[string]*config.IPsecGateway) map[string]int {
	hints := make(map[string]int, len(gateways))
	for name, gw := range gateways {
		if gw == nil || gw.LocalAddress != "" || gw.ExternalIface == "" {
			continue
		}
		hints[name] = gatewayRemoteFamilyHint(gw)
	}
	return hints
}

// gatewayRemoteFamilyHint determines the address family (4, 6, or 0 for
// either) that the local-address for this gateway must match. A gateway with
// a literal remote Address takes the family of that IP. A dynamic-hostname
// gateway is responder-only (#14590): the peer dials in from an unknown
// address presenting the FQDN as its IKE identity, so there is no remote
// family to match and NO DNS lookup — the hint is family-agnostic (a bare
// IP literal in the identity slot still classifies directly, without DNS).
func gatewayRemoteFamilyHint(gw *config.IPsecGateway) int {
	if gw == nil {
		return 0
	}
	if gw.Address != "" {
		return addressFamilyHint(gw.Address)
	}
	if gw.DynamicHostname != "" {
		return addressFamilyHint(gw.DynamicHostname)
	}
	return 0
}

// prepareConfigFromConfig is PrepareConfig resolved from the configuration ALONE (#9641).
// It replays a stored generation's render without the kernel, which cannot be
// replayed for the past. runtime names every gateway whose production local
// address could have come from the kernel, and that gateway's LocalAddress is
// left empty here.
//
// It mirrors resolveInterfaceAddress. Production takes the configured unit
// address for the remote family hint when there is one, and asks the kernel
// only when there is not. So a configured address found here is exactly
// production's answer, and a miss is runtime. The hint is pure (#14590): a
// dynamic hostname is a responder identity, never DNS-resolved, so it is
// family-agnostic unless it is an IP literal.
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
		if addr == "" && family != 0 {
			// Match resolveInterfaceAddress's single-stack fallback. The
			// preferred family may be absent while the interface still has
			// a usable configured address from the other family.
			addr = resolveConfiguredInterfaceAddress(cfg, gw.ExternalIface, 0)
		}
		if addr == "" {
			runtime[name] = true
		}
		return addr
	})
	return out, runtime
}

// configuredGatewayFamilyHint mirrors gatewayRemoteFamilyHint; both are pure
// (#14590), so it always reports ok.
func configuredGatewayFamilyHint(gw *config.IPsecGateway) (family int, ok bool) {
	return gatewayRemoteFamilyHint(gw), true
}

func resolveConfiguredInterfaceAddress(cfg *config.Config, ifaceRef string, family int) string {
	ref := cfg.SplitInterfaceUnitRef(ifaceRef)
	base := ref.Base
	unitNum := 0
	if ref.HasUnit {
		if n, err := strconv.Atoi(ref.UnitTok); err == nil {
			unitNum = n
		}
	}

	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return ""
	}

	// A link-local result needs the kernel device of the selected unit,
	// not merely the configured base. ResolveKernelIfName handles VLAN
	// IDs, IRB bridge devices, unit-0 collapse and RETH mapping.
	kernelZone := func(ref string) string {
		if resolved := cfg.ResolveKernelIfName(ref); resolved != "" {
			return resolved
		}
		if resolved := config.LinuxIfName(cfg.ResolveReth(base)); resolved != "" {
			return resolved
		}
		// Keep the prior non-empty zone when RETH resolution is
		// degenerate: an unqualified link-local address loses the
		// interface disambiguation entirely.
		return config.LinuxIfName(base)
	}

	if unit, ok := ifc.Units[unitNum]; ok {
		if addr := selectUnitAddress(unit, family); addr != "" {
			return zoneQualify(addr, kernelZone(ifaceRef))
		}
	}

	if !ref.HasUnit && len(ifc.Units) > 0 {
		unitIDs := make([]int, 0, len(ifc.Units))
		for id := range ifc.Units {
			unitIDs = append(unitIDs, id)
		}
		sort.Ints(unitIDs)
		for _, id := range unitIDs {
			if addr := selectUnitAddress(ifc.Units[id], family); addr != "" {
				return zoneQualify(addr, kernelZone(fmt.Sprintf("%s.%d", base, id)))
			}
		}
	}

	return ""
}

func selectUnitAddress(unit *config.InterfaceUnit, family int) string {
	if unit == nil {
		return ""
	}

	candidates := make([]string, 0, 4+len(unit.Addresses))
	// #15653: per-family primaries first so the family's designated
	// address wins even when selectFamilyAddress is family-blind (-1).
	candidates = append(candidates, unit.PrimaryAddressForFamily(false), unit.PrimaryAddressForFamily(true),
		unit.PreferredAddressForFamily(false), unit.PreferredAddressForFamily(true))
	candidates = append(candidates, unit.Addresses...)
	groupIDs := make([]string, 0, len(unit.VRRPGroups))
	for id := range unit.VRRPGroups {
		groupIDs = append(groupIDs, id)
	}
	sort.Strings(groupIDs)
	for _, id := range groupIDs {
		if group := unit.VRRPGroups[id]; group != nil {
			candidates = append(candidates, group.VirtualAddresses...)
		}
	}
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
	// #15766: a multi-address gateway holds a comma-joined list; the
	// hint is the family of the first literal element (net.ParseIP on
	// the joined string always failed, silently yielding the
	// family-agnostic hint and resolving the wrong local address).
	// Hostname elements carry no family without DNS, so they are
	// skipped in favour of the first literal when one exists.
	for _, part := range config.SplitIPsecEndpointList(addr) {
		ip := net.ParseIP(part)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return 4
		}
		return 6
	}
	return 0
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
