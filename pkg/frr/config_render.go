// config_render.go holds the non-protocol FRR config rendering helpers:
//
//   - generateInterfaceSettings: per-interface bandwidth + point-to-point hints
//     emitted before protocol config so OSPF auto-cost picks up bandwidth.
//   - generateStaticRoute:       per-prefix `ip route` / `ipv6 route` emission
//     with RETH name translation and IPv6 next-hop
//     interface resolution.
//   - renderGenerateRoutes:      blackhole static routes for `generate` routes.
//   - renderDHCPDefaults:        DHCP-learned default routes (AD 200), with
//     suppression when explicit static defaults exist.
//   - renderBackupRouter:        backup-router default (AD 250).
//   - renderClusterModeDefaults: cluster-mode blackhole defaults (AD 250).
//   - resolveECMP:               forwarding-table export policy → ecmpMaxPaths
//     and (side effect) fc.ConsistentHash.
package frr

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// DeclaredNetdevsForConfig builds the authored-interface → kernel-device map
// consumed by static-route rendering. In addition to interface declarations,
// it resolves every static-route interface reference and VPN bind spelling
// through Config.SecureTunnelUnitNetdev. That resolver must see the authored
// bind-interface because a bare st0 and explicit st0.0 can derive one if_id
// under different device names (#9942).
//
// Both daemon and standalone CLI FRR assembly paths use this constructor so
// their managed sections cannot disagree about secure-tunnel route devices.
func DeclaredNetdevsForConfig(cfg *config.Config, inferredIPv6 map[string]map[string]string) map[string]string {
	declared := make(map[string]string)
	if cfg == nil {
		return declared
	}
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		linuxName := config.LinuxIfName(name)
		declared[name] = linuxName
		declared[linuxName] = linuxName
	}

	refs := make([]string, 0)
	appendRouteIfaces := func(routes []*config.StaticRoute) {
		for _, sr := range routes {
			if sr == nil {
				continue
			}
			for _, nh := range sr.NextHops {
				if nh.Interface != "" {
					refs = append(refs, nh.Interface)
				}
			}
		}
	}
	appendRouteIfaces(cfg.RoutingOptions.StaticRoutes)
	appendRouteIfaces(cfg.RoutingOptions.Inet6StaticRoutes)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		appendRouteIfaces(ri.StaticRoutes)
		appendRouteIfaces(ri.Inet6StaticRoutes)
	}
	for _, byGateway := range inferredIPv6 {
		for _, iface := range byGateway {
			if iface != "" {
				refs = append(refs, iface)
			}
		}
	}
	for _, vpn := range cfg.Security.IPsec.VPNs {
		if vpn != nil && vpn.BindInterface != "" {
			refs = append(refs, vpn.BindInterface)
		}
	}
	addSecureTunnelNetdevs(declared, refs, cfg.SecureTunnelUnitNetdev)
	return declared
}

// addSecureTunnelNetdevs installs resolver results under both authored and
// Linux spellings. A map entry is added only when the config owns the secure
// tunnel reference, preserving ordinary interfaces' legacy `.0` behavior.
func addSecureTunnelNetdevs(declared map[string]string, refs []string, resolve func(string) (string, bool)) {
	if declared == nil || resolve == nil {
		return
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		dev, ok := resolve(ref)
		if !ok || dev == "" {
			continue
		}
		declared[ref] = dev
		declared[config.LinuxIfName(ref)] = dev
		declared[dev] = dev
	}
}

// generateInterfaceSettings emits FRR interface blocks for bandwidth and
// point-to-point network type. These are emitted before protocol config so
// OSPF auto-cost picks up the correct bandwidth.
func (m *Manager) generateInterfaceSettings(fc *FullConfig) string {
	if len(fc.InterfaceBandwidths) == 0 && len(fc.InterfacePointToPoint) == 0 {
		return ""
	}

	// Build set of interfaces that have explicit OSPF NetworkType so we don't override.
	ospfNetworkType := make(map[string]bool)
	if fc.OSPF != nil {
		for _, area := range fc.OSPF.Areas {
			for _, iface := range area.Interfaces {
				if iface.NetworkType != "" {
					ospfNetworkType[iface.Name] = true
				}
			}
		}
	}

	// Collect all interface names that need settings.
	ifaces := make(map[string]bool)
	for name := range fc.InterfaceBandwidths {
		ifaces[name] = true
	}
	for name := range fc.InterfacePointToPoint {
		if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
			ifaces[name] = true
		}
	}

	// Sort for deterministic output.
	names := make([]string, 0, len(ifaces))
	for name := range ifaces {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "interface %s\n", name)
		if bw, ok := fc.InterfaceBandwidths[name]; ok && bw > 0 {
			// FRR bandwidth command takes kbps
			kbps := bw / 1000
			if kbps == 0 {
				kbps = 1
			}
			fmt.Fprintf(&b, " bandwidth %d\n", kbps)
		}
		if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
			b.WriteString(" ip ospf network point-to-point\n")
		}
		b.WriteString("exit\n!\n")
	}
	return b.String()
}

// staticRouteRendersFIB reports whether generateStaticRouteInTable will emit
// at least one FRR FIB line for sr. It is the single source of truth for
// "does this static route install a route", shared by
// generateStaticRouteInTable's zero-next-hop early return and by
// renderDHCPDefaults' DHCP-default suppression (#5519) so the two can never
// disagree. It mirrors generateStaticRouteInTable's emit structure exactly:
//   - a next-table route is realized by an `ip rule` in the routing package,
//     not FRR, so it renders no FRR FIB line here;
//   - a discard/reject route renders a negative (Null0/reject) route;
//   - otherwise a route renders one line per next-hop, so it needs >= 1.
//
// A zero-next-hop, non-discard route (e.g. the last ECMP next-hop of a static
// default was deleted, #3872) renders nothing. Before #5519, renderDHCPDefaults
// treated ANY 0.0.0.0/0 static route as suppressing the DHCP-learned default,
// so such a route rendered no FIB entry yet still masked the DHCP fallback —
// leaving NO default route at all (WAN / management remote lockout). Deriving
// suppression from renderability closes that gap.
func staticRouteRendersFIB(sr *config.StaticRoute) bool {
	if sr.NextTable != "" {
		return false
	}
	return sr.Discard || sr.Reject || len(sr.NextHops) > 0
}

// generateStaticRoute produces FRR static route commands.
// Multiple next-hops produce one line each (FRR creates ECMP).
// Routes with NextTable are handled via ip rule (policy routing), not FRR.
// declaredNetdevs maps declared interface names (both spellings) to kernel
// devices (#9821); nil renders legacy behavior.
func (m *Manager) generateStaticRoute(sr *config.StaticRoute, vrfName string, rethMap map[string]string, ipv6NextHopInterfaces map[string]map[string]string, declaredNetdevs map[string]string) string {
	return m.generateStaticRouteInTable(sr, vrfName, 0, rethMap, ipv6NextHopInterfaces, declaredNetdevs)
}

// generateStaticRouteInTable is generateStaticRoute with an optional
// kernel routing-table override (#1827 PR-2). tableID > 0 emits a
// trailing "table <id>" so the route is installed into that kernel
// table instead of the default one — this is how `instance-type
// forwarding` routing instances render: no VRF device exists, but
// their routes belong in the instance's dedicated table (the same
// table the FBF/PBR `ip rule`s point at and the same table the
// userspace dataplane files under `<ri>.inet.0`). vrfName and tableID
// are mutually exclusive: FRR only accepts `table` on default-VRF
// statics, and forwarding instances always render with vrfName == "".
// declaredNetdevs (nil-safe, nil → legacy) is probed before the `.0`
// strip: declared names render their kernel device (#9821 #15v3 + D7).
func (m *Manager) generateStaticRouteInTable(sr *config.StaticRoute, vrfName string, tableID int, rethMap map[string]string, ipv6NextHopInterfaces map[string]map[string]string, declaredNetdevs map[string]string) string {
	if sr.NextTable != "" {
		return "" // handled via ip rule in routing package
	}
	// #6795: final operand-validity belt. Destination is a RAW STRING from the
	// parser, and it is interpolated into every `ip route` line this function
	// emits. A malformed value fails the WHOLE frr-reload — one vtysh
	// add-batch exits non-zero on any CMD_WARNING_CONFIG_FAILED — so a single
	// bad route takes every other route on the box with it; a value carrying
	// whitespace additionally splits into extra operands or an extra statement.
	// Commit validates it, but the tolerant load / HA config-sync paths only
	// warn (#1960 no-brick), so the renderer is the last place to stop it.
	// Skipping THIS route is the fail-closed answer: the alternative is losing
	// the entire managed section.
	if !validFRRRoutePrefix(sr.Destination) {
		return ""
	}
	isV6 := config.FRRAddrFamily(sr.Destination) == "v6"
	prefix := "ip"
	if isV6 {
		prefix = "ipv6"
	}

	vrfPart := ""
	if vrfName != "" {
		// Render belt (#5557): route the routing-instance name through
		// sanitizeFRRValue. The name is validated at commit, but the tolerant
		// load / HA config-sync paths only warn (#1960 no-brick), so a control
		// character reaching here could otherwise inject a second vtysh line
		// into the managed frr.conf. This is the single interpolation point for
		// the static-route `vrf <name>` clause, so it covers every static route
		// the function renders (v4/v6, discard/reject, ECMP). The routing
		// instance name reaches FRR through THREE vrf-interpolation sites, all
		// now sanitized: this static route, the `router <proto> ... vrf` clauses
		// (policy_render.go generateProtocols), and the `bfd` block's
		// `peer ... vrf` clause (policy_render.go bfdSection.render).
		vrfPart = " vrf " + sanitizeFRRValue(vrfName)
	} else if tableID > 0 {
		vrfPart = fmt.Sprintf(" table %d", tableID)
	}

	// Negative routes (no next-hop, single line). Junos `discard` and `reject`
	// both install an active route so matching traffic is dropped instead of
	// following a less-specific route, but differ in what the source sees:
	//   - discard → FRR Null0 (RTN_BLACKHOLE): silent drop, no ICMP.
	//   - reject  → FRR reject (RTN_UNREACHABLE): drop + ICMP unreachable.
	// Without this, a committed reject compiled to a no-next-hop route rendered
	// nothing (#5298) and the traffic fell through to the default — a fail-wide.
	if sr.Discard || sr.Reject {
		nexthop := "Null0"
		if sr.Reject {
			nexthop = "reject"
		}
		if sr.Preference > 0 {
			return fmt.Sprintf("%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, sr.Preference, vrfPart)
		}
		return fmt.Sprintf("%s route %s %s%s\n", prefix, sr.Destination, nexthop, vrfPart)
	}

	// A route with NO next-hops and no discard/reject action is incomplete —
	// e.g. every gateway of an ECMP `next-hop [ a b ]` list was deleted (#3872
	// delete-side). Render NOTHING rather than a Null0 blackhole: silently
	// blackholing traffic that would otherwise fall through to a default /
	// more-specific route is a fail-wide. (An explicit `discard`/`reject`
	// above still renders its negative-route line.) Gated through the shared
	// staticRouteRendersFIB predicate: at this point NextTable is empty and
	// discard/reject are already handled above, so this reduces exactly to
	// len(sr.NextHops) == 0 — but routing it through the predicate keeps this
	// emit test and renderDHCPDefaults' suppression test from drifting (#5519).
	if !staticRouteRendersFIB(sr) {
		return ""
	}

	// One line per next-hop → FRR creates ECMP.
	var b strings.Builder
	for _, nh := range sr.NextHops {
		// #9821/#9942: a declared interface or resolver-owned secure-tunnel
		// reference renders its kernel device before the generic `.0` strip.
		// The daemon's assembler feeds secure-tunnel route refs through
		// Config.SecureTunnelUnitNetdev while the authored bind spelling is
		// still available; this map probe is the render-side install guard.
		// For ordinary undeclared interfaces, preserve the legacy unit-zero
		// collapse below.
		ifName := nh.Interface
		if isV6 && ifName == "" && nh.Address != "" {
			ifName = ipv6NextHopInterfaces[vrfName][nh.Address]
		}
		if dev, ok := declaredNetdevs[ifName]; ok {
			ifName = dev
		} else if strings.HasSuffix(ifName, ".0") {
			// Strip Junos default unit suffix ".0" (e.g. "wan0.0" → "wan0")
			// for FRR kernel names. VLAN suffixes like ".50" in "wan0.50"
			// are real kernel interface names and must NOT be stripped.
			ifName = ifName[:len(ifName)-2]
		}
		// Resolve RETH names to physical member names (e.g. "reth0.50" → "ge-0-0-1.50").
		// FRR needs kernel interface names, not Junos RETH names.
		if len(rethMap) > 0 && ifName != "" {
			parts := strings.SplitN(ifName, ".", 2)
			if phys, ok := rethMap[parts[0]]; ok {
				phys = config.LinuxIfName(phys)
				if len(parts) == 2 {
					ifName = phys + "." + parts[1]
				} else {
					ifName = phys
				}
			}
		}

		// #6795: the same belt on the next-hop operands. Address and ifName are
		// raw strings assembled from config, RETH resolution and a `.vlan`
		// suffix; either can reach here malformed on the tolerant load /
		// peer-sync path. An unparseable gateway fails the frr-reload; one
		// carrying whitespace splits into extra operands or an extra statement.
		// Dropping the individual NEXT-HOP (not the whole route) is the right
		// granularity: a `next-hop [ a b ]` ECMP list with one bad member should
		// still install the good ones, and the no-next-hop case below already
		// renders nothing rather than a Null0 blackhole (#3872).
		if nh.Address != "" && !validFRRNextHopAddress(nh.Address) {
			continue
		}
		if ifName != "" && !validFRRInterfaceOperand(ifName) {
			continue
		}
		// #9820: family belt. An IPv6 destination with an IPv4 next-hop
		// renders a line FRR cannot use as a gateway route (FRR's `ipv6
		// route` grammar takes only an IPv6 gateway or an interface), so
		// the strict gate refuses it at commit and this belt omits the
		// next-hop — with a warning — on the tolerant load / peer-sync
		// path. Per-next-hop granularity, like the shape belt: one bad
		// ECMP member must not kill the good ones.
		//
		// Ordering is load-bearing: the destination shape check above
		// returned early for bad destinations, and the next-hop shape
		// check `continue`d for non-IP addresses (`@`-forms, bare
		// interface names), so both operands parse here and the family
		// comparison cannot misfire.
		if nh.Address != "" &&
			config.FRRAddrFamily(sr.Destination) == "v6" &&
			config.FRRAddrFamily(nh.Address) == "v4" {
			slog.Warn("frr: skipping a static-route next-hop: IPv6 destination "+
				"with IPv4 next-hop is unsupported (FRR's ipv6 route grammar takes "+
				"only an IPv6 gateway or an interface) (#9820)",
				"destination", sr.Destination, "next_hop", nh.Address)
			continue
		}
		var nexthop string
		switch {
		case nh.Address != "" && ifName != "":
			nexthop = nh.Address + " " + ifName
		case nh.Address != "":
			nexthop = nh.Address
		case ifName != "":
			nexthop = ifName
		default:
			continue
		}
		// Per-next-hop admin distance (#3871): a qualified-next-hop carries
		// its own preference (HasPreference) and renders as a FLOATING backup
		// at that distance; a plain next-hop uses the route-level distance so
		// a `next-hop [ a b ]` list stays equal-cost ECMP. FRR installs the
		// lowest-distance reachable next-hop and fails over to the higher-
		// distance one only when the primary is down. FRR's static-route CLI
		// has no metric field, so nh.Metric is not emitted — the floating
		// behavior comes entirely from the distance.
		dist := sr.Preference
		if nh.HasPreference {
			dist = nh.Preference
		}
		if dist > 0 {
			fmt.Fprintf(&b, "%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, dist, vrfPart)
		} else {
			fmt.Fprintf(&b, "%s route %s %s%s\n", prefix, sr.Destination, nexthop, vrfPart)
		}
	}
	return b.String()
}

// renderGenerateRoutes emits one blackhole static route per generate-route
// (Junos `routing-options generate route X`). v4 vs v6 is picked by the
// presence of ":" in the prefix.
func renderGenerateRoutes(b *strings.Builder, fc *FullConfig) {
	if len(fc.GenerateRoutes) == 0 {
		return
	}
	for _, gr := range fc.GenerateRoutes {
		// #6795: same belt. A generate-route renders a blackhole, so a
		// malformed prefix here fails the frr-reload and takes every route with
		// it — and a blackhole is the one route shape where a mangled operand
		// could silently widen what is dropped.
		if !validFRRRoutePrefix(gr.Prefix) {
			continue
		}
		if strings.Contains(gr.Prefix, ":") {
			fmt.Fprintf(b, "ipv6 route %s blackhole\n", gr.Prefix)
		} else {
			fmt.Fprintf(b, "ip route %s blackhole\n", gr.Prefix)
		}
	}
	b.WriteString("!\n")
}

// instanceRouteTarget resolves a BARE routing-instance name (as carried by
// DHCPRoute.VRF and RouteOverlayEntry.RoutingInstance) to the FRR rendering
// target for a route that belongs to it.
//
// The bare name is NOT a namespace FRR knows. A `virtual-router` instance is
// backed by the kernel device `vrf-<name>` (pkg/routing/vrf.go), which is what
// InstanceConfig.VRFName carries; an `instance-type forwarding` instance has no
// VRF device at all, so daemon_ipmon.go sets VRFName="" and its routes belong in
// the instance's dedicated kernel table (#1827 PR-2 — the same table the FBF
// `ip rule`s and the dataplane's `<ri>.inet.0` snapshot target).
//
// A lookup MISS falls back to the historical "vrf-<name>" rendering, per the
// InstanceConfig.Name doc, rather than to the bare name or to nothing.
//
// #9136 extracted this from renderPreferredRoutes so renderDHCPDefaults cannot
// disagree with it. It had: renderDHCPDefaults interpolated the bare name, so a
// DHCP-learned tenant default named a VRF that does not exist, and a forwarding
// instance was given a `vrf` clause it can never have.
func instanceRouteTarget(instances []InstanceConfig, name string) (vrfName string, tableID int) {
	if name == "" {
		return "", 0
	}
	vrfName = "vrf-" + name
	for i := range instances {
		if instances[i].Name != name {
			continue
		}
		vrfName = instances[i].VRFName
		if vrfName == "" {
			tableID = instances[i].TableID
		}
		break
	}
	return vrfName, tableID
}

// renderDHCPDefaults emits DHCP-learned routes at admin distance 200: the
// default route (option-3 gateway or the option-121 0.0.0.0/0 entry) plus
// any RFC 3442 classless static routes (option 121 / legacy 249), each
// carried on its DHCPRoute with a non-empty Destination. The default route
// is suppressed when a static default route of the same address family
// actually RENDERS a FIB entry (staticRouteRendersFIB) so the management
// interface's DHCP gateway doesn't compete with configured routes; a static
// 0.0.0.0/0 (or ::/0) stanza that renders nothing — a zero-next-hop,
// non-discard default (#3872) — does NOT suppress the DHCP fallback, else no
// default route is installed at all (#5519, remote lockout). Classless static
// routes are more-specific and are never suppressed by a static default. Both
// families bind the route to the originating interface when the lease records
// one (dr.Interface != ""), so that in multi-WAN / shared-gateway-IP
// deployments the kernel can pick the correct egress instead of leaving an
// ambiguous gateway-only default.
func renderDHCPDefaults(b *strings.Builder, fc *FullConfig) {
	if len(fc.DHCPRoutes) == 0 {
		return
	}
	// Suppression is derived from the static default's ACTUAL renderability, not
	// merely the presence of a 0.0.0.0/0 (or ::/0) stanza (#5519). A static
	// default that renders NO FIB entry — a zero-next-hop, non-discard route
	// left behind after the last ECMP next-hop was deleted (#3872) — must NOT
	// suppress the DHCP-learned fallback: otherwise the config installs no
	// default route at all (WAN / management remote lockout). Only a static
	// default that actually renders a FIB entry (has next-hop(s) or is an
	// explicit discard/reject) suppresses the DHCP default, matching the
	// pre-#5519 behavior for those cases exactly.
	// #8963: suppression is PER-VRF. The comparison read only the top-level
	// static lists, so a static default INSIDE a routing instance neither
	// suppressed nor was suppressed by the DHCP-learned one -- the instance
	// could end up with both, and the default context's static could suppress
	// a DHCP default that belongs to an instance entirely.
	//
	// Keyed on the same VRF name the route carries, with "" the default
	// context, so the existing top-level behaviour is the "" entry and is
	// unchanged.
	hasV4Default := map[string]bool{}
	hasV6Default := map[string]bool{}
	for _, sr := range fc.StaticRoutes {
		if sr.Destination == "0.0.0.0/0" && staticRouteRendersFIB(sr) {
			hasV4Default[""] = true
			break
		}
	}
	for _, sr := range fc.Inet6StaticRoutes {
		if sr.Destination == "::/0" && staticRouteRendersFIB(sr) {
			hasV6Default[""] = true
			break
		}
	}
	for _, inst := range fc.Instances {
		if inst.Name == "" {
			continue
		}
		for _, sr := range inst.StaticRoutes {
			if sr.Destination == "0.0.0.0/0" && staticRouteRendersFIB(sr) {
				hasV4Default[inst.Name] = true
				break
			}
		}
		for _, sr := range inst.Inet6StaticRoutes {
			if sr.Destination == "::/0" && staticRouteRendersFIB(sr) {
				hasV6Default[inst.Name] = true
				break
			}
		}
	}
	wrote := false
	for _, dr := range fc.DHCPRoutes {
		// Destination: empty means the default route; a non-empty value is
		// an RFC 3442 classless static route (option 121 / legacy 249).
		dest := dr.Destination
		isDefault := dest == "" || dest == "0.0.0.0/0" || dest == "::/0"
		if isDefault {
			// A configured static default of the same family suppresses the
			// DHCP-learned default (a static default wins). This suppression
			// applies ONLY to the default route — classless static routes are
			// more-specific and must not be dropped by a static default.
			if dr.IsIPv6 {
				dest = "::/0"
				if hasV6Default[dr.VRF] {
					continue
				}
			} else {
				dest = "0.0.0.0/0"
				if hasV4Default[dr.VRF] {
					continue
				}
			}
		}
		// #9136: dr.VRF is the BARE instance name (the suppression maps above
		// key on it, and are internally consistent that way). FRR knows the
		// kernel namespace, not the Junos one, so resolve through the shared
		// instanceRouteTarget — `vrf vrf-<name>` for a virtual-router,
		// `table <id>` for a forwarding instance, which has no VRF device.
		// This previously emitted `vrf <bare>`, naming a VRF that does not
		// exist, so the tenant's DHCP-learned default never reached its table.
		//
		// #8963: the clause goes through sanitizeFRRValue for the same #5557
		// reason the static-route clause is sanitized -- the tolerant load / HA
		// config-sync paths only warn, so a control character reaching here
		// could inject a second vtysh line into the managed frr.conf. This is
		// the single interpolation point for the DHCP route's vrf clause,
		// matching how the static renderer keeps that property. The `table`
		// arm needs no belt: TableID is an int.
		vrfPart := ""
		if vrfName, tableID := instanceRouteTarget(fc.Instances, dr.VRF); vrfName != "" {
			vrfPart = " vrf " + sanitizeFRRValue(vrfName)
		} else if tableID > 0 {
			vrfPart = fmt.Sprintf(" table %d", tableID)
		}
		if dr.IsIPv6 {
			if ifn, drop := dhcpRouteInterface(dr); drop {
				// #9501: unusable interface operand on a link-local gateway; the route is dropped.
			} else if ifn != "" {
				fmt.Fprintf(b, "ipv6 route %s %s %s 200%s\n", dest, dr.Gateway, ifn, vrfPart)
			} else {
				fmt.Fprintf(b, "ipv6 route %s %s 200%s\n", dest, dr.Gateway, vrfPart)
			}
		} else {
			if ifn, drop := dhcpRouteInterface(dr); drop {
				// #9501: unusable interface operand on a link-local gateway; the route is dropped.
			} else if ifn != "" {
				fmt.Fprintf(b, "ip route %s %s %s 200%s\n", dest, dr.Gateway, ifn, vrfPart)
			} else {
				fmt.Fprintf(b, "ip route %s %s 200%s\n", dest, dr.Gateway, vrfPart)
			}
		}
		wrote = true
	}
	if wrote {
		b.WriteString("!\n")
	}
}

// renderBackupRouter emits the system backup-router as a fallback default
// gateway with admin distance 250.
func renderBackupRouter(b *strings.Builder, fc *FullConfig) {
	if fc.BackupRouter == "" {
		return
	}
	// #8597 (muse-004 K24): the same #6795 belt generateStaticRouteInTable
	// carries, on the backup-router operands it was never extended to.
	//
	// The gap was a VALIDATOR/RENDERER DISAGREEMENT, not a missing check in
	// isolation. validateBackupRouterDst (compiler_system.go, #4808/#2911)
	// rejects a malformed next-hop, a malformed destination, and a
	// next-hop/destination FAMILY MISMATCH at strict commit — and on the
	// tolerant Store.Load / Store.SyncApply path downgrades each to a warning
	// whose text ends "(ignored: backup-router default route not installed
	// until corrected)". This renderer ignored nothing: it interpolated the
	// value verbatim, so the promise in the log was false and the line it
	// emitted failed the WHOLE managed-section reload. One vtysh add-batch
	// exits non-zero on any CMD_WARNING_CONFIG_FAILED, so every other route on
	// the box goes with it, and the operator's log actively points AWAY from
	// the cause.
	//
	// All FOUR of the validator's checks are mirrored (malformed next-hop,
	// mapped next-hop, malformed destination, family mismatch), not the two
	// an operand-shape reading suggests. A v4 next-hop with a v6 destination
	// individually well-formed on both operands and still renders
	// `ipv6 route <v6dst> <v4nh>`, which fills the interface-name slot
	// (normally inactive absent a same-named interface — #9820 corrected
	// the old blanket "frr-reload rejects" mechanism claim).
	//
	// Skipping is the fail-closed answer, and it is what the validator already
	// told the operator would happen. The alternative is losing the entire
	// managed section, which takes the routes that ARE valid with it.
	if !validFRRNextHopAddress(fc.BackupRouter) {
		slog.Warn("frr: skipping backup-router route: next-hop is not a "+
			"valid IP gateway address",
			"next_hop", fc.BackupRouter, "issue", "#8597")
		return
	}
	if fc.BackupRouterDst != "" && !validFRRRoutePrefix(fc.BackupRouterDst) {
		slog.Warn("frr: skipping backup-router default route: destination is not a "+
			"renderable prefix",
			"next_hop", fc.BackupRouter, "destination", fc.BackupRouterDst,
			"issue", "#8597")
		return
	}
	// #9820: an IPv4-mapped next-hop is refused at commit (product
	// restriction) and skipped here on the tolerant path, before the
	// family comparison it would otherwise pass or fail under a false
	// reason (it previously rendered `ipv6 route ::/0 ::ffff:… 250`).
	if config.FRRAddrIsMapped(fc.BackupRouter) {
		slog.Warn("frr: skipping backup-router route: IPv4-mapped IPv6 "+
			"next-hops are not supported for backup-router (the commit-time "+
			"gate warned this route would be ignored)",
			"next_hop", fc.BackupRouter, "issue", "#9820")
		return
	}
	if fc.BackupRouterDst != "" &&
		config.FRRAddrFamily(fc.BackupRouterDst) != config.FRRAddrFamily(fc.BackupRouter) {
		slog.Warn("frr: skipping backup-router route: destination family does "+
			"not match next-hop family; backup-router requires a next-hop and "+
			"destination of the same address family (#9820)",
			"next_hop", fc.BackupRouter, "destination", fc.BackupRouterDst,
			"issue", "#9820")
		return
	}
	// Match the route prefix family to the next-hop (backup-router) family,
	// not the destination family. An IPv6 backup-router with an empty/default
	// destination must default to ::/0 and emit `ipv6 route ::/0 <v6nh>`;
	// a v6 next-hop wants a v6 default. (The old comment claimed the
	// `0.0.0.0/0` alternative — `ip route 0.0.0.0/0 <v6nh>` — is
	// frr-reload-rejected; `ip route` in fact accepts a v6 gateway, so the
	// default is about intent, not reload survival. #9820.)
	nhV6 := config.FRRAddrFamily(fc.BackupRouter) == "v6"
	dst := fc.BackupRouterDst
	if dst == "" {
		if nhV6 {
			dst = "::/0"
		} else {
			dst = "0.0.0.0/0"
		}
	}
	prefix := "ip"
	if nhV6 || config.FRRAddrFamily(dst) == "v6" {
		prefix = "ipv6"
	}
	fmt.Fprintf(b, "%s route %s %s 250\n", prefix, dst, fc.BackupRouter)
	b.WriteString("!\n")
}

// renderPreferredRoutes emits the ip-monitoring effective-route overlay
// (#1827 PR-1b) as DISTANCE-1 statics — Static/1 on SRX — into the
// master table, the entry's routing-instance VRF, or (for
// `instance-type forwarding` instances, #1827 PR-2) the instance's
// dedicated kernel table. The overlay is already winner-resolved (one
// entry per (instance, prefix), pkg/ipmon §4.1), so emission is
// mechanical. Reuses generateStaticRouteInTable so RETH name
// translation behaves exactly like configured statics.
func (m *Manager) renderPreferredRoutes(b *strings.Builder, fc *FullConfig) {
	if len(fc.PreferredRoutes) == 0 {
		return
	}
	for _, entry := range fc.PreferredRoutes {
		vrfName, tableID := instanceRouteTarget(fc.Instances, entry.RoutingInstance)
		sr := &config.StaticRoute{
			Destination: entry.Destination,
			Preference:  1,
			NextHops:    []config.NextHopEntry{{Address: entry.NextHop}},
		}
		b.WriteString(m.generateStaticRouteInTable(sr, vrfName, tableID, fc.RethMap, fc.IPv6NextHopInterfaces, fc.DeclaredNetdevs))
	}
	b.WriteString("!\n")
}

// renderClusterModeDefaults emits cluster-mode blackhole default routes
// (admin distance 250) for both address families. When the WAN VIP moves to
// the peer and FRR withdraws the real default, this blackhole makes
// bpf_fib_lookup return BLACKHOLE (not NOT_FWDED), triggering zone-encoded
// fabric redirect for new connections. AD=250 ensures real defaults (AD=5,
// DHCP AD=200) take priority.
func renderClusterModeDefaults(b *strings.Builder, fc *FullConfig) {
	if !fc.ClusterMode {
		return
	}
	fmt.Fprintf(b, "ip route 0.0.0.0/0 Null0 250\n")
	fmt.Fprintf(b, "ipv6 route ::/0 Null0 250\n")
	b.WriteString("!\n")
}

// resolveECMP inspects the forwarding-table export policy referenced by
// fc.ForwardingTableExport and returns the ecmpMaxPaths value that should
// be applied to BGP/OSPF.
//
// Side effect: sets fc.ConsistentHash to true when the policy uses
// "load-balance consistent-hash". The daemon reads fc.ConsistentHash after
// ApplyFull returns to decide whether to flip
// net.ipv4.fib_multipath_hash_policy=1 for L4 ECMP hashing. Audited callers
// of ApplyFull read fc.ConsistentHash only after ApplyFull returns, so the
// mid-call mutation is safe.
func resolveECMP(fc *FullConfig) int {
	ecmpMaxPaths := 0
	if fc.ForwardingTableExport == "" || fc.PolicyOptions == nil {
		return ecmpMaxPaths
	}
	ps, ok := fc.PolicyOptions.PolicyStatements[fc.ForwardingTableExport]
	if !ok {
		return ecmpMaxPaths
	}
	for _, term := range ps.Terms {
		if term.LoadBalance != "" {
			ecmpMaxPaths = 64
		}
		if term.LoadBalance == "consistent-hash" {
			fc.ConsistentHash = true
		}
	}
	return ecmpMaxPaths
}
