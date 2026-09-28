package daemon

import (
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
	if cfg == nil {
		return nil
	}
	anchorOnly := dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace
	// Linux interface name -> routing-instance whose `interface` list
	// names it. Forwarding instances do not bind Linux VRFs; contested devices
	// and tunnel-stanza-owned devices are excluded from list ownership. Feeds
	// TunnelConfig.RIListMember only for tunnel-manager observation, not binding.
	riListMember := map[string]string{}
	tunMap := cfg.TunnelNameMap()
	multiClaimed := config.RoutingInstanceDualClaimedLinuxNames(cfg, tunMap)
	stanzaOwned := tunnelsWithTheirOwnRIStanza(cfg)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" {
			continue
		}
		for _, linuxName := range config.RoutingInstanceMemberLinuxNamesForInstance(cfg, tunMap, ri) {
			if !multiClaimed[linuxName] && !stanzaOwned[linuxName] {
				riListMember[linuxName] = ri.Name
			}
		}
	}
	var tunnels []*config.TunnelConfig
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		// WireGuard tunnels carry no GRE-style local `source` (the peer
		// lives in WgEndpoint; the local side is just a listen port), so
		// the Source!="" gate that screens half-configured GRE/IPIP
		// stanzas must not drop them. Found live in #1736 S2b: without
		// this, `interfaces wgN tunnel mode wireguard` compiled and fed
		// the dataplane snapshot, but applyWireguardTunLocked never ran,
		// so the persistent wgN TUN was never created and the Rust
		// control thread's open_tun failed. The dataplane side already
		// special-cases the missing source
		// (pkg/dataplane/userspace/tunnels.go); this is the routing-side
		// twin.
		// #9156: ONE predicate, shared with EmitTunnelEndpointNames. This gate
		// used to be `Source != "" || Mode == "wireguard"`, which admitted a
		// tunnel with a source and NO destination — while the emitter, which
		// requires both, gave the dataplane no endpoint for it. The device was
		// created, brought up and addressed, and every packet routed into it
		// disappeared. Refusing to create it turns a silent blackhole into an
		// absent interface plus this warning.
		if ifc.Tunnel != nil && !config.TunnelHasUsableEndpoints(ifc.Tunnel) {
			slog.Warn("tunnel not applied: missing endpoint",
				"interface", ifc.Tunnel.Name,
				"mode", ifc.Tunnel.Mode,
				"source", ifc.Tunnel.Source,
				"destination", ifc.Tunnel.Destination,
				"issue", "#9156")
		}
		if ifc.Tunnel != nil && config.TunnelHasUsableEndpoints(ifc.Tunnel) {
			tc := *ifc.Tunnel
			tc.AnchorOnly = anchorOnly
			tc.MTU = ifc.MTU
			if stanzaOwned[tc.Name] {
				tc.RIListMember = ""
			} else {
				tc.RIListMember = riListMember[tc.Name]
			}
			tunnels = append(tunnels, &tc)
		}
		for _, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			// #9156: the per-unit loop screened NOTHING. A unit tunnel with no
			// endpoints at all reached applyAnchorLocked, which has no endpoint
			// check either, so it was created and brought up. This is the same
			// shared predicate the interface-level arm and the emitter use.
			if !config.TunnelHasUsableEndpoints(unit.Tunnel) {
				slog.Warn("unit tunnel not applied: missing endpoint",
					"interface", unit.Tunnel.Name,
					"mode", unit.Tunnel.Mode,
					"source", unit.Tunnel.Source,
					"destination", unit.Tunnel.Destination,
					"issue", "#9156")
				continue
			}
			tc := *unit.Tunnel
			tc.AnchorOnly = anchorOnly
			// Unit-level MTU overrides interface-level, mirroring the
			// compiler_iface precedence (#1884).
			tc.MTU = ifc.MTU
			if unit.MTU > 0 {
				tc.MTU = unit.MTU
			}
			if stanzaOwned[tc.Name] {
				tc.RIListMember = ""
			} else {
				tc.RIListMember = riListMember[tc.Name]
			}
			tunnels = append(tunnels, &tc)
		}
	}
	return tunnels
}

// linkLocalV6Net is the fe80::/64 prefix every IPv6-capable interface
// carries implicitly (the kernel auto-assigns a link-local address; it is
// never declared under unit.Addresses). It is the synthetic connected
// prefix used to resolve an unqualified link-local static next-hop
// (#2452) to an interface scope, which FRR requires for `ipv6 route <dst>
// fe80::x <iface>`.
var linkLocalV6Net = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("fe80::/64")
	return n
}()

func inferIPv6StaticNextHopInterfaces(cfg *config.Config, overlay []config.RouteOverlayEntry) map[string]map[string]string {
	type connectedPrefix struct {
		net       *net.IPNet
		ifName    string
		bits      int
		linkLocal bool // synthetic fe80::/64 candidate (#2452)
		// #9821 D2: structural ownership — the declared config-spelling
		// interface and unit number that produced this prefix. Claims
		// match on (owner, unitNum), never on device-spelling inference,
		// so a unit device that looks like another interface's base
		// (`p.0.2` vs `p.0`) cannot be misattributed by suffix shape.
		owner   string
		unitNum int
	}

	var connected []connectedPrefix
	connectedByOwner := make(map[string][]connectedPrefix)
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for ifName := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		base := config.LinuxIfName(ifName)
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			logical := base
			// #8321 finding 07: the netdev is named for the VLAN ID, not the
			// unit number. An 802.1q sub-interface where they differ --
			// `set interfaces ge-0-0-1 unit 10 vlan-id 100` -- is created by
			// networkd as `ge-0-0-1.100`, and formatting `ge-0-0-1.10` here made
			// the FRR static route name an interface that does not exist, so
			// zebra flagged it inactive and blackholed the route.
			//
			// Every other site in this tree already does it this way, which is
			// what makes the convention unambiguous rather than a judgement:
			// daemon_dhcp.go:311-315 (the shape mirrored here, including the
			// unit fallback), daemon_ha_vip.go:327/393/678, and
			// daemon_neighbor.go:130. This was the one that did not.
			//
			// The fallback matters: a unit with NO vlan-id is not a tagged
			// sub-interface, and there `base.<unit>` is correct -- which is why
			// this is not simply a substitution of one field for the other.
			// #8597 K84/K85: the rule is shared with the consumers below
			// (config.LogicalUnitDeviceKeyForRef) so the two sides cannot drift
			// apart again the way #8321 left them.
			logical = config.LogicalUnitDeviceKey(base, unitNum, unit)
			// ipv6OnUnit tracks whether this logical unit participates in
			// IPv6 at all, so it earns a synthetic fe80::/64 candidate even
			// when it only carries a VRRP virtual address (bondless RETH,
			// #2452 secondary / agy-13).
			ipv6OnUnit := false
			addPrefix := func(ipNet *net.IPNet, linkLocal bool) {
				bits, _ := ipNet.Mask.Size()
				prefix := connectedPrefix{
					net:       ipNet,
					ifName:    logical,
					bits:      bits,
					linkLocal: linkLocal,
					owner:     ifName,
					unitNum:   unitNum,
				}
				connected = append(connected, prefix)
				connectedByOwner[ifName] = append(connectedByOwner[ifName], prefix)
			}
			for _, addr := range unit.Addresses {
				ip, ipNet, err := net.ParseCIDR(addr)
				if err != nil || ip == nil || ip.To4() != nil {
					continue
				}
				ipv6OnUnit = true
				addPrefix(ipNet, false)
			}
			// VRRP virtual-address subnets (#2452 secondary): a bondless
			// RETH member may carry only the VIP with no matching
			// unit.Addresses entry, so a next-hop inside the VIP subnet
			// would otherwise fail to resolve. The actual VIP lives in
			// VRRPGroup.VirtualAddresses (the map VALUE) as a CIDR string
			// (pkg/vrrp parses it with netlink.ParseAddr); the VRRPGroups
			// map KEY is "<CIDR>_grp<id>" (compiler_interfaces.go) and is
			// NOT a parseable address. Read the VIPs from the value and add
			// each VIP subnet as a connected prefix on the member interface.
			for _, vg := range unit.VRRPGroups {
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					ip, ipNet, err := net.ParseCIDR(vip)
					if err != nil || ip == nil || ip.To4() != nil {
						continue
					}
					ipv6OnUnit = true
					addPrefix(ipNet, false)
				}
			}
			if ipv6OnUnit {
				addPrefix(linkLocalV6Net, true)
			}
		}
	}

	// resolve maps an unqualified IPv6 next-hop to an interface scope by
	// longest-prefix match against the connected/synthetic candidates.
	//
	// Global-unicast next-hops use the normal longest-prefix + deterministic
	// (lexicographically-smallest interface) tie-break, ignoring the
	// synthetic fe80::/64 candidates entirely.
	//
	// Link-local next-hops (#2452) are interface-scoped and inherently
	// ambiguous: a fe80::x next-hop matches every interface's synthetic
	// fe80::/64. We resolve such a next-hop ONLY when exactly one IPv6-
	// capable interface is present in the candidate set (the single
	// defensible answer). With multiple IPv6 interfaces and no explicit
	// interface qualifier, we refuse to guess (return "") rather than route
	// to the wrong link — the operator must qualify the next-hop with
	// `interface <name>` (which is honoured directly by the FRR renderer and
	// never reaches this inference path).
	resolve := func(candidates []connectedPrefix, addr string) string {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil {
			return ""
		}
		if ip.IsLinkLocalUnicast() {
			llIfaces := make(map[string]struct{})
			for _, candidate := range candidates {
				if candidate.linkLocal {
					llIfaces[candidate.ifName] = struct{}{}
				}
			}
			if len(llIfaces) != 1 {
				return "" // none → unresolvable; multiple → ambiguous, don't guess
			}
			for ifName := range llIfaces {
				return ifName
			}
			return ""
		}
		bestIf := ""
		bestBits := -1
		for _, candidate := range candidates {
			if candidate.linkLocal {
				continue // synthetic fe80::/64 only serves link-local next-hops
			}
			if !candidate.net.Contains(ip) {
				continue
			}
			if candidate.bits > bestBits || (candidate.bits == bestBits && (bestIf == "" || candidate.ifName < bestIf)) {
				bestIf = candidate.ifName
				bestBits = candidate.bits
			}
		}
		return bestIf
	}

	collectPrefixesForInterface := func(ifName string) []connectedPrefix {
		// #9821 D2: claims match on structural ownership (owner, unitNum),
		// never on device-spelling inference. The member resolves to a
		// declared base (+ optional unit) through the shared 4-level alias
		// order; a whole-device reading admits every unit of the owner, a
		// unit reading admits exactly that configured unit number.
		//
		// #9063 (whole vs unit-0) is preserved structurally: the whole/unit
		// distinction comes from the member's own reading (!HasUnit), not
		// from a device key both readings share — `ge-0/0/0` admits all of
		// owner `ge-0/0/0`, while `ge-0/0/0.0` admits only unitNum 0.
		//
		// Two deliberate consequences of matching configured unit NUMBERS
		// rather than device spellings: (a) a member that textually nests a
		// separately-declared interface (`unknown` vs declared `unknown.5`)
		// claims nothing — there is no ownership; (b) vlan-id addressing
		// (`B.100` for unit 10 with vlan-id 100) misses — units are
		// addressed by unit number, aligning pools with the member-units
		// consumers (which already key on the configured unit).
		claim := config.ResolveRoutingInstanceMemberBase(cfg, ifName)
		if !claim.OK {
			return nil
		}
		var prefixes []connectedPrefix
		for _, prefix := range connectedByOwner[claim.Base] {
			if !claim.HasUnit || prefix.unitNum == claim.Unit {
				prefixes = append(prefixes, prefix)
			}
		}
		return prefixes
	}

	resolved := make(map[string]map[string]string)
	connectedByVRF := map[string][]connectedPrefix{
		"": append([]connectedPrefix(nil), connected...),
	}
	setResolved := func(vrfName, nextHop, ifName string) {
		if ifName == "" {
			return
		}
		vrfMap, ok := resolved[vrfName]
		if !ok {
			vrfMap = make(map[string]string)
			resolved[vrfName] = vrfMap
		}
		if existing, ok := vrfMap[nextHop]; !ok || ifName < existing {
			vrfMap[nextHop] = ifName
		}
	}
	addRoutes := func(vrfName string, routes []*config.StaticRoute) {
		candidates := connectedByVRF[vrfName]
		for _, sr := range routes {
			for _, nh := range sr.NextHops {
				if nh.Interface != "" || nh.Address == "" || !strings.Contains(nh.Address, ":") {
					continue
				}
				setResolved(vrfName, nh.Address, resolve(candidates, nh.Address))
			}
		}
	}

	// #9821 D2: the default-pool exclusion uses the SAME structural predicate
	// as collection (replacing the claimedByVRF string map + exact/base
	// probes + first-cut normalization). A claim excludes a default prefix
	// iff owner and (whole or unit) match — so a whole-device claim excludes
	// every sub-unit of that port (#9063: only a whole reading may), while a
	// unit claim excludes exactly its unit, and a claim never excludes a
	// separately-declared interface that merely nests textually.
	//
	// Forwarding-instance members do not exclude (their vrfName IS the
	// default pool) — preserved from the legacy `vrfName != ""` gate.
	var vrfClaims []config.MemberDeclaredBase
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		if ri.InstanceType == "forwarding" {
			vrfName = ""
		}
		for _, ifName := range ri.Interfaces {
			prefixes := collectPrefixesForInterface(ifName)
			if len(prefixes) == 0 {
				continue
			}
			connectedByVRF[vrfName] = append(connectedByVRF[vrfName], prefixes...)
			if vrfName != "" {
				if claim := config.ResolveRoutingInstanceMemberBase(cfg, ifName); claim.OK {
					vrfClaims = append(vrfClaims, claim)
				}
			}
		}
	}
	if len(vrfClaims) > 0 {
		filtered := connectedByVRF[""][:0]
		for _, prefix := range connectedByVRF[""] {
			excluded := false
			for _, claim := range vrfClaims {
				if prefix.owner == claim.Base && (!claim.HasUnit || prefix.unitNum == claim.Unit) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
			filtered = append(filtered, prefix)
		}
		connectedByVRF[""] = filtered
	}

	addRoutes("", cfg.RoutingOptions.StaticRoutes)
	addRoutes("", cfg.RoutingOptions.Inet6StaticRoutes)
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		if ri.InstanceType == "forwarding" {
			vrfName = ""
		}
		addRoutes(vrfName, ri.StaticRoutes)
		addRoutes(vrfName, ri.Inet6StaticRoutes)
	}

	// #3759: feed the ip-monitoring effective-route overlay's literal
	// next-hops through the SAME resolution as configured statics. The
	// overlay renders via generateStaticRouteInTable with this exact
	// IPv6NextHopInterfaces map (renderPreferredRoutes), so a link-local
	// preferred-route next-hop (fe80::…, common for an IPv6 WAN gateway)
	// needs an interface scope attached here — FRR rejects a scopeless
	// `ipv6 route ::/0 fe80::1`. Previously the overlay entries were never
	// fed in, so the map was always absent for the failover gateway and the
	// route silently failed to install exactly when a link went down. The
	// per-entry VRF key must match what renderPreferredRoutes passes to
	// generateStaticRouteInTable: "" for the master table AND for
	// instance-type forwarding (which renders via `table <id>`, vrfName ==
	// ""), "vrf-<name>" for a virtual-router instance. A global-unicast
	// next-hop resolves by longest-prefix as usual (bare if it matches no
	// connected subnet — FRR accepts a scopeless global next-hop); an
	// ambiguous or unresolvable link-local stays unresolved, exactly like a
	// static route (the operator must add a disambiguating interface).
	for _, entry := range overlay {
		if entry.NextHop == "" || !strings.Contains(entry.NextHop, ":") {
			continue
		}
		vrfName := ""
		if entry.RoutingInstance != "" {
			vrfName = "vrf-" + entry.RoutingInstance
			for _, ri := range cfg.RoutingInstances {
				if ri != nil && ri.Name == entry.RoutingInstance {
					if ri.InstanceType == "forwarding" {
						vrfName = ""
					}
					break
				}
			}
		}
		setResolved(vrfName, entry.NextHop, resolve(connectedByVRF[vrfName], entry.NextHop))
	}
	return resolved
}
