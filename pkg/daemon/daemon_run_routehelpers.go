package daemon

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// riMemberLinuxName converts a routing-instance `interface` list entry
// (Junos name, e.g. "gr-0/0/0.0") to the Linux interface name the
// daemon_apply step-0a bind loop targets. SHARED between step 0a and
// the RIListMember scan in collectAppliedTunnels (#1884): the tunnel
// manager's unbind-veto/observation logic must mirror exactly what 0a
// binds — both callers MUST pass a tunMap built from the SAME cfg via
// cfg.TunnelNameMap().
//
// Tunnel refs resolve through tunMap (#1904): TunnelNameMap returns
// the compiler-assigned TunnelConfig.Name verbatim — the same field
// ApplyTunnels uses to create the kernel device — so a unit>0 member
// like gr-0/0/0.1 binds the real per-unit "uN" device gr-0-0-0u1
// (pkg/config/compiler_interfaces.go) and cannot diverge from the
// device-naming scheme by construction. Non-tunnel refs keep the
// literal pre-#1904 transform (LinuxIfName + unit-0 collapse)
// byte-identically; widening to the full cfg.ResolveKernelIfName
// (reth → physical member, st0.N verbatim, irb → bridge) would
// silently activate binds 0a has never performed and needs its own
// ratification.
// logicalUnitDeviceKey is THE derivation of the kernel device name for one
// configured logical unit, and the single source both sides of this file use.
//
// #8670-adjacent (#8597 K84/K85): the netdev for an 802.1Q sub-interface is
// named for the unit's VLAN ID, not its unit number. `set interfaces ge-0-0-1
// unit 10 vlan-id 100` is created by networkd as `ge-0-0-1.100`. #8321 finding
// 07 fixed the PRODUCER of `connectedByLogical` to key on the VLAN ID and left
// every CONSUMER deriving its lookup key with config.LinuxIfName(), which
// yields the unit number — so the producer wrote `ge-0-0-1.100` and the
// consumers looked up `ge-0-0-1.10` and missed. The consumers were not wrong
// about their own rule; they were agreeing with the rule as it stood BEFORE
// #8321. Extracting the rule is what stops the two sides drifting again.
//
// config.DHCPLeaseIfName looks similar and is NOT interchangeable: it has no
// unit-number fallback, so an untagged `unit 3` yields `base` there and
// `base.3` here. Its own doc calls unit number and VLAN ID "distinct concepts,
// bridged only here" — the invariant these consumers were violating.
//
// Deliberately NOT config.ResolveKernelIfName either, which additionally
// resolves reth -> local physical member and tunnel devices. The producer does
// neither, so routing a consumer through it would make `reth0.50` resolve to a
// physical member name the map is not keyed by — trading a miss for a
// different miss.
func logicalUnitDeviceKey(base string, unitNum int, unit *config.InterfaceUnit) string {
	if unit != nil && unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", base, unit.VlanID)
	}
	// A unit with no vlan-id is not a tagged sub-interface, and there
	// `base.<unit>` is correct — which is why this is not a substitution of
	// one field for the other (#8321).
	if unitNum != 0 {
		return fmt.Sprintf("%s.%d", base, unitNum)
	}
	return base
}

// logicalUnitDeviceKeyForRef resolves a cross-subsystem interface REFERENCE
// ("ge-0/0/1.10", "reth0.50") to the key logicalUnitDeviceKey would have built
// for that unit, so a consumer holding a config reference and the producer
// holding an (interface, unit) pair land on the same string.
//
// An unknown interface or an unparseable unit falls back to the pre-#8321
// spelling rather than inventing one: those refs resolved to `base.<unit>`
// before and still do, so this cannot turn a working lookup into a miss.
func logicalUnitDeviceKeyForRef(cfg *config.Config, ref string) string {
	canon := config.CanonicalInterfaceUnitRef(ref)
	baseRef, unitTok, hasUnit := strings.Cut(canon, ".")
	base := config.LinuxIfName(baseRef)
	if !hasUnit {
		return base
	}
	unitNum, _, err := config.CanonicalLogicalUnit(unitTok)
	if err != nil {
		return config.LinuxIfName(canon)
	}
	var unit *config.InterfaceUnit
	if cfg != nil && cfg.Interfaces.Interfaces != nil {
		if ifc, ok := cfg.Interfaces.Interfaces[baseRef]; ok && ifc != nil {
			unit = ifc.Units[unitNum]
		}
	}
	return logicalUnitDeviceKey(base, unitNum, unit)
}

func riMemberLinuxName(cfg *config.Config, tunMap map[string]string, ifaceName string) string {
	// #5878 phase 2: resolve the routing-instance member on its CANONICAL
	// logical-unit identity BEFORE the tunMap lookup so a `.01` member resolves
	// to the SAME device as `.1` (and as the interface's `unit 1`). TunnelNameMap
	// keys are built from the canonical int unit number
	// (ifName + "." + strconv.Itoa(unitNum)), so canonicalizing here makes BOTH
	// the tunnel-device path (tunMap hit) AND the LinuxIfName/unit-0-collapse path
	// use the canonical name — otherwise a peer-only
	// `groups node1 { routing-instances ri interface ge-0/0/0.01 }` reference
	// binds a DIFFERENT VRF/tunnel device on the standby (the #5878 HA-divergence
	// class at the netlink layer). Note the P1 alias gate
	// (validateInterfaceUnitAliasCollisionsAST) gates `interfaces ... unit`
	// DEFINITIONS, NOT routing-instance/zone membership REFERENCES, so it does not
	// prevent this reference divergence — the canonicalization does.
	ifaceName = config.CanonicalInterfaceUnitRef(ifaceName)
	if name, ok := tunMap[ifaceName]; ok && name != "" {
		return name
	}
	// #8597 K85: derive the device the same way the connected-prefix producer
	// does. This was config.LinuxIfName + a ".0" strip, which names a tagged
	// unit by its UNIT NUMBER — so a `unit 10 vlan-id 100` member resolved to
	// `ge-0-0-1.10`, a device that does not exist, and BindInterfaceToVRF
	// failed while the commit reported success and the member silently stayed
	// in the main table. The unit-0 collapse the strip performed is now the
	// `unitNum != 0` arm of logicalUnitDeviceKey.
	return logicalUnitDeviceKeyForRef(cfg, ifaceName)
}

func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
	if cfg == nil {
		return nil
	}
	anchorOnly := dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace
	// Linux interface name -> routing-instance whose `interface` list
	// names it, mirroring the step-0a bind loop (forwarding instances
	// skipped; shared normalization; later entries overwrite, matching
	// 0a's last-bind-wins iteration). Feeds TunnelConfig.RIListMember.
	riListMember := map[string]string{}
	tunMap := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" {
			continue
		}
		for _, ifaceName := range ri.Interfaces {
			riListMember[riMemberLinuxName(cfg, tunMap, ifaceName)] = ri.Name
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
			tc.RIListMember = riListMember[tc.Name]
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
			tc.RIListMember = riListMember[tc.Name]
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
	}

	var connected []connectedPrefix
	connectedByLogical := make(map[string][]connectedPrefix)
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
			// (logicalUnitDeviceKeyForRef) so the two sides cannot drift
			// apart again the way #8321 left them.
			logical = logicalUnitDeviceKey(base, unitNum, unit)
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
				}
				connected = append(connected, prefix)
				connectedByLogical[logical] = append(connectedByLogical[logical], prefix)
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
		// #8597 K84: keyed by the producer's rule, not by LinuxIfName —
		// otherwise a tagged unit whose vlan-id differs from its unit number
		// never matches and the VRF-scoped prefix is dropped.
		normalized := logicalUnitDeviceKeyForRef(cfg, ifName)
		var prefixes []connectedPrefix
		if entries, ok := connectedByLogical[normalized]; ok {
			prefixes = append(prefixes, entries...)
		}
		// #9063: expand to every sub-unit ONLY for a WHOLE-DEVICE reference.
		//
		// The test used to be on the NORMALIZED key, and `logicalUnitDeviceKey`
		// collapses a unit with no vlan-id and unit number 0 to the bare base --
		// correctly, because `ge-0-0-0` IS the kernel device name for that unit.
		// So `ge-0/0/0.0` and the whole-port `ge-0/0/0` produced the same key,
		// and a routine
		//
		//	routing-instances blue { interface ge-0/0/0.0; }
		//
		// pulled every `ge-0-0-0.<vlan>` prefix into the VRF pool as well.
		//
		// The raw REFERENCE keeps the distinction the key cannot: a reference
		// with a unit suffix names one unit, and one without names the port.
		// Both readings are legitimate and the config text is what separates
		// them.
		if !strings.Contains(ifName, ".") {
			prefixNames := make([]string, 0, len(connectedByLogical))
			for logical := range connectedByLogical {
				if strings.HasPrefix(logical, normalized+".") {
					prefixNames = append(prefixNames, logical)
				}
			}
			sort.Strings(prefixNames)
			for _, logical := range prefixNames {
				prefixes = append(prefixes, connectedByLogical[logical]...)
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

	// #9063: the value records whether the claim named the WHOLE DEVICE
	// (`ge-0/0/0`) rather than one unit (`ge-0/0/0.0`). Both normalize to the
	// same key, and only the first may exclude a port's other sub-units.
	claimedByVRF := make(map[string]bool)
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
				// #8597: the third site of the same family, named in neither
				// K84 nor K85. claimedByVRF is compared against producer-keyed
				// names below, so it must use the producer's rule too.
				normalized := logicalUnitDeviceKeyForRef(cfg, ifName)
				// #9063: record WHICH READING this claim is. The normalized key
				// cannot say -- `ge-0/0/0` and `ge-0/0/0.0` both key to
				// `ge-0-0-0` -- and the two mean different things to the
				// base-match exclusion below. The raw reference is the only
				// place the distinction survives.
				claimedByVRF[normalized] = !strings.Contains(ifName, ".")
			}
		}
	}
	if len(claimedByVRF) > 0 {
		filtered := connectedByVRF[""][:0]
		for _, prefix := range connectedByVRF[""] {
			base := prefix.ifName
			if idx := strings.IndexByte(base, '.'); idx >= 0 {
				base = base[:idx]
			}
			if _, claimed := claimedByVRF[prefix.ifName]; claimed {
				continue
			}
			// #9063: a BASE match excludes every sub-unit of that port, so it
			// may only fire for a claim that named the whole DEVICE.
			//
			// It used to fire for any claim whose key was bare -- and
			// `ge-0/0/0.0` has a bare key, because `ge-0-0-0` is the kernel
			// device name for unit 0. So a VRF holding one unit-0 member
			// discarded every `ge-0-0-0.<vlan>` prefix from the DEFAULT pool.
			//
			// For a global-unicast next-hop that is harmless: the render emits a
			// scopeless `ipv6 route <p> <gw>` and FRR resolves it recursively.
			// For a LINK-LOCAL next-hop it is not -- FRR rejects a scopeless
			// `ipv6 route <p> fe80::1`, so the static route never installs and
			// the prefix blackholes. A dual-tenant trunk (VRF on unit 0, a
			// tagged unit on the same port in the default table) is the routine
			// layout that reaches it.
			if wholeDevice, claimed := claimedByVRF[base]; claimed && wholeDevice {
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

// riMemberLinuxNames resolves a routing-instance member to EVERY kernel device
// it claims, which for a BARE member is the base netdev and all of its
// configured units.
//
// #9754: the bind loop called riMemberLinuxName once per member string, and for
// a bare member that returns the parent netdev alone. The 802.1Q children for
// the tagged units were created with no master and never enslaved, so
// kernel-path traffic on them routed in the DEFAULT instance -- failing OPEN to
// main on a config strict accepts with no warning. FRR/zebra reads interface VRF
// membership from the same kernel master, so those units' connected prefixes
// landed in the default VRF and VRF-bound sockets never saw them.
//
// A bare reference MEANS every unit everywhere else that reads one: the
// userspace routing-instance binder consumes InterfaceUnitRefKeys (#9132) and
// the DHCP route map keys every unit of a whole-device member. This makes the
// kernel bind read it the same way, through the SAME helper rather than a second
// fan-down that could drift from it.
//
// A UNIT reference still binds exactly that unit -- InterfaceUnitRefKeys does
// not fan up to the base, deliberately (#9063): the base row carries unit 0's
// addresses, so binding the base from a unit-1 reference would move unit 0's
// prefix into unit 1's instance.
//
// A tunnel or xfrmi member resolves to ONE device and is returned before the
// fan-down: TunnelNameMap is keyed on the canonical ref, those devices have no
// 802.1Q children, and fanning them down would invent names for units that have
// no netdev of their own.
func riMemberLinuxNames(cfg *config.Config, tunMap map[string]string, ifaceName string) []string {
	canon := config.CanonicalInterfaceUnitRef(ifaceName)
	if name, ok := tunMap[canon]; ok && name != "" {
		return []string{name}
	}
	refs := config.InterfaceUnitRefKeys(cfg, ifaceName)
	if len(refs) == 0 {
		return []string{riMemberLinuxName(cfg, tunMap, ifaceName)}
	}
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		name := riMemberLinuxName(cfg, tunMap, ref)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			// A unit with no vlan-id collapses onto the base device
			// (logicalUnitDeviceKey), so the base and unit 0 name one netdev.
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
