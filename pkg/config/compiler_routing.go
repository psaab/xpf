package config

import (
	"fmt"
	"strconv"
	"strings"
)

func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig) error {
	// Parse autonomous-system
	if asNode := node.FindChild("autonomous-system"); asNode != nil {
		if v := nodeVal(asNode); v != "" {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				ro.AutonomousSystem = uint32(n)
			}
		}
	}

	// Parse forwarding-table { export <policy>; }
	//
	// #6659: read EVERY value. The leaf is declared `multi: true`, so
	// `export [ p1 p2 ]` collapses onto Keys[1:] and `export { p1; p2; }` onto
	// Children; nodeVal kept only the first, which meant the second policy was
	// neither rendered NOR reference-checked — a dangling reference in slot 2
	// committed clean. The strict gate now rejects a multi-valued list.
	//
	// #6673: the SCALAR keeps the verbatim pre-#6659 statement — FindChild plus
	// nodeVal, assigned once per compileRoutingOptions invocation. It is NOT
	// ForwardingTableExports[0]. Two authoring shapes make the two differ, and
	// both change which policy the FRR renderer installs:
	//
	//   - an EMPTY value in the first slot. `export [ "" p1 ];`, `export [ ];
	//     export p1;`, `export { ""; p1; }` and the flat-set `export ""` +
	//     `export p1` pair all select "" (no export policy) under nodeVal, but
	//     [0] over an empty-filtered list selects p1 — silently ENABLING an
	//     ECMP/consistent-hash policy the operator had blanked out.
	//   - two top-level `routing-options` roots (a `load override` artifact:
	//     the parser keeps repeated same-key blocks as separate siblings, and
	//     compiler_dispatch.go calls this function for each). The scalar
	//     assignment re-runs per root, so the LAST root wins, exactly as before
	//     #6659; an append-then-[0] made the FIRST root win instead.
	//
	// The plural still accumulates across roots, which is what the reference
	// gate wants (every named policy must exist) and what makes the cardinality
	// gate see the ambiguity.
	//
	// #6714: the LIST accumulates across every `forwarding-table` block, the
	// SCALAR still comes from the first one.
	//
	// The parser keeps repeated same-keyed blocks as siblings, so
	// `forwarding-table { export p1; } forwarding-table { export p2; }` inside
	// ONE `routing-options` root is two nodes. The pre-#6714 FindChild read
	// took the first block only, which left p2 invisible to BOTH halves: it was
	// neither rendered NOR reference-checked, and the cardinality gate below
	// could not see the ambiguity it exists to reject, so the config committed
	// clean while exactly one of the two authored policies took effect. That is
	// the same defect as the `export` LEAF one line down, one level up the tree.
	//
	// Only the plural widens. ForwardingTableExport is the value the FRR
	// renderer installs, and master selected it from the FIRST block; keeping
	// that binding means this change cannot move which policy renders on any
	// config, it can only make an ambiguous one operator-visible — strict
	// rejects at commit, tolerant load / peer-sync warns and renders the same
	// policy as before (#1960 no-brick). Two blocks naming the SAME policy
	// still commit clean: validateForwardingTableExportSingleStrict counts
	// DISTINCT non-empty values (#6673).
	for i, ftNode := range node.FindChildren("forwarding-table") {
		for _, expNode := range ftNode.FindChildren("export") {
			ro.ForwardingTableExports = append(ro.ForwardingTableExports, multiLeafAuthoredValues(expNode)...)
		}
		// The FIRST block, not the first block that HAS an export: master
		// resolved `forwarding-table` with FindChild and then looked for an
		// export inside whatever it got, so a leading export-less block left
		// the scalar unset. Selecting the next block's export instead would
		// make this change render a policy master did not, which is the one
		// thing it must not do.
		if i > 0 {
			continue
		}
		if expNode := ftNode.FindChild("export"); expNode != nil {
			ro.ForwardingTableExport = nodeVal(expNode)
		}
	}

	// Parse rib inet6.0 { static { route ... } }
	// In routing-instances, the rib name is "<instance>.inet6.0" (e.g., "ATT.inet6.0").
	for _, ribNode := range node.FindChildren("rib") {
		ribName := nodeVal(ribNode)
		if ribName == "inet6.0" || strings.HasSuffix(ribName, ".inet6.0") {
			if ribStatic := ribNode.FindChild("static"); ribStatic != nil {
				ro.Inet6StaticRoutes = compileStaticRoutes(ribStatic, ro.Inet6StaticRoutes)
			}
		}
	}

	staticNode := node.FindChild("static")
	if staticNode != nil {
		ro.StaticRoutes = compileStaticRoutes(staticNode, ro.StaticRoutes)
	}

	// Parse rib-groups
	if rgNode := node.FindChild("rib-groups"); rgNode != nil {
		if ro.RibGroups == nil {
			ro.RibGroups = make(map[string]*RibGroup)
		}
		for _, inst := range namedInstances(rgNode.FindChildren("")) {
			rg := compileRibGroup(inst.name, inst.node)
			ro.RibGroups[rg.Name] = rg
		}
		// Also handle direct children (non-named instances)
		for _, child := range rgNode.Children {
			name := child.Name()
			if _, exists := ro.RibGroups[name]; exists {
				continue
			}
			rg := compileRibGroup(name, child)
			ro.RibGroups[rg.Name] = rg
		}
	}

	// Parse generate routes (aggregate routes)
	if genNode := node.FindChild("generate"); genNode != nil {
		for _, routeNode := range genNode.FindChildren("route") {
			prefix := nodeVal(routeNode)
			if prefix == "" {
				continue
			}
			gr := &GenerateRoute{Prefix: prefix}
			if policyNode := routeNode.FindChild("policy"); policyNode != nil {
				gr.Policy = nodeVal(policyNode)
			}
			if routeNode.FindChild("discard") != nil {
				gr.Discard = true
			}
			// Also handle inline keys: "route X/Y discard" or "route X/Y policy Z"
			for i := 2; i < len(routeNode.Keys); i++ {
				switch routeNode.Keys[i] {
				case "discard":
					gr.Discard = true
				case "policy":
					if i+1 < len(routeNode.Keys) {
						gr.Policy = routeNode.Keys[i+1]
						i++
					}
				}
			}
			ro.GenerateRoutes = append(ro.GenerateRoutes, gr)
		}
	}

	// Parse global interface-routes { rib-group { inet X; inet6 Y; } }
	if irNode := node.FindChild("interface-routes"); irNode != nil {
		if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
			for _, rgChild := range rgNode.Children {
				switch rgChild.Name() {
				case "inet":
					ro.InterfaceRoutesRibGroup = nodeVal(rgChild)
				case "inet6":
					ro.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
				}
			}
			// Also handle inline: "rib-group inet NAME" or "rib-group inet6 NAME"
			for i := 1; i < len(rgNode.Keys)-1; i++ {
				switch rgNode.Keys[i] {
				case "inet":
					ro.InterfaceRoutesRibGroup = rgNode.Keys[i+1]
				case "inet6":
					ro.InterfaceRoutesRibGroupV6 = rgNode.Keys[i+1]
				}
			}
		}
	}

	return nil
}

// isRouteInlineKeyword reports whether tok is a static-route clause keyword in
// the fully-inline route-keys form (`route <dst> next-hop a b qualified-next-hop
// ...`). Used to bound a multi-value next-hop gateway run (#3872) so it stops
// at the next clause instead of swallowing a following keyword as a gateway.
func isRouteInlineKeyword(tok string) bool {
	switch tok {
	case "next-hop", "qualified-next-hop", "next-table", "discard", "reject", "preference", "metric", "interface":
		return true
	}
	return false
}

// compileStaticRoutes parses static route entries from a "static" node,
// appending to and returning the updated slice.
func compileStaticRoutes(staticNode *Node, existing []*StaticRoute) []*StaticRoute {
	// Track destination→index so flat "set" duplicates merge into one route.
	destIdx := make(map[string]int)
	for i, sr := range existing {
		destIdx[sr.Destination] = i
	}

	for _, routeInst := range namedInstances(staticNode.FindChildren("route")) {
		route := &StaticRoute{
			Destination: routeInst.name,
			Preference:  5, // default
		}

		// Handle inline keys: "route ::/0 next-hop 2001:db8::1" has all in Keys
		if len(routeInst.node.Children) == 0 && len(routeInst.node.Keys) > 2 {
			for i := 2; i < len(routeInst.node.Keys); i++ {
				switch routeInst.node.Keys[i] {
				case "next-hop":
					// Absorb a collapsed bracket list `next-hop [ a b ]` in the
					// fully-inline form: consume consecutive gateway tokens
					// until the next route keyword, installing each as an
					// equal-cost next-hop (#3872).
					var addrs []string
					for i+1 < len(routeInst.node.Keys) && !isRouteInlineKeyword(routeInst.node.Keys[i+1]) {
						i++
						addrs = append(addrs, routeInst.node.Keys[i])
					}
					// A single-gateway next-hop may carry a trailing `interface
					// <if>` egress modifier (#3881). In the fully-inline route-keys
					// form (`route <dst> next-hop fe80::1 interface reth0.50` — no
					// braces) `interface` is a route keyword, so the gateway run
					// above stops before it; without this the modifier is dropped.
					// For an IPv6 link-local next-hop the egress interface is
					// REQUIRED (a link-local gateway is unresolvable without it).
					// Consume the modifier ONLY after ≥1 gateway is parsed, so a
					// bare-first `interface` token stays a gateway value, not the
					// modifier.
					iface := ""
					if len(addrs) > 0 && i+2 < len(routeInst.node.Keys) && routeInst.node.Keys[i+1] == "interface" {
						iface = routeInst.node.Keys[i+2]
						i += 2
					}
					for _, a := range addrs {
						route.NextHops = append(route.NextHops, NextHopEntry{Address: a, Interface: iface})
					}
				case "next-table":
					if i+1 < len(routeInst.node.Keys) {
						i++
						route.NextTableRaw = routeInst.node.Keys[i]
						route.NextTable = parseNextTableInstance(routeInst.node.Keys[i])
					}
				case "qualified-next-hop":
					if i+1 < len(routeInst.node.Keys) {
						i++
						nh := NextHopEntry{Address: routeInst.node.Keys[i]}
						// Consume trailing modifiers in the fully-inline form:
						// "qualified-next-hop <gw> interface <if> preference <n>
						// metric <m>" (#3871). Each modifier carries its own
						// per-next-hop preference/metric — the floating backup's
						// admin distance — never folded into the route level.
						for i+2 < len(routeInst.node.Keys) {
							kw := routeInst.node.Keys[i+1]
							val := routeInst.node.Keys[i+2]
							consumed := true
							switch kw {
							case "interface":
								nh.Interface = val
							case "preference":
								if n, err := strconv.Atoi(val); err == nil {
									nh.Preference = n
									nh.HasPreference = true
								}
							case "metric":
								if n, err := strconv.Atoi(val); err == nil {
									nh.Metric = n
									nh.HasMetric = true
								}
							default:
								consumed = false
							}
							if !consumed {
								break
							}
							i += 2
						}
						route.NextHops = append(route.NextHops, nh)
					}
				case "discard":
					route.Discard = true
				case "reject":
					route.Reject = true
				case "preference":
					if i+1 < len(routeInst.node.Keys) {
						i++
						if n, err := strconv.Atoi(routeInst.node.Keys[i]); err == nil {
							route.Preference = n
						}
					}
				}
			}
		}

		// Handle children (hierarchical syntax)
		for _, prop := range routeInst.node.Children {
			switch prop.Name() {
			case "next-hop":
				// #3872: `next-hop [ gw1 gw2 ]` is canonical Junos ECMP — the
				// bracket list collapses onto Keys=["next-hop", gw1, gw2, ...]
				// in both AST shapes (multi leaf). Read EVERY gateway and
				// install each as an equal-cost next-hop; reading only Keys[1]
				// silently dropped all but the first. A single-gateway form may
				// carry an `interface <if>` modifier (IPv6 link-local), inline
				// on the keys (`next-hop fe80::1 interface reth0.50`) or as a
				// child node — that egress interface applies to the gateway(s).
				var addrs []string
				iface := ""
				for j := 1; j < len(prop.Keys); j++ {
					// Treat `interface` as the egress modifier only after ≥1
					// gateway has been parsed (#3881). A next-hop value literally
					// named "interface" as the FIRST token is a gateway, not the
					// modifier keyword.
					if prop.Keys[j] == "interface" && len(addrs) > 0 {
						if j+1 < len(prop.Keys) {
							iface = prop.Keys[j+1]
							j++
						}
						continue
					}
					addrs = append(addrs, prop.Keys[j])
				}
				// Child interface (hierarchical + flat-set container shapes).
				for _, child := range prop.Children {
					if child.Name() == "interface" {
						iface = nodeVal(child)
					}
				}
				if len(addrs) == 0 && iface != "" {
					// interface-only next-hop (unnumbered) — keep one entry.
					route.NextHops = append(route.NextHops, NextHopEntry{Interface: iface})
				}
				for _, a := range addrs {
					route.NextHops = append(route.NextHops, NextHopEntry{Address: a, Interface: iface})
				}
			case "discard":
				route.Discard = true
			case "reject":
				route.Reject = true
			case "preference":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						route.Preference = n
					}
				}
			case "qualified-next-hop":
				// A qualified-next-hop is a FLOATING backup: it carries its own
				// preference (admin distance) and optional metric, kept
				// PER-next-hop rather than folded into the route-level
				// Preference (#3871). preference/metric/interface arrive as
				// nested children (canonical separate `set` lines and the
				// hierarchical brace form) or as inline keys (single-line block
				// parse), so read both shapes.
				nh := NextHopEntry{}
				nh.Address = nodeVal(prop)
				// Inline keys: "qualified-next-hop <gw> interface <if> preference <n> metric <m>".
				for j := 2; j+1 < len(prop.Keys); j++ {
					switch prop.Keys[j] {
					case "interface":
						nh.Interface = prop.Keys[j+1]
					case "preference":
						if n, err := strconv.Atoi(prop.Keys[j+1]); err == nil {
							nh.Preference = n
							nh.HasPreference = true
						}
					case "metric":
						if n, err := strconv.Atoi(prop.Keys[j+1]); err == nil {
							nh.Metric = n
							nh.HasMetric = true
						}
					}
				}
				// Child nodes (flat-set separate lines + hierarchical brace form).
				if ifNode := prop.FindChild("interface"); ifNode != nil {
					nh.Interface = nodeVal(ifNode)
				}
				if pNode := prop.FindChild("preference"); pNode != nil {
					if n, err := strconv.Atoi(nodeVal(pNode)); err == nil {
						nh.Preference = n
						nh.HasPreference = true
					}
				}
				if mNode := prop.FindChild("metric"); mNode != nil {
					if n, err := strconv.Atoi(nodeVal(mNode)); err == nil {
						nh.Metric = n
						nh.HasMetric = true
					}
				}
				route.NextHops = append(route.NextHops, nh)
			case "next-table":
				if v := nodeVal(prop); v != "" {
					route.NextTableRaw = v
					route.NextTable = parseNextTableInstance(v)
				}
			}
		}

		// Merge routes with the same destination (flat "set" syntax creates duplicates).
		if idx, exists := destIdx[route.Destination]; exists {
			existingRoute := existing[idx]
			existingRoute.NextHops = append(existingRoute.NextHops, route.NextHops...)
			if route.Discard {
				existingRoute.Discard = true
			}
			if route.Reject {
				existingRoute.Reject = true
			}
			if route.Preference != 5 {
				existingRoute.Preference = route.Preference
			}
			if route.NextTable != "" {
				existingRoute.NextTable = route.NextTable
				existingRoute.NextTableRaw = route.NextTableRaw
			}
		} else {
			destIdx[route.Destination] = len(existing)
			existing = append(existing, route)
		}
	}
	return existing
}

// parseNextTableInstance extracts the routing instance name from a Junos
// next-table value like "Comcast-GigabitPro.inet.0" → "Comcast-GigabitPro".
func parseNextTableInstance(table string) string {
	// Strip the trailing .inet.N / .inet6.N table suffix to get the routing
	// instance name. A next-table target is always "<instance>.<family>.<index>",
	// so the family+index separator is the LAST ".inet" occurrence, not the
	// first. strings.Index truncated a routing-instance NAME that itself
	// contained ".inet" (an accepted dotted instance, e.g. "a.inet.b" whose
	// table is "a.inet.b.inet.0") at the embedded ".inet", corrupting the
	// emitted next-table identity to "a" and misrouting the leak (#5632). Anchor
	// on the trailing suffix with LastIndex; for a single-".inet" table the two
	// are identical, so ordinary names are unaffected.
	if idx := strings.LastIndex(table, ".inet"); idx > 0 {
		return table[:idx]
	}
	return table
}

func compileRoutingInstances(node *Node, cfg *Config) error {
	// Assign each routing-instance a STABLE kernel routing table id derived from
	// its NAME (#3855), never a positional counter. Positional assignment
	// (100, 101, … by config order) renumbered every survivor after a deleted
	// or reordered instance, so pkg/routing/vrf.go saw a stale table id on an
	// UNTOUCHED VRF and deleted+recreated its live device — a forwarding outage
	// on an unrelated VRF, on both HA nodes. A name-hashed id is invariant under
	// add/remove/reorder of siblings. See StableRoutingInstanceTableID.
	for _, child := range node.Children {
		if child.IsLeaf || len(child.Keys) == 0 {
			continue
		}
		instanceName := child.Keys[0]
		ri := &RoutingInstanceConfig{
			Name:    instanceName,
			TableID: StableRoutingInstanceTableID(instanceName),
		}

		for _, prop := range child.Children {
			switch prop.Name() {
			case "description":
				ri.Description = nodeVal(prop)
			case "instance-type":
				ri.InstanceType = nodeVal(prop)
			case "interface":
				// Multi-value leaf (#3904): `interface [ i1 i2 ]` collapses
				// onto Keys[1:] (this is an opaque implicit leaf) and/or child
				// nodes in both AST shapes. Read EVERY interface via
				// firewallMatchValues; the prior nodeVal(prop) read kept only
				// the first, stranding the remaining ports OUTSIDE the routing-
				// instance (they stayed in the default table — a VRF isolation
				// break).
				ri.Interfaces = append(ri.Interfaces, firewallMatchValues(prop)...)
			case "routing-options":
				var ro RoutingOptionsConfig
				if err := compileRoutingOptions(prop, &ro); err != nil {
					return fmt.Errorf("instance %s routing-options: %w", instanceName, err)
				}
				ri.StaticRoutes = ro.StaticRoutes
				ri.Inet6StaticRoutes = ro.Inet6StaticRoutes
				// #3870: capture the instance-level autonomous-system so a
				// per-instance BGP that omits local-as can inherit it (falling
				// back to the global routing-options AS in resolveBGPAutonomousSystem).
				ri.AutonomousSystem = ro.AutonomousSystem
				// Parse interface-routes rib-group
				if irNode := prop.FindChild("interface-routes"); irNode != nil {
					if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
						for _, rgChild := range rgNode.Children {
							switch rgChild.Name() {
							case "inet":
								ri.InterfaceRoutesRibGroup = nodeVal(rgChild)
							case "inet6":
								ri.InterfaceRoutesRibGroupV6 = nodeVal(rgChild)
							}
						}
						// Also handle inline: "rib-group inet NAME"
						for i := 1; i < len(rgNode.Keys)-1; i++ {
							switch rgNode.Keys[i] {
							case "inet":
								ri.InterfaceRoutesRibGroup = rgNode.Keys[i+1]
							case "inet6":
								ri.InterfaceRoutesRibGroupV6 = rgNode.Keys[i+1]
							}
						}
					}
				}
			case "protocols":
				var proto ProtocolsConfig
				if err := compileProtocols(prop, &proto); err != nil {
					return fmt.Errorf("instance %s protocols: %w", instanceName, err)
				}
				ri.OSPF = proto.OSPF
				ri.OSPFv3 = proto.OSPFv3
				ri.BGP = proto.BGP
				ri.RIP = proto.RIP
				ri.ISIS = proto.ISIS
			}
		}

		cfg.RoutingInstances = append(cfg.RoutingInstances, ri)
	}

	// #3855: enforce the never-share-a-table invariant. StableRoutingInstanceTableID
	// folds into a 900k-slot reserved band so a collision is astronomically
	// rare, and the strict commit gate (validateRoutingInstanceTableIDCollisionAST)
	// rejects one outright — but if we are reached on a lenient path (tolerant
	// load / peer-sync / a config a pre-#3855 binary persisted) with two names
	// folding to the same kernel table, DROP the later-sorting instance rather
	// than let two vrf-<name> devices bind the same table (a cross-VRF route
	// leak). This is the runtime half of #3719's zone quarantine, ported to
	// routing-instance tables; the decision matches QuarantinedRoutingInstanceNames
	// exactly so both HA nodes drop the identical instance.
	if len(cfg.RoutingInstances) > 1 {
		names := make([]string, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			names = append(names, ri.Name)
		}
		if quarantined := QuarantinedRoutingInstanceNames(names); len(quarantined) > 0 {
			kept := cfg.RoutingInstances[:0]
			for _, ri := range cfg.RoutingInstances {
				if _, drop := quarantined[ri.Name]; drop {
					cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
						"routing-instance %q QUARANTINED: its stable table id %d collides with"+
							" another instance's — no VRF created, its routes and inter-VRF"+
							" leaks are not programmed until one instance is renamed (#3855)",
						ri.Name, ri.TableID))
					continue
				}
				kept = append(kept, ri)
			}
			cfg.RoutingInstances = kept
		}
	}
	return nil
}

// resolveBGPAutonomousSystem fills a BGP local-AS from `routing-options
// autonomous-system` when `protocols bgp local-as` was not set (#3870).
//
// Junos accepts the BGP AS at TWO hierarchy points: the global
// `routing-options autonomous-system <N>` (the canonical vSRX placement) and
// the more specific `protocols bgp local-as <N>` override. The FRR renderer
// gates `router bgp` on BGPConfig.LocalAS > 0 (policy_render.go), and only
// `local-as` populated LocalAS — so a config that set the AS only at
// routing-options rendered NO `router bgp` block at all, silently. This
// resolves the Junos precedence into LocalAS after the whole tree is compiled
// (routing-options and protocols may appear in either order under the root):
// local-as wins if present, else the global autonomous-system. Per-instance
// BGP inherits the instance's own routing-options autonomous-system if set,
// else the global one. Must run AFTER both compileRoutingOptions and
// compileProtocols/compileRoutingInstances have populated cfg.
func resolveBGPAutonomousSystem(cfg *Config) {
	globalAS := cfg.RoutingOptions.AutonomousSystem
	if bgp := cfg.Protocols.BGP; bgp != nil && bgp.LocalAS == 0 && globalAS > 0 {
		bgp.LocalAS = globalAS
	}
	for _, ri := range cfg.RoutingInstances {
		if ri.BGP == nil || ri.BGP.LocalAS != 0 {
			continue
		}
		as := ri.AutonomousSystem // instance-level override
		if as == 0 {
			as = globalAS // inherit the global autonomous-system
		}
		if as > 0 {
			ri.BGP.LocalAS = as
		}
	}
}

func compilePolicyOptions(node *Node, po *PolicyOptionsConfig) error {
	if po.PrefixLists == nil {
		po.PrefixLists = make(map[string]*PrefixList)
	}
	if po.Communities == nil {
		po.Communities = make(map[string]*CommunityDef)
	}
	if po.PolicyStatements == nil {
		po.PolicyStatements = make(map[string]*PolicyStatement)
	}

	// Parse prefix-lists. A named prefix-list may be defined across multiple
	// separate blocks (two `prefix-list NAME { ... }` braces, or two
	// `set policy-options prefix-list NAME ...` groups). Reuse the existing
	// map entry and append so later blocks MERGE into the earlier ones rather
	// than overwriting them — mirroring the community loop below (#2641).
	for _, inst := range namedInstances(node.FindChildren("prefix-list")) {
		pl := po.PrefixLists[inst.name]
		if pl == nil {
			pl = &PrefixList{Name: inst.name}
			po.PrefixLists[inst.name] = pl
		}
		// Read EVERY prefix entry. A prefix-list body may carry its prefixes as
		// distinct sibling children (one `set ... prefix-list NAME <p>` per line,
		// or a brace block with one `<p>;` per line — each child then holds a
		// single prefix in Keys[0]) OR, via the bracketed-list form
		// `set ... prefix-list NAME [ p1 p2 p3 ]`, collapsed onto a SINGLE child
		// node's Keys (the lexer strips `[`/`]` and packs every token onto one
		// leaf — the #2419/#3842 dual-shape class). Read the FULL Keys slice of
		// each child, not just Keys[0]; the prior `entry.Keys[0]`-only read kept
		// just the FIRST prefix of a bracketed list and silently dropped the
		// rest → an under-populated prefix-list (route-filter / firewall-filter /
		// dynamic address group matched a partial prefix set) (#3996).
		for _, entry := range inst.node.Children {
			for _, p := range entry.Keys {
				if p != "" {
					pl.Prefixes = append(pl.Prefixes, p)
				}
			}
		}
	}

	// Parse community definitions
	for _, inst := range namedInstances(node.FindChildren("community")) {
		cd := po.Communities[inst.name]
		if cd == nil {
			cd = &CommunityDef{Name: inst.name}
			po.Communities[inst.name] = cd
		}
		for _, entry := range inst.node.Children {
			if entry.Name() == "members" {
				// Multi-value leaf (#2587): `members [ c1 c2 ]` (and a
				// hierarchical block) collapses onto entry.Keys[1:] and/or
				// entry.Children. Read ALL via the firewallMatchValues SSOT;
				// the prior nodeVal-only read kept just the first community.
				cd.Members = append(cd.Members, firewallMatchValues(entry)...)
			}
		}
		// Handle flat set syntax where `members` collapses onto the community
		// instance node itself: Keys like ["members", "65000:100", ...].
		if len(inst.node.Keys) > 1 && inst.node.Keys[0] == "members" {
			cd.Members = append(cd.Members, inst.node.Keys[1:]...)
		}
	}

	// Parse AS-path definitions
	if po.ASPaths == nil {
		po.ASPaths = make(map[string]*ASPathDef)
	}
	for _, child := range node.FindChildren("as-path") {
		if len(child.Keys) >= 3 {
			// Hierarchical: Keys=["as-path", "NAME", "REGEX"]
			po.ASPaths[child.Keys[1]] = &ASPathDef{
				Name:  child.Keys[1],
				Regex: child.Keys[2],
			}
		} else if len(child.Keys) >= 2 {
			// Flat set syntax may produce: Keys=["as-path","NAME"] with children
			name := child.Keys[1]
			ap := &ASPathDef{Name: name}
			// Look for path child (regex value)
			for _, entry := range child.Children {
				if len(entry.Keys) > 0 {
					ap.Regex = entry.Keys[0]
				}
			}
			po.ASPaths[name] = ap
		}
	}

	// Parse policy-statements. A named policy-statement may be defined across
	// MULTIPLE separate hierarchical blocks (two `policy-statement NAME { ... }`
	// braces), repeated `policy-options` roots, or group-expanded fragments —
	// each is a distinct AST instance. Flat `set policy-options policy-statement
	// NAME ...` lines already COMPOSE under one node via SetPath, so hierarchical
	// must merge the same way or the two shapes diverge. Reuse the existing map
	// entry (po.PolicyStatements, which persists across every instance AND across
	// repeated policy-options roots) AND a per-policy term index so later blocks
	// MERGE into the earlier one: new terms append in first-authored ORDER
	// (routing policy is ordered security/route-control state — an earlier reject
	// term must not be lost or reordered), and a repeated fragment of the SAME
	// term composes onto the existing PolicyTerm (route-filters / from / then all
	// accumulate). Within ONE policy-options root the term index (psTermIndex,
	// below) carries the composition across instances; ACROSS separate top-level
	// policy-options roots (each a distinct compilePolicyOptions call with a fresh
	// psTermIndex) the composition is re-seeded from the persisted ps.Terms
	// (#5824). Mirrors the prefix-list / community merge loops above (#5824).
	//
	// The pre-#5824 code created a FRESH PolicyStatement per instance and did an
	// unconditional `po.PolicyStatements[ps.Name] = ps`, so a second same-name
	// block silently REPLACED the first — its terms / route-filters / actions /
	// default action vanished. FRR then received a valid but INCOMPLETE route-map
	// (a lost reject term over-exports/over-imports; a lost accept term withdraws
	// reachability) while commit and daemon apply both looked successful.
	psTermIndex := make(map[string]map[string]*PolicyTerm)
	for _, inst := range namedInstances(node.FindChildren("policy-statement")) {
		ps := po.PolicyStatements[inst.name]
		if ps == nil {
			ps = &PolicyStatement{Name: inst.name}
			po.PolicyStatements[inst.name] = ps
		}
		termsByName := psTermIndex[inst.name]
		if termsByName == nil {
			termsByName = make(map[string]*PolicyTerm)
			psTermIndex[inst.name] = termsByName
			// #5824 cross-root: psTermIndex is LOCAL to this compilePolicyOptions
			// call, but compilePolicyOptions runs once PER top-level policy-options
			// AST root (NewParser appends top-level nodes without merging). So a
			// second top-level `policy-options {}` root reuses the persisted `ps`
			// (from po.PolicyStatements) but gets a FRESH, empty termsByName — a
			// same-name term in that root would append as a DUPLICATE (a malformed
			// double route-map sequence in FRR) instead of composing. Seed the fresh
			// index from ps.Terms so a same-name term composes onto the existing
			// PolicyTerm across roots, exactly as it already does within a root.
			for _, t := range ps.Terms {
				termsByName[t.Name] = t
			}
		}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "term":
				if len(prop.Keys) < 2 {
					continue
				}
				termName := prop.Keys[1]

				// Find or create term (flat set syntax may create multiple
				// nodes for the same term name)
				term, exists := termsByName[termName]
				if !exists {
					term = &PolicyTerm{Name: termName}
					termsByName[termName] = term
					ps.Terms = append(ps.Terms, term)
				}

				// Handle both hierarchical children and flat inline keys.
				// Flat: Keys=["term","t1","from","protocol","direct"] with no children
				// Hierarchical: Keys=["term","t1"] with from/then children
				if len(prop.Children) > 0 {
					// Hierarchical form
					parsePolicyTermChildren(term, prop.Children)
				} else if len(prop.Keys) > 2 {
					// Flat form: remaining keys after term name are key-value pairs
					parsePolicyTermInlineKeys(term, prop.Keys[2:])
				}
			case "then":
				// Default action at the policy level
				for _, ac := range prop.Children {
					switch ac.Name() {
					case "accept":
						ps.DefaultAction = "accept"
					case "reject":
						ps.DefaultAction = "reject"
					}
				}
				if len(prop.Keys) >= 2 {
					ps.DefaultAction = prop.Keys[1]
				}
			}
		}
		// #5824: NO unconditional overwrite here — ps is the SHARED map entry, so
		// this instance's contributions are already merged into any earlier
		// same-name block's terms/actions in authored order.
	}

	return nil
}

// collectProtocolList flattens a single "from protocol ..." node into the
// protocol names it carries. After the lexer strips the brackets, a protocol
// node reaches the compiler in one of three shapes:
//   - block parse, bracket list: every protocol is a key on the node itself
//     (Keys = ["protocol", "bgp", "ospf", "static"]).
//   - flat-set SetPath, bracket list: the first protocol is Keys[1] and the
//     remaining protocols hang off a nested single-child chain
//     (Keys = ["protocol", "bgp"] -> child Keys = ["ospf", "static"] -> ...).
//   - flat-set SetPath, separate "set ... from protocol <X>" commands: each
//     command lands its own leaf (Keys = ["protocol", "<X>"]) as a sibling
//     under the term's "from" block. The caller iterates those siblings and
//     calls this helper once per node, which then returns the single protocol.
//   - block parse, nested block: `from { protocol { bgp; ospf; static; } }`
//     leaves the node itself with Keys = ["protocol"] and files one LEAF
//     CHILD PER PROTOCOL as SIBLINGS (#6689).
//
// The fourth shape is why the descent walks every child rather than
// Children[0]. Following the single-child chain reached only the first
// sibling, so a term written to filter three protocols compiled to one — and
// with `then reject`, the two it dropped were silently ACCEPTED and installed.
// A nested block is not the flat-set chain wearing a different shape; the
// chain is one child deep at each level, the block is N children wide at one
// level, and only a full descent covers both.
//
// Every token below a protocol node is a protocol name: Junos has no
// per-protocol option keyword on this leaf, so unlike `system ntp server`
// (#6690) there is no trailing-token ambiguity and no promotion hazard from
// reading the whole subtree. Blank tokens are skipped — an empty slot is not
// a protocol, and every value this helper returns is installed as a
// `match source-protocol` line.
func collectProtocolList(protoNode *Node) []string {
	if protoNode == nil {
		return nil
	}
	var protocols []string
	add := func(tokens []string) {
		for _, tok := range tokens {
			if tok != "" {
				protocols = append(protocols, tok)
			}
		}
	}
	if len(protoNode.Keys) >= 2 {
		add(protoNode.Keys[1:])
	}
	var walk func(*Node)
	walk = func(parent *Node) {
		for _, child := range parent.Children {
			add(child.Keys)
			walk(child)
		}
	}
	walk(protoNode)
	return protocols
}

// parseRouteFilterLen parses a Junos route-filter length token of the
// form "/24" (the leading slash is how Junos writes "upto /24") or a
// bare "24". It returns (n, true) only for a well-formed length in the
// valid range 1..128; a malformed or out-of-range token yields
// (0, false) so the caller leaves UptoLen at 0 and the renderer
// degrades safely (#2072). Upper bound is 128 (IPv6 max); the renderer
// separately clamps against the per-family max and the prefix length.
//
// Zero is REJECTED on purpose (Codex #2102 MAJOR): "upto /0" is not a
// meaningful length, and UptoLen is a plain int with no presence bit, so
// accepting 0 would make an explicit "upto /0" indistinguishable from an
// unset UptoLen. Keeping 0 strictly as "unset" lets the renderer treat
// UptoLen==0 unambiguously as the degrade case.
func parseRouteFilterLen(tok string) (int, bool) {
	tok = strings.TrimPrefix(tok, "/")
	// Require digits only — strconv.Atoi would also accept signed forms
	// like "+24" or "-0", which are not valid Junos length tokens (Codex
	// #2102 MINOR). An empty token (e.g. a bare "/") has no digits and is
	// rejected here.
	if tok == "" {
		return 0, false
	}
	for _, c := range tok {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(tok)
	if err != nil || n < 1 || n > 128 {
		return 0, false
	}
	return n, true
}

// parseRouteFilterRange parses a Junos "prefix-length-range" length token of
// the form "/16-/24" (or the slashless "16-24") into its low and high
// prefix-length bounds. It returns (low, high, true) only when BOTH bounds are
// well-formed lengths in 1..128; any malformed token (missing dash, empty
// half, non-numeric, out of range) yields (0, 0, false) so the caller leaves
// RangeLow/RangeHigh at 0 and the strict gate / renderer treat 0 as "no
// parseable range" (#2525). Ordering (low<=high), the per-family max, and the
// base-prefix floor are enforced separately by validateRouteFilterMatchTypesStrict
// — this helper only parses syntax.
func parseRouteFilterRange(tok string) (low, high int, ok bool) {
	parts := strings.SplitN(tok, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, okLo := parseRouteFilterLen(parts[0])
	hi, okHi := parseRouteFilterLen(parts[1])
	if !okLo || !okHi {
		return 0, 0, false
	}
	return lo, hi, true
}

// routeFilterTrailingToken extracts the single trailing argument token of a
// hierarchical-parse route-filter node (the "/N" for upto, the "/lo-/hi" for
// prefix-length-range, the CIDR for through). It reaches the compiler in two
// shapes: brace parse puts it at Keys[3]; flat-set SetPath nests it as the
// first key of the first child. Returns "" when neither shape carries it.
func routeFilterTrailingToken(fc *Node) string {
	if len(fc.Keys) >= 4 {
		return fc.Keys[3]
	}
	if len(fc.Children) > 0 && len(fc.Children[0].Keys) > 0 {
		return fc.Children[0].Keys[0]
	}
	return ""
}

// parsePolicyTermChildren handles hierarchical form of policy term
// where "from" and "then" are child nodes.
func parsePolicyTermChildren(term *PolicyTerm, children []*Node) {
	for _, tc := range children {
		switch tc.Name() {
		case "from":
			for _, fc := range tc.Children {
				switch fc.Name() {
				case "protocol":
					// Junos "from protocol [ bgp ospf static ]" matches any
					// listed protocol. The lexer strips the brackets, so the
					// protocol list arrives in one of two AST shapes:
					//  - hierarchical block parse: all protocols land in
					//    fc.Keys (Keys=["protocol","bgp","ospf","static"]);
					//  - flat-set SetPath: the first protocol is fc.Keys[1]
					//    and the rest form a nested child chain
					//    (Keys=["protocol","bgp"] -> child Keys=["ospf","static"]).
					// Collect every protocol from both shapes, not just the
					// first (#2008 H18).
					term.FromProtocols = append(term.FromProtocols, collectProtocolList(fc)...)
				case "prefix-list":
					// Junos allows repeated `prefix-list` siblings in one
					// term (match ANY). Accumulate so multiple statements are
					// all kept, not just the last (#2642). A bracketed list
					// `prefix-list [ p1 p2 ]` ALSO collapses onto one leaf's
					// Keys[1:] / Children in BOTH AST shapes (#2419), so read
					// every value via the firewallMatchValues SSOT — the prior
					// nodeVal-only read kept just the first list entry (#2689).
					term.PrefixList = append(term.PrefixList, firewallMatchValues(fc)...)
				case "route-filter":
					if len(fc.Keys) >= 3 {
						rf := &RouteFilter{
							Prefix:    fc.Keys[1],
							MatchType: fc.Keys[2],
						}
						// "upto", "prefix-length-range", and "through" all carry
						// a trailing argument token (a "/N" length, a "/lo-/hi"
						// range, or a CIDR prefix). It reaches the compiler in
						// two shapes (#2072/#2525):
						//   - brace parse: a single leaf, the arg at Keys[3];
						//   - flat-set SetPath: a container node with the arg as
						//     its first child key (Children[0].Keys[0]). On a
						//     single-line flat set the child also folds trailing
						//     clause tokens, so read only its first key.
						switch rf.MatchType {
						case "upto":
							if argTok := routeFilterTrailingToken(fc); argTok != "" {
								if n, ok := parseRouteFilterLen(argTok); ok {
									rf.UptoLen = n
								}
							}
						case "prefix-length-range":
							if argTok := routeFilterTrailingToken(fc); argTok != "" {
								if lo, hi, ok := parseRouteFilterRange(argTok); ok {
									rf.RangeLow = lo
									rf.RangeHigh = hi
								}
							}
						case "through":
							rf.ThroughPrefix = routeFilterTrailingToken(fc)
						}
						term.RouteFilters = append(term.RouteFilters, rf)
					}
				case "community":
					// Repeated `community` siblings match ANY (#2642) — keep
					// every one, not just the last. A bracketed list
					// `community [ c1 c2 ]` ALSO collapses onto one leaf's
					// Keys[1:] / Children in BOTH AST shapes (#2419), so read
					// every value via the firewallMatchValues SSOT — the prior
					// nodeVal-only read kept just the first list entry (#2689).
					term.FromCommunity = append(term.FromCommunity, firewallMatchValues(fc)...)
				case "as-path":
					// Repeated `as-path` siblings match ANY (#2642). A bracketed
					// list `as-path [ a1 a2 ]` ALSO collapses onto one leaf's
					// Keys[1:] / Children in BOTH AST shapes (#2419), so read
					// every value via the firewallMatchValues SSOT — the prior
					// nodeVal-only read kept just the first list entry (#2689).
					term.FromASPath = append(term.FromASPath, firewallMatchValues(fc)...)
				}
			}
		case "then":
			for _, ac := range tc.Children {
				switch ac.Name() {
				case "accept":
					term.Action = "accept"
				case "reject":
					term.Action = "reject"
				case "next-hop":
					term.NextHop = nodeVal(ac)
				case "load-balance":
					term.LoadBalance = nodeVal(ac)
				case "local-preference":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.LocalPreference = n
							term.HasLocalPreference = true
						}
					}
				case "metric":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.Metric = n
							term.HasMetric = true
						}
					}
				case "metric-type":
					if v := nodeVal(ac); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							term.MetricType = n
						}
					}
				case "community":
					// `then community` is a multi-value leaf that packs an
					// optional operation keyword (add|delete|set|none) plus the
					// community value onto Keys / Children. Read every token via
					// the SSOT and interpret the operation (#2848).
					applyCommunityAction(term, firewallMatchValues(ac))
				case "as-path-prepend":
					// `then as-path-prepend` is a multi-value leaf: a quoted
					// "65001 65001" or bracketed [ 65001 65001 ] list flattens
					// onto ac.Keys[1:] and/or ac.Children. Read EVERY ASN via
					// the firewallMatchValues SSOT (reading only Keys[1] would
					// drop all but the first prepend, the #2419/#2892 trap) and
					// accumulate so repeated set lines also keep every ASN.
					term.ASPathPrepend = append(term.ASPathPrepend, firewallMatchValues(ac)...)
				case "origin":
					term.Origin = nodeVal(ac)
				}
			}
			if len(tc.Keys) >= 2 {
				term.Action = tc.Keys[1]
			}
		}
	}
}

// applyCommunityAction interprets the tokens of a `then community` clause and
// records the requested operation on the term (#2848). Junos/vSRX supports four
// community operations in a policy term:
//
//   - `then community set <value>`  → replace the whole community attribute
//   - `then community <value>`      → replace (legacy bare form, back-compat)
//   - `then community add <value>`  → append (FRR `set community <v> additive`)
//   - `then community delete <name>`→ strip members matching the named
//     community-list (FRR `set comm-list <name> delete`)
//   - `then community none`         → strip all communities (FRR `set community none`)
//
// vals is the flattened token list of the clause (operation keyword first when
// present, then the value/name). The first token selects the operation; any
// other first token is treated as a bare replace value.
func applyCommunityAction(term *PolicyTerm, vals []string) {
	if len(vals) == 0 {
		return
	}
	switch vals[0] {
	case "none":
		term.CommunityOp = "none"
		term.Community = ""
		term.CommunityAdd = ""
		term.CommunityDelete = nil
	case "add":
		if len(vals) >= 2 {
			term.CommunityOp = "add"
			term.CommunityAdd = strings.Join(vals[1:], " ")
		}
	case "delete":
		// `then community delete [ listA listB ]` flattens (the lexer strips
		// the brackets) to vals = ["delete","listA","listB"], so every
		// referenced community-list name is in vals[1:]. FRR's
		// `set comm-list <name> delete` clause strips ONE list per line, so
		// accumulate all names (reading only vals[1] would silently drop
		// listB... — the #2419/#2902 multi-value trap) and append so repeated
		// `set ... then community delete` lines also keep every name.
		if len(vals) >= 2 {
			term.CommunityOp = "delete"
			term.CommunityDelete = append(term.CommunityDelete, vals[1:]...)
		}
	case "set":
		if len(vals) >= 2 {
			term.CommunityOp = "set"
			term.Community = strings.Join(vals[1:], " ")
		}
	default:
		// Bare `then community <value>` — legacy replace form.
		term.CommunityOp = ""
		term.Community = strings.Join(vals, " ")
	}
}

// policyTermInlineKeywords is the set of clause keywords recognized by
// parsePolicyTermInlineKeys. It is used to find where a variable-length
// value run (e.g. a multi-protocol "from protocol [ ... ]" list) ends.
var policyTermInlineKeywords = map[string]bool{
	"from": true, "then": true, "protocol": true, "prefix-list": true,
	"route-filter": true, "next-hop": true, "load-balance": true,
	"local-preference": true, "metric": true, "metric-type": true,
	"community": true, "as-path": true, "as-path-prepend": true,
	"origin": true, "accept": true, "reject": true,
}

// parsePolicyTermInlineKeys handles flat set syntax where remaining keys
// after the term name are inline key-value pairs like:
// "from", "protocol", "direct" or "from", "route-filter", "10.0.0.0/8", "exact"
// or "then", "accept"
func parsePolicyTermInlineKeys(term *PolicyTerm, keys []string) {
	inFrom := false
	for i := 0; i < len(keys); i++ {
		switch keys[i] {
		case "from":
			inFrom = true
			continue
		case "then":
			inFrom = false
			if i+1 < len(keys) {
				i++
				term.Action = keys[i]
			}
		case "protocol":
			// "from protocol [ bgp ospf static ]" — the lexer strips the
			// brackets, so every protocol arrives as a separate key. Consume
			// all consecutive values until the next clause keyword, so a
			// multi-protocol list keeps every protocol (not just the first).
			for i+1 < len(keys) && !policyTermInlineKeywords[keys[i+1]] {
				i++
				term.FromProtocols = append(term.FromProtocols, keys[i])
			}
		case "prefix-list":
			if i+1 < len(keys) {
				i++
				term.PrefixList = append(term.PrefixList, keys[i])
			}
		case "route-filter":
			if i+2 < len(keys) {
				rf := &RouteFilter{
					Prefix:    keys[i+1],
					MatchType: keys[i+2],
				}
				// "upto"/"prefix-length-range"/"through" carry a trailing
				// argument token at keys[i+3] (a "/N" length, a "/lo-/hi"
				// range, or a CIDR prefix). Consume it only when present so
				// the next clause keyword is not misread as a value.
				// (#2072/#2525 — belt-and-suspenders: the inline path is not
				// reached for route-filter under the current schema, which
				// always nests "from" as a child node, but keep it correct in
				// case dispatch ever changes.)
				consumed := 2
				if i+3 < len(keys) {
					switch rf.MatchType {
					case "upto":
						if n, ok := parseRouteFilterLen(keys[i+3]); ok {
							rf.UptoLen = n
							consumed = 3
						}
					case "prefix-length-range":
						if lo, hi, ok := parseRouteFilterRange(keys[i+3]); ok {
							rf.RangeLow = lo
							rf.RangeHigh = hi
							consumed = 3
						}
					case "through":
						rf.ThroughPrefix = keys[i+3]
						consumed = 3
					}
				}
				term.RouteFilters = append(term.RouteFilters, rf)
				i += consumed
			}
		case "next-hop":
			if i+1 < len(keys) {
				i++
				term.NextHop = keys[i]
			}
		case "load-balance":
			if i+1 < len(keys) {
				i++
				term.LoadBalance = keys[i]
			}
		case "local-preference":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.LocalPreference = n
					term.HasLocalPreference = true
				}
			}
		case "metric":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.Metric = n
					term.HasMetric = true
				}
			}
		case "metric-type":
			if i+1 < len(keys) {
				i++
				if n, err := strconv.Atoi(keys[i]); err == nil {
					term.MetricType = n
				}
			}
		case "community":
			if inFrom {
				if i+1 < len(keys) {
					i++
					term.FromCommunity = append(term.FromCommunity, keys[i])
				}
				continue
			}
			// `then community` may carry an operation keyword
			// (add|delete|set|none) optionally followed by a value. Consume
			// the operation token plus, where the operation takes an
			// argument, the value token. Belt-and-suspenders: the inline path
			// is not reached for `then community` under the current schema
			// (SetPath/block parse both nest `then` as a child node), but keep
			// it correct in case dispatch ever changes (#2848).
			if i+1 < len(keys) {
				op := keys[i+1]
				switch op {
				case "add", "delete", "set":
					if i+2 < len(keys) {
						applyCommunityAction(term, []string{op, keys[i+2]})
						i += 2
					} else {
						i++
					}
				case "none":
					applyCommunityAction(term, []string{op})
					i++
				default:
					applyCommunityAction(term, []string{op})
					i++
				}
			}
		case "as-path":
			if i+1 < len(keys) {
				i++
				term.FromASPath = append(term.FromASPath, keys[i])
			}
		case "as-path-prepend":
			// `then as-path-prepend 65001 65001 ...` — the lexer strips any
			// quotes/brackets, so every ASN arrives as a separate key.
			// Consume all consecutive values until the next clause keyword so
			// a multi-ASN list keeps every ASN, not just the first (#2892).
			for i+1 < len(keys) && !policyTermInlineKeywords[keys[i+1]] {
				i++
				term.ASPathPrepend = append(term.ASPathPrepend, keys[i])
			}
		case "origin":
			if i+1 < len(keys) {
				i++
				term.Origin = keys[i]
			}
		case "accept":
			term.Action = "accept"
		case "reject":
			term.Action = "reject"
		}
	}
}

// mainRIBTableID is the Linux main routing table (RT_TABLE_MAIN). It mirrors
// pkg/routing.mainTableID; the two MUST agree on which import-rib targets are
// "main" so the commit-time warn and the runtime applier classify a rib-group
// import the same way (#3876).
const mainRIBTableID = 254

// compileRibGroup builds one RibGroup from the AST node that carries its body.
//
// It exists because compileRoutingOptions reaches a rib-group by TWO arms — the
// named-instance arm and the direct-child arm — which held byte-identical
// import-rib readers. #7126 records the hazard that duplication creates: a fix
// landing in only one arm leaves the defect in the other spelling, and nothing
// in the compiler would say so. There is now one body, so the two arms cannot
// disagree.
//
// `import-rib` is the inter-VRF route-leak membership list, so a dropped entry
// is not cosmetic: the rib-group pulls routes into one table instead of two and
// the second table's leak simply never happens, with no diagnostic, while
// `show configuration` renders the full list back. Two strict/warning
// validators also iterate ImportRibs (compiler_validate_warn_routing.go,
// compiler_validate_strict_routing.go), so a truncated list also narrows what
// those checks can see.
//
// Two reads had to widen together (#7126):
//
//   - FindChildren, not FindChild. Repeated hierarchical statements
//     (`import-rib inet.0; import-rib inet.2;`) land as SIBLING nodes and only
//     the first was ever consulted, so that spelling dropped every rib past the
//     first even though the flat-set repeated spelling — which files the same
//     configuration as CHILDREN of one node — accumulated correctly.
//   - plainListValues, not Keys[1:] plus each child's Name(). The old read
//     already covered both sides of the AST exactly as CLAUDE.md prescribes and
//     still dropped, because `set … import-rib [ inet.0 inet.2 ]` puts EVERY
//     rib on ONE child's Keys and Name() is Keys[0]. See plainListValues.
//
// The old reader also skipped literal "[" / "]" tokens. That guard was
// unreachable: the lexer strips brackets on both the hierarchical and the
// flat-set path (verified against the parsed ASTs — `import-rib [ inet.0
// inet.2 ]` yields Keys=["import-rib","inet.0","inet.2"] with no bracket
// token), which is why every other #2419 reader in this package omits it.
func compileRibGroup(name string, node *Node) *RibGroup {
	rg := &RibGroup{Name: name}
	for _, irNode := range node.FindChildren("import-rib") {
		rg.ImportRibs = append(rg.ImportRibs, plainListValues(irNode)...)
	}
	return rg
}

// ribTargetKind classifies a rib-group import-rib name against a source
// instance for the #3876 per-prefix leak. It mirrors pkg/routing.resolveRibTable
// (via ribInstanceFromName, the shared exact-suffix matcher) and returns:
//   - "main": the main table (inet.0 / inet6.0) — the Phase-1 leak target.
//   - "self": the source instance's own rib (no leak needed).
//   - "vrf":  another DEFINED instance's rib — a VRF→VRF import, deferred to
//     Phase 2 (warned, not installed).
//   - "unknown": an unresolvable name (the strict gate rejects it at commit;
//     the applier skips it — #2226).
func ribTargetKind(ribName, selfInstance string, definedInstances map[string]bool) string {
	if ribName == "inet.0" || ribName == "inet6.0" {
		return "main"
	}
	if instance, ok := ribInstanceFromName(ribName); ok {
		if instance == selfInstance {
			return "self"
		}
		if definedInstances[instance] {
			return "vrf"
		}
	}
	return "unknown"
}

// RibGroupConnectedPrefixes derives, per source routing instance carrying an
// interface-routes rib-group, the connected network prefixes eligible for the
// #3876 per-prefix leak. For each instance member interface (e.g.
// "ge-0/0/1.0") it resolves the physical interface + unit and collects the
// masked network prefix of every static address on that unit via
// ConnectedNetworkPrefix — the SAME derivation the userspace FIB uses for
// connected routes, so the leaked ip-rule set matches the connected routes in
// the source table.
//
// DHCP-only units carry no static Addresses (the lease is learned at runtime)
// and contribute no enumerable prefix; the commit-time warn
// (validateRibGroupLeakWarnings) surfaces that so the leak is fail-loud rather
// than a silent no-op. The map is keyed by routing-instance name with v4 and
// v6 prefixes mixed (the applier splits by family). Shared by the daemon
// applier input and the config warn path so the two never drift.
func RibGroupConnectedPrefixes(cfg *Config) map[string][]string {
	out := make(map[string][]string)
	if cfg == nil {
		return out
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		if ri.InterfaceRoutesRibGroup == "" && ri.InterfaceRoutesRibGroupV6 == "" {
			continue
		}
		var prefixes []string
		for _, member := range ri.Interfaces {
			base, unitTok, hasUnit := strings.Cut(member, ".")
			unitNum := 0
			if hasUnit {
				n, err := strconv.Atoi(unitTok)
				if err != nil {
					continue
				}
				unitNum = n
			}
			ifc := cfg.Interfaces.Interfaces[base]
			if ifc == nil {
				continue
			}
			unit := ifc.Units[unitNum]
			if unit == nil {
				continue
			}
			for _, addr := range unit.Addresses {
				if prefix, _, ok := ConnectedNetworkPrefix(addr); ok {
					prefixes = append(prefixes, prefix)
				}
			}
		}
		if len(prefixes) > 0 {
			out[ri.Name] = prefixes
		}
	}
	return out
}
