package config

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig, instanceName string, warnings *[]string) error {
	// #11314: SetPath can encode multiple routing-options leaves as a chain
	// under the first leaf. Split declared siblings before FindChild so a
	// router-id does not silently swallow a following autonomous-system. Work
	// on a shallow copy; strict gates still need the authored tree.
	flatChildren := expandFlatRun(node.Children, schemaRoutingOptions)
	if len(flatChildren) != len(node.Children) {
		normalized := *node
		normalized.Children = flatChildren
		node = &normalized
	}
	// Parse autonomous-system
	if asNode := node.FindChild("autonomous-system"); asNode != nil {
		if v := nodeVal(asNode); v != "" {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				ro.AutonomousSystem = uint32(n)
			}
		}
	}
	// `routing-options router-id` is a global protocol default. Per-instance
	// routing-options has a separate schema and does not admit this leaf.
	if instanceName == "" {
		if routerIDNode := node.FindChild("router-id"); routerIDNode != nil {
			ro.routerID = nodeVal(routerIDNode)
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

	// Parse rib <name> { static { route ... } }, accepting only the table whose
	// scope matches this routing-options block. The global block owns bare
	// inet.0 / inet6.0; an instance block owns only <instance>.inet.0 /
	// <instance>.inet6.0. A qualified rib from another scope must not be
	// silently filed into the current instance's route list.
	for _, ribNode := range node.FindChildren("rib") {
		ribName := nodeVal(ribNode)
		ribStatic := ribNode.FindChild("static")
		if ribMatchesRoutingOptionsScope(ribName, instanceName) {
			if ribStatic != nil {
				if ribName == "inet6.0" || strings.HasSuffix(ribName, ".inet6.0") {
					ro.Inet6StaticRoutes = compileStaticRoutes(ribStatic, ro.Inet6StaticRoutes)
				} else {
					// The IPv4 unicast table is the SAME destination as a bare
					// `routing-options static` block, so routes reached either way
					// land in one list and append rather than replace.
					ro.StaticRoutes = compileStaticRoutes(ribStatic, ro.StaticRoutes)
				}
			}
			continue
		}
		// Not implemented in this scope (either an unsupported table or a table
		// owned by another scope). Record it ONLY when routes were actually lost;
		// an empty `rib foo { }` discards nothing, and warning there would be noise.
		if ribStatic == nil {
			continue
		}
		if n := len(compileStaticRoutes(ribStatic, nil)); n > 0 {
			ro.UnhandledRibs = append(ro.UnhandledRibs, UnhandledRib{Name: ribName, Routes: n})
		}
	}

	staticNode := node.FindChild("static")
	if staticNode != nil {
		ro.StaticRoutes = compileStaticRoutes(staticNode, ro.StaticRoutes)
	}

	// Parse every rib-groups container. Duplicate names in one container are
	// folded before compilation; definitions across containers or roots merge
	// here in source order.
	for _, rgNode := range node.FindChildren("rib-groups") {
		if ro.RibGroups == nil {
			ro.RibGroups = make(map[string]*RibGroup)
		}
		for _, inst := range namedInstances(rgNode.FindChildren("")) {
			mergeRibGroupDefinition(ro.RibGroups, compileRibGroup(inst.name, inst.node), warnings)
		}
		// Also handle direct children (non-named instances).
		for _, child := range rgNode.Children {
			mergeRibGroupDefinition(ro.RibGroups, compileRibGroup(child.Name(), child), warnings)
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
			// #8939: split a packed run before reading. `generate route <p>
			// discard policy P` nests as `[route <p>] > [discard policy P]`, so
			// FindChild("discard") matched and `policy P` -- sitting on that
			// same node's Keys -- was never read. The generated route was
			// installed with no policy, which is the opposite of what the
			// operator wrote: a policy is what SELECTS the contributing routes,
			// so without it the aggregate's contributor set is unconstrained.
			routeChildren := expandFlatRun(routeNode.Children, generateRouteSchema8939())
			for _, rc := range routeChildren {
				switch rc.Name() {
				case "policy":
					if v := nodeVal(rc); v != "" {
						gr.Policy = v
					}
				case "discard":
					gr.Discard = true
				}
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
			// #8939: split a packed run. `rib-group inet RG inet6 RG` is ONE
			// command and SetPath nests the second family onto the first
			// rather than making them siblings, so this loop saw `inet` and
			// dropped the v6 rib-group with it — a leak the operator asked
			// for that silently does not happen for one family.
			for _, rgChild := range expandFlatRun(rgNode.Children, interfaceRoutesRibGroupSchema8939()) {
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

// ribMatchesRoutingOptionsScope reports whether ribName selects the main
// unicast table in global routing-options or the current instance's own table.
// Keeping the selector scope check separate from family handling prevents a
// qualified rib from another scope being silently installed in the enclosing
// scope's route list.
func ribMatchesRoutingOptionsScope(ribName, instanceName string) bool {
	if instanceName == "" {
		return ribName == "inet.0" || ribName == "inet6.0"
	}
	return ribName == instanceName+".inet.0" || ribName == instanceName+".inet6.0"
}

// isRouteInlineKeyword reports whether tok is a static-route clause keyword in
// the fully-inline route-keys form (`route <dst> next-hop a b qualified-next-hop
// ...`). Used to bound a multi-value next-hop gateway run (#3872) so it stops
// at the next clause instead of swallowing a following keyword as a gateway.
func isRouteInlineKeyword(tok string) bool {
	switch tok {
	case "next-hop", "qualified-next-hop", "next-table", "discard", "reject", "no-install", "preference", "metric", "interface":
		return true
	}
	return false
}

// staticNextHopEntry compiles a scalar `next-hop <value>`. A bare interface
// name is a valid Junos next-hop and must be represented as an interface-only
// entry so both FRR and the userspace snapshot install the same dev route
// (#12036). IP and `ip@interface` values remain address-form next-hops.
func staticNextHopEntry(raw, iface string) NextHopEntry {
	if iface == "" && !isRouteInlineKeyword(raw) && !strings.Contains(raw, "@") &&
		net.ParseIP(raw) == nil && plausibleInterfaceName(raw) {
		return NextHopEntry{Interface: raw}
	}
	return NextHopEntry{Address: raw, Interface: iface}
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
						route.NextHops = append(route.NextHops, staticNextHopEntry(a, iface))
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
				case "no-install":
					route.NoInstall = true
				case "discard":
					route.Discard = true
				case "reject":
					route.Reject = true
				case "preference":
					if i+1 < len(routeInst.node.Keys) {
						i++
						if n, err := strconv.Atoi(routeInst.node.Keys[i]); err == nil {
							route.Preference = n
							route.HasPreference = true
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
				// Compact inline normalization can leave a route-level
				// `no-install` token in the next-hop leaf's packed keys. Keep
				// that option out of the gateway list and apply it to the route.
				for j := 1; j < len(prop.Keys); j++ {
					if prop.Keys[j] == "no-install" {
						route.NoInstall = true
						continue
					}
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
				// Child interface (hierarchical + flat-set container shapes),
				// and #6564: the INVERSE shape, where the gateway itself is a
				// CHILD rather than a trailing key —
				// `next-hop { 192.168.1.1; }`. The pre-#6564 loop recognised
				// only the `interface` modifier here, so that block compiled to
				// ZERO next-hops. staticRouteDispositionConflict rejects only
				// TWO or more dispositions, never zero, so the route committed
				// clean and then rendered nothing into FRR — a silently missing
				// route rather than a refused config.
				for _, child := range prop.Children {
					switch child.Name() {
					case "interface":
						iface = nodeVal(child)
						continue
					case "no-install":
						route.NoInstall = true
						continue
					}
					for _, k := range child.Keys {
						if k != "" {
							addrs = append(addrs, k)
						}
					}
				}
				if len(addrs) == 0 && iface != "" {
					// interface-only next-hop (unnumbered) — keep one entry.
					route.NextHops = append(route.NextHops, NextHopEntry{Interface: iface})
				}
				for _, a := range addrs {
					route.NextHops = append(route.NextHops, staticNextHopEntry(a, iface))
				}
			case "no-install":
				route.NoInstall = true
			case "discard":
				route.Discard = true
			case "reject":
				route.Reject = true
			case "preference":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						route.Preference = n
						route.HasPreference = true
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
				//
				// #9235: a flat `qualified-next-hop <gw> interface <if> metric <m>`
				// whose tokens did NOT all land on this node's Keys arrives as a
				// nested chain ([interface <if>] > [metric <m>]), so FindChild
				// found `interface` and missed `metric`. A floating backup's METRIC
				// is what orders two equal-preference backups, so losing it
				// silently reorders failover. Lenient path only.
				qnh := expandRun9235(prop, staticQualifiedNextHopSchema9235())
				if ifNode := qnh.FindChild("interface"); ifNode != nil {
					nh.Interface = nodeVal(ifNode)
				}
				if pNode := qnh.FindChild("preference"); pNode != nil {
					if n, err := strconv.Atoi(nodeVal(pNode)); err == nil {
						nh.Preference = n
						nh.HasPreference = true
					}
				}
				if mNode := qnh.FindChild("metric"); mNode != nil {
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
			if route.NoInstall {
				existingRoute.NoInstall = true
			}
			// #9125: HasPreference, not `!= 5`. The old test could not tell an
			// operator who wrote `preference 5` from one who wrote nothing,
			// because 5 is also the compiler's own default -- so an explicit 5
			// in a later block was silently dropped while any other value
			// applied.
			if route.HasPreference {
				existingRoute.Preference = route.Preference
				existingRoute.HasPreference = true
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

func compileRoutingInstances(node *Node, cfg *Config, opts compileOpts) error {
	// Assign each routing-instance a STABLE kernel routing table id derived from
	// its NAME (#3855), never a positional counter. Positional assignment
	// (100, 101, … by config order) renumbered every survivor after a deleted
	// or reordered instance, so pkg/routing/vrf.go saw a stale table id on an
	// UNTOUCHED VRF and deleted+recreated its live device — a forwarding outage
	// on an unrelated VRF, on both HA nodes. A name-hashed id is invariant under
	// add/remove/reorder of siblings. See StableRoutingInstanceTableID.
	for _, child := range node.Children {
		if len(child.Keys) == 0 {
			continue
		}
		// #9657: an apply statement is not an instance. Expansion strips only
		// apply-groups, so an apply-groups-except or apply-macro reached this
		// loop and became a routing instance and a VRF named after the keyword.
		// The #3855 collision scan skips the same statements.
		if isApplyStatementNode(child) {
			continue
		}
		// #8787: a brace-elided instance is a LEAF, and skipping it dropped
		// the ENTIRE routing instance rather than one property:
		//
		//	routing-instances { ri1 { instance-type forwarding; } }  -> 1 instance
		//	routing-instances { ri1 instance-type forwarding; }      -> 0 instances
		//
		// on a commit reporting success. The harmful direction is `forwarding`:
		// InstanceType == "forwarding" is what makes the daemon SKIP VRF
		// creation, so a dropped value creates a VRF the operator asked NOT to
		// have and moves interfaces into it.
		//
		// The #8690 normalizer's scoped fold cannot reach this site: its pair
		// would be ("ri1", "instance-type"), the operator's INSTANCE NAME, and no
		// scope entry can name it. Since #9620 that normalizer rewrites the elided
		// instance into its braced shape anyway (normalizeElidedRoutingInstance9620),
		// before group expansion and SchemaValidate, so this loop reads only
		// `ri1 { ... }`. Reading the Keys run here instead, after both, compiled an
		// elided body that validation and expansion had never seen.
		//
		// A bare `routing-instances { ri1; }` carries no properties and is
		// still skipped.
		if child.IsLeaf && len(child.Keys) < 2 {
			continue
		}
		instanceName := child.Keys[0]
		ri := &RoutingInstanceConfig{
			Name:    instanceName,
			TableID: StableRoutingInstanceTableID(instanceName),
		}

		for _, prop := range expandResolvingRuns9792(child.Children, routingInstanceSchema9792()) { // #9792: expand a lenient-path packed run (#9235).
			switch prop.Name() {
			case "description":
				ri.Description = nodeVal(prop)
			case "instance-type":
				ri.InstanceType = nodeVal(prop)
				// #9814 round 2: mark authored presence even when the value
				// is empty, so the strict gate can tell explicitly-EMPTY
				// (malformed, incl. a stray hoisted by #9792 that overwrote
				// a valid value) from genuinely OMITTED (silent VRF).
				ri.instanceTypeExplicit9814 = true
			case "vrf-target", "vrf-table-label", "route-distinguisher":
				// #9814: accepted and inert, by the deliberate #9323 decision —
				// say so #9374-style on BOTH paths rather than compiling to
				// nothing in silence. Never rejected: Junos L3VPN configs
				// migrated as-is carry these, and they boot and forward today.
				// Keyword-only, per occurrence (repeats with distinct values
				// are legitimate Junos; values are shape-complex — bracket
				// lists, block forms, multi-token — and the inert STATEMENT
				// is the actionable signal). prop.Name() matches every shape
				// including the valueless flag and `vrf-target { ...; }`.
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
					"routing-instance %q %s is ACCEPTED but NOT APPLIED: xpf compiles "+
						"no BGP/MPLS VPN state from it — the statement is stored and "+
						"displayed but configures nothing (#9814)",
					instanceName, prop.Name()))
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
				if err := compileRoutingOptions(prop, &ro, instanceName, &cfg.Warnings); err != nil {
					return fmt.Errorf("instance %s routing-options: %w", instanceName, err)
				}
				ri.StaticRoutes = ro.StaticRoutes
				ri.Inet6StaticRoutes = ro.Inet6StaticRoutes
				// #7512: carried explicitly — this copy is field-by-field, so a
				// VRF's dropped ribs are unreported unless named here.
				ri.UnhandledRibs = ro.UnhandledRibs
				// #3870: capture the instance-level autonomous-system so a
				// per-instance BGP that omits local-as can inherit it (falling
				// back to the global routing-options AS in resolveBGPAutonomousSystem).
				ri.AutonomousSystem = ro.AutonomousSystem
				// #11782: carry the remaining parsed per-instance routing-options
				// fields too. These are separate slots rather than global
				// RoutingOptionsConfig state; omitting one here silently discarded
				// the successfully compiled stanza when `ro` went out of scope.
				ri.GenerateRoutes = ro.GenerateRoutes
				ri.RibGroups = ro.RibGroups
				ri.ForwardingTableExport = ro.ForwardingTableExport
				ri.ForwardingTableExports = ro.ForwardingTableExports
				// Parse interface-routes rib-group
				if irNode := prop.FindChild("interface-routes"); irNode != nil {
					if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
						// #8939: the routing-instance TWIN of the global site
						// above. Fixing one and not the other is how this class
						// keeps coming back.
						for _, rgChild := range expandFlatRun(rgNode.Children, interfaceRoutesRibGroupSchema8939()) {
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
				if err := compileProtocols(prop, &proto, opts, &cfg.Warnings); err != nil {
					return fmt.Errorf("instance %s protocols: %w", instanceName, err)
				}
				ri.OSPF = proto.OSPF
				ri.OSPFv3 = proto.OSPFv3
				ri.BGP = proto.BGP
				ri.RIP = proto.RIP
				ri.ISIS = proto.ISIS
				// #9374: whatever compileProtocols built that is NOT copied
				// above goes out of scope with `proto`. Say so, rather than
				// letting the stanza compile to nothing in silence.
				cfg.Warnings = append(cfg.Warnings,
					inertPerInstanceProtocolWarnings9374(instanceName, prop)...)
			}
		}

		cfg.RoutingInstances = append(cfg.RoutingInstances, ri)
	}

	// #9622: a routing instance named for a daemon-reserved VRF (the management
	// VRF) never reaches the daemon. The strict commit gate
	// (validateReservedRoutingInstanceNamesAST) rejects it outright; on a lenient
	// path (tolerant load / peer-sync / a config an older binary persisted) drop
	// it here, so the daemon never plans a second vrf-mgmt with a different table.
	// This runs BEFORE the #3855 collision pass below, and the AST table-id gate
	// leaves reserved names out of its union to match, so a reserved instance
	// never claims a table or displaces an instance that shares its hash.
	if len(cfg.RoutingInstances) > 0 {
		kept := cfg.RoutingInstances[:0]
		for _, ri := range cfg.RoutingInstances {
			if IsReservedRoutingInstanceName(ri.Name) {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
					"routing-instance %q QUARANTINED: the name is reserved for %s — no VRF created,"+
						" its members are not bound and its routes are not programmed until it is renamed (#9622)",
					ri.Name, reservedRoutingInstanceNames[ri.Name]))
				// #9956 F-032: record the evictee for the snapshot builders
				// (APPEND — the #11391 and #3855 passes below append their own).
				cfg.QuarantinedRoutingInstances = append(cfg.QuarantinedRoutingInstances, ri)
				continue
			}
			kept = append(kept, ri)
		}
		cfg.RoutingInstances = kept
	}
	// #11391: the runtime creates vrf-<name> without canonicalizing a VRF
	// routing-instance name. Forwarding instances do not create that device and
	// therefore remain active regardless of whether the derived name is valid.
	// Quarantine an uncreatable VRF before the #3855 table-id pass so it cannot
	// claim or displace a table.
	if len(cfg.RoutingInstances) > 0 {
		kept := cfg.RoutingInstances[:0]
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType == "forwarding" {
				kept = append(kept, ri)
				continue
			}
			deviceName, reason := routingInstanceVRFDeviceNameIssue(ri.Name)
			if reason != "" {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
					"routing-instance %q QUARANTINED: derived Linux VRF device name %q is invalid: %s — "+
						"no VRF created, its members are not bound and its routes are not programmed until the name is fixed (#11391)",
					ri.Name, deviceName, reason))
				// #9956 F-032: record the evictee for the snapshot builders.
				cfg.QuarantinedRoutingInstances = append(cfg.QuarantinedRoutingInstances, ri)
				continue
			}
			kept = append(kept, ri)
		}
		cfg.RoutingInstances = kept
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
					// #9956 F-032: record the evictee for the snapshot builders
					// (APPEND — the #9622 and #11391 passes above appended their own.)
					cfg.QuarantinedRoutingInstances = append(cfg.QuarantinedRoutingInstances, ri)
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

// resolveRoutingOptionsRouterID fills empty protocol router-ids from the
// global Junos `routing-options router-id` default. Explicit protocol-level
// values take precedence. Run after the full tree is compiled because the
// routing-options and protocols sections can appear in either order.
func resolveRoutingOptionsRouterID(cfg *Config) {
	if cfg == nil || cfg.RoutingOptions.routerID == "" {
		return
	}
	routerID := cfg.RoutingOptions.routerID
	inherit := func(ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig) {
		if ospf != nil && ospf.RouterID == "" {
			ospf.RouterID = routerID
		}
		if ospfv3 != nil && ospfv3.RouterID == "" {
			ospfv3.RouterID = routerID
		}
		if bgp != nil && bgp.RouterID == "" {
			bgp.RouterID = routerID
		}
	}
	inherit(cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP)
	for _, ri := range cfg.RoutingInstances {
		if ri != nil {
			inherit(ri.OSPF, ri.OSPFv3, ri.BGP)
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
		// #6564: the COMPACT-LEAF spelling `prefix-list PL 10.0.0.0/8;` is a
		// single leaf, Keys=["prefix-list","PL","10.0.0.0/8"], with NO children
		// at all — namedInstances takes Keys[1] as the name and hands back the
		// same node, so the Children loop below saw nothing and the list
		// compiled NAMED but EMPTY. A filter term scoped by it then silently
		// stopped matching, on a config that committed clean. Read the
		// instance node's own trailing keys as well as its children.
		// #7568: take the tail relative to the instance NAME, not a fixed
		// index. namedInstances returns two node shapes and the tail starts
		// at a different offset in each (see instanceValueTail). Reading
		// Keys[2:] unconditionally PANICKED on the block spelling
		// `prefix-list { NAME; }`, and a bare length guard silently drops the
		// prefix in `prefix-list { NAME 10.0.0.0/8; }` — compiling the list
		// NAMED BUT EMPTY, which is the #6564 defect in the other shape.
		for _, p := range instanceValueTail(inst.node, inst.name) {
			if p != "" {
				pl.Prefixes = append(pl.Prefixes, p)
			}
		}
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
		if len(child.Keys) < 2 {
			continue
		}
		// Keys=["as-path", NAME, REGEX-TOKEN...]. The `policy-options
		// as-path` schema node is `args: 2, multi: true`, so the regex is
		// the whole trailing token run, not one key: a QUOTED regex
		// (`as-path AP1 ".* 65000 .*"`) is one lexer string token and
		// arrives whole in Keys[2], while the UNQUOTED spelling of the
		// same value arrives as Keys[2:] = [".*" "65000" ".*"]. The prior
		// `Regex: child.Keys[2]` read kept only the FIRST token, so the
		// unquoted spelling compiled `.* 65000 .*` to `.*` — the
		// whole-path wildcard — and a `from as-path AP1; then accept`
		// term built on it accepted EVERY BGP path (#6686). Reproduced in
		// BOTH spellings (flat `set` and a hierarchical brace block),
		// both of which committed clean with zero warnings while
		// `show configuration` displayed the authored regex back verbatim.
		name := child.Keys[1]
		regex := ASPathRegexFromTokens(child.Keys[2:])
		// The flag travels with the WINNING span only: the instance tail
		// when it is non-empty, else the last non-empty body entry. A
		// bracketed span the join ignores (a shadowed body, an overwritten
		// entry) must not refuse a config whose effective regex is clean.
		unquotedBracket := asPathKeysHaveUnquotedBracket(child, 2)
		if regex == "" {
			// No tail on the instance node: the regex sits on a CHILD
			// leaf instead, which is what a hierarchical brace body
			// (`as-path AP1 { ".* 65000 .*"; }`) produces. Join that
			// leaf's keys for the same reason — an unquoted body lands as
			// Keys=[".*" "65000" ".*"] one level down and the previous
			// `entry.Keys[0]` read widened it identically. Last child
			// wins, preserving the pre-#6686 behaviour for a body that
			// somehow carries several leaves.
			for _, entry := range child.Children {
				if v := ASPathRegexFromTokens(entry.Keys); v != "" {
					regex = v
					unquotedBracket = asPathKeysHaveUnquotedBracket(entry, 0)
				}
			}
		}
		po.ASPaths[name] = &ASPathDef{Name: name, Regex: regex, RegexUnquotedBracket: unquotedBracket}
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
				// Handle hierarchical children and flat inline keys independently:
				// Junos permits packed `term T from ... { then ...; }` nodes whose
				// body and key tail both carry semantics.
				if len(prop.Children) > 0 {
					parsePolicyTermChildren(term, prop.Children)
				}
				if len(prop.Keys) > 2 {
					var bracketed, quoted []bool
					if len(prop.KeysBracketed) == len(prop.Keys) {
						bracketed = prop.KeysBracketed[2:]
					}
					if len(prop.KeysQuoted) == len(prop.Keys) {
						quoted = prop.KeysQuoted[2:]
					}
					parsePolicyTermInlineKeys(term, prop.Keys[2:], bracketed, quoted, prop.BracketedClosed)
				}
			case "from":
				ps.UnknownFrom = append(ps.UnknownFrom, policyStatementUnknownFrom11779(prop)...)
			case "then":
				// Default action at the policy level. #8939: the only two
				// leaves here are `accept` and `reject`, which are mutually
				// exclusive, so a flat run of both is not a command an
				// operator writes -- but the two spellings disagreed about
				// which one won (split last-wins `reject`, packed `accept`),
				// and a spelling difference on a contradictory input is still
				// a spelling difference.
				for _, ac := range expandFlatRun(prop.Children, policyStatementThenSchema8939()) {
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

// resolvePolicyCommunityOperands resolves defined community names used by
// `then community add|set` and the legacy bare replacement form. It runs
// after all policy-options roots compile, so forward definitions resolve too.
// Failed operands remain authored and set a compiler-only flag so strict
// validation and tolerant rendering preserve this first lookup result.
func resolvePolicyCommunityOperands(cfg *Config) {
	if cfg == nil {
		return
	}
	po := &cfg.PolicyOptions
	for _, ps := range po.PolicyStatements {
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			term.CommunityResolutionFailed = false
			switch term.CommunityOp {
			case "add":
				if term.CommunityAdd != "" {
					if value, ok := ResolveCommunityValue(po, term.CommunityAdd); ok {
						term.CommunityAdd = value
					} else {
						term.CommunityResolutionFailed = true
					}
				}
			case "", "set":
				if term.Community != "" {
					if value, ok := ResolveCommunityValue(po, term.Community); ok {
						term.Community = value
					} else {
						term.CommunityResolutionFailed = true
					}
				}
			}
		}
	}
}
func policyStatementUnknownFrom11779(node *Node) []string {
	if node == nil {
		return nil
	}
	if len(node.Keys) > 1 {
		return []string{node.Keys[1]}
	}
	return policyFromOpaqueChildNames11779(node)
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

func markMalformedPolicyFromList11779(term *PolicyTerm, leaf, reason string) {
	if term == nil || term.invalidFromSyntax11779 != "" {
		return
	}
	term.invalidFromSyntax11779 = fmt.Sprintf(
		"malformed bracketed `from %s` list: %s", leaf, reason,
	)
}

// policyTermFromChildren11779 reads typed children from a policy `from` node.
// Compact `from leaf ...` keys and child-body statements are both semantic.
func policyTermFromChildren11779(term *PolicyTerm, fromNode *Node, fromSchema *schemaNode) []*Node {
	if fromNode == nil {
		return nil
	}

	splitChildren := func(children []*Node) []*Node {
		var split []*Node
		for i, child := range children {
			parts := splitPolicyTermFromRun11779(term, child, fromSchema, true)
			if len(parts) == 1 && parts[0] == child {
				if split != nil {
					split = append(split, child)
				}
				continue
			}
			if split == nil {
				split = make([]*Node, 0, len(children))
				split = append(split, children[:i]...)
			}
			split = append(split, parts...)
		}
		if split == nil {
			return children
		}
		return split
	}

	children := splitChildren(fromNode.Children)
	if len(fromNode.Keys) <= 1 {
		return children
	}
	tail := *fromNode
	tail.Keys = append([]string(nil), fromNode.Keys[1:]...)
	tail.Children = nil
	if len(fromNode.KeysQuoted) == len(fromNode.Keys) {
		tail.setKeysQuoted(fromNode.KeysQuoted[1:])
	}
	if len(fromNode.KeysBracketed) == len(fromNode.Keys) {
		tail.setKeysBracketed(fromNode.KeysBracketed[1:])
	}
	parts := splitPolicyTermFromRun11779(term, &tail, fromSchema, true)
	return append(parts, children...)
}

// splitPolicyTermFromRun11779 separates schema-known match siblings in a
// packed `from` key run. Opaque tails are retained as synthetic leaves for the
// ordinary UnknownFrom gate.
func splitPolicyTermFromRun11779(
	term *PolicyTerm, run *Node, fromSchema *schemaNode, preserveUnknown bool,
) []*Node {
	if run == nil || len(run.Keys) == 0 || len(run.Children) > 0 || fromSchema == nil {
		return []*Node{run}
	}
	keys := run.Keys
	var nodes []*Node
	appendSpan := func(start, end int) {
		if start == 0 && end == len(keys) {
			nodes = append(nodes, run)
			return
		}
		part := *run
		part.Keys = append([]string(nil), keys[start:end]...)
		part.Children = nil
		part.IsLeaf = true
		if len(run.KeysQuoted) == len(keys) {
			part.setKeysQuoted(run.KeysQuoted[start:end])
		} else {
			part.setKeysQuoted(nil)
		}
		if len(run.KeysBracketed) == len(keys) {
			part.setKeysBracketed(run.KeysBracketed[start:end])
		} else {
			part.setKeysBracketed(nil)
		}
		nodes = append(nodes, &part)
	}

	routeFilterSchema := resolveSchemaChild(fromSchema, "route-filter")
	for i := 0; i < len(keys); {
		if run.KeyQuoted(i) {
			if preserveUnknown {
				appendSpan(i, len(keys))
			}
			break
		}
		childSchema := resolveSchemaChild(fromSchema, keys[i])
		if childSchema == nil {
			if preserveUnknown {
				appendSpan(i, len(keys))
			}
			break
		}
		n, _ := consumeNodeKeys(keys[i:], childSchema)
		if childSchema == routeFilterSchema {
			n = packedRouteFilterWidth(keys, i, n)
		}
		if n <= 0 {
			break
		}
		if childSchema.multi && childSchema.children == nil && n > 1 {
			for j := i + n - 1; j < i+n; j++ {
				if run.KeyBracketed(j) && !run.BracketedClosed {
					markMalformedPolicyFromList11779(term, keys[i], "list did not close")
					break
				}
			}
			for n < len(keys)-i {
				next := i + n
				if run.KeyBracketed(next) {
					if !run.BracketedClosed && policyTermClauseKeyword11779(keys[next]) {
						break
					}
					n++
					continue
				}
				if run.KeyQuoted(next) {
					n++
					continue
				}
				if resolveSchemaChild(fromSchema, keys[next]) != nil ||
					policyTermInlineKeywords[keys[next]] {
					break
				}
				n++
			}
		}
		if i == 0 && n == len(keys) {
			return []*Node{run}
		}
		appendSpan(i, i+n)
		i += n
	}
	return nodes
}

// parsePolicyTermChildren handles hierarchical form of policy term
// where "from" and "then" are child nodes.
func parsePolicyTermChildren(term *PolicyTerm, children []*Node) {
	for _, tc := range children {
		switch tc.Name() {
		case "from":
			fromSchema := schemaForPath("policy-options", "policy-statement", "term", "from")
			for _, fc := range policyTermFromChildren11779(term, tc, fromSchema) {
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
					if len(fc.Keys) > 1 && len(fc.Children) > 0 {
						term.FromProtocols = append(term.FromProtocols, fc.Keys[1:]...)
						term.UnknownFrom = append(term.UnknownFrom, policyFromOpaqueChildNames11779(fc)...)
					} else {
						term.FromProtocols = append(term.FromProtocols, collectProtocolList(fc)...)
					}
				case "prefix-list":
					// Junos allows repeated `prefix-list` siblings in one
					// term (match ANY). Accumulate so multiple statements are
					// all kept, not just the last (#2642). A bracketed list
					// `prefix-list [ p1 p2 ]` ALSO collapses onto one leaf's
					// Keys[1:] / Children in BOTH AST shapes (#2419), so read
					// every value via the firewallMatchValues SSOT — the prior
					// nodeVal-only read kept just the first list entry (#2689).
					if !fc.IsLeaf && len(fc.Children) > 0 {
						term.PrefixList = append(term.PrefixList, fc.Keys[1:]...)
						term.UnknownFrom = append(term.UnknownFrom, policyFromOpaqueChildNames11779(fc)...)
					} else {
						term.PrefixList = append(term.PrefixList, firewallMatchValues(fc)...)
					}
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
					if !fc.IsLeaf && len(fc.Children) > 0 {
						term.FromCommunity = append(term.FromCommunity, fc.Keys[1:]...)
						term.UnknownFrom = append(term.UnknownFrom, policyFromOpaqueChildNames11779(fc)...)
					} else {
						term.FromCommunity = append(term.FromCommunity, firewallMatchValues(fc)...)
					}
				case "as-path":
					// Repeated `as-path` siblings match ANY (#2642). A bracketed
					// list `as-path [ a1 a2 ]` ALSO collapses onto one leaf's
					// Keys[1:] / Children in BOTH AST shapes (#2419), so read
					// every value via the firewallMatchValues SSOT — the prior
					// nodeVal-only read kept just the first list entry (#2689).
					if !fc.IsLeaf && len(fc.Children) > 0 {
						term.FromASPath = append(term.FromASPath, fc.Keys[1:]...)
						term.UnknownFrom = append(term.UnknownFrom, policyFromOpaqueChildNames11779(fc)...)
					} else {
						term.FromASPath = append(term.FromASPath, firewallMatchValues(fc)...)
					}
				case "then":
					term.UnknownFrom = append(term.UnknownFrom, fc.Name())
				default:
					term.UnknownFrom = append(term.UnknownFrom, fc.Name())
				}
			}
		case "then":
			// #8939: `set … term t1 then accept load-balance per-packet
			// local-preference 200` nests each action under the previous one,
			// so this loop saw only `accept`. The route is still ACCEPTED --
			// `accept` is alphabetically first, so it is the one token that
			// survives -- and installed WITHOUT the attributes the operator
			// attached to it: default local-preference, no ECMP.
			for _, ac := range expandFlatRun(tc.Children, policyTermThenSchema8939()) {
				switch ac.Name() {
				case "accept":
					term.Action = "accept"
				case "reject":
					term.Action = "reject"
				case "next":
					recordPolicyNextAction11780(term, nodeVal(ac))
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
					// `then as-path-prepend` is multi-value. Read every entry
					// through the firewallMatchValues SSOT, then split quoted
					// multi-ASN values before storing the operands (#2892/#12070).
					term.ASPathPrepend = appendPolicyASPathPrependOperands(term.ASPathPrepend, firewallMatchValues(ac))
				case "origin":
					term.Origin = nodeVal(ac)
				}
			}
			if len(tc.Keys) >= 2 {
				parsePolicyTermInlineKeys(term, tc.Keys, tc.KeysBracketed, tc.KeysQuoted, tc.BracketedClosed)
			}
		}
	}
}
func policyFromOpaqueChildNames11779(node *Node) []string {
	if node == nil {
		return nil
	}
	var names []string
	for _, child := range node.Children {
		if child != nil && child.Name() != "" {
			names = append(names, child.Name())
		}
	}
	return names
}

func recordPolicyNextAction11780(term *PolicyTerm, value string) {
	if value == "policy" {
		term.NextPolicy = true
		return
	}
	term.invalidNextPolicy11780 = true
	term.invalidNextPolicyValue11780 = value
	term.Action = "reject"
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
	"origin": true, "accept": true, "reject": true, "next": true,
	"neighbor": true, "rib": true, "instance": true, "interface": true,
	"family": true, "tag": true, "area": true,
}

var policyTermFromUnsupportedThenKeywords11779 = map[string]bool{
	"accept": true, "as-path-prepend": true, "load-balance": true,
	"local-preference": true, "metric": true, "metric-type": true,
	"next": true, "next-hop": true, "origin": true, "reject": true,
}

func skipUnknownPolicyTermFromTail11779(keys []string, i int) int {
	for i+1 < len(keys) && !policyTermInlineKeywords[keys[i+1]] {
		i++
	}
	return i
}
func policyTermClauseKeyword11779(key string) bool {
	return key == "from" || key == "then"
}

// appendInlineBracketedMatchValues11779 reads all values of a multi-value
// `from` leaf until a known leaf/action boundary. Bracket metadata determines
// whether a keyword belongs to a closed value list or an unclosed list.
func appendInlineBracketedMatchValues11779(
	dst, keys []string, bracketed, quoted []bool, i int, closed bool,
) ([]string, int, string) {
	if i+1 >= len(keys) {
		return dst, i, ""
	}
	sawBracketed := false
	for next := i + 1; next < len(keys); next++ {
		isBracketed := next < len(bracketed) && bracketed[next]
		isQuoted := next < len(quoted) && quoted[next]
		if isBracketed {
			sawBracketed = true
			if !closed && policyTermClauseKeyword11779(keys[next]) {
				return dst, next - 1, "list did not close before clause keyword"
			}
		}
		if !isQuoted && !isBracketed && policyTermInlineKeywords[keys[next]] {
			break
		}
		dst = append(dst, keys[next])
		i = next
	}
	if sawBracketed && !closed {
		return dst, i, "list did not close"
	}
	return dst, i, ""
}

// parsePolicyTermInlineKeys handles flat set syntax where remaining keys
// after the term name are inline key-value pairs like:
// "from", "protocol", "direct" or "from", "route-filter", "10.0.0.0/8", "exact"
// or "then", "accept"
func parsePolicyTermInlineKeys(term *PolicyTerm, keys []string, bracketed, quoted []bool, bracketedClosed bool) {
	inFrom := false
	for i := 0; i < len(keys); i++ {
		if inFrom && policyTermFromUnsupportedThenKeywords11779[keys[i]] {
			term.UnknownFrom = append(term.UnknownFrom, keys[i])
			i = skipUnknownPolicyTermFromTail11779(keys, i)
			continue
		}
		switch keys[i] {
		case "from":
			inFrom = true
			continue
		case "then":
			inFrom = false
			if i+1 < len(keys) {
				if keys[i+1] == "next" {
					i++
					value := ""
					if i+1 < len(keys) {
						i++
						value = keys[i]
					}
					recordPolicyNextAction11780(term, value)
					continue
				}
				i++
				term.Action = keys[i]
			}
		case "next":
			if !inFrom {
				value := ""
				if i+1 < len(keys) {
					i++
					value = keys[i]
				}
				recordPolicyNextAction11780(term, value)
			}
		case "protocol":
			// "from protocol [ bgp ospf static ]" — the lexer strips the
			// brackets, so every protocol arrives as a separate key. Consume
			// all consecutive values until the next clause keyword, so a
			// multi-protocol list keeps every protocol (not just the first).
			sawBracketed := false
			for i+1 < len(keys) {
				next := i + 1
				isBracketed := next < len(bracketed) && bracketed[next]
				isQuoted := next < len(quoted) && quoted[next]
				if isBracketed {
					sawBracketed = true
					if !bracketedClosed && policyTermClauseKeyword11779(keys[next]) {
						markMalformedPolicyFromList11779(term, "protocol", "list did not close before clause keyword")
						break
					}
				} else if isQuoted || !policyTermInlineKeywords[keys[next]] {
					i++
					term.FromProtocols = append(term.FromProtocols, keys[i])
					continue
				} else {
					break
				}
				i++
				term.FromProtocols = append(term.FromProtocols, keys[i])
			}
			if sawBracketed && !bracketedClosed {
				markMalformedPolicyFromList11779(term, "protocol", "list did not close")
			}
		case "prefix-list":
			var badClause string
			term.PrefixList, i, badClause = appendInlineBracketedMatchValues11779(
				term.PrefixList, keys, bracketed, quoted, i, bracketedClosed)
			if badClause != "" {
				markMalformedPolicyFromList11779(term, "prefix-list", badClause)
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
			} else {
				// A term-line tail is outside the schema walk. Preserve the
				// bare route-filter marker so the strict #11779 gate rejects
				// it rather than compiling a match-all permit with no filter.
				term.UnknownFrom = append(term.UnknownFrom, "route-filter")
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
				var badClause string
				term.FromCommunity, i, badClause = appendInlineBracketedMatchValues11779(
					term.FromCommunity, keys, bracketed, quoted, i, bracketedClosed)
				if badClause != "" {
					markMalformedPolicyFromList11779(term, "community", badClause)
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
			var badClause string
			term.FromASPath, i, badClause = appendInlineBracketedMatchValues11779(
				term.FromASPath, keys, bracketed, quoted, i, bracketedClosed)
			if badClause != "" {
				markMalformedPolicyFromList11779(term, "as-path", badClause)
			}
		case "as-path-prepend":
			// Consume consecutive values until the next clause keyword,
			// splitting quoted multi-ASN values before storing each operand.
			for i+1 < len(keys) && !policyTermInlineKeywords[keys[i+1]] {
				i++
				term.ASPathPrepend = appendPolicyASPathPrependOperand(term.ASPathPrepend, keys[i])
			}
		case "origin":
			if i+1 < len(keys) {
				i++
				term.Origin = keys[i]
			}
		case "accept":
			if !inFrom {
				term.Action = "accept"
			}
		case "reject":
			if !inFrom {
				term.Action = "reject"
			}
		default:
			if inFrom {
				term.UnknownFrom = append(term.UnknownFrom, keys[i])
				i = skipUnknownPolicyTermFromTail11779(keys, i)
			}
		}
	}
}

// mainRIBTableID is the Linux main routing table (RT_TABLE_MAIN). It mirrors
// pkg/routing.mainTableID; the two MUST agree on which import-rib targets are
// "main" so the commit-time warn and the runtime applier classify a rib-group
// import the same way (#3876).
const mainRIBTableID = 254

// mergeRibGroupDefinition accumulates import-rib entries from repeated blocks
// into the first definition, matching the union produced by flat-set syntax.
// Repeats across separate routing-options roots are also announced to the user.
func mergeRibGroupDefinition(ribGroups map[string]*RibGroup, next *RibGroup, warnings *[]string) {
	if next == nil {
		return
	}
	if first := ribGroups[next.Name]; first != nil {
		first.ImportRibs = append(first.ImportRibs, next.ImportRibs...)
		if warnings != nil {
			*warnings = append(*warnings, duplicateBlockMergeWarning9023("rib-groups "+next.Name))
		}
		return
	}
	ribGroups[next.Name] = next
}

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

// RoutingInstanceConnectedPrefixes derives the statically configured connected
// network prefixes for every routing instance. Prefixes are masked through
// ConnectedNetworkPrefix, the same derivation the userspace FIB uses for
// connected routes. Callers split the mixed IPv4/IPv6 list by family.
//
// Dynamic DHCP addresses are intentionally absent: they cannot be enumerated
// during config apply.
func RoutingInstanceConnectedPrefixes(cfg *Config) map[string][]string {
	out := make(map[string][]string)
	if cfg == nil {
		return out
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		var prefixes []string
		for _, member := range ri.Interfaces {
			// A disabled interface is administratively inactive even though
			// its configured unit addresses remain in the typed config. Do not
			// publish those prefixes to rib-group derivation (the same set is
			// used to install connected routes and leak rules).
			memberBase := cfg.SplitInterfaceUnitRef(member).Base
			if iface := cfg.Interfaces.Interfaces[memberBase]; iface != nil && iface.Disable {
				continue
			}
			// #9809: every configured unit of a bare member, as the FIB binds it.
			for _, mu := range RoutingInstanceMemberUnits(cfg, member) {
				for _, addr := range mu.Addresses {
					if prefix, _, ok := ConnectedNetworkPrefix(addr); ok {
						prefixes = append(prefixes, prefix)
					}
				}
			}
		}
		if len(prefixes) > 0 {
			out[ri.Name] = prefixes
		}
	}
	return out
}

// RibGroupConnectedPrefixes returns the sorted, duplicate-free
// connected-prefix subset whose instances configure interface-routes
// rib-groups. It is the #3876 per-prefix leak set and the source for #11062
// reciprocal peer-prefix matching.
func RibGroupConnectedPrefixes(cfg *Config) map[string][]string {
	out := RoutingInstanceConnectedPrefixes(cfg)
	if cfg == nil {
		return out
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if ri.Name == "" || (ri.InterfaceRoutesRibGroup == "" && ri.InterfaceRoutesRibGroupV6 == "") {
			delete(out, ri.Name)
		}
	}
	for name, prefixes := range out {
		slices.Sort(prefixes)
		out[name] = slices.Compact(prefixes)
	}
	return out
}

// policyStatementThenSchema8939 / policyTermThenSchema8939 resolve the two
// `then` containers under `policy-options policy-statement`.
//
// THEY ARE NOT EQUALLY INTERESTING AND THE CENSUS CANNOT SAY SO. The
// policy-level `then` declares exactly `accept` and `reject`, which are
// mutually exclusive, so its census row is the only pair that exists and is
// not a command anyone writes. The TERM-level `then` declares ten children --
// `load-balance`, `local-preference`, `metric`, `next-hop`, `origin`,
// `as-path-prepend`, `community` among them -- and `then { local-preference
// 200; load-balance per-packet; accept; }` is ordinary Junos. That is the row
// with the operator behind it.
func policyStatementThenSchema8939() *schemaNode {
	po := resolveSchemaChild(setSchema, "policy-options")
	ps := resolveSchemaChild(po, "policy-statement")
	if ps != nil && ps.wildcard != nil {
		ps = ps.wildcard
	}
	return resolveSchemaChild(ps, "then")
}

func policyTermThenSchema8939() *schemaNode {
	po := resolveSchemaChild(setSchema, "policy-options")
	ps := resolveSchemaChild(po, "policy-statement")
	if ps != nil && ps.wildcard != nil {
		ps = ps.wildcard
	}
	term := resolveSchemaChild(ps, "term")
	if term != nil && term.wildcard != nil {
		term = term.wildcard
	}
	return resolveSchemaChild(term, "then")
}
