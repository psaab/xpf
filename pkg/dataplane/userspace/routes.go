package userspace

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// ruleListFn is the netlink ip-rule enumerator, indirected so tests can
// inject a transient failure and assert it is surfaced (#3772 M9).
var ruleListFn = netlink.RuleList

// buildRouteSnapshots derives the helper FIB from config statics,
// connected prefixes, and ip-rule leak rules, then applies the
// ip-monitoring route overlay (#1827 PR-1b): each overlay entry
// REPLACES the entire (table, family, prefix) entry set — never merges
// next-hops — so an ECMP half-override is impossible by construction.
//
// It returns an error when the kernel ip-rule enumeration fails (#3772
// M9): the synthetic rib-group / next-table leak routes are derived from
// the live ip-rule table, so a transient RuleList failure must fail the
// whole snapshot build closed (the apply path then retains the prior
// dataplane state) rather than silently emitting a PARTIAL snapshot that
// drops every route-leak route for that family while the kernel/FRR leak
// path stays up — a divergence with no signal. Mirrors #3731's
// surface-don't-swallow contract on the RuleAdd (write) side.
// The second return value reports whether the #8355 learned-route cap DECLINED
// the import (#9054). It is not a diagnostic: the helper's NoRoute adjudication
// (#7480) decides whether to drop or delegate a frame whose destination is not
// in its FIB, and that decision is only sound while the FIB is a near-complete
// mirror of the kernel's. When the cap declines the import wholesale, NoRoute
// stops meaning "there is no route" and starts meaning "we did not tell you" —
// so the caller must put the fact on the wire.
func buildRouteSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot, overlay []config.RouteOverlayEntry) ([]RouteSnapshot, bool, error) {
	if cfg == nil {
		return nil, false, nil
	}
	out := make([]RouteSnapshot, 0)
	seen := make(map[string]struct{})
	addSnapshot := func(snap RouteSnapshot) {
		// #6568 (member 1): the destination must reach the wire as something
		// the Rust FIB can PARSE. `populate_routes` (forwarding_build/fib.rs)
		// tries `Ipv4Net` then `Ipv6Net` and, before this, fell off the end of
		// the loop body when both failed — no Err, no counter, no log — at a
		// boundary whose whole #2409/#2410/#3771 contract is "no silent skips".
		//
		// That is a traffic FAIL-OPEN for a discard/blackhole route, not the
		// low-materiality residual it was filed as. `ipnet`'s parsers REQUIRE a
		// prefix length, and nothing in the config compiler validates the
		// destination, so measured: `route 10.0.0.1 discard`,
		// `route 2001:db8::1 discard` and `route default discard` all commit,
		// all ship, and all vanish in the helper — traffic then longest-prefix
		// matches a LESS-SPECIFIC route (typically the default) and is
		// FORWARDED where the operator asked for it to be dropped.
		//
		// A bare host address is normalised to its /32 or /128 host prefix,
		// which is what the operator meant and what the kernel/FRR path already
		// does with it. Anything still unparseable is dropped HERE, loudly, so
		// it never reaches the helper: the operator gets a diagnostic naming
		// the route instead of a silent forwarding hole. The Rust side now
		// fails the snapshot closed on the same condition as defence in depth.
		if dest, ok := routeDestinationForWire(snap.Destination); ok {
			snap.Destination = dest
		} else {
			slog.Warn("dropping route with an unusable destination from the "+
				"helper FIB: it is neither a CIDR prefix nor a bare IP "+
				"address, so the userspace dataplane cannot install it "+
				"(#6568). Traffic to it will follow a less-specific route",
				"destination", snap.Destination, "table", snap.Table,
				"family", snap.Family, "discard", snap.Discard)
			return
		}
		// #3770 (H8): the dedupe key MUST include Discard and Preference.
		// A discard (blackhole) route and a normal route to the same prefix
		// are DISTINCT forwarding decisions — omitting Discard let one
		// silently hide the other. Two routes differing only in preference
		// (e.g. a static next-table route at its configured preference and
		// the kernel ip-rule mirror at preference 0) collided on the old key
		// and the second was dropped before the Rust FIB could apply its
		// preference tie-break (fib.rs sort_routes).
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%t|%d",
			snap.Table, snap.Family, snap.Destination,
			strings.Join(snap.NextHops, ","), snap.NextTable,
			snap.Discard, snap.Preference)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, snap)
	}
	// #7357: the shared drop verdict for every static route in this config,
	// computed once. See config.StaticRouteExclusions — it owns the
	// order-dependent #6467 next-table ip-rule window as well as the three
	// per-route causes, and the show surfaces consult the same function.
	staticRouteExclusions := config.StaticRouteExclusions(cfg)
	addRoutes := func(table, family string, routes []*config.StaticRoute, perInstance bool) {
		for _, route := range routes {
			if route == nil {
				continue
			}
			// #7357: ONE verdict for both halves. config.StaticRouteExclusions
			// is the same map the `show routing-options` /
			// `show routing-instances` surfaces consult, so a route this
			// builder refuses cannot render there as installed.
			//
			// It carries the ORDER-DEPENDENT next-table window too (#6467:
			// the applier installs at most NextTableRuleWindow ip rules, so the
			// FIB mirror must truncate the same tail the kernel drops). That
			// used to be an inline counter here — a SECOND implementation of a
			// rule the predicate already had to reproduce for the renderer,
			// which is precisely the drift #6534 is about. There is now one.
			if reason := staticRouteExclusions[route]; reason != "" {
				continue
			}
			tableName, familyName := normalizeRouteSnapshotFamily(table, family, route.Destination)
			base := RouteSnapshot{
				Table:       tableName,
				Family:      familyName,
				Destination: route.Destination,
				// #5298: a `reject` route drops on the AF_XDP fast path the same
				// way `discard` does. Without an entry in the userspace FIB, a
				// reject prefix would longest-prefix-match a less-specific route
				// (e.g. the default) and forward — the identical fail-wide the
				// FRR/kernel reject route closes. Fold reject into the helper's
				// silent-drop disposition (fail-closed). The ICMP-unreachable
				// distinction (reject vs discard) is emitted by the kernel/FRR
				// reject route today; a userspace-generated ICMP unreachable is a
				// follow-up that would need a dedicated RouteSnapshot field.
				Discard:    route.Discard || route.Reject,
				NextTable:  route.NextTable,
				Preference: route.Preference,
			}
			// #5678: group next-hops by their EFFECTIVE preference. A
			// qualified-next-hop carries its own admin distance (#3871
			// HasPreference — the Junos floating-static idiom: a primary
			// next-hop plus a less-preferred backup); a plain next-hop uses the
			// route-level preference. Emit ONE snapshot per distinct preference
			// so a backup lowers as a SEPARATE, higher-preference standby route,
			// NOT co-installed with the primary as an equal-cost ECMP member.
			// The Rust FIB tie-breaks same-prefix routes by ascending
			// preference (#2390 sort_routes) and selects the lowest via
			// first-match lookup, holding the higher-preference backup as a
			// standby entry — so folding the backup into the primary's next-hop
			// list load-balanced traffic across both instead of preferring the
			// primary (the #5678 silent routing-semantics change). Next-hops
			// that share a preference (a plain `next-hop [ a b ]` list, or
			// qualified next-hops at the SAME distance) stay a single
			// equal-cost ECMP snapshot — no regression for real ECMP. Mirrors
			// the FRR renderer (pkg/frr/config_render.go), which emits one `ip
			// route` line per next-hop at dist = nh.Preference when
			// HasPreference else the route-level distance.
			type prefGroup struct {
				preference int
				nextHops   []string
			}
			order := make([]int, 0, len(route.NextHops))
			groups := make(map[int]*prefGroup)
			for _, nh := range route.NextHops {
				var target string
				switch {
				case nh.Address != "" && nh.Interface != "":
					target = nh.Address + "@" + nh.Interface
				case nh.Address != "":
					target = nh.Address
				case nh.Interface != "":
					target = "@" + nh.Interface
				default:
					continue
				}
				pref := route.Preference
				if nh.HasPreference {
					pref = nh.Preference
				}
				g, ok := groups[pref]
				if !ok {
					g = &prefGroup{preference: pref}
					groups[pref] = g
					order = append(order, pref)
				}
				g.nextHops = append(g.nextHops, target)
			}
			if len(order) == 0 {
				// No forwarding next-hops (discard / reject / next-table, or
				// every next-hop had an empty target): emit the base
				// disposition unchanged so the negative-route / leak entry is
				// preserved.
				addSnapshot(base)
				continue
			}
			for _, pref := range order {
				snap := base
				snap.Preference = groups[pref].preference
				snap.NextHops = groups[pref].nextHops
				addSnapshot(snap)
			}
		}
	}
	interfaceTablesV4, interfaceTablesV6 := buildInterfaceRouteTables(cfg)
	addConnectedRoutes := func(family, table string, prefixes []string) {
		for _, prefix := range prefixes {
			snap := RouteSnapshot{
				Table:       table,
				Family:      family,
				Destination: prefix,
			}
			addSnapshot(snap)
		}
	}
	addRoutes("inet.0", "inet", cfg.RoutingOptions.StaticRoutes, false)
	addRoutes("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes, false)

	if len(cfg.RoutingInstances) > 0 {
		insts := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			if ri != nil {
				insts = append(insts, ri)
			}
		}
		sort.Slice(insts, func(i, j int) bool { return insts[i].Name < insts[j].Name })
		for _, ri := range insts {
			addRoutes(ri.Name+".inet.0", "inet", ri.StaticRoutes, true)
			addRoutes(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes, true)
		}
	}
	for _, iface := range interfaces {
		if iface.Name == "" {
			continue
		}
		v4Table := interfaceTablesV4[iface.Name]
		if v4Table == "" {
			v4Table = "inet.0"
		}
		v6Table := interfaceTablesV6[iface.Name]
		if v6Table == "" {
			v6Table = "inet6.0"
		}
		v4Prefixes, v6Prefixes := connectedPrefixesForInterface(iface)
		addConnectedRoutes("inet", v4Table, v4Prefixes)
		addConnectedRoutes("inet6", v6Table, v6Prefixes)
	}

	// Add synthetic routes for ip rule entries that implement inter-VRF
	// route leaking (rib-groups, next-table). These rules send traffic
	// matching a destination prefix to a different routing table.
	// Without these, the userspace FIB can't cross-reference VRF tables.
	//
	// #3768 (H6): key the map on the BARE routing-instance name and derive
	// the family-specific next-table name (".inet.0" vs ".inet6.0") per
	// family INSIDE the loop below. The old map baked in "<inst>.inet.0"
	// unconditionally and the AF_INET6 pass reused it verbatim, so an IPv6
	// ip-rule leaking e.g. 2001:db8:1::/48 into instance "blue" emitted
	// RouteSnapshot{Table:"inet6.0", Family:"inet6", NextTable:"blue.inet.0"}.
	// The Rust FIB keys routes_v6 as canonical_route_table(table, true) =
	// "blue.inet6.0", so the v6 next-table recursion into "blue.inet.0"
	// missed -> NoRoute -> leaked IPv6 traffic blackholed. Note that
	// normalizeRouteSnapshotFamily canonicalizes static-route tables but is
	// NOT applied to these synthetic ip-rule leak snapshots.
	tableIDToInst := make(map[int]string)
	for _, inst := range cfg.RoutingInstances {
		if inst != nil && inst.TableID > 0 {
			tableIDToInst[inst.TableID] = inst.Name
		}
	}
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rules, err := ruleListFn(family)
		if err != nil {
			// #3772 (M9): do NOT swallow. A partial snapshot missing this
			// family's route-leak routes would blackhole or policy-bypass
			// inter-VRF traffic that the kernel/FRR still routes.
			return nil, false, fmt.Errorf("route snapshot: list ip-rules for family %d: %w", family, err)
		}
		for _, rule := range rules {
			// A Dst-less rule (`from all lookup <table>`) cannot be
			// represented as a per-prefix NextTable leak (it would mean
			// "leak the whole table"), so it is skipped here. The rib-group
			// import leak installs per-prefix `to <prefix> lookup
			// <sourceTable>` rules (pkg/routing, #3876) that DO carry a Dst,
			// so they are auto-captured by this loop as NextTable leaks into
			// main — no change to this skip is needed for the fix.
			if rule.Dst == nil || rule.Table <= 0 {
				continue
			}
			// #4479 (opus-172 M-2): SKIP policy-based-routing / filter-based-
			// forwarding rules. xpf installs FBF `then routing-instance`
			// filter actions as ip rules in the PBR priority band
			// (config.PBRRulePriorityBase, 31000-31999; pkg/routing
			// pbrRulePriority) that carry match SELECTORS — source/dest
			// address, DSCP, protocol, source/dest port — IN ADDITION to a
			// Dst that happens to point at a routing-instance table. This
			// synthetic snapshot can only express a bare per-prefix NextTable
			// leak, so ingesting a PBR rule here would DROP every selector and
			// widen a constrained, source-scoped steer into an unconditional
			// dst-only VRF leak — the exact fail-open the kernel FBF path was
			// hardened against in #3730. Fail CLOSED instead: leave the PBR
			// rule out of the userspace FIB entirely. The kernel still applies
			// the real, fully-qualified PBR rule (and the userspace filter
			// path enforces the term), so the leak is not lost — it just is
			// not wrongly widened. Only xpf's own pure per-prefix leak bands
			// (next-table 100-199, rib-group per-prefix import 30000-30999)
			// carry a Dst with no selectors and are safe to mirror below.
			if rule.Priority >= config.PBRRulePriorityBase &&
				rule.Priority < config.PBRRulePriorityBase+config.PBRRuleWindow {
				continue
			}
			instName, ok := tableIDToInst[rule.Table]
			if !ok {
				continue
			}
			familyStr := "inet"
			mainTable := "inet.0"
			nextTable := instName + ".inet.0"
			if family == syscall.AF_INET6 {
				familyStr = "inet6"
				mainTable = "inet6.0"
				nextTable = instName + ".inet6.0"
			}
			addSnapshot(RouteSnapshot{
				Table:       mainTable,
				Family:      familyStr,
				Destination: rule.Dst.String(),
				NextTable:   nextTable,
			})
		}
	}

	// #7409 (fifth source): kernel-learned routes.
	//
	// The four sources above are ALL config-derived, so a route FRR installs
	// (BGP/OSPF/IS-IS/RIP) or that a DHCP lease on a non-management interface
	// contributes (the AD-200 default and its RFC 3442 classless routes) is
	// invisible to the helper FIB while the kernel routes it happily. A
	// transit packet toward such a destination either resolves NoRoute and is
	// REINJECTED to the kernel unadjudicated — no zone policy, no session, no
	// NAT, no screen, and no nftables `hook forward` chain behind it — or, if
	// a config default happens to cover it, is forwarded to the STATIC
	// default's next-hop instead of the learned one. Import closes both.
	//
	// GAP-FILL ONLY. An imported route is dropped whenever the config-derived
	// set above already carries the same (table, family, prefix). That single
	// rule is what makes this safe to add without renegotiating any existing
	// precedence contract: the #3770 dedupe key, the #2390 preference
	// tie-break and the overlay's whole-entry replacement all keep operating
	// on exactly the routes they did before, because no imported route can
	// ever contend with one of theirs.
	//
	// THE OVERLAY ALWAYS WINS, and the gap-fill rule — not this call's
	// position — is what guarantees it. Measured, because the obvious claim
	// is wrong: moving this call BELOW applyRouteOverlay changes nothing.
	// Import-first, the overlay's whole-entry replacement removes anything
	// imported for its prefix; import-last, `covered` is computed from an
	// `out` that already holds the overlay's entries, so the imported route
	// is suppressed as covered. Both orders end with only the overlay's
	// route, so #1827's no-half-override contract holds either way.
	//
	// It runs here anyway because the overlay is documented as the LAST
	// transform on the snapshot and reading it that way should stay true.
	// Do not restate the position as a safety property: it is not one, and a
	// comment claiming a guarantee the code does not depend on is how the
	// next reader stops looking for the guarantee that matters.
	capped, err := addLearnedRouteSnapshots(cfg, out, addSnapshot)
	if err != nil {
		return nil, false, err
	}

	out = applyRouteOverlay(out, overlay)

	// #3770 (M10): stable sort with a TOTAL order. The old comparator
	// keyed only on Table/Family/Destination, so two same-prefix routes
	// (distinct after the H8 dedupe fix, e.g. a next-table leak and its
	// ip-rule mirror, or a discard and a connected route) compared equal
	// and their relative order followed the non-deterministic build input
	// order (map iteration, kernel ip-rule order) under an UNSTABLE sort —
	// producing spurious snapshot-to-snapshot diffs and ECMP-member churn
	// that re-installed the FIB for no config change. Tie-break on
	// next-hops, next-table, discard, then preference so the wire order is
	// a deterministic function of content alone.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		an, bn := strings.Join(a.NextHops, ","), strings.Join(b.NextHops, ",")
		if an != bn {
			return an < bn
		}
		if a.NextTable != b.NextTable {
			return a.NextTable < b.NextTable
		}
		if a.Discard != b.Discard {
			// Non-discard (false) sorts before discard (true).
			return b.Discard
		}
		return a.Preference < b.Preference
	})
	return out, capped, nil
}

// applyRouteOverlay folds the winner-resolved ip-monitoring overlay
// into the route set: for each entry, every existing snapshot for the
// same (table, family, canonical prefix) is REMOVED (whole-entry
// replacement, including all ECMP next-hops) and the single overlay
// route is appended.
func applyRouteOverlay(routes []RouteSnapshot, overlay []config.RouteOverlayEntry) []RouteSnapshot {
	if len(overlay) == 0 {
		return routes
	}
	type key struct{ table, family, dest string }
	replaced := make(map[key]RouteSnapshot, len(overlay))
	for _, entry := range overlay {
		table, family := overlayTableFamily(entry)
		dest := canonicalRoutePrefix(entry.Destination)
		if dest == "" {
			continue
		}
		replaced[key{table, family, dest}] = RouteSnapshot{
			Table:       table,
			Family:      family,
			Destination: dest,
			NextHops:    []string{entry.NextHop},
			// #3770 (M7): the ip-monitoring overlay injects the documented
			// Static/1 route (route preference 1, PreferredRoute contract in
			// pkg/config/types_system.go). Leaving it at 0 made the Rust FIB
			// sort it as MORE preferred than the documented value and diverged
			// from the FRR managed-section render (distance-1 static).
			Preference: 1,
		}
	}
	out := make([]RouteSnapshot, 0, len(routes)+len(replaced))
	for _, snap := range routes {
		k := key{snap.Table, snap.Family, canonicalRoutePrefix(snap.Destination)}
		if _, gone := replaced[k]; gone {
			continue
		}
		out = append(out, snap)
	}
	for _, snap := range replaced {
		out = append(out, snap)
	}
	return out
}

// overlayTableFamily maps an overlay entry to its snapshot table and
// family names ("<ri>.inet.0" / "inet6.0" etc.).
func overlayTableFamily(entry config.RouteOverlayEntry) (string, string) {
	family := "inet"
	table := "inet.0"
	if strings.Contains(entry.Destination, ":") {
		family = "inet6"
		table = "inet6.0"
	}
	if entry.RoutingInstance != "" {
		table = entry.RoutingInstance + "." + table
	}
	return table, family
}

// canonicalRoutePrefix mask-normalizes a CIDR for overlay matching and
// returns "" when the input does not parse as a CIDR (#3772 M8). The
// caller in applyRouteOverlay treats "" as "skip this entry", so an
// overlay destination that fails to parse is dropped rather than being
// injected into the FIB verbatim as a garbage prefix. Previously the
// function returned the raw string, contradicting this contract and its
// own doc comment, and let a malformed overlay destination through.
// routeDestinationForWire returns the destination in the form the Rust FIB can
// parse, and whether it is usable at all (#6568).
//
//   - a valid CIDR prefix passes through UNCHANGED. It is deliberately not
//     re-canonicalised: masking a host-bearing prefix such as 10.0.0.5/24 down
//     to 10.0.0.0/24 would change both the installed prefix and the
//     addSnapshot dedupe key, which is a behaviour change this fix has no
//     business making.
//   - a BARE IP address gains its host prefix (/32 or /128). `ipnet`'s
//     Ipv4Net/Ipv6Net parsers require a prefix length, so a bare address is
//     exactly the plausible operator input that vanished silently.
//   - anything else (a typo, or the Junos `default` keyword, which the config
//     compiler accepts verbatim) is unusable and reports false.
func routeDestinationForWire(dest string) (string, bool) {
	if _, _, err := net.ParseCIDR(dest); err == nil {
		return dest, true
	}
	if ip := net.ParseIP(dest); ip != nil {
		// The family test is the TEXT, not ip.To4(): net.IP.To4() folds an
		// IPv4-MAPPED IPv6 address (::ffff:10.0.0.1) to its 4-byte form, so
		// keying on it would emit "::ffff:10.0.0.1/32" — a v6 literal carrying
		// a v4 prefix length, which parses as neither. Colon-means-v6 is the
		// same discriminator normalizeRouteSnapshotFamily already uses on this
		// exact field, so the two cannot disagree about a route's family.
		if strings.Contains(dest, ":") {
			return dest + "/128", true
		}
		if ip.To4() != nil {
			return dest + "/32", true
		}
		return "", false
	}
	return "", false
}

func canonicalRoutePrefix(s string) string {
	_, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		return ""
	}
	return n.String()
}

func buildInterfaceRouteTables(cfg *config.Config) (map[string]string, map[string]string) {
	v4 := make(map[string]string)
	v6 := make(map[string]string)
	if cfg == nil {
		return v4, v6
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifname := range ri.Interfaces {
			if ifname == "" {
				continue
			}
			// #5878 phase 2: canonicalize the .<unit> suffix so ge-0/0/0.01 binds
			// the same route table as ge-0/0/0.1 (the per-unit snapshot consumer
			// keys these maps by the canonical "%s.%d" unit name).
			key := config.CanonicalInterfaceUnitRef(ifname)
			v4[key] = ri.Name + ".inet.0"
			v6[key] = ri.Name + ".inet6.0"
		}
	}
	return v4, v6
}

// buildInterfaceRoutingInstances maps each interface (config name, e.g.
// "ge-0-0-1.80") to the routing-instance it belongs to. The default
// instance is the empty string. This mirrors buildInterfaceRouteTables'
// membership lookup, but carries the bare instance NAME so the Rust
// dataplane can scope its rebuilt-from-interface connected routes to the
// owning routing table (#2388): without it, the Rust connected store is
// global and a per-table (VRF / next-table) FIB lookup can match a
// connected prefix owned by a different routing-instance.
func buildInterfaceRoutingInstances(cfg *config.Config) map[string]string {
	out := make(map[string]string)
	if cfg == nil {
		return out
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifname := range ri.Interfaces {
			if ifname == "" {
				continue
			}
			// #5878 phase 2: canonicalize the .<unit> suffix so ge-0/0/0.01 binds
			// the same routing-instance as ge-0/0/0.1 (the per-unit snapshot
			// consumer keys this map by the canonical "%s.%d" unit name).
			out[config.CanonicalInterfaceUnitRef(ifname)] = ri.Name
		}
	}
	return out
}

// routingInstanceDomain maps a bare routing-instance name to the #7160 (#2387)
// ROUTING DOMAIN id carried on `InterfaceSnapshot.RoutingDomain` and, from
// there, into `SessionKey.routing_domain` in the Rust dataplane.
//
// The default instance ("") is domain 0. Every named instance folds through
// `config.StableRoutingInstanceTableID`, which is a pure FNV-1a of the NAME
// into [RoutingInstanceTableIDBase, +Span) = [100000, 999999] — so a named
// instance can never produce the 0 that means "default", and a rename is a
// genuine reconfiguration rather than a renumbering of its siblings.
//
// Reusing the kernel-table id rather than minting a second numbering is
// deliberate: the id already has a commit-time collision gate
// (validateRoutingInstanceTableIDCollisionAST, pkg/config/routinginstanceid.go),
// and a second parallel numbering would need its own gate to say the same
// thing. It is a routing-domain LABEL here, not a kernel table handle — the
// dataplane never indexes a kernel table with it.
func routingInstanceDomain(name string) uint32 {
	if name == "" {
		return 0
	}
	return uint32(config.StableRoutingInstanceTableID(name))
}

func connectedPrefixesForInterface(iface InterfaceSnapshot) ([]string, []string) {
	var v4 []string
	var v6 []string
	for _, addr := range iface.Addresses {
		if addr.Scope != 0 && addr.Scope != int(netlink.SCOPE_UNIVERSE) {
			continue
		}
		// Mask-to-network + skip-host + skip-link-local is factored into
		// config.ConnectedNetworkPrefix so the rib-group per-prefix leak
		// (pkg/routing, #3876) derives the identical connected-prefix set
		// from the config addresses and the ip rules it installs match the
		// connected routes this FIB carries in the source table.
		prefix, family, ok := config.ConnectedNetworkPrefix(addr.Address)
		if !ok {
			continue
		}
		switch family {
		case "inet":
			v4 = append(v4, prefix)
		case "inet6":
			v6 = append(v6, prefix)
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	return slices.Compact(v4), slices.Compact(v6)
}

func normalizeRouteSnapshotFamily(table, family, destination string) (string, string) {
	isIPv6 := strings.Contains(destination, ":")
	if isIPv6 {
		family = "inet6"
		switch {
		case table == "inet.0":
			table = "inet6.0"
		case strings.HasSuffix(table, ".inet.0"):
			table = strings.TrimSuffix(table, ".inet.0") + ".inet6.0"
		}
		return table, family
	}
	family = "inet"
	switch {
	case table == "inet6.0":
		table = "inet.0"
	case strings.HasSuffix(table, ".inet6.0"):
		table = strings.TrimSuffix(table, ".inet6.0") + ".inet.0"
	}
	return table, family
}

// learnedRouteImportFn is the kernel-FIB importer, indirected so the
// snapshot builder can be driven against synthetic kernel tables.
//
// It defaults to a DISABLED importer, not to routing.ImportLearnedRoutes,
// and that default is load-bearing in two directions:
//
//   - HERMETICITY. buildRouteSnapshots is called by a large number of unit
//     tests with synthetic configs. A default that read the real kernel
//     would splice the BUILD HOST's routing table into every one of those
//     snapshots — measured on a dev box, a `default via ... proto dhcp`
//     route is RTN_UNICAST, has a gateway and carries an admitted RTPROT,
//     so it satisfies every import predicate and would appear in test
//     snapshots as a phantom default route. Tests would then pass or fail
//     according to the machine they ran on, which is worse than not having
//     the feature.
//   - FAIL-SAFE DEFAULT. A caller that has not deliberately enabled the
//     import gets exactly the pre-#7409 config-derived FIB. The import can
//     only ever be switched on by an explicit production wiring decision,
//     never by forgetting to switch it off.
//
// EnableLearnedRouteImport installs the real importer; production calls it
// once during dataplane bring-up.
var learnedRouteImportFn func(tableIDs []int) ([]routing.LearnedRoute, error)

// EnableLearnedRouteImport turns on the #7409 kernel-learned route import
// for every subsequent snapshot build.
//
// Idempotent, and deliberately a package-level switch rather than a config
// stanza: importing the routes the kernel would have used is a correctness
// property of the dataplane, not an operator preference. There is no
// supported configuration in which the helper FIB should knowingly disagree
// with the kernel FIB the slow path reinjects into.
func EnableLearnedRouteImport() {
	learnedRouteImportFn = routing.ImportLearnedRoutes
}

// learnedRouteTableName maps a kernel table id to the Junos-style route
// table name the snapshot wire format uses.
//
// Returns ok=false for a table the config does not name, so a table xpf
// does not own can never be published into the helper FIB under a
// fabricated name.
func learnedRouteTableName(tableID int, family string, instByTableID map[int]string) (string, bool) {
	suffix := ".inet.0"
	if family == "inet6" {
		suffix = ".inet6.0"
	}
	if tableID == learnedRouteMainTableID {
		if family == "inet6" {
			return "inet6.0", true
		}
		return "inet.0", true
	}
	if name, ok := instByTableID[tableID]; ok && name != "" {
		return name + suffix, true
	}
	return "", false
}

// learnedRouteMainTableID mirrors pkg/routing mainTableID (RT_TABLE_MAIN).
// Duplicated rather than exported because the two packages agree on a
// kernel constant, not on a shared policy.
const learnedRouteMainTableID = 254

// addLearnedRouteSnapshots imports kernel-learned routes and feeds the ones
// that fill a genuine gap to addSnapshot.
//
// `existing` is the config-derived snapshot set built so far; it is read to
// compute the gap-fill key and never mutated. The key is built from the
// SAME (table, family, destination) triple the caller's dedupe uses, and
// the imported destination is normalised through routeDestinationForWire
// first so a kernel rendering can never miss a config route it is
// semantically identical to (which would let a duplicate through and hand
// the Rust FIB two routes for one prefix to tie-break).
//
// A failure from the importer is returned, not swallowed: same #3772 M9
// reasoning as the ip-rule enumeration above — a snapshot silently missing
// a subset of learned destinations is a FIB that disagrees with the kernel
// in exactly the way this issue exists to stop.
// The bool reports whether the #8355 cap DECLINED the import. It is distinct
// from "nothing was imported": an empty kernel table and a refused 100k-route
// table both add zero routes, and only the second one leaves the helper FIB
// deliberately incomplete. #9054 is what happens when the two are conflated
// downstream.
func addLearnedRouteSnapshots(cfg *config.Config, existing []RouteSnapshot, addSnapshot func(RouteSnapshot)) (bool, error) {
	if learnedRouteImportFn == nil {
		return false, nil
	}
	instByTableID := make(map[int]string)
	instanceTableIDs := make([]int, 0, len(cfg.RoutingInstances))
	for _, inst := range cfg.RoutingInstances {
		if inst == nil || inst.TableID <= 0 {
			continue
		}
		instByTableID[inst.TableID] = inst.Name
		instanceTableIDs = append(instanceTableIDs, inst.TableID)
	}
	sort.Ints(instanceTableIDs)

	learned, err := learnedRouteImportFn(routing.LearnedRouteTableIDs(instanceTableIDs))
	if err != nil {
		return false, fmt.Errorf("route snapshot: %w", err)
	}
	if len(learned) == 0 {
		return false, nil
	}
	// #8355: refuse a table larger than one publish can carry, rather than
	// importing a prefix of it. See learned_route_cap_8355.go for why this
	// degrades to NO import instead of a bounded subset.
	if learnedRouteCapExceeded(len(learned)) {
		return true, nil
	}

	covered := make(map[string]struct{}, len(existing))
	for _, snap := range existing {
		covered[learnedRouteGapKey(snap.Table, snap.Family, snap.Destination)] = struct{}{}
	}

	// Deterministic emission order. The kernel dump order is not a stable
	// function of content, and the caller's final sort tie-breaks on
	// next-hops/next-table/discard/preference — all of which two learned
	// routes for different prefixes share — so leaving kernel order to leak
	// through would produce snapshot-to-snapshot diffs (and a needless FIB
	// re-install) for an unchanged routing table.
	sorted := make([]routing.LearnedRoute, len(learned))
	copy(sorted, learned)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.TableID != b.TableID {
			return a.TableID < b.TableID
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		return strings.Join(a.NextHops, ",") < strings.Join(b.NextHops, ",")
	})

	for _, lr := range sorted {
		family := "inet"
		if lr.Family == netlink.FAMILY_V6 {
			family = "inet6"
		}
		table, ok := learnedRouteTableName(lr.TableID, family, instByTableID)
		if !ok {
			continue
		}
		dest := lr.Destination
		if normalized, ok := routeDestinationForWire(dest); ok {
			dest = normalized
		} else {
			// Unparseable from the kernel should be impossible, but the
			// #6568 contract at this boundary is "no silent skips" — and a
			// destination the Rust FIB cannot parse is dropped there
			// anyway, so refuse it here where the operator can see why.
			slog.Warn("dropping a kernel-learned route with an unusable "+
				"destination from the helper FIB (#7409)",
				"destination", lr.Destination, "table", table,
				"family", family, "protocol", lr.Protocol)
			continue
		}
		if _, ok := covered[learnedRouteGapKey(table, family, dest)]; ok {
			// The operator's own route wins, always. This is the gap-fill
			// rule; see the call site for why it is what makes the import
			// safe to add.
			continue
		}
		addSnapshot(RouteSnapshot{
			Table:       table,
			Family:      family,
			Destination: dest,
			NextHops:    lr.NextHops,
			Preference:  routing.LearnedRouteImportPreference,
		})
	}
	return false, nil
}

// learnedRouteGapKey is the (table, family, destination) identity the
// gap-fill test uses.
//
// Deliberately NARROWER than the caller's #3770 dedupe key, which also
// spans next-hops, next-table, discard and preference. The dedupe key
// answers "is this the same route?"; this key answers "does the operator
// already have an answer for this destination?" — and if they do, the
// kernel's answer must not be published alongside it, however different its
// next-hop is. Using the wider key here would let an imported route sit
// beside a config route for the same prefix and leave the Rust FIB to pick
// between them by preference, which is precisely the contention the
// gap-fill rule exists to prevent.
//
// The destination is CANONICALISED, matching what applyRouteOverlay does on
// both sides of its own comparison. routeDestinationForWire passes a parseable
// CIDR through untouched, so a config static written with host bits set
// (`route 10.20.30.1/24`) reaches the snapshot in that literal form while the
// kernel always reports the masked prefix — comparing the raw strings would
// therefore MISS the coverage, emit the imported route alongside the
// operator's, and hand the Rust FIB two routes for one prefix. An
// uncanonicalisable destination falls back to its raw text so it can still
// match itself rather than collapsing every such route onto one empty key.
func learnedRouteGapKey(table, family, destination string) string {
	if canonical := canonicalRoutePrefix(destination); canonical != "" {
		destination = canonical
	}
	return table + "|" + family + "|" + destination
}
