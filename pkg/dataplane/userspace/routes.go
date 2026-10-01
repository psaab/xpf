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

// routeSnapshotDedupeKey returns the canonical identity used to suppress
// duplicate route snapshots during route collection.
func routeSnapshotDedupeKey(snap RouteSnapshot) string {
	return fmt.Sprintf("%s|%s|%s|%s|%v|%s|%t|%d|%d|%d",
		snap.Table, snap.Family, snap.Destination,
		strings.Join(snap.NextHops, ","), snap.NextHopWeights, snap.NextTable,
		snap.Discard, snap.Preference, snap.RulePriority, snap.MTU)
}

// nonDefaultRouteWeights omits the wire vector when all entries mean weight 1.
// The Rust FIB defaults absent, short, and zero weights to 1; retaining the
// full vector here would needlessly grow common single-path snapshot publishes.
func nonDefaultRouteWeights(weights []uint32) []uint32 {
	for _, weight := range weights {
		if weight > 1 {
			return weights
		}
	}
	return nil
}

// routeSnapshotLeakIdentity canonicalizes only the target-table spelling and
// CIDR masking used to compare the config-static mirror with a live ip-rule
// mirror. Config stores a global next-table target as a bare routing-instance
// name, while a live rule is emitted with its family-qualified table. They
// are the same kernel rule identity and the live row must replace the config
// mirror if their priorities differ. This helper does not participate in
// dedupe: two live rows with distinct priorities remain distinct candidates.
func routeSnapshotLeakIdentity(snap RouteSnapshot) string {
	if snap.NextTable == "" {
		return ""
	}
	target := snap.NextTable
	suffix := ".inet.0"
	if snap.Family == "inet6" {
		suffix = ".inet6.0"
	}
	if target == "inet.0" || target == "inet6.0" {
		target = suffix
	} else if strings.HasSuffix(target, ".inet.0") || strings.HasSuffix(target, ".inet6.0") {
		target = target[:strings.LastIndex(target, ".inet")] + suffix
	} else {
		target += suffix
	}
	destination := snap.Destination
	if canonical := canonicalRoutePrefix(destination); canonical != "" {
		destination = canonical
	}
	return fmt.Sprintf("%s|%s|%s|%s", snap.Table, snap.Family, destination, target)
}

// configNextTableRulePriorities mirrors the kernel's next-table admission
// order and cap. Each published row carries the shared prefix-derived
// priority used by both next-table and rib-group rules.
func configNextTableRulePriorities(cfg *config.Config, exclusions map[*config.StaticRoute]string) map[*config.StaticRoute]uint32 {
	out := make(map[*config.StaticRoute]uint32)
	if cfg == nil {
		return out
	}
	ingress := len(config.DefaultInstanceIngressIfaces(cfg))
	if ingress == 0 {
		return out
	}

	// The two config lists are one kernel sequence. Preserve the stable
	// IPv4-first partition used by nextTableManager when drawing down the cap.
	combined := make([]*config.StaticRoute, 0,
		len(cfg.RoutingOptions.StaticRoutes)+len(cfg.RoutingOptions.Inet6StaticRoutes))
	combined = append(combined, cfg.RoutingOptions.StaticRoutes...)
	combined = append(combined, cfg.RoutingOptions.Inet6StaticRoutes...)
	ordered := make([]*config.StaticRoute, 0, len(combined))
	v6 := make([]*config.StaticRoute, 0)
	for _, route := range combined {
		if route == nil {
			ordered = append(ordered, route)
			continue
		}
		_, dst, err := net.ParseCIDR(route.Destination)
		if err != nil || dst.IP.To4() != nil {
			ordered = append(ordered, route)
			continue
		}
		v6 = append(v6, route)
	}
	ordered = append(ordered, v6...)

	admitted := 0
	for _, route := range ordered {
		if route == nil || route.NextTable == "" || exclusions[route] != "" {
			continue
		}
		_, dst, err := net.ParseCIDR(route.Destination)
		if err != nil || dst == nil {
			continue
		}
		if admitted+ingress > config.NextTableRuleWindow {
			break
		}
		prefixLength, addressBits := dst.Mask.Size()
		out[route] = uint32(config.RouteLeakRulePriority(
			prefixLength, addressBits, config.RouteLeakNextTable))
		admitted += ingress
	}
	return out
}

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
// The second return value reports whether #8355's learned-route budget shed
// one or more complete (table, protocol) groups. It is distinct from "nothing
// was imported": the helper may deliberately omit an over-budget group while
// retaining unrelated protocols' routes.
func buildRouteSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot, overlay []config.RouteOverlayEntry) ([]RouteSnapshot, bool, error) {
	if cfg == nil {
		return nil, false, nil
	}
	out := make([]RouteSnapshot, 0)
	seen := make(map[string]struct{})
	configLeakSnapshotKeys := make(map[string]struct{})
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
		// #3770 (H8): the dedupe key includes NextHopWeights, Discard,
		// Preference, and RulePriority. An otherwise identical ECMP group with
		// a different weight vector is a distinct forwarding decision;
		// omitting weights would flatten it. A discard (blackhole) route and
		// a normal route to the same prefix are distinct: omitting Discard let
		// one silently hide the other. Two routes differing only in preference
		// likewise remain distinct.
		// RulePriority is the kernel rule identity for a NextTable leak:
		// collapsing rows that share a prefix and target but have different
		// priorities would discard one stage-1 candidate and make the helper
		// disagree with first-match kernel rule evaluation.
		key := routeSnapshotDedupeKey(snap)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, snap)
	}
	// Config-global static next-table rows are added before the live netlink
	// mirror. Track their exact dedupe keys so a live row can remove only its
	// matching config identity, while leaving every live row whose actual
	// priority is distinct.
	addConfigSnapshot := func(snap RouteSnapshot) {
		if snap.NextTable != "" {
			// addSnapshot normalises bare host destinations before deriving its
			// dedupe key. Mirror that normalisation here so live-wins removal
			// still finds a config leak written with a bare address.
			if destination, ok := routeDestinationForWire(snap.Destination); ok {
				snap.Destination = destination
			}
			configLeakSnapshotKeys[routeSnapshotDedupeKey(snap)] = struct{}{}
		}
		addSnapshot(snap)
	}
	removeConfigLeak := func(snap RouteSnapshot) {
		identity := routeSnapshotLeakIdentity(snap)
		if identity == "" {
			return
		}
		kept := out[:0]
		for _, existing := range out {
			key := routeSnapshotDedupeKey(existing)
			_, isConfigLeak := configLeakSnapshotKeys[key]
			if isConfigLeak && routeSnapshotLeakIdentity(existing) == identity {
				delete(seen, key)
				delete(configLeakSnapshotKeys, key)
				continue
			}
			kept = append(kept, existing)
		}
		out = kept
	}
	addLiveSnapshot := func(snap RouteSnapshot) {
		// A netlink rule is authoritative for the same leak identity. This
		// matters when a synthetic/config fixture and a live dump disagree:
		// retaining the config row at an invented lower priority would make
		// the Rust stage-1 index select it before the actual kernel rule.
		removeConfigLeak(snap)
		addSnapshot(snap)
	}
	// #7357: the shared drop verdict for every static route in this config,
	// computed once. See config.StaticRouteExclusions — it owns the
	// order-dependent #6467 next-table ip-rule window as well as the six
	// per-route causes, and the show surfaces consult the same function.
	staticRouteExclusions := config.StaticRouteExclusions(cfg)
	nextTableRulePriorities := configNextTableRulePriorities(cfg, staticRouteExclusions)
	connectedNetworks := make(map[routeSnapshotTableFamily][]*net.IPNet)
	interfaceTablesV4, interfaceTablesV6 := buildInterfaceRouteTables(cfg)
	addConnectedRoutes := func(table, family string, prefixes []string) {
		for _, prefix := range prefixes {
			addSnapshot(RouteSnapshot{
				Table:       table,
				Family:      family,
				Destination: prefix,
			})
			_, network, err := net.ParseCIDR(prefix)
			if err != nil {
				continue
			}
			key := routeSnapshotTableFamily{table: table, family: family}
			connectedNetworks[key] = append(connectedNetworks[key], network)
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
		addConnectedRoutes(v4Table, "inet", v4Prefixes)
		addConnectedRoutes(v6Table, "inet6", v6Prefixes)
	}
	addRoutes := func(table, family string, routes []*config.StaticRoute, instanceName, instanceType string) {
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
			if staticRouteHasOnlyUnresolvedBareGateways(
				route, tableName, familyName, instanceName, instanceType,
				connectedNetworks, interfaces,
			) {
				// When every bare gateway is recursive, the config row would
				// resolve with ifindex 0 and suppress the kernel's resolved
				// copy in the learned-route gap fill (#11317). Mixed rows stay:
				// Rust's live selection can still use a resolvable member.
				continue
			}
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
				Discard:      route.Discard || route.Reject,
				NextTable:    route.NextTable,
				RulePriority: nextTableRulePriorities[route],
				Preference:   route.Preference,
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
				addConfigSnapshot(base)
				continue
			}
			for _, pref := range order {
				snap := base
				snap.Preference = groups[pref].preference
				snap.NextHops = groups[pref].nextHops
				addConfigSnapshot(snap)
			}
		}
	}
	addRoutes("inet.0", "inet", cfg.RoutingOptions.StaticRoutes, "", "")
	addRoutes("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes, "", "")

	if len(cfg.RoutingInstances) > 0 {
		insts := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			if ri != nil {
				insts = append(insts, ri)
			}
		}
		sort.Slice(insts, func(i, j int) bool { return insts[i].Name < insts[j].Name })
		for _, ri := range insts {
			addRoutes(ri.Name+".inet.0", "inet", ri.StaticRoutes, ri.Name, ri.InstanceType)
			addRoutes(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes, ri.Name, ri.InstanceType)
		}
	}

	// Add synthetic routes for ip-rule entries that implement inter-VRF
	// route leaking (rib-groups, next-table) and destination-scoped rib-group
	// returns. These destination rules are expressible as NextTable rows in the
	// userspace FIB.
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
	instanceNameToTableID := make(map[string]int)
	for _, inst := range cfg.RoutingInstances {
		if inst != nil && inst.TableID > 0 {
			tableIDToInst[inst.TableID] = inst.Name
			instanceNameToTableID[inst.Name] = inst.TableID
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
			// A Dst-less rule cannot be represented as a per-prefix NextTable
			// leak. Rib-group imports and their scoped return rules carry Dst,
			// so each direction is expressible without widening its match.
			if rule.Dst == nil || rule.Table <= 0 {
				continue
			}
			// #4479/#11319: SKIP current and legacy policy-based-routing /
			// filter-based-forwarding rules. These carry match selectors that a
			// per-prefix NextTable row cannot represent; ingesting one would widen
			// the FBF steer, including during an in-place priority-band upgrade.
			inPBRBand := rule.Priority >= config.PBRRulePriorityBase &&
				rule.Priority < config.PBRRulePriorityBase+config.PBRRuleWindow
			inLegacyPBRBand := rule.Priority >= config.LegacyPBRRulePriorityBase &&
				rule.Priority < config.LegacyPBRRulePriorityBase+config.PBRRuleWindow
			if inPBRBand || inLegacyPBRBand {
				continue
			}
			familyStr := "inet"
			mainTable := "inet.0"
			suffix := ".inet.0"
			if family == syscall.AF_INET6 {
				familyStr = "inet6"
				mainTable = "inet6.0"
				suffix = ".inet6.0"
			}
			// A pref-1500 return rule looks up the peer VRF's table and is
			// scoped to the source VRF by iif/oif. Mirror it in the reverse
			// direction: source VRF table → peer table, for this destination
			// prefix only. Looking up main here could select main's default.
			if rule.Priority == routing.RibGroupReturnRulePriority {
				sourceName, ok := ribGroupReturnRuleInstance(rule, instanceNameToTableID)
				if !ok {
					continue
				}
				peerName, ok := tableIDToInst[rule.Table]
				if !ok || peerName == sourceName {
					continue
				}
				addLiveSnapshot(RouteSnapshot{
					Table:        sourceName + suffix,
					Family:       familyStr,
					Destination:  rule.Dst.String(),
					NextTable:    peerName + suffix,
					RulePriority: uint32(rule.Priority),
				})
				continue
			}
			instName, ok := tableIDToInst[rule.Table]
			if !ok {
				continue
			}
			addLiveSnapshot(RouteSnapshot{
				Table:        mainTable,
				Family:       familyStr,
				Destination:  rule.Dst.String(),
				NextTable:    instName + suffix,
				RulePriority: uint32(rule.Priority),
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
	// REINJECTED to the kernel with no zone verdict — no zone policy, no
	// session, no NAT, no screen — through the marked-TUN pinhole of the
	// armed forward fence (#10302; pre-fence this read "and no nftables
	// `hook forward` chain behind it") — or, if
	// a config default happens to cover it, is forwarded to the STATIC
	// default's next-hop instead of the learned one. Import closes both.
	//
	// PREFERENCE-AWARE GAP-FILL. Keep a config-derived route when its
	// preference is at least as good as the imported route's 200. When the
	// config route is a worse-preference fallback (for example preference
	// 250), publish both: the Rust FIB's ascending-preference tie-break then
	// selects the kernel's already-selected learned route. This preserves
	// ordinary config routes as winners while honoring floating fallbacks.
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
	// #10046: forwarding-instance static routes may use a gateway on an
	// interface that remains in the default routing instance. The Rust FIB
	// deliberately scopes bare-gateway inference to the route's own table
	// (#4446), so qualify those snapshots with the interface the kernel route
	// resolves through. This keeps VRF inference isolated while making FBF
	// forwarding-instance defaults usable on the AF_XDP path. Apply this
	// after overlays because an ip-monitoring replacement has the same route
	// semantics and must not reintroduce a bare gateway.
	qualifyForwardingInstanceNextHops(cfg, interfaces, out)

	// #3770 (M10): stable ordering by table/family/destination, followed by
	// route-specific tie-breaks. The old comparator keyed only on the first three
	// fields, so distinct same-prefix rows (for example, a next-table leak and
	// its ip-rule mirror, or a discard and a connected route) compared equal;
	// their order then followed build input such as map or kernel iteration,
	// causing snapshot diffs and ECMP-member churn.
	//
	// Leak rows are stage-1 rules, so RulePriority orders them at the same
	// destination. Equal-priority leaks retain producer order because kernel
	// rules with a shared priority are installed and observed in that order.
	// Ordinary rows keep the existing next-hop/weight/next-table/discard/
	// preference ordering.
	//
	// A NextTable row is always a leak; an ordinary route never competes with
	// it in this priority comparison. The Rust consumer builds a separate
	// priority-ordered leak index and performs ordinary LPM only after a leak
	// target misses.
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
		if a.NextTable != "" && b.NextTable != "" {
			if a.RulePriority != b.RulePriority {
				return a.RulePriority < b.RulePriority
			}
			return false
		}
		an, bn := strings.Join(a.NextHops, ","), strings.Join(b.NextHops, ",")
		if an != bn {
			return an < bn
		}
		if weights := slices.Compare(a.NextHopWeights, b.NextHopWeights); weights != 0 {
			return weights < 0
		}
		if a.NextTable != b.NextTable {
			return a.NextTable < b.NextTable
		}
		if a.Discard != b.Discard {
			// Non-discard (false) sorts before discard (true).
			return b.Discard
		}
		if a.Preference != b.Preference {
			return a.Preference < b.Preference
		}
		return a.MTU < b.MTU
	})
	return out, capped, nil
}

func ribGroupReturnRuleInstance(rule netlink.Rule, instanceTableIDs map[string]int) (string, bool) {
	instanceName := ""
	for _, selector := range []string{rule.IifName, rule.OifName} {
		if selector == "" {
			continue
		}
		if !strings.HasPrefix(selector, "vrf-") {
			return "", false
		}
		candidate := strings.TrimPrefix(selector, "vrf-")
		if tableID, ok := instanceTableIDs[candidate]; !ok || tableID <= 0 ||
			config.IsReservedRoutingInstanceName(candidate) {
			return "", false
		}
		if instanceName != "" && instanceName != candidate {
			return "", false
		}
		instanceName = candidate
	}
	return instanceName, instanceName != ""
}

// qualifyForwardingInstanceNextHops makes a forwarding-instance route's
// gateway interface explicit when the gateway is reachable through a
// same-instance or default-instance connected prefix. A bare gateway in a
// virtual-router must remain bare: #4446 intentionally prevents that route
// from borrowing an overlapping connected prefix from another table.
func qualifyForwardingInstanceNextHops(cfg *config.Config, interfaces []InterfaceSnapshot, routes []RouteSnapshot) {
	if cfg == nil || len(interfaces) == 0 || len(routes) == 0 {
		return
	}
	forwardingTables := make(map[string]string)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" || ri.InstanceType != "forwarding" {
			continue
		}
		forwardingTables[ri.Name+".inet.0"] = ri.Name
		forwardingTables[ri.Name+".inet6.0"] = ri.Name
	}
	if len(forwardingTables) == 0 {
		return
	}
	for i := range routes {
		riName, ok := forwardingTables[routes[i].Table]
		if !ok {
			continue
		}
		for j, nextHop := range routes[i].NextHops {
			if nextHop == "" || strings.Contains(nextHop, "@") {
				continue
			}
			ip := net.ParseIP(nextHop)
			if ip == nil {
				continue
			}
			iface := forwardingGatewayInterface(riName, routes[i].Family, ip, interfaces)
			if iface != "" {
				routes[i].NextHops[j] = nextHop + "@" + iface
			}
		}
	}
}

// forwardingGatewayInterface returns the deterministic interface to use for a
// forwarding-instance bare gateway. Same-instance links win, then links in
// the default instance. A gateway that only matches a different VRF remains
// unresolved rather than crossing the VRF boundary.
func forwardingGatewayInterface(riName, family string, gateway net.IP, interfaces []InterfaceSnapshot) string {
	bestRank := 3
	bestName := ""
	for _, iface := range interfaces {
		rank := 2
		switch iface.RoutingInstance {
		case riName:
			rank = 0
		case "":
			rank = 1
		default:
			continue
		}
		name := iface.Name
		if name == "" {
			name = iface.LinuxName
		}
		if name == "" || rank > bestRank || (rank == bestRank && name >= bestName && bestName != "") {
			continue
		}
		matched := false
		for _, addr := range iface.Addresses {
			if addr.Scope != 0 && addr.Scope != int(netlink.SCOPE_UNIVERSE) {
				continue
			}
			prefix, addrFamily, ok := config.ConnectedNetworkPrefix(addr.Address)
			if !ok || addrFamily != family {
				continue
			}
			_, network, err := net.ParseCIDR(prefix)
			if err == nil && network.Contains(gateway) {
				matched = true
				break
			}
		}
		if matched {
			bestRank = rank
			bestName = name
		}
	}
	return bestName
}

// applyRouteOverlay folds the winner-resolved ip-monitoring overlay
// into the route set: for each entry, every existing ORDINARY snapshot for the
// same (table, family, canonical prefix) is REMOVED (whole-entry replacement,
// including all ECMP next-hops) and the single overlay route is appended.
// NextTable snapshots are priority-ordered stage-1 leak rules and are retained
// even when their prefix matches an overlay entry.
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
		// A NextTable row is a priority-ordered ip-rule leak, not an
		// ordinary table route. The monitoring overlay replaces an ordinary
		// route entry only; letting it remove a leak would erase a stage-1
		// rule and silently change the kernel's resolution order.
		if snap.NextTable != "" {
			out = append(out, snap)
			continue
		}
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

// #9132: visit each routing-instance member twice — explicit refs first, then
// generated keys from bare-member fanout. The shared config resolver supplies
// both snapshot keys and kernel-device identities, preserving one alias/tunnel
// interpretation across validation, binding, and userspace maps.
// #11312: forwarding instances have no VRF device; skip their member keys so
// tolerant loads keep connected routes and ingress scope in the kernel's
// default instance. Strict config commits reject the unsupported membership.
func forEachRoutingInstanceInterfaceKey(cfg *config.Config, bind func(riName, key string)) {
	if cfg == nil {
		return
	}
	type memberKeys struct {
		riName string
		keys   []config.RoutingInstanceMemberDeviceKey
	}
	tunnelNames := cfg.TunnelNameMap()
	dualClaimed := config.RoutingInstanceDualClaimedLinuxNames(cfg, tunnelNames)
	members := make([]memberKeys, 0)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		if ri.InstanceType == "forwarding" {
			continue
		}
		for _, member := range ri.Interfaces {
			keys := config.RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member)
			if len(keys) != 0 {
				members = append(members, memberKeys{riName: ri.Name, keys: keys})
			}
		}
		for _, claim := range cfg.QuarantinedRIMemberPrimaryClaims {
			if claim.Instance == ri.Name && claim.InterfaceKey != "" && claim.LinuxName != "" {
				members = append(members, memberKeys{riName: ri.Name, keys: []config.RoutingInstanceMemberDeviceKey{{
					InterfaceKey: claim.InterfaceKey, LinuxName: claim.LinuxName,
				}}})
			}
		}
	}
	seen := make(map[string]struct{})
	for pass := range 2 {
		for _, member := range members {
			if pass == 0 {
				primary := member.keys[0]
				seen[primary.InterfaceKey] = struct{}{}
				if !dualClaimed[primary.LinuxName] {
					bind(member.riName, primary.InterfaceKey)
				}
				continue
			}
			for _, key := range member.keys[1:] {
				if !key.Fanout {
					continue
				}
				if _, exists := seen[key.InterfaceKey]; exists {
					continue
				}
				seen[key.InterfaceKey] = struct{}{}
				if !dualClaimed[key.LinuxName] {
					bind(member.riName, key.InterfaceKey)
				}
			}
		}
	}
}

func buildInterfaceRouteTables(cfg *config.Config) (map[string]string, map[string]string) {
	v4 := make(map[string]string)
	v6 := make(map[string]string)
	forEachRoutingInstanceInterfaceKey(cfg, func(riName, key string) {
		v4[key] = riName + ".inet.0"
		v6[key] = riName + ".inet6.0"
	})
	return v4, v6
}

// buildInterfaceRoutingInstances maps each interface (config name, e.g.
// "ge-0-0-1.80") to the routing-instance it belongs to. A BARE reference is
// fanned down onto every configured unit (#9132) — see
// forEachRoutingInstanceInterfaceKey and config.InterfaceUnitRefKeys. The
// default instance is the empty string. This mirrors buildInterfaceRouteTables'
// membership lookup, but carries the bare instance NAME so the Rust
// dataplane can scope its rebuilt-from-interface connected routes to the
// owning routing table (#2388): without it, the Rust connected store is
// global and a per-table (VRF / next-table) FIB lookup can match a
// connected prefix owned by a different routing-instance.
// Forwarding-instance member keys are excluded above: the daemon leaves those
// devices in default, so they retain the default routing domain on tolerant loads.
func buildInterfaceRoutingInstances(cfg *config.Config) map[string]string {
	out := make(map[string]string)
	forEachRoutingInstanceInterfaceKey(cfg, func(riName, key string) {
		out[key] = riName
	})
	return out
}

// QuarantinedRoutingInstanceDomain is the session-domain label for an
// interface no surviving routing instance claims but a quarantined one does
// (#9956 F-032). 2, not 1: the HA session-sync codec maps wire 1 to
// Present(default) (`routing_domain_wire.rs`), so 1 would reintroduce the
// default-domain aliasing on the peer; 2 decodes Unrecognized and the peer
// REFUSES the import (fail-closed) while bumping
// SyncedImportUnknownRoutingDomain. Outside the stable band [100000, 999999),
// so never a real tenant's domain — which matters because the #3855 door
// means StableRoutingInstanceTableID(quarantined) EQUALS the survivor's. A
// const, so both HA nodes agree with no synced state.
const QuarantinedRoutingInstanceDomain uint32 = 2

// quarantinedInterfaceKeys expands every quarantined routing instance's
// interface refs to the same alias and fanout contract as the survivor maps —
// cross-spelled unit keys are translated to their declared stanza, while
// existing same-spelling bare refs retain their normal fanout. A survivor map
// always wins later in routingDomainForInterfaceKey, so these extra keys
// cannot overwrite a surviving claim. That fanout reads cfg.Interfaces.Units,
// never cfg.RoutingInstances, so dropped instances expand normally. Returns
// nil when nothing was quarantined (the common case).
func quarantinedInterfaceKeys(cfg *config.Config) map[string]struct{} {
	if cfg == nil || len(cfg.QuarantinedRoutingInstances) == 0 {
		return nil
	}
	out := make(map[string]struct{})
	tunnelNames := cfg.TunnelNameMap()
	for _, ri := range cfg.QuarantinedRoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifname := range ri.Interfaces {
			if ifname == "" {
				continue
			}
			for _, key := range config.RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, ifname) {
				out[key.InterfaceKey] = struct{}{}
			}
		}
	}
	return out
}

// routingDomainForInterfaceKey resolves the session domain for one snapshot
// row key. Survivor-wins: a key the survivor map claims keeps the survivor's
// domain (the byte-identical survivor path); a key ONLY the quarantined set
// claims takes the sentinel; anything else keeps today's answer (0 = default).
func routingDomainForInterfaceKey(key string, ifaceRI map[string]string, quarantined map[string]struct{}) uint32 {
	if name, survives := ifaceRI[key]; survives {
		return routingInstanceDomain(name)
	}
	if _, drop := quarantined[key]; drop {
		return QuarantinedRoutingInstanceDomain
	}
	return 0
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
//
// Quarantined interfaces do NOT flow through this function: row builders call
// routingDomainForInterfaceKey, which returns QuarantinedRoutingInstanceDomain
// (2) for a key only a quarantined instance claims (#9956 F-032). The #7160
// band test pins THIS function's band; the sentinel deliberately lives outside
// it (the #3855 door means the stable id itself would collide).
func routingInstanceDomain(name string) uint32 {
	if name == "" {
		return 0
	}
	return uint32(config.StableRoutingInstanceTableID(name))
}

type routeSnapshotTableFamily struct {
	table  string
	family string
}

func staticRouteHasOnlyUnresolvedBareGateways(
	route *config.StaticRoute,
	table, family, instanceName, instanceType string,
	connectedNetworks map[routeSnapshotTableFamily][]*net.IPNet,
	interfaces []InterfaceSnapshot,
) bool {
	// Without an interface inventory there is no evidence that a gateway is
	// recursive; preserve the config-only snapshot behavior for callers that
	// intentionally build a partial route view.
	if route == nil || len(interfaces) == 0 || route.Discard || route.Reject ||
		route.NextTable != "" || len(route.NextHops) == 0 {
		return false
	}
	networks := connectedNetworks[routeSnapshotTableFamily{table: table, family: family}]
	hasBare, hasDirect := false, false
	for _, nextHop := range route.NextHops {
		if nextHop.Interface != "" {
			// An explicit interface is already a qualified egress path. Keep
			// mixed ECMP rows that have one alongside a recursive bare gateway.
			hasDirect = true
			continue
		}
		if nextHop.Address == "" {
			continue
		}
		gateway := net.ParseIP(nextHop.Address)
		if gateway == nil || (family == "inet" && gateway.To4() == nil) ||
			(family == "inet6" && gateway.To4() != nil) {
			continue
		}
		hasBare = true
		direct := false
		for _, network := range networks {
			if network.Contains(gateway) {
				direct = true
				break
			}
		}
		if !direct && instanceType == "forwarding" {
			// Forwarding instances have no VRF connected table of their own;
			// the existing qualifier explicitly scopes gateways reachable via
			// an interface in this instance or in the default instance.
			direct = forwardingGatewayInterface(instanceName, family, gateway, interfaces) != ""
		}
		hasDirect = hasDirect || direct
	}
	return hasBare && !hasDirect
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
// that fill a genuine gap or outrank the configured route at that prefix to
// addSnapshot.
//
// `existing` is the config-derived snapshot set built so far; it is read to
// find the best preference at each canonical (table, family, destination) key
// and never mutated. Only ORDINARY table routes count. A NextTable row is a
// priority-ordered stage-1 rule, not an answer from a table's LPM; if its
// target table misses, kernel evaluation falls through and the ordinary
// main-table route must still be imported. The imported destination is
// normalised through routeDestinationForWire first so a kernel rendering can
// never miss an ordinary config route it is semantically identical to.
// A failure from the importer is returned, not swallowed: same #3772 M9
// reasoning as the ip-rule enumeration above — a snapshot silently missing
// a subset of learned destinations is a FIB that disagrees with the kernel
// in exactly the way this issue exists to stop.
// The bool reports whether the #8355 cap shed any complete (table, protocol)
// group. It is distinct from "nothing was imported": an empty kernel table and
// a budget-limited table both may add zero routes, but only the latter leaves
// the helper FIB deliberately incomplete.
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
	// #10824: shed complete (table, protocol) groups rather than declining the
	// entire learned-route import. The cap-hit counters identify the affected
	// protocol so one flooded BGP peer cannot evict unrelated learned routes.
	learned, capped := capLearnedRouteGroups(learned)
	if capped && len(learned) == 0 {
		return true, nil
	}

	configuredPreference := make(map[string]int, len(existing))
	for _, snap := range existing {
		// A NextTable row is a stage-1 rule, not a table route. Its presence
		// must not make the helper believe the ordinary main-table answer is
		// covered: if the leak target misses, lookup continues to the next
		// rule and eventually reaches this ordinary fallback.
		if snap.NextTable != "" {
			continue
		}
		key := learnedRouteGapKey(snap.Table, snap.Family, snap.Destination)
		if best, ok := configuredPreference[key]; !ok || snap.Preference < best {
			configuredPreference[key] = snap.Preference
		}
	}

	// Deterministic emission order. The kernel dump order is not stable, so
	// order by table, family, destination, metric, next-hops, and their parallel
	// weights. This keeps lowest-metric selection and weighted snapshots stable
	// when dump ordering changes.
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
		if a.Metric != b.Metric {
			return a.Metric < b.Metric
		}
		an, bn := strings.Join(a.NextHops, ","), strings.Join(b.NextHops, ",")
		if an != bn {
			return an < bn
		}
		if cmp := slices.Compare(a.NextHopWeights, b.NextHopWeights); cmp != 0 {
			return cmp < 0
		}
		return a.MTU < b.MTU
	})

	var lastMetricKey string
	var lowestMetric int
	haveMetricKey := false
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
		key := learnedRouteGapKey(table, family, dest)
		// Imported destinations are canonical CIDRs, so the table/family/
		// destination sort above keeps every same-prefix metric group adjacent.
		// Keep equal-metric entries (including same-cost paths), but discard
		// strictly worse kernel metrics before stamping the shared preference.
		if haveMetricKey && key == lastMetricKey {
			if lr.Metric > lowestMetric {
				continue
			}
		} else {
			lastMetricKey = key
			lowestMetric = lr.Metric
			haveMetricKey = true
		}
		if best, ok := configuredPreference[key]; ok &&
			best <= routing.LearnedRouteImportPreference {
			// The configured route is at least as preferred as the imported
			// route, so keep it as the sole candidate. A worse-preference
			// fallback remains beside the imported route for the Rust FIB's
			// established preference ordering to select the better path.
			continue
		}
		addSnapshot(RouteSnapshot{
			Table:          table,
			Family:         family,
			Destination:    dest,
			NextHops:       lr.NextHops,
			NextHopWeights: nonDefaultRouteWeights(lr.NextHopWeights),
			Preference:     routing.LearnedRouteImportPreference,
			MTU:            lr.MTU,
		})
	}
	return capped, nil
}

// learnedRouteGapKey is the (table, family, destination) identity used to
// find the best configured preference for an imported route.
//
// Deliberately NARROWER than the caller's #3770 dedupe key, which also spans
// next-hops, next-table, discard and preference. The dedupe key answers "is
// this the same route?"; this key answers "what is the best configured route
// for this destination?" An imported route may coexist with the configured
// route only when its preference is strictly better; the Rust FIB then
// selects it through #2390's ascending-preference tie-break.
//
// The destination is CANONICALISED, matching what applyRouteOverlay does on
// both sides of its own comparison. routeDestinationForWire passes a parseable
// CIDR through untouched, so a config static written with host bits set
// (`route 10.20.30.1/24`) reaches the snapshot in that literal form while the
// kernel always reports the masked prefix — comparing raw strings would miss
// the configured candidate's preference. The kernel result would then be
// treated as a gap regardless of whether its preference should lose or win.
// An uncanonicalisable destination falls back to its raw text so it can still
// match itself rather than collapsing every such route onto one empty key.
func learnedRouteGapKey(table, family, destination string) string {
	if canonical := canonicalRoutePrefix(destination); canonical != "" {
		destination = canonical
	}
	return table + "|" + family + "|" + destination
}
