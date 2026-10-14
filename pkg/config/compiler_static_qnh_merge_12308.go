package config

// QUALIFIED-NEXT-HOP GATEWAY MERGE (#12308).
//
// compileStaticRoutes appended one NextHopEntry per qualified-next-hop NODE,
// and one authored qualified-next-hop is not always one node. SetPath keeps a
// bare leaf and a container with the same key as two siblings, so ordinary
// flat-set authoring already produces two nodes for one gateway:
//
//	set ... route 0.0.0.0/0 qualified-next-hop 192.168.1.1
//	set ... route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference 200
//	  -> [qualified-next-hop 192.168.1.1]                      (leaf)
//	     [qualified-next-hop 192.168.1.1] > [preference 200]   (container)
//
// So does every hierarchical re-opening: two blocks for the gateway in one
// route, two `route <p>` blocks, two `routing-options` roots, `rib inet.0
// static` beside `static`, and each of those inside a routing instance.
// Measured in both authoring orders, interface in one statement and
// preference in the other:
//
//	split  -> {iface, no preference} + {no iface, preference 250}
//	merged -> {iface, preference 250}
//
// The halves land in different failover tiers. The interface half has no
// preference of its own, so it inherits the route's (5) and joins the PRIMARY
// tier: one authored floating backup became an equal-cost primary path plus an
// interfaceless backup. The bare+preference `set` pair did the same, leaving a
// preference-5 copy of the backup in the primary tier.
//
// THE FIX IS THE #9192 SHAPE, NOT A GATE. A commit gate on repeated nodes was
// this issue's first draft, and it refused the bare+preference `set` sequence
// above: configuration an operator can legally type and cannot re-spell. Every
// statement for one gateway now folds into the entry that gateway already has
// (in the same route block, a later same-spelling block, or a later root), and
// a later statement overrides only the settings it authors. That is what
// flat-set replay of the same statements produces, so the census now finds the
// site CONSERVED instead of listing it SILENT.
//
// THE BOUNDARIES, each pinned in qnh_gateway_merge_12308_test.go:
//
//   - Two DISTINCT gateways never fold: they do not share the key.
//   - A plain `next-hop <gw>` never absorbs a qualified statement for the same
//     address. The plain one is a primary ECMP member and the qualified one a
//     floating backup, so the key is the qualified-next-hop STATEMENT's
//     gateway. That is why an entry carries a compile-only provenance bit
//     instead of the merge matching on Address alone.
//   - The scope is one route list. A routing instance, an unhandled rib and a
//     distinct-spelling alias (folded later as an independent source, #12084)
//     never share an entry with another list.

// mergeQualifiedNextHop12308 folds one qualified-next-hop statement into hops.
// The entry that already carries stmt's gateway takes every setting stmt
// authors; otherwise stmt is appended as that gateway's entry.
//
// #12909: the fold keys on the authored gateway scalar (Address) and runs
// BEFORE the interface-only promotion in finalizeQualifiedNextHops12308, so
// every statement for one gateway — whichever spelling, block or root —
// still merges on the raw gateway while the entries are address-form.
func mergeQualifiedNextHop12308(hops []NextHopEntry, stmt NextHopEntry) []NextHopEntry {
	stmt.qualified = true
	for i := range hops {
		if !hops[i].qualified || hops[i].Address != stmt.Address {
			continue
		}
		if stmt.Interface != "" {
			hops[i].Interface = stmt.Interface
		}
		if stmt.HasPreference {
			hops[i].Preference, hops[i].HasPreference = stmt.Preference, true
		}
		if stmt.HasMetric {
			hops[i].Metric, hops[i].HasMetric = stmt.Metric, true
		}
		return hops
	}
	return append(hops, stmt)
}

// finalizeQualifiedNextHops12308 closes the merge window once every source
// for routes has compiled. It clears the provenance bit, so no compiled Config
// carries it, and then applies the exact-duplicate fold that compileStaticRoutes
// skips while qualified entries can still change: a bare qualified next-hop
// that ends up identical to a plain `next-hop` for the same address collapses
// into it, exactly as it did before #12308.
//
// #12909: closing the window is also where an interface-valued
// qualified-next-hop gateway (e.g. a floating backup over `st0.0`) is
// promoted to an interface-only entry, exactly as a plain
// `next-hop <ifname>` is promoted at parse time (#12036). Left in Address,
// the tunnel name is neither an IP FRR can render nor a gateway the
// userspace FIB can parse, so the backup silently never installs — and it
// skips the #11422 route-vs-selector gate. Promoting HERE, after every
// #12308 fold, keeps split statements merging on the raw gateway scalar and
// keeps an authored `interface` modifier authoritative: an entry that merged
// a real egress interface keeps the address form. Only qualified entries
// are promoted; plain next-hops were normalized by staticNextHopEntry.
func finalizeQualifiedNextHops12308(routes []*StaticRoute) {
	for _, route := range routes {
		if route == nil {
			continue
		}
		qualified := false
		for i := range route.NextHops {
			if !route.NextHops[i].qualified {
				continue
			}
			route.NextHops[i].qualified = false
			qualified = true
			if route.NextHops[i].Interface == "" &&
				interfaceOnlyNextHopValue(route.NextHops[i].Address) {
				route.NextHops[i].Interface, route.NextHops[i].Address =
					route.NextHops[i].Address, ""
			}
		}
		if qualified {
			route.NextHops = dedupeStaticRouteNextHops(route.NextHops)
		}
	}
}
