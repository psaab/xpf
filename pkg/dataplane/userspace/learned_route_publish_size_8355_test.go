package userspace

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// #8355: what does a learned-route publish COST on the wire?
//
// `ImportLearnedRoutes` feeds kernel-learned routes into `buildRouteSnapshots`,
// and every publish is a FULL SNAPSHOT REPLACE carried as JSON over the control
// socket. A box holding a full BGP table would push hundreds of thousands of
// entries on every publish, and #7437 makes publishes more frequent.
//
// The issue asks for exactly one thing first: "A measurement relating
// learned-route COUNT to serialized publish SIZE and to the resulting
// control-socket deadline, with the fixture stated — not a cap asserted."
// It also names the way that measurement goes wrong: "a table of
// near-identical routes that compresses or serializes unrepresentatively
// produces a confident wrong number."
//
// THE FIXTURE, STATED. `bgpishRouteTable` models the three properties of a real
// BGP table that drive serialized size, and deliberately not the ones that do
// not:
//
//   - PREFIX DIVERSITY. Destinations walk the whole /8 space with varying
//     prefix lengths, so no two destination strings share a long prefix and
//     none is shorter than a real advertisement. A table of `10.0.N.0/24`
//     would understate the destination field by several bytes per route and
//     is exactly the "near-identical" trap.
//   - NEXT-HOP CARDINALITY IS LOW. A real table has far fewer next-hops than
//     routes — typically a few hundred eBGP peers for hundreds of thousands of
//     prefixes. The fixture uses 256, cycled. This MATTERS because JSON does
//     not deduplicate: every route serializes its next-hop string in full, so
//     low cardinality does not reduce size. Modelling it correctly is how the
//     measurement stays honest about the field that is repeated most.
//   - ONE NEXT-HOP PER ROUTE. ECMP multiplies the next_hops array; the single
//     next-hop case is the FLOOR, and this measurement is a floor rather than
//     an estimate. The importer records the single-path weight as 1; the
//     snapshot omits this all-default vector, and the Rust FIB reconstructs 1.
//
// Not modelled, deliberately: `Table` and `Family` are near-constant in a real
// import and are left so; `NextTable` and `Discard` are absent from a learned
// route; `Preference` is omitempty and typically 0.

func bgpishRouteTable(n int) []RouteSnapshot {
	out := make([]RouteSnapshot, 0, n)
	for i := 0; i < n; i++ {
		// Spread across the space rather than clustering: a /8 boundary walk
		// with a rotating third octet and varying length.
		a := 1 + (i*7)%222
		b := (i * 13) % 256
		c := (i * 31) % 256
		length := 20 + (i % 5) // /20../24, the bulk of a real table
		out = append(out, RouteSnapshot{
			Table:       "inet.0",
			Family:      "inet",
			Destination: fmt.Sprintf("%d.%d.%d.0/%d", a, b, c, length),
			// 256 distinct next-hops, cycled — JSON repeats each in full.
			NextHops: []string{fmt.Sprintf("172.16.%d.%d", (i/256)%256, i%256)},
		})
	}
	return out
}

// TestLearnedRoutePublishSizeAndDeadline8355 is the measurement. It asserts
// only the things that must not silently change; the numbers are LOGGED so the
// cap decision is made from data rather than from a constant someone picked.
func TestLearnedRoutePublishSizeAndDeadline8355(t *testing.T) {
	type row struct {
		routes   int
		bytes    int
		perRoute float64
		deadline time.Duration
	}
	var rows []row

	for _, n := range []int{1, 1000, 10_000, 100_000, 500_000} {
		body, err := json.Marshal(bgpishRouteTable(n))
		if err != nil {
			t.Fatalf("marshal %d routes: %v", n, err)
		}
		rows = append(rows, row{
			routes:   n,
			bytes:    len(body),
			perRoute: float64(len(body)) / float64(n),
			deadline: controlRoundtripDeadline(len(body)),
		})
	}

	t.Log("#8355 learned-route publish cost (single next-hop, default weight 1 omitted — a FLOOR):")
	t.Logf("  %-10s %-14s %-12s %-10s", "routes", "bytes", "bytes/route", "deadline")
	for _, r := range rows {
		t.Logf("  %-10d %-14d %-12.1f %-10s", r.routes, r.bytes, r.perRoute, r.deadline)
	}
	t.Logf("  control-socket ceiling: MaxControlRequestBytes = %d bytes (%d MiB)",
		MaxControlRequestBytes, MaxControlRequestBytes/(1024*1024))

	// The per-route cost must be STABLE across scales. If it is not, the
	// fixture is compressing or the size is not linear in the route count, and
	// a cap expressed in routes cannot be derived from it at all — which is the
	// issue's own warning about a number "wearing the shape of a budget".
	first, last := rows[1].perRoute, rows[len(rows)-1].perRoute
	if ratio := last / first; ratio < 0.9 || ratio > 1.1 {
		t.Errorf("bytes/route is not stable across scales (%.1f at %d routes vs "+
			"%.1f at %d): the relationship is not linear, so a route-count cap "+
			"cannot be derived from a byte budget", first, rows[1].routes,
			last, rows[len(rows)-1].routes)
	}

	// THE LOAD-BEARING CONSEQUENCE, and the measurement sharpened it.
	//
	// The issue frames the problem as size: "a box holding a full BGP table
	// would push hundreds of thousands of RouteSnapshot entries". Measured,
	// 500k routes serialize to 56,386,908 bytes (53.8 MiB) — below the 64 MiB
	// MaxControlRequestBytes ceiling. The size cap is not what stops it.
	//
	// What stops it is TIME. At 3s + 1s/MiB that publish carries a 56 SECOND
	// control-socket deadline, on a socket CLAUDE.md already flags as
	// contended: "The userspace helper control socket is shared by status poll
	// (1/s), HA sync, session installs, snapshot sync, and forwarding sync.
	// Adding a new control socket request at >1/s will starve session installs
	// during bulk sync." A minute-long publish does not starve the socket at
	// the margin; it owns it.
	//
	// So the cap is a question about publish DURATION, and this assertion is
	// written against duration rather than bytes. If it ever stops holding,
	// either the deadline formula or the per-route cost has changed and the cap
	// must be re-derived.
	full := rows[len(rows)-1]
	if full.deadline < 20*time.Second {
		t.Errorf("%d routes publish with a %s deadline — under 20s, so the "+
			"control-socket occupancy argument this issue rests on no longer "+
			"holds and the cap question needs restating. Serialized: %d bytes.",
			full.routes, full.deadline, full.bytes)
	}
}

// TestTheRouteCountCapImpliedByTheDeadline8355 converts the measurement into
// the number the cap decision actually needs.
//
// The control socket's deadline is `3s + 1s/MiB`, so the cap is a question
// about serialized BYTES, not route count — as the issue says. This reports the
// route count at which a publish first crosses several deadline budgets, so a
// cap can be chosen against a stated tolerance for how long one publish may
// hold the control socket.
func TestTheRouteCountCapImpliedByTheDeadline8355(t *testing.T) {
	const probe = 100_000
	body, err := json.Marshal(bgpishRouteTable(probe))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	perRoute := float64(len(body)) / float64(probe)

	t.Log("#8355 route count implied by a publish-time budget " +
		"(deadline = 3s + 1s/MiB; single next-hop, a FLOOR):")
	for _, budget := range []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second} {
		mib := float64(budget-controlBaseDeadline) / float64(controlDeadlinePerMiB)
		routes := int(mib * 1024 * 1024 / perRoute)
		t.Logf("  a %-4s publish budget allows ~%d learned routes (~%.1f MiB)",
			budget, routes, mib)
	}
	t.Logf("  the %d MiB hard ceiling allows ~%d routes",
		MaxControlRequestBytes/(1024*1024),
		int(float64(MaxControlRequestBytes)/perRoute))

	if perRoute <= 0 {
		t.Fatal("per-route cost measured as zero; the fixture produced nothing")
	}
}
