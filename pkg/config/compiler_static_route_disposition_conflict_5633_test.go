package config

import (
	"strings"
	"testing"
)

// #5633: the compiler merges repeated same-destination static-route blocks
// (flat "set" syntax emits one block per line) into a single StaticRoute
// (compileStaticRoutes): next-hops are APPENDED and the terminal / next-table
// fields are STICKY (discard/reject latch true, next-table is last-writer-wins).
// A config that declares the SAME prefix once as `discard` (or `next-table X`)
// and once with a `next-hop` therefore compiled into ONE route holding BOTH a
// blackhole/leak AND a forwarding next-hop — a contradiction the strict gate
// accepted. The live snapshot copies every field and the Rust forwarder
// resolves discard > next-table > next-hop, so the stale terminal/leak wins and
// the later next-hop meant to restore ordinary forwarding is silently ignored.
//
// validateStaticRouteDispositionConflictStrict rejects that mix at commit.
//
// FAIL-ON-REVERT: neutralize the gate (make
// validateStaticRouteDispositionConflictStrict return nil, or drop its call in
// runUniformGates) and CompileConfig silently merges the contradiction — every
// assertCommitRejects below fires RED.

func TestStaticRouteDispositionConflictRejected_5633(t *testing.T) {
	// discard THEN next-hop for the same prefix (flat-set).
	t.Run("discard-then-nexthop", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 10.0.0.0/8 discard",
			"set routing-options static route 10.0.0.0/8 next-hop 10.0.0.1",
		)
		assertCommitRejects(t, tree, "contradictory dispositions")
	})

	// next-hop THEN discard — the sticky-latch is order-independent, so the
	// reverse authoring order must reject identically.
	t.Run("nexthop-then-discard", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 10.0.0.0/8 next-hop 10.0.0.1",
			"set routing-options static route 10.0.0.0/8 discard",
		)
		assertCommitRejects(t, tree, "contradictory dispositions")
	})

	// next-table VRF leak PLUS a reachable next-hop. The routing-instance is
	// DEFINED so the #5693 next-table-definedness gate passes and this gate is
	// the one that fires (non-tautological: the error is the disposition
	// conflict, not an undefined target).
	t.Run("nexttable-plus-nexthop", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances secret instance-type virtual-router",
			// #9810: one unclaimed unit (N=1) so the window gate passes and the disposition gate is the one that fires.
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 172.16.0.0/12 next-table secret.inet.0",
			"set routing-options static route 172.16.0.0/12 next-hop 10.0.0.1",
		)
		assertCommitRejects(t, tree, "contradictory dispositions")
	})

	// Two terminal dispositions on one prefix (discard is a silent blackhole,
	// reject is an ICMP-unreachable drop — they are mutually exclusive).
	t.Run("discard-plus-reject", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 192.168.0.0/16 discard",
			"set routing-options static route 192.168.0.0/16 reject",
		)
		assertCommitRejects(t, tree, "contradictory dispositions")
	})

	// Hierarchical AST shape (load merge / saved config): duplicate route blocks
	// with contradictory dispositions must reject too. The parser folds the two
	// same-prefix blocks the same way the compiler merges flat-set duplicates.
	t.Run("hierarchical-discard-nexthop", func(t *testing.T) {
		tree := hierTree(t, `routing-options {
    static {
        route 10.1.0.0/16 {
            discard;
        }
        route 10.1.0.0/16 {
            next-hop 10.0.0.9;
        }
    }
}`)
		assertCommitRejects(t, tree, "contradictory dispositions")
	})

	// inet6.0 rib: the gate covers the v6 route set as well.
	t.Run("inet6-discard-nexthop", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options rib inet6.0 static route 2001:db8::/32 discard",
			"set routing-options rib inet6.0 static route 2001:db8::/32 next-hop 2001:db8::1",
		)
		assertCommitRejects(t, tree, "contradictory dispositions")
	})

	// Per-routing-instance static routes flow through the SAME merge path, so a
	// contradiction inside a VRF must reject too. The error names the instance.
	t.Run("per-instance-conflict", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances blue routing-options static route 10.9.0.0/16 discard",
			"set routing-instances blue routing-options static route 10.9.0.0/16 next-hop 10.9.0.1",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected CompileConfig to reject a per-instance disposition conflict")
		}
		if !strings.Contains(err.Error(), "contradictory dispositions") {
			t.Fatalf("error %q must report a disposition conflict", err.Error())
		}
		if !strings.Contains(err.Error(), "routing-instances blue") {
			t.Fatalf("error %q must name the offending routing-instance", err.Error())
		}
	})
}

// TestStaticRouteLegitMultipathAccepted_5633 proves the gate does NOT regress
// legitimate route shapes: ECMP (multiple next-hops for one prefix), a floating
// qualified-next-hop backup, and each single-disposition route all still
// compile cleanly. Only a mix of ≥2 DISTINCT dispositions is a conflict.
func TestStaticRouteLegitMultipathAccepted_5633(t *testing.T) {
	// ECMP: two next-hop `set` lines for the same prefix merge into one route
	// with two equal-cost next-hops. That is a single "next-hop" disposition,
	// not a conflict.
	t.Run("ecmp-multi-nexthop", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 10.0.0.0/8 next-hop 10.0.0.1",
			"set routing-options static route 10.0.0.0/8 next-hop 10.0.0.2",
		)
		cfg := assertCommitAccepts(t, tree)
		r := findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.0.0.0/8")
		if len(r.NextHops) != 2 {
			t.Fatalf("ECMP route NextHops = %d, want 2: %+v", len(r.NextHops), r.NextHops)
		}
		if r.Discard || r.Reject || r.NextTable != "" {
			t.Fatalf("ECMP route must carry no terminal/leak disposition: %+v", r)
		}
	})

	// A primary next-hop plus a qualified-next-hop backup is still the single
	// "next-hop" disposition (both forward), so it must not trip the gate.
	t.Run("qualified-nexthop-backup", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 10.5.0.0/16 next-hop 10.0.0.1",
			"set routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2 preference 250",
		)
		cfg := assertCommitAccepts(t, tree)
		r := findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.5.0.0/16")
		if len(r.NextHops) != 2 {
			t.Fatalf("floating route NextHops = %d, want 2: %+v", len(r.NextHops), r.NextHops)
		}
	})

	// Each single disposition on its own remains valid.
	t.Run("single-dispositions", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances secret instance-type virtual-router",
			// #9810: one unclaimed unit (N=1) so the per-ingress window gate admits the leak.
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 10.1.0.0/16 discard",
			"set routing-options static route 10.2.0.0/16 reject",
			"set routing-options static route 10.3.0.0/16 next-hop 10.0.0.1",
			"set routing-options static route 10.4.0.0/16 next-table secret.inet.0",
		)
		assertCommitAccepts(t, tree)
	})
}

// TestStaticRouteDispositionConflict_LenientDowngrade_5633 proves the
// strict/tolerant split: the gate hard-rejects on the strict commit path but is
// downgraded to a warning on the tolerant load path (CompileConfigLenient), so
// an already-persisted or peer-synced config carrying the contradiction still
// LOADS (#1960 no-brick) — the dataplane resolves the deterministic disposition
// precedence.
func TestStaticRouteDispositionConflict_LenientDowngrade_5633(t *testing.T) {
	sets := []string{
		"set routing-options static route 10.0.0.0/8 discard",
		"set routing-options static route 10.0.0.0/8 next-hop 10.0.0.1",
	}

	// Strict path rejects.
	if _, err := CompileConfig(flatTreeFromSets(t, sets...)); err == nil {
		t.Fatal("strict CompileConfig must reject the disposition conflict")
	}

	// Tolerant path loads with a warning instead of failing.
	cfg, err := CompileConfigLenient(flatTreeFromSets(t, sets...))
	if err != nil {
		t.Fatalf("tolerant load must NOT hard-fail on a disposition conflict, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "static route disposition conflict") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a disposition-conflict warning on the lenient path, warnings=%v", cfg.Warnings)
	}
}
