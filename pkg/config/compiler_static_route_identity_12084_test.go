package config

import (
	"strings"
	"testing"
)

// #12084: static-route identity was the AUTHORED destination string —
// destIdx in compileStaticRoutes keyed on raw sr.Destination /
// route.Destination — so two spellings of one masked prefix compiled to two
// one-disposition routes and bypassed the #5633 contradictory-disposition
// gate: '192.168.0.0/16 discard' + '192.168.1.1/16 next-hop X' (v4 host
// bits), v6 case/compression variants, or next-table A/B. The compiler now
// canonicalises (masked prefix) before the merge key, so the aliases fold
// into one route and the gate fires naming BOTH spellings.
//
// FAIL-ON-REVERT: key destIdx on the raw string again and each conflicting-
// spelling case below compiles clean instead of tripping the #5633 gate.

func TestStaticRouteIdentityAliasRejected_12084(t *testing.T) {
	// v4 host bits, flat-set: 192.168.1.1/16 masks to 192.168.0.0/16, the
	// same prefix as the discard line. Must reject with the #5633 message
	// naming both spellings.
	t.Run("v4-hostbits-flat", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 192.168.0.0/16 discard",
			"set routing-options static route 192.168.1.1/16 next-hop 10.0.0.1",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected strict compile to reject aliased-spelling disposition conflict, got nil error")
		}
		for _, want := range []string{"contradictory dispositions", "192.168.0.0/16", "192.168.1.1/16"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err.Error(), want)
			}
		}
	})

	// v6 case/compression variants, flat-set: 2001:DB8:0:0:0:0:0:0/32 and
	// 2001:db8::/32 are one masked prefix. Reverse disposition order proves
	// the latch is order-independent across spellings too.
	t.Run("v6-case-compression-flat", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options rib inet6.0 static route 2001:DB8:0:0:0:0:0:0/32 next-hop 2001:db8::1",
			"set routing-options rib inet6.0 static route 2001:db8::/32 discard",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected strict compile to reject aliased-spelling disposition conflict, got nil error")
		}
		for _, want := range []string{"contradictory dispositions", "2001:DB8:0:0:0:0:0:0/32", "2001:db8::/32"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err.Error(), want)
			}
		}
	})

	// Hierarchical AST shape (load merge / saved config): duplicate route
	// blocks with DIFFERENT spellings of one prefix must fold and reject,
	// the same way same-spelling blocks do (#5633 hierarchical subtest).
	t.Run("v4-hostbits-hierarchical", func(t *testing.T) {
		tree := hierTree(t, `routing-options {
    static {
        route 10.1.0.0/16 {
            discard;
        }
        route 10.1.7.9/16 {
            next-hop 10.0.0.9;
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected strict compile to reject aliased-spelling disposition conflict, got nil error")
		}
		for _, want := range []string{"contradictory dispositions", "10.1.0.0/16", "10.1.7.9/16"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err.Error(), want)
			}
		}
	})
	t.Run("v6-case-compression-hierarchical", func(t *testing.T) {
		tree := hierTree(t, `routing-options {
    static {
        route 2001:DB8:0:0:0:0:0:0/32 {
            discard;
        }
        route 2001:db8::/32 {
            next-hop 2001:db8::1;
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected strict compile to reject aliased-spelling disposition conflict, got nil error")
		}
		for _, want := range []string{"contradictory dispositions", "2001:DB8:0:0:0:0:0:0/32", "2001:db8::/32"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err.Error(), want)
			}
		}
	})

	// next-table A/B across spellings: same-spelling next-table lines merge
	// into ONE route (last-writer-wins, single next-table disposition), so
	// the compiled route set must carry exactly one row for the masked
	// prefix — never the two same-priority leak rules that let the kernel
	// (insertion order) and the helper (string order) pick different
	// instances.
	t.Run("nexttable-alias-single-row", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances aaa instance-type virtual-router",
			"set routing-instances zzz instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 172.16.0.0/12 next-table aaa.inet.0",
			"set routing-options static route 172.16.9.9/12 next-table zzz.inet.0",
		)
		cfg := assertCommitAccepts(t, tree)
		var rows []*StaticRoute
		for _, sr := range cfg.RoutingOptions.StaticRoutes {
			if sr != nil && (sr.Destination == "172.16.0.0/12" || sr.Destination == "172.16.9.9/12") {
				rows = append(rows, sr)
			}
		}
		if len(rows) != 1 {
			t.Fatalf("expected one compiled row for the aliased prefix, got %d", len(rows))
		}
		if rows[0].NextTable != "zzz" {
			t.Fatalf("expected last-writer-wins next-table %q, got %q", "zzz", rows[0].NextTable)
		}
	})
}

// TestStaticRouteIdentityAliasLegitAccepted_12084 proves the canonical merge
// key does NOT regress legitimate shapes: ECMP next-hops split across two
// spellings of one prefix fold into one multi-next-hop route (single
// next-hop disposition), and single-disposition routes for DISTINCT prefixes
// still compile independently.
func TestStaticRouteIdentityAliasLegitAccepted_12084(t *testing.T) {
	// ECMP across spellings: two next-hops for one masked prefix are a
	// single disposition, not a conflict — and must fold to ONE row.
	t.Run("ecmp-across-spellings", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 10.2.0.0/16 next-hop 10.0.0.1",
			"set routing-options static route 10.2.8.8/16 next-hop 10.0.0.2",
		)
		cfg := assertCommitAccepts(t, tree)
		var rows []*StaticRoute
		for _, sr := range cfg.RoutingOptions.StaticRoutes {
			if sr != nil && (sr.Destination == "10.2.0.0/16" || sr.Destination == "10.2.8.8/16") {
				rows = append(rows, sr)
			}
		}
		if len(rows) != 1 {
			t.Fatalf("expected ECMP spellings to fold to one route, got %d rows", len(rows))
		}
		if len(rows[0].NextHops) != 2 {
			t.Fatalf("expected 2 merged next-hops, got %d", len(rows[0].NextHops))
		}
	})

	// Distinct masked prefixes stay distinct routes.
	t.Run("distinct-prefixes-unaffected", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 10.3.0.0/16 discard",
			"set routing-options static route 10.4.0.0/16 next-hop 10.0.0.1",
		)
		cfg := assertCommitAccepts(t, tree)
		if len(cfg.RoutingOptions.StaticRoutes) != 2 {
			t.Fatalf("expected 2 routes for distinct prefixes, got %d", len(cfg.RoutingOptions.StaticRoutes))
		}
	})
}

func TestStaticRouteCrossCollectionIdentityRejected_12084(t *testing.T) {
	t.Run("global-bare-static-and-inet6-rib", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 2001:db8::/32 discard",
			"set routing-options rib inet6.0 static route 2001:DB8:0:0:0:0:0:0/32 next-hop 2001:db8::1",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected cross-collection disposition conflict to reject")
		}
		for _, want := range []string{
			"contradictory dispositions",
			"2001:db8::/32",
			"2001:DB8:0:0:0:0:0:0/32",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err.Error(), want)
			}
		}
	})

	t.Run("blue-instance-bare-static-and-inet6-rib", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances blue routing-options static route 2001:db8::/32 discard",
			"set routing-instances blue routing-options rib blue.inet6.0 static route 2001:DB8:0:0:0:0:0:0/32 next-hop 2001:db8::1",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected blue-instance cross-collection conflict to reject")
		}
		for _, want := range []string{
			"contradictory dispositions",
			"routing-instances blue",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err.Error(), want)
			}
		}
	})

	t.Run("competing-next-table-targets", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances aaa instance-type virtual-router",
			"set routing-instances zzz instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 2001:db8::/32 next-table aaa.inet6.0",
			"set routing-options rib inet6.0 static route 2001:DB8:0:0:0:0:0:0/32 next-table zzz.inet6.0",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected aliases with competing next-table targets to reject")
		}
		for _, want := range []string{"competing next-table targets", "aaa", "zzz"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not mention %q", err.Error(), want)
			}
		}
		lenientCfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compilation should warn but keep one route: %v", err)
		}
		routes := append(
			append([]*StaticRoute(nil), lenientCfg.RoutingOptions.StaticRoutes...),
			lenientCfg.RoutingOptions.Inet6StaticRoutes...)
		if len(routes) != 1 || routes[0].NextTable != "zzz" {
			t.Fatalf("lenient cross-container routes = %+v, want one last-writer target zzz", routes)
		}
		warned := false
		for _, warning := range lenientCfg.Warnings {
			if strings.Contains(warning, "competing next-table targets") {
				warned = true
				break
			}
		}
		if !warned {
			t.Fatalf("lenient compile did not warn about competing targets: %v", lenientCfg.Warnings)
		}
	})

	t.Run("global-and-blue-scopes-remain-isolated", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances blue instance-type virtual-router",
			"set routing-options static route 2001:db8::/32 discard",
			"set routing-instances blue routing-options rib blue.inet6.0 static route 2001:DB8:0:0:0:0:0:0/32 next-hop 2001:db8::1",
		)
		assertCommitAccepts(t, tree)
	})

	t.Run("different-routing-instances-remain-isolated", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances red instance-type virtual-router",
			"set routing-instances blue routing-options static route 2001:db8::/32 discard",
			"set routing-instances red routing-options rib red.inet6.0 static route 2001:DB8:0:0:0:0:0:0/32 next-hop 2001:db8::1",
		)
		assertCommitAccepts(t, tree)
	})
}
