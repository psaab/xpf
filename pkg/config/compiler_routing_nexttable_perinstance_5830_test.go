package config

import (
	"strings"
	"testing"
)

// TestPerInstanceNextTableRejected_5830 proves the #5830 fix: a `next-table`
// authored UNDER a routing-instance is hard-rejected at the strict commit path
// (CompileConfig). Before the fix it was accepted at commit, omitted from the
// kernel/FRR forwarding plane, yet PUBLISHED as a live NextTable route in the
// instance's userspace FIB table — a control-plane/data-plane split-brain that
// leaked traffic in the userspace dataplane only, and (for an undefined
// target) sidestepped the #5693 definedness gate.
//
// Per-instance next-table is not a supported forwarding disposition (it is not
// programmed on any kernel/FRR surface), so BOTH a defined and an undefined
// target are rejected.
//
// FAIL-ON-REVERT: removing the per-instance loop from
// validateNextTableTargetReferencesStrict makes CompileConfig accept these
// configs, so every reject assertion below fires RED.
func TestPerInstanceNextTableRejected_5830(t *testing.T) {
	t.Run("inet-defined-target", func(t *testing.T) {
		// The target instance IS defined, but per-instance next-table is still
		// unsupported (never programmed on kernel/FRR) so it must be rejected.
		tree := flatTreeFromSets(t,
			"set routing-instances leaker instance-type virtual-router",
			"set routing-instances target instance-type virtual-router",
			"set routing-instances leaker routing-options static route 10.0.0.0/8 next-table target.inet.0",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected CompileConfig to reject a per-instance next-table (defined target)")
		}
		if !strings.Contains(err.Error(), "routing-instances leaker") ||
			!strings.Contains(err.Error(), "not supported") {
			t.Fatalf("error %q must name the offending instance and flag the unsupported disposition", err.Error())
		}
	})

	t.Run("inet-undefined-target", func(t *testing.T) {
		// The target instance is NOT defined — this is the #5693-bypass case:
		// the global gate never saw a per-instance route, so an undefined
		// per-instance target used to commit green.
		tree := flatTreeFromSets(t,
			"set routing-instances leaker instance-type virtual-router",
			"set routing-instances leaker routing-options static route 10.0.0.0/8 next-table Nope.inet.0",
		)
		err := mustRejectCompile(t, tree)
		if !strings.Contains(err.Error(), "Nope.inet.0") {
			t.Fatalf("error %q must quote the raw next-table token", err.Error())
		}
		if !strings.Contains(err.Error(), "undefined") {
			t.Fatalf("error %q must note the undefined target", err.Error())
		}
	})

	t.Run("inet6-undefined-target", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances leaker instance-type virtual-router",
			"set routing-instances leaker routing-options rib leaker.inet6.0 static route ::/0 next-table Nope.inet6.0",
		)
		mustRejectCompile(t, tree)
	})

	t.Run("hierarchical-defined-target", func(t *testing.T) {
		tree := hierTree(t, `routing-instances {
    target {
        instance-type virtual-router;
    }
    leaker {
        instance-type virtual-router;
        routing-options {
            static {
                route 10.0.0.0/8 {
                    next-table target.inet.0;
                }
            }
        }
    }
}`)
		mustRejectCompile(t, tree)
	})
}

// TestPerInstanceNextTableLenientDowngrade_5830 proves the tolerant load /
// peer-sync path (CompileConfigLenient) does NOT brick on an already-persisted
// or peer-synced legacy config carrying a per-instance next-table: it compiles
// with a persistent WARNING instead (#1960 no-brick). The userspace snapshot
// drops the route and the kernel/FRR plane never programmed it, so the config
// boots inert.
func TestPerInstanceNextTableLenientDowngrade_5830(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-instances leaker instance-type virtual-router",
		"set routing-instances target instance-type virtual-router",
		"set routing-instances leaker routing-options static route 10.0.0.0/8 next-table target.inet.0",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must NOT brick on a per-instance next-table, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "next-table") && strings.Contains(w, "downgraded to warning") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant load must emit a persistent next-table warning, got warnings %v", cfg.Warnings)
	}
}

// TestGlobalNextTableUnaffected_5830 guards against regression: the GLOBAL
// routing-options next-table path (defined target accepted, undefined target
// rejected by the #5693 definedness gate) is unchanged by the #5830
// per-instance rejection.
func TestGlobalNextTableUnaffected_5830(t *testing.T) {
	t.Run("global-defined-accepted", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances Comcast instance-type virtual-router",
			// #9810: one unclaimed unit (N=1) so the per-ingress window gate admits the leak.
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 0.0.0.0/0 next-table Comcast.inet.0",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("a global next-table with a defined target must still compile, got %v", err)
		}
		if len(cfg.RoutingOptions.StaticRoutes) != 1 ||
			cfg.RoutingOptions.StaticRoutes[0].NextTable != "Comcast" {
			t.Fatalf("global next-table route not compiled as expected: %+v", cfg.RoutingOptions.StaticRoutes)
		}
	})

	t.Run("global-undefined-rejected", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 next-table Ghost.inet.0",
		)
		err := mustRejectCompile(t, tree)
		// The global gate reports "undefined routing-instance", not the
		// per-instance "not supported" wording.
		if !strings.Contains(err.Error(), "undefined") {
			t.Fatalf("global undefined next-table error %q must flag the undefined target", err.Error())
		}
	})
}

func mustRejectCompile(t *testing.T, tree *ConfigTree) error {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected CompileConfig to reject the config")
	}
	return err
}
