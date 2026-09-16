package config

import (
	"strings"
	"testing"
)

// TestNextTableUndefinedTargetRejected_5693 proves the #5693 fix: a static
// route whose `next-table <target>` names an UNDEFINED routing-instance is
// REJECTED at the strict commit path (CompileConfig) instead of being silently
// accepted and then dropped at apply time (the applier's tableIDs lookup
// misses, warns, and skips — the intended inter-VRF leak never happens).
//
// FAIL-ON-REVERT: removing the validateNextTableTargetReferencesStrict call
// from runUniformGates (or reverting the gate to a no-op) makes CompileConfig
// accept the undefined-target config, so the reject assertions below fire RED.
func TestNextTableUndefinedTargetRejected_5693(t *testing.T) {
	// inet.0 (global) undefined target.
	t.Run("inet-flatset-undefined", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options static route 0.0.0.0/0 next-table Comcst-GigabitPro.inet.0",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected CompileConfig to reject a next-table naming an undefined routing-instance")
		}
		// The error must name the RAW token the operator typed (#5693
		// grammar preservation), not just the stripped instance.
		if !strings.Contains(err.Error(), "Comcst-GigabitPro.inet.0") {
			t.Fatalf("error %q must quote the raw next-table token", err.Error())
		}
	})

	// inet6.0 rib undefined target — the gate covers both global route sets.
	t.Run("inet6-flatset-undefined", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-options rib inet6.0 static route ::/0 next-table ATT.inet6.0",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("expected CompileConfig to reject an undefined inet6 next-table target")
		}
	})

	// Hierarchical AST shape (load merge / saved config).
	t.Run("hierarchical-undefined", func(t *testing.T) {
		tree := hierTree(t, `routing-options {
    static {
        route 10.0.0.0/8 {
            next-table nope.inet.0;
        }
    }
}`)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("expected CompileConfig to reject an undefined hierarchical next-table target")
		}
	})
}

// TestNextTableDefinedTargetAccepted_5693 proves the happy path is undisturbed:
// a next-table pointing at a DEFINED routing-instance compiles, and both the
// parsed instance (NextTable) and the preserved raw token (NextTableRaw) are
// populated.
func TestNextTableDefinedTargetAccepted_5693(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-instances Comcast-GigabitPro instance-type virtual-router",
		// #9810: one unclaimed unit (N=1) so the per-ingress window gate admits the leak.
		"set interfaces ge-0/0/0 unit 0",
		"set routing-options static route 0.0.0.0/0 next-table Comcast-GigabitPro.inet.0",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined next-table target must compile, got %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("StaticRoutes = %d, want 1", len(cfg.RoutingOptions.StaticRoutes))
	}
	sr := cfg.RoutingOptions.StaticRoutes[0]
	if sr.NextTable != "Comcast-GigabitPro" {
		t.Errorf("NextTable = %q, want Comcast-GigabitPro", sr.NextTable)
	}
	// #5693 grammar preservation: the raw token survives to validation.
	if sr.NextTableRaw != "Comcast-GigabitPro.inet.0" {
		t.Errorf("NextTableRaw = %q, want Comcast-GigabitPro.inet.0", sr.NextTableRaw)
	}
}

// TestNextTableTargetGate_LenientDowngrade_5693 proves the strict/tolerant
// split: the definedness gate hard-rejects on the strict commit path but is
// downgraded to a warning on the tolerant load path (CompileConfigLenient), so
// an already-persisted config carrying a dangling next-table still LOADS (#1960
// no-brick) — the applier keeps it inert.
func TestNextTableTargetGate_LenientDowngrade_5693(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 0.0.0.0/0 next-table ghost.inet.0",
	)
	// Strict path rejects.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig must reject the dangling next-table")
	}
	// Tolerant path loads with a warning instead of failing.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must NOT hard-fail on a dangling next-table, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "next-table") && strings.Contains(w, "ghost") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant load must record a next-table downgrade warning, got %v", cfg.Warnings)
	}
}
