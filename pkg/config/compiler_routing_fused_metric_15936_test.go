package config

import (
	"strings"
	"testing"
)

// #15936 R1 (Codex config NEEDS_VALIDATION): an unsupported fused routing
// `metric` on a next-hop leaf may swallow following supported route
// clauses (`next-hop 10.0.0.1 metric 5 no-install`).
//
// Admission fixture (the decisive check the retro required): strict
// configstore admission (SchemaValidate, as CheckText runs it) REJECTS
// every fused spelling below — the #8437 fused-sibling gate names the
// first swallowed sibling token — so the discard in
// applyFusedRouteTail15777 (no `metric` case, returns immediately) has
// no strict-commit consequence. The lenient/tolerant compiler still
// discards the tail silently; that path backs Store.Load/SyncApply of
// already-persisted config, so this file also pins the tolerant
// behaviour explicitly rather than leaving it implicit: the route
// compiles, `metric` draws the #10707 advisory, and the swallowed
// clause does NOT take effect (documented residual, strict gate is the
// operator-facing protection).

func TestFusedMetricSwallowsTailRejectedStrict15936(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		swallowed string
	}{
		{"no-install", "routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 metric 5 no-install; } } }", "no-install"},
		{"preference", "routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 metric 5 preference 123; } } }", "preference"},
		{"reject", "routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 metric 5 reject; } } }", "reject"},
		{"discard", "routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 metric 5 discard; } } }", "discard"},
		{"next-table", "routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 metric 5 next-table blue.inet.0; } } }", "next-table"},
		{"compact-route", "routing-options { static { route 10.85.0.0/16 next-hop 10.0.0.1 metric 5 no-install; } }", "no-install"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, tc.src)
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("strict admission must reject fused metric tail (%s): %s", tc.name, tc.src)
			}
			if !strings.Contains(err.Error(), "#8437") || !strings.Contains(err.Error(), tc.swallowed) {
				t.Fatalf("strict rejection must name the swallowed %q via #8437, got: %v", tc.swallowed, err)
			}
		})
	}
}

// Tolerant-load pin: the same spelling compiles leniently (no-brick,
// #1960), draws the #10707 advisory for `metric`, and the swallowed
// clause does not take effect. This documents the residual precisely:
// only already-persisted config reaches this path, and the advisory
// makes the dropped clause visible in warnings.
func TestFusedMetricTailLenientDocumented15936(t *testing.T) {
	src := "routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 metric 5 no-install; } } }"
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("lenient compile must not brick on fused metric tail: %v", err)
	}
	r := findRoute15777(t, cfg.RoutingOptions.StaticRoutes, "10.85.0.0/16")
	if r.NoInstall {
		t.Fatalf("lenient: swallowed no-install must not take effect (documented discard), route=%+v", r)
	}
	if len(r.NextHops) != 1 || r.NextHops[0].Address != "10.0.0.1" {
		t.Fatalf("lenient: NextHops = %+v, want only 10.0.0.1 (fused tokens must not become gateways)", r.NextHops)
	}
	// Controls: the supported fused tails without metric DO take effect
	// leniently, proving the discard is specific to the metric head.
	ctl, err := CompileConfigLenient(hierTree(t, "routing-options { static { route 10.85.0.0/16 { next-hop 10.0.0.1 preference 123; } } }"))
	if err != nil {
		t.Fatalf("lenient control compile: %v", err)
	}
	cr := findRoute15777(t, ctl.RoutingOptions.StaticRoutes, "10.85.0.0/16")
	if cr.Preference != 123 || !cr.HasPreference {
		t.Fatalf("lenient control: fused preference must take effect, route=%+v", cr)
	}
}
