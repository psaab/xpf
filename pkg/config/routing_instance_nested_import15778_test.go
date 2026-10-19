package config

import (
	"strings"
	"testing"
)

// #15778: canonical Junos `routing-instances <name> routing-options
// { instance-import/export }` bypassed the #11314 strict rejection that
// the direct `routing-instances <name> instance-import/export` form
// carries, and compact (packed) unknown leaves under open-world routing
// grammars escaped the #10707 warning that their braced twins draw.
//
// RED at master (measured):
//   - braced/flat nested import/export: strict accepts, only generic
//     #10707 warning (not the #11314 rejection).
//   - elided `routing-options instance-import …` and packed-instance
//     forms: strict accepts with NO warning at all.
//   - compact `route … metric/resolve/bfd-liveness-detection …` and
//     compact unknown tokens generally: no #10707 warning, while the
//     braced spelling warns.

func check11314Diagnostic(t *testing.T, where, diagnostic, keyword string) {
	t.Helper()
	for _, want := range []string{
		`"` + keyword + `"`,
		"cross-RIB policy-leak engine",
		"connected prefixes only",
		"not instance-import/export policy",
		"#11314",
	} {
		if !strings.Contains(diagnostic, want) {
			t.Errorf("%s diagnostic lacks %q: %s", where, want, diagnostic)
		}
	}
}

func TestNestedRoutingOptionsInstanceImportExportRejected15778(t *testing.T) {
	for _, tc := range []struct {
		name, keyword string
		hier          string
		flat          []string
	}{
		{
			name: "instance-import", keyword: "instance-import",
			hier: "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    routing-options {\n      instance-import policy-a;\n    }\n  }\n}\n",
			flat: []string{
				"set routing-instances VRF-A instance-type vrf",
				"set routing-instances VRF-A routing-options instance-import policy-a",
			},
		},
		{
			name: "instance-export", keyword: "instance-export",
			hier: "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    routing-options {\n      instance-export policy-a;\n    }\n  }\n}\n",
			flat: []string{
				"set routing-instances VRF-A instance-type vrf",
				"set routing-instances VRF-A routing-options instance-export policy-a",
			},
		},
		{
			name: "elided-instance-import", keyword: "instance-import",
			hier: "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    routing-options instance-import policy-a;\n  }\n}\n",
		},
		{
			name: "elided-instance-export", keyword: "instance-export",
			hier: "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    routing-options instance-export policy-a;\n  }\n}\n",
		},
		{
			name: "packed-instance-import", keyword: "instance-import",
			hier: "routing-instances {\n  VRF-A routing-options instance-import policy-a;\n}\n",
		},
	} {
		t.Run(tc.name+"/hier", func(t *testing.T) {
			if _, err := CompileConfig(parse9323(t, tc.hier)); err == nil {
				t.Fatalf("strict CompileConfig ACCEPTED nested %s via routing-options", tc.keyword)
			} else {
				check11314Diagnostic(t, "strict hier", err.Error(), tc.keyword)
			}
			cfg, err := CompileConfigLenient(parse9323(t, tc.hier))
			if err != nil {
				t.Fatalf("lenient REJECTED nested %s (no-brick #1960): %v", tc.keyword, err)
			}
			if cfg == nil || len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != "VRF-A" {
				t.Fatalf("lenient lost valid instance: %+v", cfg)
			}
			check11314Diagnostic(t, "lenient hier warning", strings.Join(cfg.Warnings, "\n"), tc.keyword)
		})
		if len(tc.flat) > 0 {
			t.Run(tc.name+"/flat", func(t *testing.T) {
				if _, err := CompileConfig(tree9323(t, tc.flat...)); err == nil {
					t.Fatalf("strict CompileConfig ACCEPTED flat nested %s", tc.keyword)
				} else {
					check11314Diagnostic(t, "strict flat", err.Error(), tc.keyword)
				}
				cfg, err := CompileConfigLenient(tree9323(t, tc.flat...))
				if err != nil {
					t.Fatalf("lenient REJECTED flat nested %s: %v", tc.keyword, err)
				}
				check11314Diagnostic(t, "lenient flat warning", strings.Join(cfg.Warnings, "\n"), tc.keyword)
			})
		}
	}

	// Direct form still rejected (regression guard, not the fix).
	if err := validate9323(t,
		"set routing-instances VRF-A instance-type vrf",
		"set routing-instances VRF-A instance-import policy-a"); err == nil {
		t.Fatal("direct instance-import no longer rejected")
	}

	// Valid routing-instance config still commits clean of #11314/#10707
	// instance-import diagnostics.
	valid := "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    routing-options {\n      static {\n        route 10.0.0.0/24 next-hop 10.0.0.1;\n      }\n    }\n  }\n}\n"
	cfg, err := CompileConfig(parse9323(t, valid))
	if err != nil {
		t.Fatalf("valid routing-instance config rejected: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "instance-import") || strings.Contains(w, "instance-export") {
			t.Fatalf("valid config drew instance policy warning: %q", w)
		}
	}
	// Global routing-options instance-import is NOT the per-instance
	// #11314 form: it stays on the #10707 warn-only path.
	gcfg, err := CompileConfig(parse9323(t, "routing-options {\n  instance-import policy-a;\n}\n"))
	if err != nil {
		t.Fatalf("global routing-options instance-import must stay warn-only (#10707), got reject: %v", err)
	}
	found := false
	for _, w := range gcfg.Warnings {
		if strings.Contains(w, "#10707") && strings.Contains(w, `"instance-import"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("global instance-import lost #10707 warning: %v", gcfg.Warnings)
	}
}

func has10707For(warnings []string, keyword string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "#10707") && strings.Contains(w, `"`+keyword+`"`) {
			return true
		}
	}
	return false
}

func TestCompactUnknownRoutingLeavesWarn10707_15778(t *testing.T) {
	for _, tc := range []struct {
		name, keyword, hier string
		flat                []string
	}{
		{
			name: "static-route-metric-compact", keyword: "metric",
			hier: "routing-options {\n  static {\n    route 10.0.0.0/24 metric 5 next-hop 10.0.0.1;\n  }\n}\n",
		},
		{
			name: "static-route-resolve-compact", keyword: "resolve",
			hier: "routing-options {\n  static {\n    route 10.0.0.0/24 resolve next-hop 10.0.0.1;\n  }\n}\n",
		},
		{
			name: "static-route-bfd-compact", keyword: "bfd-liveness-detection",
			hier: "routing-options {\n  static {\n    route 10.0.0.0/24 bfd-liveness-detection minimum-interval 300 next-hop 10.0.0.1;\n  }\n}\n",
		},
		{
			name: "routing-options-bogus-elided", keyword: "frobnicate",
			hier: "routing-options frobnicate 7;\n",
		},
		{
			name: "static-route-bogus-compact", keyword: "frobnicate",
			hier: "routing-options {\n  static route 10.0.0.0/24 frobnicate 7;\n}\n",
		},
		{
			name: "ospf-interface-bogus-compact", keyword: "frobnicate",
			hier: "protocols {\n  ospf {\n    area 0.0.0.0 {\n      interface ge-0/0/1.0 frobnicate 7;\n    }\n  }\n}\n",
		},
		{
			name: "instance-routing-options-bogus-elided", keyword: "frobnicate",
			hier: "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    routing-options frobnicate 7;\n  }\n}\n",
		},
		{
			name: "instance-static-route-metric-compact", keyword: "metric",
			hier: "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    routing-options {\n      static {\n        route 10.0.0.0/24 metric 5 next-hop 10.0.0.1;\n      }\n    }\n  }\n}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parse9323(t, tc.hier))
			if err != nil {
				t.Fatalf("compact unknown leaf must stay warn-only (#10707), got reject: %v", err)
			}
			if !has10707For(cfg.Warnings, tc.keyword) {
				t.Fatalf("compact form escaped #10707 warning for %q; warnings=%v", tc.keyword, cfg.Warnings)
			}
			lcfg, err := CompileConfigLenient(parse9323(t, tc.hier))
			if err != nil {
				t.Fatalf("lenient: %v", err)
			}
			if !has10707For(lcfg.Warnings, tc.keyword) {
				t.Fatalf("lenient compact form escaped #10707 for %q; warnings=%v", tc.keyword, lcfg.Warnings)
			}
		})
	}

	// Controls: valid packed/compact forms must NOT draw #10707.
	// A quoted value that spells an unknown keyword is a value, not a
	// statement head (#9635).
	for _, tc := range []struct {
		name, hier string
		flat       []string
	}{
		{
			name: "ospf-bfd-compact-valid",
			hier: "protocols {\n  ospf {\n    area 0.0.0.0 {\n      interface ge-0/0/1.0 bfd-liveness-detection minimum-interval 300;\n    }\n  }\n}\n",
		},
		{
			name: "static-route-valid-compact",
			hier: "routing-options {\n  static {\n    route 10.0.0.0/24 next-hop 10.0.0.1;\n  }\n}\n",
		},
		{
			name: "quoted-value-spells-keyword",
			hier: "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    description \"metric\";\n  }\n}\n",
		},
	} {
		t.Run("control/"+tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parse9323(t, tc.hier))
			if err != nil {
				t.Fatalf("valid compact control rejected: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#10707") {
					t.Fatalf("valid compact control drew #10707: %q (all=%v)", w, cfg.Warnings)
				}
			}
		})
	}
	// Flat valid static route control.
	cfg, err := CompileConfig(tree9323(t, "set routing-options static route 10.0.0.0/24 next-hop 10.0.0.1"))
	if err != nil {
		t.Fatalf("flat valid static route rejected: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#10707") {
			t.Fatalf("flat valid control drew #10707: %q", w)
		}
	}
}
