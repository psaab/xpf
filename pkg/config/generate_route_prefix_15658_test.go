package config

import (
	"strings"
	"testing"
)

// #15658: `routing-options generate route` carried an untyped destination
// and no same-prefix merge. A malformed prefix (999.999.0.0/99) committed
// clean, FRR silently omitted the blackhole (validFRRRoutePrefix), and the
// userspace snapshot passed the prefix to a helper that refuses the whole
// snapshot — FRR-vs-userspace split-brain. Duplicate same-prefix blocks
// appended divergent GenerateRoute entries instead of merging.
//
// FAIL-ON-REVERT: drop keyValidator from the schema generate route node
// and the SchemaValidate cases stop erroring; drop mergeGenerateRoute /
// canonicalizeGenerateRoutes and the merge cases see 2 routes again; drop
// the uniform gates and the strict CompileConfig cases stop erroring.

func TestGenerateRouteInvalidPrefixRejected15658(t *testing.T) {
	for _, prefix := range []string{"999.999.0.0/99", "10.0.0.0/99", "10.0.0.0", "not-a-prefix", "2001:db8::/129"} {
		t.Run(prefix, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set routing-options generate route " + prefix + " discard",
			})
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("SchemaValidate accepted generate prefix %q", prefix)
			} else if !strings.Contains(err.Error(), prefix) {
				t.Fatalf("SchemaValidate error should quote %q: %v", prefix, err)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict CompileConfig accepted generate prefix %q", prefix)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile rejected persisted generate prefix %q: %v", prefix, err)
			}
			if len(cfg.RoutingOptions.GenerateRoutes) != 1 ||
				cfg.RoutingOptions.GenerateRoutes[0].Prefix != prefix {
				t.Fatalf("tolerant compile did not preserve generate route: %+v", cfg.RoutingOptions.GenerateRoutes)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "generate-route prefix") && strings.Contains(w, prefix) {
					found = true
				}
			}
			if !found {
				t.Fatalf("tolerant compile missing generate-route prefix warning for %q: %v", prefix, cfg.Warnings)
			}
		})
	}
}

func TestGenerateRouteInvalidPrefixHierarchical15658(t *testing.T) {
	tree := parseHierarchical(t, `routing-options {
    generate {
        route 999.999.0.0/99 {
            discard;
        }
    }
}`)
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("SchemaValidate accepted hierarchical 999.999.0.0/99")
	}
}

func TestGenerateRouteInstanceInvalidPrefix15658(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances BLUE instance-type virtual-router",
		"set routing-instances BLUE routing-options generate route 999.999.0.0/99 discard",
	})
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("SchemaValidate accepted per-instance 999.999.0.0/99")
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig accepted per-instance 999.999.0.0/99")
	}
}

func TestGenerateRouteValidPrefixesAccepted15658(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16", "::/0", "2001:db8::/32"} {
		tree := buildTree(t, []string{
			"set routing-options generate route " + prefix + " discard",
		})
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate rejected valid generate prefix %q: %v", prefix, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile rejected valid generate prefix %q: %v", prefix, err)
		}
		if len(cfg.RoutingOptions.GenerateRoutes) != 1 ||
			cfg.RoutingOptions.GenerateRoutes[0].Prefix != prefix ||
			!cfg.RoutingOptions.GenerateRoutes[0].Discard {
			t.Fatalf("valid generate route %q compiled wrong: %+v", prefix, cfg.RoutingOptions.GenerateRoutes)
		}
	}
}

func TestGenerateRouteSamePrefixMerge15658(t *testing.T) {
	// Hierarchical duplicate blocks: discard in one, no clause in the other.
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set routing-options generate route 10.0.0.0/8 discard",
	}))
	if err != nil {
		t.Fatal(err)
	}
	_ = cfg

	hier := parseHierarchical(t, `routing-options {
    generate {
        route 10.0.0.0/8 { discard; }
        route 10.0.0.0/8 { }
    }
}`)
	merged, err := CompileConfigLenient(hier)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.RoutingOptions.GenerateRoutes) != 1 {
		t.Fatalf("hierarchical same-prefix routes = %d, want 1 merged: %+v",
			len(merged.RoutingOptions.GenerateRoutes), merged.RoutingOptions.GenerateRoutes)
	}
	if !merged.RoutingOptions.GenerateRoutes[0].Discard {
		t.Errorf("merged route lost discard: %+v", merged.RoutingOptions.GenerateRoutes[0])
	}

	// Masked aliases of one prefix (host bits differ) merge too, first
	// spelling wins.
	alias := parseHierarchical(t, `routing-options {
    generate {
        route 10.1.2.3/8 { discard; }
        route 10.0.0.0/8 { }
    }
}`)
	mergedAlias, err := CompileConfigLenient(alias)
	if err != nil {
		t.Fatal(err)
	}
	if len(mergedAlias.RoutingOptions.GenerateRoutes) != 1 ||
		mergedAlias.RoutingOptions.GenerateRoutes[0].Prefix != "10.1.2.3/8" ||
		!mergedAlias.RoutingOptions.GenerateRoutes[0].Discard {
		t.Fatalf("masked-alias merge wrong: %+v", mergedAlias.RoutingOptions.GenerateRoutes)
	}

	// Distinct prefixes stay distinct, in source order.
	distinct := parseHierarchical(t, `routing-options {
    generate {
        route 10.0.0.0/8 { discard; }
        route 192.168.0.0/16 { discard; }
        route 10.0.0.0/8 { }
    }
}`)
	mergedDistinct, err := CompileConfigLenient(distinct)
	if err != nil {
		t.Fatal(err)
	}
	if len(mergedDistinct.RoutingOptions.GenerateRoutes) != 2 ||
		mergedDistinct.RoutingOptions.GenerateRoutes[0].Prefix != "10.0.0.0/8" ||
		mergedDistinct.RoutingOptions.GenerateRoutes[1].Prefix != "192.168.0.0/16" {
		t.Fatalf("distinct-prefix merge wrong: %+v", mergedDistinct.RoutingOptions.GenerateRoutes)
	}

	// Per-instance same-prefix merge.
	inst := buildTree(t, []string{
		"set routing-instances BLUE instance-type virtual-router",
		"set routing-instances BLUE routing-options generate route 198.51.100.0/24 discard",
		"set routing-instances BLUE routing-options generate route 198.51.100.0/24",
	})
	mergedInst, err := CompileConfigLenient(inst)
	if err != nil {
		t.Fatal(err)
	}
	if len(mergedInst.RoutingInstances) != 1 ||
		len(mergedInst.RoutingInstances[0].GenerateRoutes) != 1 ||
		!mergedInst.RoutingInstances[0].GenerateRoutes[0].Discard {
		t.Fatalf("per-instance merge wrong: %+v", mergedInst.RoutingInstances)
	}
}

func TestGenerateRouteMaskSpelling15658(t *testing.T) {
	// Helper-supported padding is written canonically so FRR and the
	// helper see the same spelling.
	cfg, err := CompileConfig(buildTree(t, []string{
		"set routing-options generate route 10.0.0.0/08 discard",
	}))
	if err != nil {
		t.Fatalf("strict compile rejected helper-supported padded mask: %v", err)
	}
	if len(cfg.RoutingOptions.GenerateRoutes) != 1 ||
		cfg.RoutingOptions.GenerateRoutes[0].Prefix != "10.0.0.0/8" {
		t.Fatalf("padded mask not canonicalised: %+v", cfg.RoutingOptions.GenerateRoutes)
	}

	// Helper-refused padding: strict rejects, tolerant keeps + warns.
	tree := buildTree(t, []string{
		"set routing-options generate route 10.0.0.0/008 discard",
	})
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "userspace helper cannot parse") {
		t.Fatalf("strict compile error = %v, want helper-refused mask rejection", err)
	}
	lenient, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile rejected helper-refused mask: %v", err)
	}
	if len(lenient.RoutingOptions.GenerateRoutes) != 1 ||
		lenient.RoutingOptions.GenerateRoutes[0].Prefix != "10.0.0.0/008" {
		t.Fatalf("tolerant compile did not preserve refused spelling: %+v", lenient.RoutingOptions.GenerateRoutes)
	}
	found := false
	for _, w := range lenient.Warnings {
		if strings.Contains(w, "generate-route CIDR mask spelling") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant compile missing mask-spelling warning: %v", lenient.Warnings)
	}

	// A refused spelling folded into a parseable alias of the same prefix
	// keeps the canonical prefix (the helper parses the published route),
	// but strict still rejects: the operator authored a spelling the
	// helper cannot parse, mirroring staticRouteHelperRefusedMaskSpellings
	// checking folded aliases, not just the survivor.
	folded := parseHierarchical(t, `routing-options {
    generate {
        route 10.0.0.0/008 { discard; }
        route 10.0.0.0/8 { discard; }
    }
}`)
	if _, err := CompileConfig(folded); err == nil ||
		!strings.Contains(err.Error(), "merged into") {
		t.Fatalf("strict compile error = %v, want folded-alias mask rejection", err)
	}
	foldedCfg, err := CompileConfigLenient(folded)
	if err != nil {
		t.Fatalf("tolerant compile rejected folded alias: %v", err)
	}
	if len(foldedCfg.RoutingOptions.GenerateRoutes) != 1 ||
		foldedCfg.RoutingOptions.GenerateRoutes[0].Prefix != "10.0.0.0/8" {
		t.Fatalf("folded alias merge wrong: %+v", foldedCfg.RoutingOptions.GenerateRoutes)
	}
}
