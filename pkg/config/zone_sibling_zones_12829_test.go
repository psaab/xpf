package config

import (
	"strings"
	"testing"
)

// #12829: collectZoneNamesAST used FindChild("zones"), seeing only the
// FIRST zones stanza under a security root, while compileSecurity /
// compileZones iterate every zones sibling. Colliding StableZoneIDs
// split across sibling zones blocks therefore escaped the strict
// collision gate, and the runtime quarantine name set omitted zones
// declared only in the second block.

func parseSiblingZones12829(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func TestCollectZoneNamesSeesSecondZonesBlock12829(t *testing.T) {
	tree := parseSiblingZones12829(t, `
security {
    zones { security-zone trust { } }
    zones { security-zone secondonly { } }
}
`)
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatal("no security root")
	}
	if got := len(sec.FindChildren("zones")); got != 2 {
		t.Fatalf("fixture premise: expected 2 sibling zones blocks, got %d", got)
	}
	names := map[string]struct{}{}
	collectZoneNamesAST(sec, names)
	for _, want := range []string{"trust", "secondonly"} {
		if _, ok := names[want]; !ok {
			t.Errorf("collectZoneNamesAST missed zone %q from sibling zones blocks: %v (#12829)", want, names)
		}
	}
}

func TestZoneIDCollisionAcrossSiblingZonesBlocks12829(t *testing.T) {
	if StableZoneID("z174") != StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide")
	}
	tree := parseSiblingZones12829(t, `
security {
    zones { security-zone z174 { } }
    zones { security-zone z214 { } }
}
`)
	if _, _, err := validateZoneIDCollisionAST(tree, false); err == nil {
		t.Fatalf("strict gate accepted colliding zones split across sibling zones blocks (z174/z214 fold to %d) (#12829)", StableZoneID("z174"))
	} else if !strings.Contains(err.Error(), "z174") || !strings.Contains(err.Error(), "z214") {
		t.Fatalf("collision error must name both zones, got: %v", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted colliding zones split across sibling zones blocks (#12829)")
	}
	// Lenient: warn, and runtime set must contain both so quarantine drops z214.
	_, runtime, err := validateZoneIDCollisionAST(tree, true)
	if err != nil {
		t.Fatalf("lenient gate errored: %v", err)
	}
	found174, found214 := false, false
	for _, n := range runtime {
		if n == "z174" {
			found174 = true
		}
		if n == "z214" {
			found214 = true
		}
	}
	if !found174 || !found214 {
		t.Fatalf("runtime quarantine set %v must contain both colliding zones from sibling blocks (#12829)", runtime)
	}
	if q := QuarantinedZoneNames(runtime); q["z214"] != struct{}{} || len(q) != 1 {
		t.Fatalf("quarantine must drop only later-sorting z214, got %v", q)
	}
	// End-to-end lenient compile records both names.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	warned := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") && strings.Contains(w, "z214") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("lenient compile carried no collision warning for sibling-block pair: %v", cfg.Warnings)
	}
	if q := ZoneQuarantineExclusionsForConfig(cfg); q["z214"] != struct{}{} {
		t.Fatalf("ZoneQuarantineExclusionsForConfig must quarantine z214 from second zones block, got %v (recorded %v)", q, cfg.ZoneQuarantineNames)
	}
}

func TestSiblingZonesNoFalsePositive12829(t *testing.T) {
	// Nil nodes and an empty security root contribute no names.
	names := map[string]struct{}{}
	collectZoneNamesAST(nil, names)
	empty := parseSiblingZones12829(t, "security { }").FindChild("security")
	collectZoneNamesAST(empty, names)
	if len(names) != 0 {
		t.Fatalf("nil or empty security root contributed zone names: %v", names)
	}

	tree := parseSiblingZones12829(t, `
security {
    zones { security-zone trust { } }
    zones { security-zone untrust { } }
}
`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile rejected distinct zones across sibling blocks: %v", err)
	}
	// Single-block unchanged.
	tree2 := parseSiblingZones12829(t, `
security {
    zones { security-zone trust { } security-zone untrust { } }
}
`)
	if _, err := CompileConfig(tree2); err != nil {
		t.Fatalf("single-block compile rejected: %v", err)
	}
}
