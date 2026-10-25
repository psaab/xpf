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

func TestCollectZoneNamesSeesSecondZonesBlock12829(t *testing.T) {
	tree := parseHierText(t, `
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
	if StableZoneID("zzq17760") != StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide")
	}
	tree := parseHierText(t, `
security {
    zones { security-zone zzq17760 { } }
    zones { security-zone zzq8100 { } }
}
`)
	if _, _, err := validateZoneIDCollisionAST(tree, false); err == nil {
		t.Fatalf("strict gate accepted colliding zones split across sibling zones blocks (zzq17760/zzq8100 fold to %d) (#12829)", StableZoneID("zzq17760"))
	} else if !strings.Contains(err.Error(), "zzq17760") || !strings.Contains(err.Error(), "zzq8100") {
		t.Fatalf("collision error must name both zones, got: %v", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted colliding zones split across sibling zones blocks (#12829)")
	}
	// Lenient: warn, and runtime set must contain both so quarantine drops zzq8100.
	_, runtime, err := validateZoneIDCollisionAST(tree, true)
	if err != nil {
		t.Fatalf("lenient gate errored: %v", err)
	}
	found174, found214 := false, false
	for _, n := range runtime {
		if n == "zzq17760" {
			found174 = true
		}
		if n == "zzq8100" {
			found214 = true
		}
	}
	if !found174 || !found214 {
		t.Fatalf("runtime quarantine set %v must contain both colliding zones from sibling blocks (#12829)", runtime)
	}
	if q := QuarantinedZoneNames(runtime); q["zzq8100"] != struct{}{} || len(q) != 1 {
		t.Fatalf("quarantine must drop only later-sorting zzq8100, got %v", q)
	}
	// End-to-end lenient compile records both names.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	warned := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") && strings.Contains(w, "zzq8100") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("lenient compile carried no collision warning for sibling-block pair: %v", cfg.Warnings)
	}
	if q := ZoneQuarantineExclusionsForConfig(cfg); q["zzq8100"] != struct{}{} {
		t.Fatalf("ZoneQuarantineExclusionsForConfig must quarantine zzq8100 from second zones block, got %v (recorded %v)", q, cfg.ZoneQuarantineNames)
	}
}

func TestSiblingZonesNoFalsePositive12829(t *testing.T) {
	// Nil nodes and an empty security root contribute no names.
	names := map[string]struct{}{}
	collectZoneNamesAST(nil, names)
	empty := parseHierText(t, "security { }").FindChild("security")
	collectZoneNamesAST(empty, names)
	if len(names) != 0 {
		t.Fatalf("nil or empty security root contributed zone names: %v", names)
	}

	tree := parseHierText(t, `
security {
    zones { security-zone trust { } }
    zones { security-zone untrust { } }
}
`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile rejected distinct zones across sibling blocks: %v", err)
	}
	// Single-block unchanged.
	tree2 := parseHierText(t, `
security {
    zones { security-zone trust { } security-zone untrust { } }
}
`)
	if _, err := CompileConfig(tree2); err != nil {
		t.Fatalf("single-block compile rejected: %v", err)
	}
}
