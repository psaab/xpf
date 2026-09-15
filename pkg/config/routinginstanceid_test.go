package config

import (
	"fmt"
	"strings"
	"testing"
)

// compileRoutingInstanceTableIDs compiles a routing-instances block containing
// the named instances (in the given order) and returns name -> kernel TableID.
func compileRoutingInstanceTableIDs(t *testing.T, names ...string) map[string]int {
	t.Helper()
	var b strings.Builder
	b.WriteString("routing-instances {\n")
	for _, n := range names {
		fmt.Fprintf(&b, "    %s {\n        instance-type virtual-router;\n    }\n", n)
	}
	b.WriteString("}\n")
	tree, errs := NewParser(b.String()).Parse()
	if errs != nil {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	out := make(map[string]int, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		out[ri.Name] = ri.TableID
	}
	return out
}

// TestStableRoutingInstanceTableIDInReservedBand asserts every folded id lands
// in the reserved band and clears every other reserved kernel-table constant.
func TestStableRoutingInstanceTableIDInReservedBand(t *testing.T) {
	names := []string{"", "a", "A", "BLUE", "ATT", "Comcast-GigabitPro", "isp-a",
		"vr", "mgmt", "trust", "wan", "x", "zzz", "é-vrf"}
	for i := 0; i < 5000; i++ {
		names = append(names, fmt.Sprintf("ri-%d", i))
	}
	for _, name := range names {
		id := StableRoutingInstanceTableID(name)
		if id < RoutingInstanceTableIDBase || id >= RoutingInstanceTableIDBase+RoutingInstanceTableIDSpan {
			t.Errorf("name %q: id %d out of band [%d, %d)", name, id,
				RoutingInstanceTableIDBase, RoutingInstanceTableIDBase+RoutingInstanceTableIDSpan)
		}
		// Must never land on the mgmt table, the RPM probe band, or below the
		// historical >= 100 floor.
		if id == 999 {
			t.Errorf("name %q folds to the mgmt table 999", name)
		}
		if id >= ProbeTableBase && id < ProbeTableBase+ProbeTableCount {
			t.Errorf("name %q folds into the RPM probe band %d..%d", name, ProbeTableBase, ProbeTableBase+ProbeTableCount-1)
		}
		if id < 100 {
			t.Errorf("name %q folds below the >= 100 floor: %d", name, id)
		}
	}
	// Pure function of the name.
	if StableRoutingInstanceTableID("foo") != StableRoutingInstanceTableID("foo") {
		t.Fatal("StableRoutingInstanceTableID not deterministic")
	}
}

// TestRoutingInstanceTableIDStableUnderSiblingChurn is the RED-on-revert core:
// deleting/reordering a sibling must NEVER renumber an untouched instance.
// Reverting to positional assignment renumbers survivors after the deleted one
// and this test goes RED.
func TestRoutingInstanceTableIDStableUnderSiblingChurn(t *testing.T) {
	before := compileRoutingInstanceTableIDs(t, "A", "B", "C")

	// Every id must equal the pure name-hash, independent of position.
	for name, id := range before {
		if want := StableRoutingInstanceTableID(name); id != want {
			t.Errorf("instance %q: TableID %d != stable name-hash %d", name, id, want)
		}
	}

	// Delete B. A and C must keep their ORIGINAL table ids. Under positional
	// assignment C would renumber (102 -> 101) and vrf.go would recreate it.
	afterDelete := compileRoutingInstanceTableIDs(t, "A", "C")
	if afterDelete["A"] != before["A"] {
		t.Errorf("A renumbered on sibling delete: %d -> %d", before["A"], afterDelete["A"])
	}
	if afterDelete["C"] != before["C"] {
		t.Errorf("C renumbered on sibling delete: %d -> %d "+
			"(positional-identity regression #3855 — vrf.go would recreate C)",
			before["C"], afterDelete["C"])
	}

	// Reorder must not renumber anything.
	reordered := compileRoutingInstanceTableIDs(t, "C", "B", "A")
	for _, n := range []string{"A", "B", "C"} {
		if reordered[n] != before[n] {
			t.Errorf("reorder renumbered %q: %d -> %d", n, before[n], reordered[n])
		}
	}

	// Adding a new instance gives it a fresh stable id without disturbing the
	// existing ones.
	withNew := compileRoutingInstanceTableIDs(t, "A", "B", "C", "D")
	for _, n := range []string{"A", "B", "C"} {
		if withNew[n] != before[n] {
			t.Errorf("adding D disturbed %q: %d -> %d", n, before[n], withNew[n])
		}
	}
	if withNew["D"] != StableRoutingInstanceTableID("D") {
		t.Errorf("new instance D: TableID %d != stable %d", withNew["D"], StableRoutingInstanceTableID("D"))
	}
	if withNew["D"] == before["A"] || withNew["D"] == before["B"] || withNew["D"] == before["C"] {
		t.Errorf("new instance D collided with an existing id: %d", withNew["D"])
	}
}

// findCollidingRoutingInstanceNames brute-forces two instance names that fold to
// the same kernel table id (expected within ~1200 iterations for a 900k band).
// Returns them sorted so the caller knows which is the survivor/quarantined.
func findCollidingRoutingInstanceNames(t *testing.T) (first, second string) {
	t.Helper()
	seen := make(map[int]string)
	for i := 0; i < 5_000_000; i++ {
		name := fmt.Sprintf("ri-collide-%08d", i)
		id := StableRoutingInstanceTableID(name)
		if prev, ok := seen[id]; ok {
			if prev < name {
				return prev, name
			}
			return name, prev
		}
		seen[id] = name
	}
	t.Fatal("no StableRoutingInstanceTableID collision found in 5M names")
	return "", ""
}

// TestQuarantinedRoutingInstanceNames verifies the sorted-first name keeps the
// table and the later-sorting colliding name is quarantined.
func TestQuarantinedRoutingInstanceNames(t *testing.T) {
	if got := QuarantinedRoutingInstanceNames([]string{"solo"}); got != nil {
		t.Errorf("single name should never be quarantined, got %v", got)
	}
	if got := QuarantinedRoutingInstanceNames([]string{"a", "b", "c"}); len(got) != 0 {
		t.Errorf("non-colliding names quarantined: %v", got)
	}

	survivor, quarantined := findCollidingRoutingInstanceNames(t)
	if StableRoutingInstanceTableID(survivor) != StableRoutingInstanceTableID(quarantined) {
		t.Fatalf("helper returned non-colliding pair %q/%q", survivor, quarantined)
	}
	q := QuarantinedRoutingInstanceNames([]string{quarantined, survivor})
	if _, ok := q[quarantined]; !ok {
		t.Errorf("later-sorting %q not quarantined", quarantined)
	}
	if _, ok := q[survivor]; ok {
		t.Errorf("sorted-first %q must survive, was quarantined", survivor)
	}
	if len(q) != 1 {
		t.Errorf("quarantine set = %v, want exactly {%q}", q, quarantined)
	}
}

// TestRoutingInstanceTableIDCollisionGate verifies the strict commit path
// REJECTS a colliding pair and the lenient load path keeps booting but drops
// (quarantines) the later-sorting colliding instance so two VRFs never share a
// kernel table.
func TestRoutingInstanceTableIDCollisionGate(t *testing.T) {
	survivor, quarantined := findCollidingRoutingInstanceNames(t)

	cfgText := fmt.Sprintf("routing-instances {\n"+
		"    %s {\n        instance-type virtual-router;\n    }\n"+
		"    %s {\n        instance-type virtual-router;\n    }\n}\n", survivor, quarantined)
	tree, errs := NewParser(cfgText).Parse()
	if errs != nil {
		t.Fatalf("parse: %v", errs)
	}

	// Strict: commit rejects the colliding config.
	if _, err := CompileConfig(tree.Clone()); err == nil {
		t.Fatal("strict CompileConfig accepted a table-id collision; want reject")
	} else if !strings.Contains(err.Error(), survivor) || !strings.Contains(err.Error(), quarantined) {
		t.Errorf("strict error should name both instances: %v", err)
	}

	// Lenient: boots, warns, and drops the later-sorting instance.
	cfg, err := CompileConfigLenient(tree.Clone())
	if err != nil {
		t.Fatalf("lenient compile should not error: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("lenient compile kept %d instances, want 1 (later dropped): %+v",
			len(cfg.RoutingInstances), cfg.RoutingInstances)
	}
	if cfg.RoutingInstances[0].Name != survivor {
		t.Errorf("survivor = %q, want sorted-first %q", cfg.RoutingInstances[0].Name, survivor)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, quarantined) && strings.Contains(strings.ToUpper(w), "QUARANTINE") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a QUARANTINE warning naming %q; warnings=%v", quarantined, cfg.Warnings)
	}
}

// TestStableRoutingInstanceTableIDLiterals9752 pins name->id vectors the Rust
// mirror must agree with (`install_table_identity_matches_go_vectors_9752` in
// userspace-dp/src/session/routing_domain_wire_tests.rs pins the same list).
// Either implementation drifting reds its own suite; agreement is by shared
// literals, not by running each other's code. If this reds after touching
// StableRoutingInstanceTableID, verify against the Rust mirror before "fixing".
func TestStableRoutingInstanceTableIDLiterals9752(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{"blue", 525590},
		{"tenant-a", 259731},
		{"tenant-b", 788198},
		{"sfmix", 488570},
		{"scrub", 633963},
		{"ISP-B", 236616},
		{"vr1", 627081},
		{"mgmt", 579198},
		{"trust", 361106},
		{"wan", 384696},
		// UTF-8 multibyte: hashing is over raw bytes.
		{"é-vrf", 704427},
		{"a", 969824},
		{"A", 737632},
		{"Comcast-GigabitPro", 676172},
		{"x", 644139},
		{"zzz", 497540},
	} {
		if got := StableRoutingInstanceTableID(tc.name); got != tc.want {
			t.Errorf("StableRoutingInstanceTableID(%q) = %d, want %d (Rust mirror pins the same)", tc.name, got, tc.want)
		}
	}
}
