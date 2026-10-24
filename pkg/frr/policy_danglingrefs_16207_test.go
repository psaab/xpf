package frr

import (
	"testing"
)

// #16207: danglingRefs is the extracted collection idiom shared by the
// as-path (#9881), community (#10822) and prefix-list (#14136) term
// rules. These cells pin the helper directly: empty names skipped,
// each distinct name probed exactly once, `any` true iff any distinct
// name dangles, and absent names (including the "" sentinel) never
// dangling in the returned map.
//
// FAIL-ON-REVERT: inlining the helper away (or breaking its dedup /
// empty-skip / any computation) reds here — e.g. probing a duplicate
// twice, recording "", or computing any over map iteration after a
// lost early verdict.

func TestDanglingRefs16207ProbesDistinctNamesOnce(t *testing.T) {
	probed := map[string]int{}
	refs, any := danglingRefs([]string{"A", "", "B", "A", "B", ""}, func(name string) bool {
		probed[name]++
		return name == "B"
	})
	if !any {
		t.Fatalf("any = false, want true (B dangles)")
	}
	if len(refs) != 2 || refs["A"] || !refs["B"] {
		t.Fatalf("refs = %v, want map[A:false B:true]", refs)
	}
	if _, ok := refs[""]; ok {
		t.Fatalf("empty name recorded in refs: %v", refs)
	}
	for name, n := range probed {
		if n != 1 {
			t.Fatalf("name %q probed %d times, want exactly 1 (dedup)", name, n)
		}
	}
	if len(probed) != 2 {
		t.Fatalf("probed = %v, want exactly {A, B}", probed)
	}
}

func TestDanglingRefs16207NoneDangling(t *testing.T) {
	refs, any := danglingRefs([]string{"A", "B"}, func(string) bool { return false })
	if any {
		t.Fatalf("any = true, want false when no name dangles")
	}
	if len(refs) != 2 || refs["A"] || refs["B"] {
		t.Fatalf("refs = %v, want map[A:false B:false]", refs)
	}
	// Absent names — including the "" no-match sentinel the dispatch
	// looks up — read as not dangling.
	if refs[""] || refs["MISSING"] {
		t.Fatalf("absent name reported dangling: %v", refs)
	}
}

func TestDanglingRefs16207EmptyAndNil(t *testing.T) {
	for _, names := range [][]string{nil, {}, {""}} {
		refs, any := danglingRefs(names, func(string) bool {
			t.Fatalf("probe must not run for %v", names)
			return true
		})
		if any || len(refs) != 0 {
			t.Fatalf("names=%v: refs=%v any=%v, want empty/false", names, refs, any)
		}
	}
}

func TestDanglingRefs16207AllDangling(t *testing.T) {
	refs, any := danglingRefs([]string{"A", "A"}, func(string) bool { return true })
	if !any || len(refs) != 1 || !refs["A"] {
		t.Fatalf("refs=%v any=%v, want map[A:true]/true", refs, any)
	}
}
