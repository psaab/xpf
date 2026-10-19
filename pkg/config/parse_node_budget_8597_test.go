package config

import (
	"runtime"
	"strings"
	"testing"
)

// #8597 (muse-004 K14) — the parser retained an unbounded AST.
//
// #5827 capped the retained DIAGNOSTICS and said so precisely: "only the
// parser's RETENTION is capped". The tree was not capped, and a VALID-syntax
// payload produces zero diagnostics, so it sails past that cap by construction.
//
// Measured before the fix (runtime.MemStats.HeapAlloc after GC, tree alive):
//
//	stmts=10000   live heap 1,824,960   -> 182 B/statement
//	stmts=100000  live heap 18,589,296  -> 185 B/statement
//	stmts=500000  live heap 92,647,960  -> 185 B/statement
//
// Linear. The 16 MiB MaxConfigSize ceiling admits ~5.6M minimal statements and
// about a GIGABYTE of live AST, built before any gate runs — on entry points
// that take untrusted input. configstore.CheckText validates a day-0
// config-drive blob on first boot with no operator involved.
//
// Neither existing cap covers it: maxParseDepth bounds STACK and a flat
// `a;a;a;...` payload never nests; the group-expansion budget runs after the
// tree already exists.

// parseHeap parses n minimal statements and returns the live heap the tree
// retains, the node count, and the parse errors.
func parseHeap(t *testing.T, n int) (heap uint64, nodes int, errs []ParseError) {
	t.Helper()
	text := strings.Repeat("a;\n", n)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	p := NewParser(text)
	tree, e := p.Parse()
	runtime.GC()
	runtime.ReadMemStats(&after)
	h := after.HeapAlloc - before.HeapAlloc
	nodes = len(tree.Children)
	runtime.KeepAlive(tree)
	return h, nodes, e
}

// TestParseHeapDoesNotScalePastTheBudget_8597 is the RED-on-revert core, and it
// measures the property rather than the mechanism: quadrupling the input past
// the cap must not change the retained heap.
//
// Asserting "the node count is capped" alone would pass a fix that capped the
// slice while still building and discarding the nodes. What matters is the LIVE
// heap after the parse returns.
func TestParseHeapDoesNotScalePastTheBudget_8597(t *testing.T) {
	atCap, nodesAt, errsAt := parseHeap(t, maxParseNodes+50_000)
	wayPast, nodesPast, errsPast := parseHeap(t, 4*maxParseNodes)

	// #15195: the budget now charges 1+len(Keys) per statement, so the
	// minimal `a;` statement costs 2 units and the tree stops at
	// maxParseNodes/2 nodes. The invariant is that BOTH sizes stop at the
	// SAME bounded count, not the pre-#15195 exact node count.
	if nodesAt != maxParseNodes/2 || nodesPast != maxParseNodes/2 {
		t.Fatalf("node counts %d and %d; both must stop at the %d budget "+
			"(%d single-key statements)", nodesAt, nodesPast, maxParseNodes, maxParseNodes/2)
	}
	if len(errsAt) == 0 || len(errsPast) == 0 {
		t.Fatal("a truncated parse MUST report an error: a truncated tree with no " +
			"diagnostic is silently accepted as the whole configuration")
	}
	// 4x the input, and the retained heap must not follow. A wide margin: this
	// is a ratio between two real measurements, so it carries GC noise.
	if wayPast > atCap*2 {
		t.Fatalf("4x the input retained %d bytes vs %d (%.2fx): the AST is still "+
			"proportional to the payload, so a 16 MiB config-drive blob still builds "+
			"~1 GB of live heap before any gate runs (#8597/K14)",
			wayPast, atCap, float64(wayPast)/float64(atCap))
	}
}

// TestParseHeapProbeCanSeeUnboundedGrowth_8597 is the POSITIVE CONTROL for the
// cell above. A ratio near 1.0 is also what a probe that measures nothing
// returns. This measures the same two sizes BELOW the cap, where growth is
// still linear and must be visible.
func TestParseHeapProbeCanSeeUnboundedGrowth_8597(t *testing.T) {
	// #15195: each `a;` costs 2 budget units (node + its one key), so the
	// below-budget sizes are halved to stay under maxParseNodes units.
	small, nSmall, _ := parseHeap(t, 10_000)
	large, nLarge, _ := parseHeap(t, 80_000)
	if nSmall != 10_000 || nLarge != 80_000 {
		t.Fatalf("both fixtures must be BELOW the %d budget so growth is unbounded "+
			"here; got %d and %d nodes", maxParseNodes, nSmall, nLarge)
	}
	if large < small*4 {
		t.Fatalf("8x the input retained %d vs %d (%.2fx): the probe cannot see linear "+
			"growth even where it exists, so the bounded assertion above proves nothing",
			large, small, float64(large)/float64(small))
	}
}

// TestBudgetErrorSurvivesTheDiagnosticCap_8597 is the interaction the two caps
// have with each other, and the one a naive implementation gets wrong.
//
// A hostile payload can exhaust maxParseErrors (64) AND the node budget. If the
// budget diagnostic went through addError it would be dropped as the 65th, and
// the caller would receive a TRUNCATED tree whose error list says nothing about
// truncation — a silently shortened configuration. It is appended directly, for
// the same reason #5827's suppressed-count summary is.
func TestBudgetErrorSurvivesTheDiagnosticCap_8597(t *testing.T) {
	// Enough invalid tokens to exhaust maxParseErrors, then enough valid
	// statements to exhaust maxParseNodes.
	//
	// The invalid tokens are stray BYTES, not unterminated strings. The first
	// draft of this cell used `"unterminated` lines, which produce ZERO parse
	// errors — the cell passed, and the mutation that routes the budget
	// diagnostic through the capped addError ESCAPED it. Measured: a run of
	// 0x01 bytes yields 64 errors plus the #5827 suppressed summary, which is
	// the state this cell needs.
	var b strings.Builder
	for i := 0; i < maxParseErrors+50; i++ {
		b.WriteString("\x01\n")
	}
	b.WriteString(strings.Repeat("a;\n", maxParseNodes+1000))

	p := NewParser(b.String())
	tree, errs := p.Parse()

	if len(tree.Children) > maxParseNodes {
		t.Fatalf("tree has %d nodes, above the %d budget", len(tree.Children), maxParseNodes)
	}
	// Non-vacuity: the diagnostic cap must actually be exhausted, or this cell
	// is testing an uncapped error list and the direct append is doing nothing.
	var suppressed bool
	for _, e := range errs {
		if strings.Contains(e.Message, "suppressed") {
			suppressed = true
		}
	}
	if !suppressed {
		t.Fatalf("the fixture did not exhaust the %d-error retention cap (errors=%d): "+
			"this cell is about what happens WHEN it is exhausted, so without that it "+
			"proves nothing", maxParseErrors, len(errs))
	}

	var found bool
	for _, e := range errs {
		if strings.Contains(e.Message, "parse budget") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the node-budget diagnostic was dropped by the %d-error retention cap; "+
			"the caller gets a truncated tree and no error saying it was truncated. "+
			"errors=%d", maxParseErrors, len(errs))
	}
}

// TestRealConfigurationsAreFarBelowTheBudget_8597 is the OVER-BROAD control and
// the justification for the number.
//
// A cap chosen against the 16 MiB input ceiling rather than against real
// configurations would be useless (16 MiB of `a;` IS 5.6M nodes). This pins the
// other side: the largest configuration in this repository must remain orders
// of magnitude below the budget, so the cap can never reject a real config.
func TestRealConfigurationsAreFarBelowTheBudget_8597(t *testing.T) {
	// A generously oversized stand-in for a real configuration: ten times the
	// statement count of the largest .conf in the tree (test/incus/xpf-test.conf,
	// ~250 statements), with nesting, must parse clean.
	var b strings.Builder
	for i := 0; i < 2500; i++ {
		b.WriteString("interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }\n")
	}
	p := NewParser(b.String())
	tree, errs := p.Parse()
	for _, e := range errs {
		if strings.Contains(e.Message, "parse budget") {
			t.Fatalf("a configuration 10x the largest one in this repository hit the "+
				"%d-statement budget; the cap must be chosen against real configurations, "+
				"not against the input ceiling", maxParseNodes)
		}
	}
	if len(tree.Children) == 0 {
		t.Fatal("fixture parsed to nothing")
	}
}

// TestNestedStatementsCountTowardTheBudget_8597: the counter is parser-wide,
// not per-block. A per-block counter would let a payload of many small blocks
// build an unbounded tree while no single block exceeded anything.
func TestNestedStatementsCountTowardTheBudget_8597(t *testing.T) {
	// Each line is 4 nested statements; well past the budget in total.
	var b strings.Builder
	for i := 0; i < maxParseNodes; i++ {
		b.WriteString("a { b { c; } }\n")
	}
	p := NewParser(b.String())
	_, errs := p.Parse()
	var found bool
	for _, e := range errs {
		if strings.Contains(e.Message, "parse budget") {
			found = true
		}
	}
	if !found {
		t.Fatal("a payload of many small NESTED blocks did not hit the budget: the " +
			"counter must be parser-wide, or a per-block cap bounds nothing")
	}
}
