package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"testing"
)

// occupancyReportingSurfaces are the files that RENDER source-NAT pool
// occupancy to an operator or to monitoring. Each must take its number from
// the helper's live status; none may read the legacy `nat_port_counters` map.
//
// Paths are repo-relative from this package.
var occupancyReportingSurfaces = []string{
	"../../grpcapi/server_nat.go",
	"../../cli/cli_show_nat.go",
	"../../api/nat.go",
	"../../api/metrics_nat.go",
}

// TestOccupancyReportingSurfacesDoNotReadTheLegacyPortCounter is the
// fail-on-revert guard for #8606.
//
// THE DEFECT. `Manager.SeedNATPortCounters` seeds `nat_port_counters` with
// `rand.Uint64()` -- deliberately, so a restarted daemon does not re-issue
// ports a peer still holds. The eBPF programs that advanced that cursor were
// deleted in #1476, so on the only runtime forwarding path the product has,
// reading the map returns the random seed unmodified. Four surfaces reported
// it as pool occupancy; on the gRPC path it converted through an unchecked
// `int64(cnt)` and saturated to `math.MinInt32`, rendering
// "Ports allocated: -2147483648".
//
// WHY A CONTENT SCAN RATHER THAN A BEHAVIOURAL CELL. The failure is a surface
// reading the WRONG SOURCE, and every wrong source returns a plausible
// `uint64`. A behavioural cell that stubs the dataplane cannot tell the two
// sources apart -- it sees whichever number the stub was told to return. What
// distinguishes them is which call the code makes, which is a property of the
// source. A value cell is still owed and lives below; it catches a broken
// conversion, not a re-adopted source.
func TestOccupancyReportingSurfacesDoNotReadTheLegacyPortCounter(t *testing.T) {
	// BOTH spellings that reach the map, because there are two.
	//
	// `Manager.ReadNATPortCounter` is the map read. `Telemetry.NATPortCounter`
	// (`pkg/dataplane/apply.go:490`) is a thin wrapper that returns
	// `t.dp.ReadNATPortCounter(poolID)`, and it is the spelling the gRPC
	// surface used. An earlier revision of this guard banned only the first
	// name; a mutation re-adopting the counter through the WRAPPER escaped it
	// cleanly. Defining the banned set by one call name was a claim that the
	// name is the only route to the behaviour, and it was false -- the
	// falsifier for a call is a wrapper.
	banned := map[string]bool{
		"ReadNATPortCounter": true,
		"NATPortCounter":     true,
	}

	// Parsed, not grepped. A literal scan matches the method name inside
	// COMMENTS -- and one of these files legitimately discusses the legacy
	// counter in prose (#2938 recorded there that it is dead under the AF_XDP
	// dataplane). A guard that a correct file cannot satisfy without deleting
	// accurate documentation is mis-specified; the check is on CALL
	// EXPRESSIONS, which is what the property is actually about.
	for _, rel := range occupancyReportingSurfaces {
		path := filepath.Clean(rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			// A moved or renamed surface must FAIL here, not silently drop out
			// of the scanned set. A guard whose subject list can go stale
			// without complaint stops guarding while still passing.
			t.Fatalf("occupancy reporting surface %s did not parse: %v -- if it moved, update occupancyReportingSurfaces", rel, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || !banned[sel.Sel.Name] {
				return true
			}
			t.Errorf("%s:%d calls %s. That map is a rand.Uint64() seed with no writer since "+
				"#1476; reporting it as pool occupancy is what #8606 fixed. Take the number "+
				"from SourceNATPoolOccupancy(status) instead.",
				rel, fset.Position(call.Pos()).Line, sel.Sel.Name)
			return true
		})
	}
}

// TestOccupancyReportingSurfacesActuallyUseTheSharedHelper is the POSITIVE
// CONTROL for the guard above.
//
// Without it, the absence check passes trivially for a file that no longer
// reports occupancy at all -- including one emptied by a bad refactor, or a
// path that silently stopped matching. Asserting the replacement is PRESENT is
// what makes the absence meaningful: the pair says "this surface reports
// occupancy, and it reports it from the right source", where the ban alone
// only says "not from the wrong one".
func TestOccupancyReportingSurfacesActuallyUseTheSharedHelper(t *testing.T) {
	// Accepted spellings of "reaches the shared occupancy source": the helper
	// itself, each package's thin accessor for it.
	wired := map[string]bool{
		"SourceNATPoolOccupancy": true,
		"sourceNATPoolOccupancy": true,
		"runtimeSourceNATPools":  true,
	}

	// AST, for the same reason the ban above is AST -- and this half learned it
	// the harder way. An earlier revision asserted the helper's NAME appeared
	// in the file text. A mutation that stripped every call but left the
	// accessor's doc comment referring to it PASSED: the control was satisfied
	// by a MENTION, so it certified wiring that was no longer there. A control
	// weaker than the guard it protects silently stops protecting it.
	for _, rel := range occupancyReportingSurfaces {
		path := filepath.Clean(rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("occupancy reporting surface %s did not parse: %v", rel, err)
		}
		found := false
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || !wired[sel.Sel.Name] {
				return true
			}
			found = true
			return false
		})
		if !found {
			t.Errorf("%s makes no CALL reaching the shared occupancy source (one of %v). "+
				"Either it stopped reporting occupancy -- in which case remove it from "+
				"occupancyReportingSurfaces deliberately -- or the #8606 wiring was lost.",
				rel, occupancyWiredNames(wired))
		}
	}
}

// TestSourceNATPoolOccupancyDedupsByPoolNameAndNeverSums pins the contract the
// four surfaces now share.
//
// Rules referencing one pool share a single Arc<PortAllocatorShared> in the
// helper and therefore report IDENTICAL UsedPorts. Summing across rules
// multiplies occupancy by the number of referencing rules, which is the defect
// the dedup exists to prevent -- so the fixture deliberately carries two rules
// on one pool with the SAME UsedPorts, the shape where a sum is silently wrong
// rather than obviously wrong.
func TestSourceNATPoolOccupancyDedupsByPoolNameAndNeverSums(t *testing.T) {
	st := ProcessStatus{
		SourceNATPools: []SourceNATPoolStatus{
			{PoolName: "p1", RuleName: "r1", UsedPorts: 700},
			{PoolName: "p1", RuleName: "r2", UsedPorts: 700},
			{PoolName: "p2", RuleName: "r3", UsedPorts: 5},
			{PoolName: "", RuleName: "r4", UsedPorts: 999},
		},
	}

	got := SourceNATPoolOccupancy(st)

	if len(got) != 2 {
		t.Fatalf("want 2 pools after dedup, got %d: %+v", len(got), got)
	}
	if got["p1"].UsedPorts != 700 {
		t.Errorf("p1 UsedPorts = %d, want 700 (a sum would give 1400 -- rules sharing a pool "+
			"share one allocator and report the same number)", got["p1"].UsedPorts)
	}
	if got["p2"].UsedPorts != 5 {
		t.Errorf("p2 UsedPorts = %d, want 5", got["p2"].UsedPorts)
	}
	if _, ok := got[""]; ok {
		t.Error("an unnamed pool was indexed; it cannot be correlated with a config pool")
	}
}

// TestSourceNATPoolOccupancyEmptyStatusIsNilNotZero separates "no measurement"
// from "measured zero".
//
// The distinction is the whole point of #8606: a surface that cannot tell them
// apart renders a fabricated healthy reading for a pool nobody measured, which
// is what the random seed was doing in a less obvious way.
func TestSourceNATPoolOccupancyEmptyStatusIsNilNotZero(t *testing.T) {
	if got := SourceNATPoolOccupancy(ProcessStatus{}); got != nil {
		t.Errorf("empty status must yield a nil map so callers can distinguish "+
			"'no measurement' from 'measured zero'; got %+v", got)
	}
	if got := SourceNATPoolOccupancy(ProcessStatus{
		SourceNATPools: []SourceNATPoolStatus{{PoolName: "p1", UsedPorts: 0}},
	}); got == nil || len(got) != 1 {
		t.Fatalf("a reported pool with zero used ports IS a measurement and must be present; got %+v", got)
	}
}

func occupancyWiredNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// #9902 F-026: the reporting surfaces share AppliedNATView's constructed-
// first contract — a poisoned rule's MaxTrackedFlows==0 row must not shadow
// the live allocator's row on `show`/API while the alarm evaluates the live
// one. Both orders (first-wins takes the poisoned row when it sorts first).
func TestSourceNATPoolOccupancySelectsConstructed9902(t *testing.T) {
	healthy := SourceNATPoolStatus{
		PoolName: "p1", RuleName: "good",
		AddressCount: 1, PortLow: 1, PortHigh: 100,
		UsedPorts: 50, MaxTrackedFlows: 90,
		LiveFlows: 43, PersistentLeases: 13,
	}
	poisoned := SourceNATPoolStatus{PoolName: "p1", RuleName: "bad"}
	for _, tc := range []struct {
		name string
		rows []SourceNATPoolStatus
	}{
		{"poisoned-first", []SourceNATPoolStatus{poisoned, healthy}},
		{"healthy-first", []SourceNATPoolStatus{healthy, poisoned}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SourceNATPoolOccupancy(ProcessStatus{SourceNATPools: tc.rows})
			if len(got) != 1 {
				t.Fatalf("expected 1 deduped pool, got %d", len(got))
			}
			if got["p1"].UsedPorts != 50 {
				t.Fatalf("constructed row must win, got %+v", got["p1"])
			}
			if p := got["p1"]; p.LiveFlows != 43 || p.MaxTrackedFlows != 90 || p.PersistentLeases != 13 {
				t.Fatalf("constructed row's flow leg must survive dedup, got %+v", p)
			}
		})
	}
}
