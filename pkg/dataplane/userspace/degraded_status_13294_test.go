package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/cilium/ebpf"
)

func TestRecordHelperStatusProjectsDegradedPathCounters13294(t *testing.T) {
	m := New()
	stats, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: uint32(len(degradedPathReasonNames)),
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new degraded-path stats map", err)
	}
	t.Cleanup(func() { _ = stats.Close() })
	injectShimMap(t, m.bpfShim, mapNameUserspaceShimDegradedStats, stats)

	perCPU := make([]uint64, ebpf.MustPossibleCPU())
	perCPU[0] = 7
	if len(perCPU) > 1 {
		perCPU[1] = 11
	}
	if err := stats.Update(uint32(15), perCPU, ebpf.UpdateAny); err != nil {
		skipIfBPFMapUnavailable(t, "seed degraded-path stats map", err)
	}

	var status ProcessStatus
	m.recordHelperStatusLocked(&status)
	if got, want := status.DegradedPathCounters["transit_drop"], uint64(7+11); got != want {
		t.Fatalf("DegradedPathCounters[transit_drop] = %d, want %d; manager status must project the pinned XDP counter map", got, want)
	}
}

func TestRecordHelperStatusContainsDegradedPathProjection13294(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "manager_status.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := ""
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "recordHelperStatusLocked" {
			fn = f.Name.Name
			ast.Inspect(f.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
					return true
				}
				lhs, ok := as.Lhs[0].(*ast.SelectorExpr)
				if !ok || lhs.Sel.Name != "DegradedPathCounters" {
					return true
				}
				rhs, ok := as.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := rhs.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "readDegradedPathStatsLocked" {
					fn = "projection-present"
				}
				return true
			})
		}
	}
	if fn != "projection-present" {
		t.Fatal("recordHelperStatusLocked must project readDegradedPathStatsLocked into ProcessStatus.DegradedPathCounters")
	}
}
