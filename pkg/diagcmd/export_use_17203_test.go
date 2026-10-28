package diagcmd_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestAllExportedDiagBudgetSymbolsAreUsed17203 pins the #17203
// consolidation: every exported budget/exec symbol diagcmd declares
// for the shared implementation must have at least one real caller
// outside this package's own tests. An unused export is how the
// pre-fix tree hid the defect — diagcmd.PingExecTimeout existed and
// looked shared while no server called it — so a future
// re-duplication that leaves a diagcmd export orphaned reds here
// even before the duplicate formula itself is noticed.
func TestAllExportedDiagBudgetSymbolsAreUsed17203(t *testing.T) {
	// The budget/exec surface this issue consolidated. Kept explicit
	// (not "every export in the package") so unrelated diagcmd
	// exports with in-package-only use do not churn this list.
	// Only the entry points are listed: the tuning constants
	// (PingPacketInterval, PingExecSlack, …) are inputs to
	// PingExecTimeout inside this package, so their "use" is the
	// function itself — orphaned constants cannot be detected this
	// way and are instead pinned by TestPingExecTimeoutTable17203.
	want := []string{
		"TracerouteTimeout",
		"RequestExecTimeout", "RequestExecWaitDelay",
		"PingExecTimeout", "ClampDiagTimeout", "PingClientTimeout",
		"RunTimeout", "OutputTimeout", "CombinedOutputTimeout",
	}

	// Repository root is three directories above pkg/diagcmd.
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip the package under test's own test files' package
			// and VCS metadata; production and other packages' tests
			// count as real use.
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Dir(path) == filepath.Join(root, "pkg", "diagcmd") {
			return nil // diagcmd's own definitions are not use
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "diagcmd" {
					used[sel.Sel.Name] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	var orphaned []string
	for _, name := range want {
		if !used[name] {
			orphaned = append(orphaned, name)
		}
	}
	sort.Strings(orphaned)
	for _, name := range orphaned {
		t.Errorf("diagcmd.%s has no production caller outside pkg/diagcmd — "+
			"an orphaned shared budget is the #17203 defect shape; wire the "+
			"servers to it or remove the export", name)
	}
}
