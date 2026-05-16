package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func TestUserspaceManagerBPFShimDebtMatchesSplitPlan(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "manager.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse manager.go: %v", err)
	}

	var hasEmbeddedDataPlane bool
	var hasInnerDataplaneManager bool
	ast.Inspect(file, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Manager" {
			return true
		}
		st, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			t.Fatalf("Manager is %T, want struct", typeSpec.Type)
		}
		for _, field := range st.Fields.List {
			switch exprString(field.Type) {
			case "dataplane.DataPlane":
				if len(field.Names) == 0 {
					hasEmbeddedDataPlane = true
				}
			case "*dataplane.Manager":
				for _, name := range field.Names {
					if name.Name == "inner" {
						hasInnerDataplaneManager = true
					}
				}
			}
		}
		return false
	})

	if !hasEmbeddedDataPlane {
		t.Fatal("userspace Manager no longer embeds dataplane.DataPlane; invert this scaffold canary as part of #1381")
	}
	if !hasInnerDataplaneManager {
		t.Fatal("userspace Manager no longer has inner *dataplane.Manager; invert this scaffold canary as part of #1381")
	}
}

func exprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(e.X)
	default:
		return ""
	}
}
