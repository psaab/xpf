package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestUserspaceManagerDoesNotEmbedLegacyDataPlane(t *testing.T) {
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

	if hasEmbeddedDataPlane {
		t.Fatal("userspace Manager must not embed dataplane.DataPlane; use LegacyDataPlaneAdapter for old callers")
	}
	if !hasInnerDataplaneManager {
		t.Fatal("userspace Manager no longer has inner *dataplane.Manager; update #1381 docs and remove this remaining-debt canary")
	}
}

func TestUserspaceManagerRuntimeContractDoesNotExposeLegacyDataPlane(t *testing.T) {
	t.Parallel()

	var manager any = &Manager{}
	if _, ok := manager.(dataplane.DataPlane); ok {
		t.Fatal("userspace Manager unexpectedly implements legacy dataplane.DataPlane")
	}
	if _, ok := manager.(dataplane.RuntimeDataPlane); !ok {
		t.Fatal("userspace Manager does not implement dataplane.RuntimeDataPlane")
	}

	var adapter any = NewLegacyDataPlaneAdapter(New())
	if _, ok := adapter.(dataplane.DataPlane); !ok {
		t.Fatal("LegacyDataPlaneAdapter does not implement dataplane.DataPlane")
	}
	if _, ok := adapter.(dataplane.RuntimeDataPlane); !ok {
		t.Fatal("LegacyDataPlaneAdapter does not implement dataplane.RuntimeDataPlane")
	}
}

func TestUserspaceBackendRegistryReturnsLegacyAdapter(t *testing.T) {
	t.Parallel()

	dp, err := dataplane.NewDataPlane(dataplane.TypeUserspace)
	if err != nil {
		t.Fatalf("NewDataPlane(userspace): %v", err)
	}
	if _, ok := any(dp).(*LegacyDataPlaneAdapter); !ok {
		t.Fatalf("NewDataPlane(userspace) = %T, want *LegacyDataPlaneAdapter", dp)
	}
	if _, ok := any(dp).(*Manager); ok {
		t.Fatal("NewDataPlane(userspace) returned *Manager directly")
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
