package cluster

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #13226 (D4-08): RethController/RethMapping/isVirtualRethMAC were dead
// (zero production callers) and HandleStateChange discarded LinkSetUp
// errors. They must not be re-introduced; live RETH helpers must remain.
func TestRethDeadCodeRemoved13226(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "reth.go", nil, 0)
	if err != nil {
		t.Fatalf("parse reth.go: %v", err)
	}
	dead := map[string]bool{
		"RethController": true, "RethMapping": true, "NewRethController": true,
		"IsVirtualRethMAC": true,
	}
	live := map[string]bool{
		"RethMAC": false, "StableRethLinkLocal": false, "IsStableRethLinkLocal": false,
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok && dead[ts.Name.Name] {
					t.Errorf("dead type %s still declared in reth.go (#13226)", ts.Name.Name)
				}
			}
		case *ast.FuncDecl:
			if dead[d.Name.Name] {
				t.Errorf("dead func %s still declared in reth.go (#13226)", d.Name.Name)
			}
			if _, ok := live[d.Name.Name]; ok {
				live[d.Name.Name] = true
			}
			// Methods on the dead controller.
			if d.Recv != nil && len(d.Recv.List) > 0 {
				if star, ok := d.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok && dead[id.Name] {
						t.Errorf("dead method %s on %s still declared (#13226)", d.Name.Name, id.Name)
					}
				}
			}
		}
	}
	for name, found := range live {
		if !found {
			t.Errorf("live helper %s missing from reth.go", name)
		}
	}
}
