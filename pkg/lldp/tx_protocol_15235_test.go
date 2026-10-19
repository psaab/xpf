package lldp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestLLDPTxProtocolNotGlobalTap15235 is the A51-04 regression: the TX
// socket must not be created with ETH_P_ALL. An unbound ETH_P_ALL
// AF_PACKET socket is a global tap (/proc/net/packet type 0003).
// AST-only so it compiles and assert-fails on the pre-fix tree.
func TestLLDPTxProtocolNotGlobalTap15235(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "lldp.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "newIfSession" {
			continue
		}
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Socket" {
				return true
			}
			for _, a := range call.Args {
				if id, ok := a.(*ast.Ident); ok && id.Name == "txProtocol" {
					found = true
				}
				if s, ok := a.(*ast.SelectorExpr); ok && s.Sel.Name == "ETH_P_ALL" {
					t.Fatal("newIfSession still creates a socket with ETH_P_ALL")
				}
			}
			return true
		})
		if !found {
			t.Fatal("newIfSession does not pass txProtocol to Socket")
		}
		return
	}
	t.Fatal("newIfSession not found")
}
