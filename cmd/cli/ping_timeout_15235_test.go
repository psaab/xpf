package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestRemotePingTimeoutCoversCount100_15235 is the A51-02 regression at
// the remote-CLI surface: the deadline derived from the parsed count
// must cover the 115s server budget for count 100 (pre-fix: 60s).
func TestRemotePingTimeoutCoversCount100_15235(t *testing.T) {
	// Source guard: handlePing must derive deadline via PingClientTimeout, not 60s.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "handlePing" {
			continue
		}
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "PingClientTimeout" {
					found = true
				}
				// literal 60s WithTimeout in handlePing is the bug
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithTimeout" {
					for _, a := range call.Args {
						if bin, ok := a.(*ast.BinaryExpr); ok {
							if lit, ok := bin.X.(*ast.BasicLit); ok && lit.Value == "60" {
								t.Fatal("handlePing still uses 60s deadline")
							}
						}
					}
				}
			}
			return true
		})
		if !found {
			t.Fatal("handlePing does not use diagcmd.PingClientTimeout")
		}
		return
	}
	t.Fatal("handlePing not found")
}
