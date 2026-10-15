package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #13227 (D4-09): the legacy all-RG service hooks and the non-snapshot
// DHCP wrappers had zero production callers and were a dual-RA/dual-DHCP
// footgun: applyRethServices applied RA for ALL RGs (ignoring per-RG
// mastership) and enqueued the UNFILTERED DHCP config, bypassing the
// per-RG, snapshot-based path every production caller actually uses.
// They must never come back: no declaration and no call site may exist
// for any of them anywhere in this package.
func TestLegacyAllRGServicesRemoved13227(t *testing.T) {
	legacy := map[string]bool{
		"applyRethServices":            true,
		"clearRethServices":            true,
		"isAnyRethInstanceMaster":      true,
		"desiredClusterDHCPConfig":     true,
		"filterDHCPConfigForMasterRGs": true,
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && legacy[fn.Name.Name] {
					t.Errorf("legacy dead method %s re-declared at %s",
						fn.Name.Name, fset.Position(fn.Pos()))
				}
			}
		}
	}
}
