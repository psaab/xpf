package showaudit

import (
	"go/ast"
	"go/parser"
	"os"
	"strings"
	"testing"
)

// #17710 / #16659 acceptance: deleting writeInterfacesDetail's
// ZoneQuarantineExcludedReason call must turn that renderer into a census
// finding. Its collection reads live in exempt helpers (interfaceZoneMap and
// allInterfaceNames), so direct-range admission silently omitted the renderer
// before this regression.
func TestInterfaceDetailQualifierDeletionRedsCensus17710(t *testing.T) {
	pkg := parsePackage(t, "pkg/api")
	key := "writeInterfacesDetail"
	rec := pkg.funcs[key]
	if rec == nil {
		t.Fatalf("pkg/api no longer declares %s; update the #17710 regression", key)
	}
	f := families[7] // security zone: Security.Zones / ZoneIDs
	id, member, annotated := surfaceEntry(pkg, key, "pkg/api", f)
	if !member {
		t.Fatalf("control: %s is absent from the security-zone census; "+
			"the census does not follow collection reads through helpers", id)
	}
	if !annotated {
		t.Fatalf("control: %s is unannotated before mutation; the qualifier "+
			"is not recognized by the census", id)
	}

	original, err := os.ReadFile(rec.file)
	if err != nil {
		t.Fatalf("read %s: %v", rec.file, err)
	}
	const qualifier = `config.ZoneQuarantineExcludedReason(zone, cfg) != ""`
	if strings.Count(string(original), qualifier) != 1 {
		t.Fatalf("expected exactly one qualifier expression in %s; found %d",
			rec.file, strings.Count(string(original), qualifier))
	}
	mutated := strings.Replace(string(original), qualifier, "false", 1)
	mutatedFile, err := parser.ParseFile(pkg.fset, rec.file, mutated, 0)
	if err != nil {
		t.Fatalf("parse in-memory qualifier deletion: %v", err)
	}
	var mutatedRenderer *ast.FuncDecl
	for _, decl := range mutatedFile.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok && fd.Name.Name == key {
			mutatedRenderer = fd
			break
		}
	}
	if mutatedRenderer == nil {
		t.Fatalf("mutation no longer contains %s", key)
	}

	// Reuse the real package census with only the target renderer replaced by
	// its in-memory mutation; no source file is written or changed by this test.
	mutatedPkg := &parsedPkg{
		dir:   pkg.dir,
		fset:  pkg.fset,
		funcs: make(map[string]*fnRec, len(pkg.funcs)),
		order: append([]string(nil), pkg.order...),
	}
	for name, fn := range pkg.funcs {
		mutatedPkg.funcs[name] = fn
	}
	mutatedPkg.funcs[key] = &fnRec{fd: mutatedRenderer, file: rec.file}
	_, member, annotated = surfaceEntry(mutatedPkg, key, "pkg/api", f)
	if !member {
		t.Fatal("mutated renderer disappeared from the census instead of being "+
			"reported unannotated")
	}
	if annotated {
		t.Fatal("deleting ZoneQuarantineExcludedReason did not make "+
			"writeInterfacesDetail an unannotated security-zone census member")
	}
}
