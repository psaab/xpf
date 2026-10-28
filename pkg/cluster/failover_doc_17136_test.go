package cluster

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// #17136: ManualFailover's doc comment was orphaned onto FailoverOutcome by
// #8000, so ManualFailover has no godoc and FailoverOutcome's godoc describes
// ManualFailover. These tests parse failover.go with go/parser (comments
// attached to the declaration they immediately precede) rather than grep,
// so only the doc comment actually attached to each symbol counts.

func parseFailoverGo17136(t *testing.T) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "failover.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing failover.go: %v", err)
	}
	return f
}

func funcDoc17136(t *testing.T, f *ast.File, name string) string {
	t.Helper()
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name {
			continue
		}
		if fd.Doc == nil {
			return ""
		}
		return fd.Doc.Text()
	}
	t.Fatalf("func %s not found in failover.go — if it moved, move this test with it; a missing declaration must not silently pass", name)
	return ""
}

func typeDoc17136(t *testing.T, f *ast.File, name string) string {
	t.Helper()
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != name {
				continue
			}
			if ts.Doc != nil {
				return ts.Doc.Text()
			}
			if gd.Doc != nil {
				return gd.Doc.Text()
			}
			return ""
		}
	}
	t.Fatalf("type %s not found in failover.go — if it moved, move this test with it; a missing declaration must not silently pass", name)
	return ""
}

func TestManualFailoverDocComment17136(t *testing.T) {
	doc := funcDoc17136(t, parseFailoverGo17136(t), "ManualFailover")
	if !strings.HasPrefix(doc, "ManualFailover forces a redundancy group to transfer out of primary.") {
		t.Errorf("ManualFailover godoc must start with its transfer-out description; got %q", doc)
	}
	if !strings.Contains(doc, "preserves the group's monitor-derived weight") {
		t.Errorf("ManualFailover godoc must describe preserving monitor-derived weight; got %q", doc)
	}
}

func TestFailoverOutcomeDocComment17136(t *testing.T) {
	doc := typeDoc17136(t, parseFailoverGo17136(t), "FailoverOutcome")
	if !strings.HasPrefix(doc, "FailoverOutcome reports") {
		t.Errorf("FailoverOutcome godoc must begin with %q; got %q", "FailoverOutcome reports", doc)
	}
	if strings.Contains(doc, "ManualFailover forces") {
		t.Errorf("FailoverOutcome godoc must not contain ManualFailover's description; got %q", doc)
	}
}

// Positive control: a neighbouring doc comment that is correct both before
// and after the fix. Proves the parser helpers actually extract attached
// docs, so a clean result above cannot be an artefact of finding nothing.
func TestFailoverDocControl17136(t *testing.T) {
	doc := funcDoc17136(t, parseFailoverGo17136(t), "nextFailoverOwnerLocked")
	if !strings.Contains(doc, "allocates an identity for a failover reservation") {
		t.Errorf("control: nextFailoverOwnerLocked godoc should be found unchanged; got %q", doc)
	}
}
