package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16171 AST canary: the #4957/#6296 applied marker may be written from
// production daemon code ONLY through the two …UnderSem helpers, except
// for the allowlisted discharge / retry sites below, which deliberately
// keep their own explicitly-gated MarkAppliedDigest calls because they
// settle the policy debt themselves (or, for the #9811 retry, deliberately
// omit the PublishLanded term) immediately before stamping. Folding those
// sites into the PublishLanded gate would change debt-discharge
// semantics, so they are allowlisted BY ENCLOSING FUNCTION NAME — not by
// blanket-forbidding MarkAppliedDigest, which would fail on these
// legitimate sites.
//
// A new direct MarkActiveApplied / MarkAppliedDigest call anywhere else
// (including inside a discharge-named function on a different receiver,
// or a plain function with a colliding name) is a violation: new stamp
// sites must go through stampActiveAppliedIfConvergedUnderSem /
// stampDigestIfConvergedUnderSem so the convergence gate (apply error,
// policy debt, PublishLanded, nil store) cannot be hand-copied wrong —
// the #4957 fail-open re-entered via re-promotion (#9175) is the
// historical instance of that class.

// stampHelperFuncs are the ONLY functions allowed to call
// Store.MarkActiveApplied / Store.MarkAppliedDigest directly besides the
// allowlisted discharge sites.
var stampHelperFuncs = map[string]bool{
	"stampActiveAppliedIfConvergedUnderSem": true,
	"stampDigestIfConvergedUnderSem":        true,
}

// stampDischargeAllowlist names, by enclosing *Daemon method, the
// deliberate direct-MarkAppliedDigest sites that must NOT be folded into
// the PublishLanded gate.
var stampDischargeAllowlist = map[string]bool{
	// dischargePolicyInvalidationDebtLocked nils the debt itself at the
	// stamp (daemon_policy_invalidate_capture.go).
	"dischargePolicyInvalidationDebtLocked": true,
	// completeDeferredSnapshotApply gates on debt==nil itself; the
	// deferred publication callback is the publish-landed proof.
	"completeDeferredSnapshotApply": true,
	// resolveDeferredSnapshotApplyAfterSynchronousPublish runs only from
	// applyConfigLocked's synchronous-publish defer.
	"resolveDeferredSnapshotApplyAfterSynchronousPublish": true,
	// retirePolicyInvalidationScanDebtAfterFullClearLocked nils the debt
	// itself immediately before stamping (daemon_dp_live.go).
	"retirePolicyInvalidationScanDebtAfterFullClearLocked": true,
	// reassertConfigApplyOnce (#9811 retry) captures the digest under
	// applySem and deliberately omits PublishLanded: applyConfigLocked
	// has already settled publication by the time the retry stamps.
	"reassertConfigApplyOnce": true,
}

func stampCanaryViolations(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(root, name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		type fnSpan struct {
			name      string
			body      *ast.BlockStmt
			isDaemonM bool
		}
		var fns []fnSpan
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				span := fnSpan{name: fn.Name.Name, body: fn.Body}
				if fn.Recv != nil && len(fn.Recv.List) == 1 {
					if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
						if id, ok := star.X.(*ast.Ident); ok && id.Name == "Daemon" {
							span.isDaemonM = true
						}
					}
				}
				fns = append(fns, span)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "MarkActiveApplied" && sel.Sel.Name != "MarkAppliedDigest") {
				return true
			}
			enclosing := "<file scope>"
			allowed := false
			for _, fn := range fns {
				if fn.body.Pos() <= sel.Pos() && sel.Pos() < fn.body.End() {
					enclosing = fn.name
					allowed = fn.isDaemonM &&
						(stampHelperFuncs[fn.name] || stampDischargeAllowlist[fn.name])
					break
				}
			}
			if !allowed {
				pos := fset.Position(sel.Pos())
				violations = append(violations,
					name+":"+pos.String()+" calls ."+sel.Sel.Name+" outside the …UnderSem helpers / allowlisted discharge sites (in "+enclosing+")")
			}
			return true
		})
	}
	return violations
}

func TestAppliedStampCanary16171(t *testing.T) {
	t.Parallel()
	if violations := stampCanaryViolations(t, "."); len(violations) > 0 {
		t.Fatalf("direct applied-marker stamps outside the #16171 helpers/allowlist:\n%s",
			strings.Join(violations, "\n"))
	}
}

func TestAppliedStampCanary16171SelfTest(t *testing.T) {
	t.Parallel()

	clean := `package daemon

type fakeStore struct{}

func (fakeStore) MarkActiveApplied()          {}
func (fakeStore) MarkAppliedDigest(string)    {}

type Daemon struct{ store *fakeStore }

func (d *Daemon) stampActiveAppliedIfConvergedUnderSem(err error) bool {
	d.store.MarkActiveApplied()
	return true
}

func (d *Daemon) dischargePolicyInvalidationDebtLocked(a, b int) error {
	d.store.MarkAppliedDigest("x")
	return nil
}
`
	bypass := clean + `
func (d *Daemon) sneaky() {
	d.store.MarkActiveApplied()
}
`
	collision := clean + `
type other struct{ store *fakeStore }

func (o other) dischargePolicyInvalidationDebtLocked() {
	o.store.MarkAppliedDigest("x")
}
`

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("write clean fixture: %v", err)
	}
	if violations := stampCanaryViolations(t, dir); len(violations) > 0 {
		t.Fatalf("helper+allowlist fixture reported violations: %v", violations)
	}
	if err := os.WriteFile(filepath.Join(dir, "bypass.go"), []byte(bypass), 0o644); err != nil {
		t.Fatalf("write bypass fixture: %v", err)
	}
	violations := stampCanaryViolations(t, dir)
	if len(violations) != 1 || !strings.Contains(violations[0], "sneaky") {
		t.Fatalf("bypass fixture violations = %v, want exactly one naming sneaky", violations)
	}

	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "clean.go"), []byte(clean), 0o644); err != nil {
		t.Fatalf("write clean fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "collision.go"), []byte(collision), 0o644); err != nil {
		t.Fatalf("write collision fixture: %v", err)
	}
	violations2 := stampCanaryViolations(t, dir2)
	if len(violations2) != 1 || !strings.Contains(violations2[0], "collision.go") {
		t.Fatalf("type-collision fixture violations = %v, want exactly one in collision.go", violations2)
	}
}
