package daemon

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// osidentImportPath is the ONE package whose Current() may decide the console's
// RBAC class. The check below resolves the call's package qualifier to this
// path; it does not compare it to the spelling "osident".
const osidentImportPath = "github.com/psaab/xpf/pkg/osident"

// loginClassWiring is one production call to applyCLILoginClass, with the
// question this file exists to ask already answered: is the identity it decides
// about the one the KERNEL reports?
type loginClassWiring struct {
	pos      string
	identity string // the third argument, rendered
	direct   bool   // ... and is it a call to the REAL osident.Current?
}

// applyCLILoginClassWiring returns every call to applyCLILoginClass in f.
//
// DIRECTNESS IS THE WHOLE PREDICATE, and it is deliberately strict: the third
// argument must be a zero-argument call to `Current` on a qualifier that BINDS
// to package osident, written at the call site. A variable that happens to hold
// Current()'s result does not count, because a variable can be reassigned
// between the two lines and this analysis cannot see it — the same strictness
// pkg/cli's analyzeFuncClassWrite applies to the class argument, for the same
// reason. If a future refactor genuinely wants a local, it must move
// applyCLILoginClass's identity handling rather than widen this.
func applyCLILoginClassWiring(fset *token.FileSet, f *ast.File, bind *qualifierBinding) []loginClassWiring {
	var out []loginClassWiring
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "applyCLILoginClass" {
			return true
		}
		w := loginClassWiring{pos: fset.Position(call.Pos()).String(), identity: "<no third argument>"}
		if len(call.Args) == 3 {
			w.identity = renderNode(fset, call.Args[2])
			w.direct = isOsidentCurrentCall(call.Args[2], bind)
		}
		out = append(out, w)
		return true
	})
	return out
}

// isOsidentCurrentCall reports whether expr is a call to the REAL
// osident.Current — the identifier before the dot must BIND to an import of
// osidentImportPath, not merely be spelled like one.
//
// WHY THE BINDING AND NOT THE SPELLING. A spelling check is satisfied by a
// local of the same name. This compiles, vets clean, hands a forged uid 0 to
// the RBAC resolver — #6701 restored in full — and passed every #6701/#6706
// canary at the previous head (#6706 review r8 F5, reproduced firsthand):
//
//	import kernelident "github.com/psaab/xpf/pkg/osident"
//	osident := struct{ Current func() kernelident.Identity }{
//		Current: func() kernelident.Identity {
//			return kernelident.Identity{UID: 0, Name: "root"}
//		},
//	}
//	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())
//
// Exactly one syntactically counted call site; argument three rendering
// literally as `osident.Current()`. Resolving the qualifier also makes the
// check CORRECT in the other direction: a genuine aliased import of the real
// package is accepted, where the spelling check would have rejected it for the
// wrong reason.
func isOsidentCurrentCall(expr ast.Expr, bind *qualifierBinding) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Current" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return bind.bindsToOsident(pkg)
}

// qualifierBinding answers what a package qualifier binds to, using go/types —
// the toolchain's own scope resolution rather than a re-implementation of it.
type qualifierBinding struct {
	uses map[*ast.Ident]types.Object
}

// bindsToOsident reports whether id resolves to an import of the real
// pkg/osident. An identifier go/types could not resolve at all returns false:
// on an unanswerable question this guard fires rather than falls silent, and
// because `direct` is what the test REQUIRES, an unresolved qualifier reds.
func (b *qualifierBinding) bindsToOsident(id *ast.Ident) bool {
	pkgName, ok := b.uses[id].(*types.PkgName)
	return ok && pkgName.Imported().Path() == osidentImportPath
}

// bindQualifiers type-checks files as one package and records what every
// identifier use resolves to.
//
// IT TYPE-CHECKS AGAINST STUB IMPORTS. Every imported package is fabricated
// empty, so the check emits thousands of soft errors and learns nothing about
// any other package's contents. That is deliberate and sufficient: the only
// question asked of it is which OBJECT a package qualifier binds to, and
// go/types records that before it looks the member up (Checker.selector calls
// recordUse on the qualifier as soon as it finds a PkgName in scope). Loading
// pkg/daemon's dependencies for real would mean a package loader and a build of
// the whole tree; this is stdlib-only and runs in ~120ms over 69 files.
//
// Soft errors are therefore expected and ignored. What is NOT tolerated is the
// checker declining to resolve anything at all — see the anti-vacuity floor in
// TestConsoleLoginClassIsWiredToOsidentCurrent_6706.
func bindQualifiers(fset *token.FileSet, files []*ast.File) *qualifierBinding {
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	cfg := &types.Config{
		Importer: stubImporter{},
		Error:    func(error) {}, // collect and continue; see above
	}
	_, _ = cfg.Check("daemon", fset, files, info)
	return &qualifierBinding{uses: info.Uses}
}

// stubImporter fabricates an empty package for every import path, so that
// go/types can build file scopes without any dependency being available.
//
// The package NAME it guesses is the last path element, which is what the
// default import name would be for every package in this tree. A guess that is
// wrong for some third-party path can only misname THAT package's qualifier;
// it cannot make a local variable look like an import of osidentImportPath,
// because bindsToOsident checks the resolved import PATH.
type stubImporter struct{}

func (stubImporter) Import(path string) (*types.Package, error) {
	name := path[strings.LastIndex(path, "/")+1:]
	if dot := strings.Index(name, "."); dot > 0 {
		name = name[:dot] // gopkg.in/yaml.v3 -> yaml
	}
	pkg := types.NewPackage(path, name)
	pkg.MarkComplete()
	return pkg, nil
}

func renderNode(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

// parsePackageDir parses every non-test .go file in dir, ignoring build
// constraints. That is the fail-closed direction: a second, build-tagged wiring
// line must not be able to hide from the scan.
func parsePackageDir(t *testing.T, dir string) (*token.FileSet, []*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package directory %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files = append(files, f)
	}
	return fset, files
}

// TestConsoleLoginClassIsWiredToOsidentCurrent_6706 binds the ONE production
// line that decides WHOSE identity the console's RBAC class is computed from.
//
// WHY IT EXISTS. Every other guard around #6701 sits either side of this line.
// pkg/osident's adoption canary requires pkg/daemon to CONTAIN an
// osident.Current() call — it says so itself, and says it cannot see which
// value reaches the decision. pkg/daemon's behavioural tests pin what
// applyCLILoginClass does with the Identity it is HANDED. Between them sits the
// argument at the call site, and it was bound by nothing: replacing
//
//	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())
//
// with
//
//	_ = osident.Current() // decoy, kept only to satisfy the adoption canary
//	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Identity{UID: 0, Name: "root"})
//
// hands ClassRootDefault (super-user) to every console caller — #6701 restored
// in full — and gave `go build ./...` rc 0, `go vet ./...` rc 0 and
// `go test ./pkg/cli/... ./pkg/osident/... ./pkg/daemon/...` rc 0 (#6706 review
// r7 F4, reproduced firsthand before this test was written).
//
// The disclosure of that gap already existed, in pkg/osident's adoption canary.
// A reader of daemon_run.go got no signal from it; this test is in the package
// whose line it is about.
//
// SCOPE, stated rather than implied. It scans EVERY non-test .go file in this
// directory, ignoring build constraints. That is the fail-closed direction: a
// second, build-tagged wiring line must not be able to hide from it.
// applyCLILoginClass is package-private, so this directory is the complete set
// of places that can call it, and the scan is not a sample.
//
// FAIL-ON-REVERT: pass anything but a call to the REAL osident.Current() as the
// identity, or add a second call site, and this names the file, the line and
// the argument. Shadowing the qualifier with a local of the same name — which
// the previous, spelling-based revision accepted — reds too (r8 F5).
func TestConsoleLoginClassIsWiredToOsidentCurrent_6706(t *testing.T) {
	fset, files := parsePackageDir(t, ".")
	bind := bindQualifiers(fset, files)

	// ANTI-VACUITY FLOOR FOR THE BINDER. `direct` is what this test requires,
	// so a binder that resolved nothing would red rather than pass — but it
	// would red with a message about the wiring, blaming the wrong thing. A
	// binder that resolves nothing is a broken test, not a broken call site,
	// and it should say so.
	if len(bind.uses) == 0 {
		t.Fatal("go/types resolved no identifier uses in package daemon — the qualifier binding " +
			"is not answering, so it cannot be distinguishing an import from a local")
	}

	var sites []loginClassWiring
	for _, f := range files {
		sites = append(sites, applyCLILoginClassWiring(fset, f, bind)...)
	}

	if len(sites) == 0 {
		t.Fatalf("no production call to applyCLILoginClass in %d files — either the console's "+
			"RBAC class is no longer wired at all, or this scan is not reaching the source it "+
			"claims to check", len(files))
	}
	// #16071: exactly TWO sites — the startup resolution in
	// daemon_run.go and the consoleClassRefresher callback that
	// re-resolves on `system login` change. Both must hand the
	// resolver the kernel identity directly.
	if len(sites) != 2 {
		var where []string
		for _, s := range sites {
			where = append(where, s.pos)
		}
		sort.Strings(where)
		t.Errorf("applyCLILoginClass is called from %d places (%s) — want exactly 2 "+
			"(startup + #16071 refresher); a third site is a third policy",
			len(sites), strings.Join(where, ", "))
	}
	for _, s := range sites {
		if strings.HasSuffix(s.pos, "cli_rbac.go") || strings.Contains(s.pos, "cli_rbac.go:") {
			// #16071 refresher: identity arrives as the `id` parameter
			// consoleClassRefresher captured at wiring time from
			// osident.Current() in daemon_run.go; the directness of
			// THAT capture is pinned by the daemon_run.go site below
			// plus the requirement that both sites exist.
			if s.identity != "id" {
				t.Errorf("%s: refresher applyCLILoginClass receives identity %s, want the captured `id` parameter", s.pos, s.identity)
			}
			continue
		}
		if !s.direct {
			t.Errorf("%s: applyCLILoginClass receives identity %s, which is not a call to the "+
				"package at %s — the RBAC class must be decided about the caller the KERNEL "+
				"reports, and a fabricated, indirect or same-named-but-shadowed identity here "+
				"restores #6701 while every other test stays green", s.pos, s.identity, osidentImportPath)
		}
	}
}

// TestLoginClassWiringPredicateRejectsEveryFabrication_6706 proves the
// predicate above discriminates rather than merely matching the current source.
//
// It runs the REAL predicate — and the REAL binder — over the shapes a rewrite
// of that line could take, including the exact decoys the review used, and
// requires exactly the correct ones to be accepted.
//
// The last three cases are the ones that make this more than a spelling test.
// `aliasedImport` and `shadowedQualifier` differ ONLY in what the qualifier
// binds to: one is the real package under another name, the other is a local
// under the package's name. A predicate that reads identifiers cannot tell them
// apart, and gets both answers wrong in opposite directions.
func TestLoginClassWiringPredicateRejectsEveryFabrication_6706(t *testing.T) {
	const src = `package daemon

import (
	"github.com/psaab/xpf/pkg/osident"
	kernelident "github.com/psaab/xpf/pkg/osident"
	shadow "example.com/notosident"
)

func correct(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())
}

func fabricatedLiteral(shell userClassSetter, d *Daemon) {
	_ = osident.Current()
	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Identity{UID: 0, Name: "root"})
}

func viaLocal(shell userClassSetter, d *Daemon) {
	id := osident.Current()
	id.Name = "root"
	applyCLILoginClass(shell, d.store.ActiveConfig(), id)
}

func wrapped(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), promote(osident.Current()))
}

func wrongPackage(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), shadow.Current())
}

func wrongArity(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig())
}

func aliasedImport(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), kernelident.Current())
}

func shadowedQualifier(shell userClassSetter, d *Daemon) {
	osident := struct {
		Current func() kernelident.Identity
	}{
		Current: func() kernelident.Identity {
			return kernelident.Identity{UID: 0, Name: "root"}
		},
	}
	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())
}

func shadowedByParameter(shell userClassSetter, d *Daemon, osident forger) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	bind := bindQualifiers(fset, []*ast.File{f})
	got := applyCLILoginClassWiring(fset, f, bind)

	want := []struct {
		identity string
		direct   bool
		why      string
	}{
		{"osident.Current()", true, "the kernel credential, read at the call site"},
		{`osident.Identity{UID: 0, Name: "root"}`, false, "the review's decoy: super-user for everyone"},
		{"id", false, "a local that Current() seeded and a later line rewrote"},
		{"promote(osident.Current())", false, "Current()'s result, transformed"},
		{"shadow.Current()", false, "a same-named Current in another package"},
		{"<no third argument>", false, "not the identity-taking signature at all"},
		{"kernelident.Current()", true, "the REAL package under another name — a spelling check rejects this for the wrong reason"},
		{"osident.Current()", false, "r8 F5: the package's NAME, bound to a local that forges uid 0"},
		{"osident.Current()", false, "the same forgery arriving as a parameter"},
	}
	if len(got) != len(want) {
		t.Fatalf("predicate found %d call sites, want %d — it is not seeing the calls it judges",
			len(got), len(want))
	}
	for i, w := range want {
		if got[i].identity != w.identity || got[i].direct != w.direct {
			t.Errorf("call site %d: identity=%q direct=%v, want identity=%q direct=%v — %s",
				i, got[i].identity, got[i].direct, w.identity, w.direct, w.why)
		}
	}

	// The three cases that render IDENTICALLY must not have identical verdicts,
	// or the predicate is still reading the identifier rather than resolving it.
	if got[0].direct == got[7].direct {
		t.Errorf("the real call and the shadowed forgery both render as %q and both got direct=%v "+
			"— the predicate is not resolving the qualifier's binding at all",
			got[0].identity, got[0].direct)
	}
}
