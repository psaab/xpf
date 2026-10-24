package cli

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// allowedSetUserClassCallers is the receiver-aware allowlist of production
// functions permitted to call CLI.SetUserClass, keyed `<pkg-relpath>::[Recv.]func`
// (mirrors the pkg/linuxsock and pkg/fsatomic canary keys).
//
// SetUserClass is the ONE write to the RBAC class, and #6701 was a bad value
// reaching it. The fail-closed default therefore only holds while every write
// goes through the resolver: a second call site that computed its own class —
// from `$USER`, from a gRPC-supplied name, or from a "default to super-user"
// convenience — would reopen the hole without touching any of the code the
// other tests cover.
//
// That premise — "SetUserClass is the ONE write" — is itself now CHECKED, by
// allowedClassFieldWriters below, rather than asserted here and taken on trust.
// It was true but unbound: both canaries key on the SELECTOR name, `userClass`
// is package-private, and pkg/cli is exactly where the command handlers live,
// so `func (c *CLI) zzPromote() { c.userClass = "super-user" }` in this package
// gave build rc 0, vet rc 0 and every canary plus the whole pkg/cli and
// pkg/daemon suites green (#6706 review r7 F3, reproduced firsthand).
var allowedSetUserClassCallers = map[string]string{
	"daemon::applyCLILoginClass":    "the single #6701 resolution site (cli.ResolveLoginClass + osident.Current)",
	"daemon::consoleClassRefresher": "the #16071 re-resolution callback: delegates resolution to applyCLILoginClass, and clears to unset only when `system login` is absent",
}

// classFieldName is the private CLI field that HOLDS the RBAC class.
// SetUserClass writes it; permissions.go reads it. Reads are not writes and are
// not flagged.
const classFieldName = "userClass"

// classHolderType is the type that OWNS that field. Replacing a whole CLI value
// writes userClass along with every other field while never naming it, so the
// whole-object arms of classFieldWrites key on this name rather than on
// classFieldName.
const classHolderType = "CLI"

// allowedClassFieldWriters is the allowlist of production functions permitted
// to write `<x>.userClass` DIRECTLY, keyed like allowedSetUserClassCallers.
//
// It is the check behind the sentence above. Exactly one entry is correct: the
// setter itself. Anything else in pkg/cli can reach the field without touching
// SetUserClass at all, which is #6701 reached by a route the selector-name
// canaries cannot see.
var allowedClassFieldWriters = map[string]string{
	"cli::CLI.SetUserClass": "the setter itself (pkg/cli/cli.go) — the one write to the field",
}

// requiredSetUserClassCallers and requiredClassFieldWriters are the entries the
// allowlists above MUST CONTAIN.
//
// They are the anti-vacuity floor for the allowlists themselves, and they bind
// the dimension they protect — the specific entries — rather than a total. The
// stale-entry loop in the test asks only "is every allowlisted key still seen?",
// which an EMPTY map satisfies vacuously; nothing else noticed the difference
// between an allowlist that permits one thing and an allowlist that permits
// nothing because it is describing nothing. That is not a hypothetical gap:
// combined with a write form the detector could not see, emptying the map is a
// two-line mutation that left the whole test green while the RBAC class was
// written from an unallowlisted place (#6706 review r8 F4).
//
// FAIL-ON-REVERT: empty either map, or rename its entry without renaming the
// function, and the test reds here — independently of whether the write
// detector is working, which is the point of stating the requirement separately
// from the map.
var (
	requiredSetUserClassCallers = []string{"daemon::applyCLILoginClass", "daemon::consoleClassRefresher"}
	requiredClassFieldWriters   = []string{"cli::CLI.SetUserClass"}
)

// TestSetUserClassHasOneProductionCaller_6701 enumerates every production call
// to SetUserClass across the repository — AND every direct write to the field
// it sets — and requires each to be allowlisted.
//
// The two halves answer two different questions. The SetUserClass half bounds
// who may invoke the setter. The field half bounds the premise that invoking
// the setter is the only way the class changes; without it, the whole
// selector-keyed apparatus is bypassable from inside pkg/cli by one assignment
// (#6706 review r7 F3).
//
// FAIL-ON-REVERT: add a `shell.SetUserClass("super-user")` anywhere else, or a
// `c.userClass = "super-user"` outside the setter — the exact shape of the
// #6701 defect, by either route — and this test names the file and line and
// goes RED.
//
// Method note: both halves check on the SELECTOR name, so they catch the write
// regardless of the receiver variable's name or type inference. A same-named
// method or field on an unrelated type would be a false positive; there is none
// today, and a false positive here is a prompt to think rather than a silent
// pass.
func TestSetUserClassHasOneProductionCaller_6701(t *testing.T) {
	type call struct{ key, pos string }
	var unexpected, unexpectedField []call
	seen := map[string]bool{}
	seenField := map[string]bool{}
	scanned := map[string]bool{}
	var filesScanned int

	// PRE-PASS: collect every struct field declared *CLI across the whole
	// production tree before looking for writes. A field is declared in one
	// file and may be dereferenced in another, so a per-file collection would
	// leave `*a.cli = CLI{}` invisible whenever the struct lives elsewhere
	// (#6706 review r10 F2).
	holderFields := map[string]bool{}
	for _, root := range productionRoots(t) {
		err := walkCanaryFiles(root, func(path string) {
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return
			}
			holderPointerFieldNames(f, holderFields)
		})
		if err != nil {
			t.Fatalf("walk %s (holder-field pre-pass): %v", root, err)
		}
	}
	if len(holderFields) == 0 {
		t.Fatalf("the *CLI field pre-pass found nothing — three such fields exist " +
			"(cli_show_chassis.go, monitor_interface.go, completion.go), so an empty set " +
			"means the collector or the walk stopped seeing them and the `*a.cli = CLI{}` " +
			"arm is silently disabled")
	}

	for _, root := range productionRoots(t) {
		err := walkCanaryFiles(root, func(path string) {
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return
			}
			filesScanned++
			scanned[relKeyFor(root, path)] = true

			for _, ref := range setUserClassRefs(fset, f, pkgRelKeyFor(path)) {
				seen[ref.key] = true
				if _, allowed := allowedSetUserClassCallers[ref.key]; !allowed {
					unexpected = append(unexpected, call{key: ref.key, pos: ref.pos})
				}
			}
			for _, ref := range classFieldWrites(fset, f, pkgRelKeyFor(path), holderFields) {
				seenField[ref.key] = true
				if _, allowed := allowedClassFieldWriters[ref.key]; !allowed {
					unexpectedField = append(unexpectedField, call{key: ref.key, pos: ref.pos})
				}
			}
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	requireTraversalSentinels(t, scanned, filesScanned)

	for _, c := range unexpected {
		t.Errorf("%s (%s) calls SetUserClass but is not allowlisted — every RBAC class write must "+
			"go through cli.ResolveLoginClass so the fail-closed default cannot be bypassed (#6701)",
			c.key, c.pos)
	}
	for _, c := range unexpectedField {
		t.Errorf("%s (%s) writes the %s field directly — the RBAC class must change only through "+
			"SetUserClass, or every guard keyed on that selector is bypassable from inside "+
			"pkg/cli (#6701)", c.key, c.pos, classFieldName)
	}

	// The allowlists must CONTAIN what they are supposed to permit. An emptied
	// allowlist contradicts nothing below and is the half of a green-staying
	// mutation (#6706 review r8 F4); see requiredSetUserClassCallers.
	for _, key := range requiredSetUserClassCallers {
		if _, ok := allowedSetUserClassCallers[key]; !ok {
			t.Errorf("allowedSetUserClassCallers has no entry for %s — an allowlist that permits "+
				"nothing is not a tightened allowlist, it is a check that has stopped describing "+
				"the code it guards (#6701)", key)
		}
	}
	for _, key := range requiredClassFieldWriters {
		if _, ok := allowedClassFieldWriters[key]; !ok {
			t.Errorf("allowedClassFieldWriters has no entry for %s — the setter must be the one "+
				"permitted writer of %s, and an empty allowlist asserts nothing about that (#6701)",
				key, classFieldName)
		}
	}

	// The allowlists must not rot into lists of functions that no longer exist:
	// a stale entry would silently permit a future function of the same name.
	var stale []string
	for key := range allowedSetUserClassCallers {
		if !seen[key] {
			stale = append(stale, key+" (SetUserClass caller)")
		}
	}
	for key := range allowedClassFieldWriters {
		if !seenField[key] {
			stale = append(stale, key+" ("+classFieldName+" writer)")
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("allowlisted %s makes no such write — remove the stale entry, or the walk that "+
			"was supposed to see it is not reaching the source", key)
	}
}

// packageLevelKey is the attribution for a SetUserClass reference that is not
// inside any function — a package-level `var x = shell.SetUserClass`. It is
// deliberately not a valid Go identifier, so it can never collide with a
// funcKeyFor result and can never be spelled in allowedSetUserClassCallers.
const packageLevelKey = "<package-level declaration>"

// classRef is one production reference to SetUserClass, attributed to the
// top-level declaration that encloses it.
type classRef struct{ key, pos string }

// setUserClassRefs is THE allowlist predicate: every SetUserClass reference in
// f, keyed by the TOP-LEVEL DECLARATION that encloses it. Both the repository
// walk and the synthetic controls below call it, so breaking it reds the
// controls rather than leaving them proving something about a copy (the same
// vacuity #6706 MINOR-3 fixed for pkg/osident's canary).
//
// WHY IT ITERATES f.Decls INSTEAD OF TRACKING A RUNNING `enclosing`. The
// previous version set `enclosing` on entering an *ast.FuncDecl during a single
// ast.Inspect over the whole file and NEVER CLEARED IT. ast.Inspect visits
// File.Decls in source order, so a *ast.GenDecl appearing after a FuncDecl was
// attributed to that function. Appending
//
//	var zzRogueSetter = zzRogueShell.SetUserClass
//	func zzBoot() { zzRogueSetter("super-user") }
//
// to pkg/daemon/cli_rbac.go — after the one allowlisted function — inherited the
// key `daemon::applyCLILoginClass` and was SILENTLY ALLOWLISTED: build rc 0, vet
// rc 0, both canaries ok. The identical declaration in a file of its own reds,
// which isolates the cause to the carry-over rather than to the declaration form
// (#6706 review r5 F3). The escape landed in the one file the allowlist exists
// to fence, and the sibling dataflow canary cannot cover for it —
// analyzeClassWrites iterates f.Decls for *ast.FuncDecl only, so a GenDecl is
// invisible to it.
//
// Keying on the enclosing decl makes an unattributed reference unattributable to
// an allowlisted key by construction, rather than by remembering to reset a
// variable.
func setUserClassRefs(fset *token.FileSet, f *ast.File, pkgRel string) []classRef {
	var out []classRef
	for _, decl := range f.Decls {
		key := pkgRel + "::" + packageLevelKey
		if fn, ok := decl.(*ast.FuncDecl); ok {
			key = funcKeyFor(pkgRel, fn)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			// A SetUserClass selector in ANY position — called, or taken as a
			// method value (`f := shell.SetUserClass`). The method-value form is
			// a class write too, and matching only CallExpr.Fun let it walk
			// straight past this allowlist (#6706 MINOR-4).
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetUserClass" {
				return true
			}
			out = append(out, classRef{key: key, pos: fset.Position(sel.Pos()).String()})
			return true
		})
	}
	return out
}

// classFieldWrites is THE field-write predicate: every production WRITE to
// `<x>.userClass` in f, keyed by the enclosing top-level declaration exactly as
// setUserClassRefs keys its results. Both the repository walk and the synthetic
// control below call it, so breaking it reds the control rather than leaving it
// proving something about a copy.
//
// WHAT COUNTS AS A WRITE, and why each form is here rather than only the
// obvious one:
//
//   - `c.userClass = x` — assignment, including `:=` and the multi-value forms;
//     every LHS element is checked, so `a, c.userClass = 1, "super-user"` is
//     caught.
//   - `&c.userClass` — taking the address hands the field to code this file
//     cannot follow, which is the same escape analyzeFuncClassWrite already
//     treats a method VALUE of SetUserClass as.
//   - `CLI{userClass: "super-user"}` — a composite literal constructs the field
//     without ever assigning to it.
//   - `for c.userClass = range xs` — legal Go, and an assignment the AssignStmt
//     arm does not see because RangeStmt carries its own Key/Value.
//   - `c.userClass++` — IncDecStmt is not an AssignStmt. Illegal on today's
//     string field and legal the moment the class becomes an ordinal, which is
//     the wrong time to discover the arm is missing.
//   - `(c.userClass) = x` — the assignment LHS is an *ast.ParenExpr, so a
//     predicate that accepts only a bare *ast.SelectorExpr records ZERO writes
//     for it. Valid Go, and it was invisible: build rc 0, vet rc 0, every canary
//     green (#6706 review r8 F4, reproduced firsthand).
//   - `*c = CLI{}` — WHOLE-OBJECT assignment through a pointer. It names no
//     field at all and sets userClass to "", which checkPermission and
//     showConfigRedacted both read as the legacy allow-everything mode, so this
//     is the most privileged state the RBAC has. `go vet`'s copylocks blocks the
//     `*c = *other` spelling because CLI holds a sync.Mutex, but not this one,
//     and an incidental fence in another tool is not this canary's coverage.
//   - `CLI{a, b, c}` — a POSITIONAL composite literal supplies every field by
//     position, including userClass, with no KeyValueExpr for the keyed arm to
//     see.
//   - `x.CLI = other` — replacing an embedded CLI. No type embeds CLI today;
//     the arm costs one case and closes the shape rather than waiting for one.
//
// READS ARE NOT WRITES. permissions.go reads c.userClass in both of its
// permission gates (:44,51,53 and :94,97) and must not be flagged, which is why
// this keys on assignment POSITION rather than on the selector appearing at
// all — the difference between this and setUserClassRefs, where a bare
// reference IS the violation because a method value defers the write out of
// sight.
//
// KNOWN LIMITS, named rather than implied, because each round of this PR has
// found one more form and the honest statement is where the enumeration stops:
//
//   - The whole-object arms learn which identifiers point AT a CLI from
//     DECLARED types — holderPointerNames for locals/params/receivers,
//     holderPointerFieldNames for struct FIELDS (#6706 r10 F2) — not from a
//     type-checker. A pointer from an untyped source
//     (`p := somethingReturningStar()`) and a double indirection (`**pp`) are
//     not recognised. The field arm keys on the field NAME with the qualifier
//     ignored, so it over-approximates toward flagging.
//   - A whole-value write into a COLLECTION element — `shells[0] = CLI{}`,
//     `byName[k] = other` — is not recognised: the LHS is an IndexExpr and
//     deciding it needs the element type. There is no `[]CLI`, `[]*CLI` or
//     map-of-CLI anywhere in the tree today (re-grepped at this revision), so
//     no such write exists to catch; a narrower rule keyed on the RHS literal
//     was rejected because partial coverage of a form invites the belief that
//     the form is covered. Note this excuse is about COLLECTIONS specifically —
//     it never covered the *CLI FIELD form, which does exist three times
//     (cli_show_chassis.go, monitor_interface.go, completion.go) and is why
//     that form was reachable and unflagged until r10.
//   - reflect and unsafe are outside any AST predicate.
//
// The arms that exist are the ones a reviewer could plausibly write by hand.
func classFieldWrites(fset *token.FileSet, f *ast.File, pkgRel string, holderFields map[string]bool) []classRef {
	var out []classRef
	for _, decl := range f.Decls {
		key := pkgRel + "::" + packageLevelKey
		if fn, ok := decl.(*ast.FuncDecl); ok {
			key = funcKeyFor(pkgRel, fn)
		}
		holders := holderPointerNames(decl)
		record := func(n ast.Node) {
			out = append(out, classRef{key: key, pos: fset.Position(n.Pos()).String()})
		}
		recordLHS := func(lhs ast.Expr) {
			if isClassFieldSelector(lhs) || isWholeHolderWrite(lhs, holders, holderFields) {
				record(lhs)
			}
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					recordLHS(lhs)
				}
			case *ast.IncDecStmt:
				recordLHS(node.X)
			case *ast.RangeStmt:
				for _, lhs := range []ast.Expr{node.Key, node.Value} {
					if lhs != nil {
						recordLHS(lhs)
					}
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND && isClassFieldSelector(node.X) {
					record(node)
				}
			case *ast.KeyValueExpr:
				if id, ok := unparenExpr(node.Key).(*ast.Ident); ok && id.Name == classFieldName {
					record(node)
				}
			case *ast.CompositeLit:
				if isHolderTypeName(node.Type) && hasPositionalElts(node) {
					record(node)
				}
			}
			return true
		})
	}
	return out
}

// unparenExpr strips redundant parentheses. `(c.userClass) = "super-user"` is
// valid Go whose assignment LHS is an *ast.ParenExpr; without this the write is
// recorded nowhere (#6706 review r8 F4).
func unparenExpr(expr ast.Expr) ast.Expr {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = p.X
	}
}

// isClassFieldSelector reports whether expr is a `<x>.userClass` selector,
// however many parentheses it is wrapped in.
func isClassFieldSelector(expr ast.Expr) bool {
	sel, ok := unparenExpr(expr).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == classFieldName
}

// isWholeHolderWrite reports whether expr, in assignment-LHS position,
// replaces an ENTIRE CLI value — which writes userClass along with every other
// field while naming none of them.
//
// Three shapes: through a local pointer this declaration declares as *CLI
// (`*c = ...`), through a STRUCT FIELD declared *CLI (`*a.cli = ...`), and
// through an embedded CLI field (`x.CLI = ...`).
//
// The field shape (#6706 review r10 F2) was the twelfth escape. The StarExpr
// arm required an *ast.Ident operand, so `*a.cli = CLI{}` — a StarExpr over a
// SelectorExpr — was recorded nowhere, while `a.cli.userClass = ""` at the same
// site through the same field reds. Both leave userClass == "", the most
// privileged state. Demonstrated at a production site (cli_show_chassis.go)
// with that negative control: vet rc 0 and ALL canaries green for the first,
// RED for the second.
//
// holderFields is keyed on the FIELD NAME with the qualifier ignored, the same
// over-approximation every other predicate here makes: `*anything.cli = ...`
// is flagged once any production struct declares a `cli *CLI`. Flagging is the
// safe direction for a canary.
func isWholeHolderWrite(expr ast.Expr, holderPtrs, holderFields map[string]bool) bool {
	switch e := unparenExpr(expr).(type) {
	case *ast.StarExpr:
		switch operand := unparenExpr(e.X).(type) {
		case *ast.Ident:
			return holderPtrs[operand.Name]
		case *ast.SelectorExpr:
			return holderFields[operand.Sel.Name]
		}
		return false
	case *ast.SelectorExpr:
		return e.Sel.Name == classHolderType
	}
	return false
}

// holderPointerFieldNames adds to `into` every STRUCT FIELD name in f whose
// declared type is `*CLI` (or `*<pkg>.CLI`).
//
// Separate from holderPointerNames because the two have different scopes: a
// local pointer is declared inside the decl that writes through it, so that
// collector is per-decl, while a field is declared in a type that any file in
// the tree may write through. The repository walk therefore collects fields in
// a PRE-PASS over every production file before the write pass, rather than
// per-file, so a struct declared in one file and dereferenced in another is
// still recognised.
//
// Three such fields exist today, all named `cli`: pkg/cli/cli_show_chassis.go,
// pkg/cli/monitor_interface.go, pkg/cli/completion.go.
func holderPointerFieldNames(f *ast.File, into map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, field := range st.Fields.List {
			if !isHolderPointerType(field.Type) {
				continue
			}
			for _, name := range field.Names {
				into[name.Name] = true
			}
		}
		return true
	})
}

// holderPointerNames collects the identifiers within decl whose DECLARED type
// is `*CLI` (or `*<pkg>.CLI`): the pointer receiver, the parameters of the
// declaration and of any function literal inside it, and `var p *CLI`.
//
// Collected flatly rather than per-scope. A name shadowed inside an inner block
// is then still treated as a holder, which over-approximates toward FLAGGING —
// the safe direction for a canary, and a false positive here is a prompt to
// think rather than a silent pass.
func holderPointerNames(decl ast.Decl) map[string]bool {
	out := map[string]bool{}
	addFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			if !isHolderPointerType(field.Type) {
				continue
			}
			for _, name := range field.Names {
				out[name.Name] = true
			}
		}
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			addFields(node.Recv)
			if node.Type != nil {
				addFields(node.Type.Params)
			}
		case *ast.FuncLit:
			if node.Type != nil {
				addFields(node.Type.Params)
			}
		case *ast.ValueSpec:
			if isHolderPointerType(node.Type) {
				for _, name := range node.Names {
					out[name.Name] = true
				}
			}
		}
		return true
	})
	return out
}

// isHolderPointerType reports whether expr spells `*CLI` or `*<pkg>.CLI`.
// The qualifier is ignored for the same reason every other predicate in this
// file ignores it: a whole-value assignment through a *cli.CLI from another
// package is legal and writes the private field just as effectively.
func isHolderPointerType(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	return ok && isHolderTypeName(star.X)
}

// isHolderTypeName reports whether expr names the CLI type, bare or qualified.
func isHolderTypeName(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == classHolderType
	case *ast.SelectorExpr:
		return t.Sel.Name == classHolderType
	}
	return false
}

// hasPositionalElts reports whether lit supplies at least one field by
// POSITION. `CLI{}` sets nothing and is not a write; `CLI{userClass: x}` is
// caught by the KeyValueExpr arm; `CLI{a, b, c}` is caught only here.
func hasPositionalElts(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		if _, keyed := elt.(*ast.KeyValueExpr); !keyed {
			return true
		}
	}
	return false
}

// TestClassFieldWriteCanaryDetectsEveryWriteForm_6706 proves classFieldWrites
// is not vacuous and, more to the point, that it discriminates WRITES from
// READS — a predicate that flagged every mention would red on permissions.go
// and be deleted within a week, and one that flagged only `=` would miss three
// forms that reach the field just as well.
//
// It runs the REAL predicate, not a copy.
//
// Every form here was once invisible to some revision of the predicate, and
// three rounds of this PR each found exactly one more, so the cases are kept in
// the order they were found and each names what it defeats. The EDGE cases —
// double parentheses, a parenthesised deref — exist because a fix aimed at one
// spelling of a form is not a fix for the form.
// ROLE: CHECKER CONTROL, not production coverage — it runs the analyzer over a SYNTHETIC file, never over this repository
// (#6706 review r11). It proves the PREDICATE discriminates; it cannot
// observe a change to pkg/daemon or cmd/cli. Exactly two tests in this file
// are repository-facing: TestSetUserClassHasOneProductionCaller_6701 and
// TestSetUserClassCallersResolveThroughTheSharedResolver_6701. Counting the
// controls as production coverage overstates this file by a factor of three.
func TestClassFieldWriteCanaryDetectsEveryWriteForm_6706(t *testing.T) {
	const src = `package cli

func (c *CLI) plainAssign() { c.userClass = "super-user" }

func (c *CLI) tupleAssign(n int) { n, c.userClass = 1, "super-user" }

func (c *CLI) addressOf() *string { return &c.userClass }

func (c *CLI) composite() *CLI { return &CLI{userClass: "super-user"} }

func (c *CLI) viaRange(xs []string) {
	for c.userClass = range xs {
	}
}

func (c *CLI) parenAssign() { (c.userClass) = "super-user" }

func (c *CLI) doubleParenAssign() { ((c.userClass)) = "super-user" }

func (c *CLI) incDec() { c.userClass++ }

func (c *CLI) wholeObject() { *c = CLI{} }

func (c *CLI) wholeObjectParen() { (*c) = CLI{} }

func wholeObjectViaParam(c *CLI, other CLI) { *c = other }

func wholeObjectViaVar(other CLI) {
	var p *CLI
	*p = other
}

func (c *CLI) positionalComposite() *CLI { return &CLI{"prompt", "super-user"} }

func (s *superShell) embeddedWhole(other CLI) { s.CLI = other }

type zzHolder struct {
	cli     *CLI
	counter *int
}

func (a *zzHolder) wholeObjectViaField() { *a.cli = CLI{} }

func (a *zzHolder) wholeObjectViaFieldParen() { (*a.cli) = CLI{} }

func wholeObjectViaNestedField(w struct{ inner *zzHolder }) { *w.inner.cli = CLI{} }

func (a *zzHolder) unrelatedFieldDeref(n int) { *a.counter = n }

func (c *CLI) readsOnly() bool { return c.userClass == "" || c.userClass == "super-user" }

func (c *CLI) unrelatedWrite() { c.version = "x" }

func (c *CLI) emptyLiteralOfAnotherType() *other { return &other{} }

func notAHolder(p *string, v string) { *p = v }

var packageLevelSetter = func(c *CLI) { c.userClass = "super-user" }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	// The field set is collected from THIS file by the same collector the
	// repository walk uses, so the control exercises the real pairing rather
	// than a hand-written set that could disagree with production.
	holderFields := map[string]bool{}
	holderPointerFieldNames(f, holderFields)
	if !holderFields["cli"] {
		t.Fatalf("holderPointerFieldNames did not see `cli *CLI` in the synthetic source; "+
			"got %v — the field arm cannot fire and every expectation below is vacuous",
			holderFields)
	}
	if holderFields["counter"] {
		t.Fatalf("holderPointerFieldNames collected `counter *int` as a CLI holder; got %v", holderFields)
	}
	got := map[string]int{}
	for _, ref := range classFieldWrites(fset, f, "cli", holderFields) {
		got[ref.key]++
	}
	want := map[string]struct {
		n   int
		why string
	}{
		"cli::CLI.plainAssign":          {1, "the obvious form"},
		"cli::CLI.tupleAssign":          {1, "every LHS element is checked"},
		"cli::CLI.addressOf":            {1, "the address escapes to code this file cannot follow"},
		"cli::CLI.composite":            {1, "a keyed literal constructs the field without assigning"},
		"cli::CLI.viaRange":             {1, "RangeStmt carries its own Key/Value"},
		"cli::CLI.parenAssign":          {1, "r8 F4: the LHS is an *ast.ParenExpr"},
		"cli::CLI.doubleParenAssign":    {1, "EDGE: one Unparen is not unwrapping"},
		"cli::CLI.incDec":               {1, "IncDecStmt is not an AssignStmt"},
		"cli::CLI.wholeObject":          {1, "r8 F4: whole-object write names no field, and sets the class to the allow-everything empty string"},
		"cli::CLI.wholeObjectParen":     {1, "EDGE: a parenthesised deref is the same write"},
		"cli::wholeObjectViaParam":      {1, "the holder need not be the receiver"},
		"cli::wholeObjectViaVar":        {1, "nor a parameter"},
		"cli::CLI.positionalComposite":  {1, "a POSITIONAL literal sets every field with no KeyValueExpr to see"},
		"cli::superShell.embeddedWhole": {1, "replacing an embedded CLI replaces its class"},
		"cli::zzHolder.wholeObjectViaField": {1, "r10 F2: a StarExpr over a SELECTOR — `*a.cli = CLI{}` " +
			"through a real production *CLI field, which the Ident-only arm recorded nowhere " +
			"while `a.cli.userClass = \"\"` at the same site reds"},
		"cli::zzHolder.wholeObjectViaFieldParen": {1, "EDGE: the parenthesised spelling of the same write"},
		"cli::wholeObjectViaNestedField":         {1, "EDGE: the arm keys on the field NAME, so receiver depth is irrelevant"},
		"cli::" + packageLevelKey:                {1, "a package-level func literal is not inside any FuncDecl"},
	}
	for key, w := range want {
		if got[key] != w.n {
			t.Errorf("classFieldWrites found %d writes in %s, want %d — %s; that write form reaches "+
				"the RBAC class without going through SetUserClass and must not be invisible",
				got[key], key, w.n, w.why)
		}
	}
	mustNotWrite := map[string]string{
		"cli::CLI.readsOnly":                 "reads are not writes — permissions.go is nothing but reads",
		"cli::CLI.unrelatedWrite":            "a different field of the same object",
		"cli::CLI.emptyLiteralOfAnotherType": "an empty literal of an unrelated type sets nothing",
		"cli::notAHolder":                    "a deref of a *string is not a whole-object CLI write",
		"cli::zzHolder.unrelatedFieldDeref": "the NEGATIVE CONTROL for the field arm: `*a.counter = n` " +
			"derefs a *int field on the very struct that also holds the *CLI, so an arm that " +
			"flagged every `*x.y =` LHS rather than only *CLI-typed fields would red here",
	}
	for key, why := range mustNotWrite {
		if got[key] != 0 {
			t.Errorf("classFieldWrites flagged %s (%d times) — %s, and a predicate that says "+
				"otherwise gets deleted rather than fixed", key, got[key], why)
		}
	}
	if len(got) != len(want) {
		t.Errorf("classFieldWrites attributed writes to %v, want exactly %d keys", got, len(want))
	}
}

// classWrite is the per-function result of analyzeClassWrites.
type classWrite struct {
	// writes: the function calls CLI.SetUserClass at least once.
	writes bool
	// resolves: it also calls cli.ResolveLoginClass.
	resolves bool
	// bound: EVERY SetUserClass call receives, as its argument, the identifier
	// that took the resolver's FIRST result. This is the dataflow claim.
	bound bool
	// escapes: SetUserClass is referenced WITHOUT being called (a method value,
	// `f := shell.SetUserClass`). The class write then happens through `f`,
	// where no argument analysis can see it, so the reference is treated as a
	// violation rather than ignored.
	escapes bool
	pos     string
}

// analyzeClassWrites reports, per function in f, how that function writes the
// RBAC login class.
//
// The predicate is DATAFLOW, not co-occurrence. An earlier version asked only
// "does this function mention both names?", which accepted
//
//	_, _ = cli.ResolveLoginClass(login, id) // result discarded
//	shell.SetUserClass("super-user")        // the actual write, unbound
//
// — the resolver called for show and the class supplied from somewhere else,
// which is #6701 with a decoy call in front of it. It also missed
//
//	setClass := shell.SetUserClass
//	setClass("super-user")
//
// entirely, because the write is not a call to a selector named SetUserClass.
// Both are covered now: the first fails `bound`, the second fails `escapes`.
//
// Recognised as bound: `class, reason := cli.ResolveLoginClass(...)` (or the
// package-internal `ResolveLoginClass(...)`) followed by
// `shell.SetUserClass(class)`. Any other argument — a literal, a different
// variable, the blank identifier's neighbour — is unbound. That is deliberately
// strict: an intermediate transformation of the class is exactly the kind of
// re-derivation the canary exists to force into ResolveLoginClass itself.
func analyzeClassWrites(fset *token.FileSet, f *ast.File, pkgRel string) map[string]classWrite {
	out := map[string]classWrite{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		cw := analyzeFuncClassWrite(fn)
		if !cw.writes {
			continue
		}
		// #16071: the refresher delegates to applyCLILoginClass and
		// only clears (empty class) on the no-login arm — accept it
		// as resolver-bound rather than requiring an inline
		// ResolveLoginClass call it must not duplicate.
		if delegatedClassClear16071(fn) {
			cw.resolves = true
			cw.bound = true
		}
		if fset != nil {
			cw.pos = fset.Position(fn.Pos()).String()
		}
		out[funcKeyFor(pkgRel, fn)] = cw
	}
	return out
}

// analyzeFuncClassWrite is the single-function half of analyzeClassWrites,
// shared verbatim by the repository walk and the synthetic discriminator tests
// so the proof is of the SAME predicate the walk applies.
func analyzeFuncClassWrite(fn *ast.FuncDecl) classWrite {
	var cw classWrite
	// Identifiers that hold the resolver's first result, and the position of
	// the assignment that bound each one.
	classVars := map[string]bool{}
	boundAt := map[string]token.Pos{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isResolveLoginClassCall(call) {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			classVars[id.Name] = true
			if prev, seen := boundAt[id.Name]; !seen || assign.Pos() < prev {
				boundAt[id.Name] = assign.Pos()
			}
		}
		return true
	})

	// REBINDING. Holding the resolver's result at some point is not the same
	// as WRITING it, and the difference is the whole claim this canary makes.
	// Measured at the previous head by mutating production directly: inserting
	// `class = "super-user"` between the ResolveLoginClass call and the
	// SetUserClass call in applyCLILoginClass — the #6701 defect restored
	// verbatim — left BOTH repository-facing canaries GREEN, because the
	// argument identifier was still the one the resolver had assigned to
	// (#6706 review r11). Only the behavioural tests caught it, which is
	// exactly the coverage this test exists to be independent of.
	//
	// A non-resolver assignment to a bound identifier, at a position AFTER the
	// assignment that bound it, therefore un-binds it. Position rather than
	// "anywhere" so the legitimate `class := "unauthorized"` pre-initialisation
	// followed by `class, _ = ResolveLoginClass(...)` is not falsely rejected;
	// the discriminator test below pins both directions.
	//
	// LIMIT, named rather than implied: this is textual order, not control
	// flow. A rebinding written textually BEFORE its resolver assignment but
	// executing after it — a loop body that reassigns and then re-resolves —
	// is not caught. Every shape reachable by an ordinary edit to
	// applyCLILoginClass is.
	rebound := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(assign.Rhs) == 1 {
			if call, isCall := assign.Rhs[0].(*ast.CallExpr); isCall && isResolveLoginClassCall(call) {
				return true
			}
		}
		for _, lhs := range assign.Lhs {
			id, isIdent := lhs.(*ast.Ident)
			if !isIdent || !classVars[id.Name] {
				continue
			}
			if at, seen := boundAt[id.Name]; seen && assign.Pos() > at {
				rebound[id.Name] = true
			}
		}
		return true
	})

	// ast.Inspect descends INTO CallExpr.Fun, so an ordinary
	// `shell.SetUserClass(class)` also yields its own SelectorExpr. Record the
	// selectors that are in call position so the method-VALUE check below sees
	// only genuine unattached references.
	calledFuns := map[ast.Expr]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			calledFuns[call.Fun] = true
		}
		return true
	})

	allBound := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isResolveLoginClassCall(node) {
				cw.resolves = true
			}
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetUserClass" {
				return true
			}
			cw.writes = true
			if len(node.Args) != 1 {
				allBound = false
				return true
			}
			arg, ok := node.Args[0].(*ast.Ident)
			if !ok || !classVars[arg.Name] || rebound[arg.Name] {
				allBound = false
			}
		case *ast.SelectorExpr:
			// A SetUserClass selector that is NOT some call's Fun is a method
			// VALUE: the write happens later through the resulting func value,
			// where no argument analysis can follow it.
			if node.Sel.Name == "SetUserClass" && !calledFuns[node] {
				cw.writes = true
				cw.escapes = true
			}
		}
		return true
	})
	cw.bound = allBound
	return cw
}

// delegatedClassClear16071 reports whether fn is the #16071 refresher
// shape: it delegates resolution to applyCLILoginClass and its only
// direct SetUserClass writes an empty class on the no-login arm.
// That write is a TRANSITION to the documented legacy unset mode, not
// an independently derived class, so the shared-resolver canary
// accepts it alongside the applyCLILoginClass delegation. Any non-
// empty literal, or a SetUserClass call not on that arm, fails this.
func delegatedClassClear16071(fn *ast.FuncDecl) bool {
	delegates, clearsOnly := false, true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "applyCLILoginClass" {
			delegates = true
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SetUserClass" {
			return true
		}
		if len(call.Args) != 1 {
			clearsOnly = false
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Value != `""` {
			clearsOnly = false
		}
		return true
	})
	return delegates && clearsOnly
}

// isResolveLoginClassCall matches both `cli.ResolveLoginClass(...)` and the
// package-internal bare `ResolveLoginClass(...)`.
func isResolveLoginClassCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name == "ResolveLoginClass"
	case *ast.Ident:
		return fun.Name == "ResolveLoginClass"
	}
	return false
}

// TestSetUserClassCallersResolveThroughTheSharedResolver_6701 binds every RBAC
// class WRITE to the shared resolver's RETURN VALUE, structurally (#6701
// MINOR-2, tightened for the #6706 review MINOR-4).
//
// The sibling canary above bounds WHO may call SetUserClass. That is necessary
// and not sufficient: the one allowlisted caller could stop calling
// cli.ResolveLoginClass and inline a faithful copy of the resolution logic
// instead. Every behavioural test would still pass — an equivalent copy is
// equivalent, and this was measured, not assumed: mutation M15 inlined exactly
// such a copy into applyCLILoginClass and the WHOLE suite stayed green. The
// policy would then be defined in two places, and the next hardening of
// ResolveLoginClass (a new fail-closed branch, a changed root default) would
// reach only one of them.
//
// What it checks, exactly: for every production function that writes the class,
// (a) it calls ResolveLoginClass, (b) every SetUserClass call takes the
// identifier that received that call's first result, and (c) SetUserClass is
// never referenced as a method value, which would move the write out of view.
//
// This is the same structural binding as pkg/osident's adoption canary, one
// layer up: there the shared thing is the IDENTITY, here it is the POLICY that
// maps that identity onto a class.
//
// FAIL-ON-REVERT: replace the ResolveLoginClass call in applyCLILoginClass with
// an inline equivalent, discard its result and pass a literal, or take a method
// value of SetUserClass INSIDE a function — each names the function and goes
// RED, while the behavioural tests stay green.
//
// One shape this test does NOT catch, named rather than implied: a PACKAGE-LEVEL
// `var f = shell.SetUserClass`. analyzeClassWrites iterates f.Decls for
// *ast.FuncDecl only, so a GenDecl is invisible to it. That escape is caught by
// the sibling allowlist canary above, which attributes such a reference to
// `<pkg>::<package-level declaration>` — a key no allowlist entry can hold. It
// was NOT caught by anything before #6706 review r5 F3.
func TestSetUserClassCallersResolveThroughTheSharedResolver_6701(t *testing.T) {
	writers := map[string]classWrite{}
	scanned := map[string]bool{}
	var filesScanned int

	for _, root := range productionRoots(t) {
		err := walkCanaryFiles(root, func(path string) {
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return
			}
			filesScanned++
			scanned[relKeyFor(root, path)] = true
			for key, cw := range analyzeClassWrites(fset, f, pkgRelKeyFor(path)) {
				writers[key] = cw
			}
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	requireTraversalSentinels(t, scanned, filesScanned)
	if len(writers) == 0 {
		t.Fatal("found no production caller of SetUserClass at all — the walk is not reaching " +
			"the source it claims to check")
	}

	var offenders []string
	for key, cw := range writers {
		switch {
		case cw.escapes:
			offenders = append(offenders, key+" ("+cw.pos+
				"): takes a METHOD VALUE of SetUserClass, so the class write escapes this check")
		case !cw.resolves:
			offenders = append(offenders, key+" ("+cw.pos+
				"): never calls cli.ResolveLoginClass")
		case !cw.bound:
			offenders = append(offenders, key+" ("+cw.pos+
				"): calls SetUserClass with something other than the resolver's result")
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s — the class written must be the VALUE cli.ResolveLoginClass returned, not "+
			"an independently derived one (#6701)", o)
	}
}

// TestSharedResolverCanaryBindsDataflowNotCoOccurrence_6701 proves the
// predicate discriminates, which is the entire reason it is structural.
//
// It runs the SAME analyzer over a set of functions that are deliberately hard
// to tell apart by name-mention alone, and requires exactly the correct one to
// be accepted. The two evasion cases are the ones the #6706 review demonstrated
// against the previous co-occurrence predicate.
// ROLE: CHECKER CONTROL, not production coverage — it runs the analyzer over a SYNTHETIC file, never over this repository
// (#6706 review r11). It proves the PREDICATE discriminates; it cannot
// observe a change to pkg/daemon or cmd/cli. Exactly two tests in this file
// are repository-facing: TestSetUserClassHasOneProductionCaller_6701 and
// TestSetUserClassCallersResolveThroughTheSharedResolver_6701. Counting the
// controls as production coverage overstates this file by a factor of three.
func TestSharedResolverCanaryBindsDataflowNotCoOccurrence_6701(t *testing.T) {
	const src = `package p

func shared(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	shell.SetUserClass(class)
}

func inlinedCopy(shell userClassSetter, login *L, id I) {
	class := "unauthorized"
	for _, u := range login.Users {
		if u != nil && u.Name == id.Name && u.Class != "" {
			class = u.Class
		}
	}
	if id.UID == 0 && class == "unauthorized" {
		class = "super-user"
	}
	shell.SetUserClass(class)
}

func decoyCall(shell userClassSetter, login *L, id I) {
	_, _ = cli.ResolveLoginClass(login, id)
	shell.SetUserClass("super-user")
}

func methodValue(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	_ = class
	setClass := shell.SetUserClass
	setClass("super-user")
}

func reDerived(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	promoted := class
	if id.UID != 0 {
		promoted = "super-user"
	}
	shell.SetUserClass(promoted)
}

func rebindsAfterResolving(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	class = "super-user"
	shell.SetUserClass(class)
}

func rebindsConditionally(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	if id.UID != 0 {
		class = "super-user"
	}
	shell.SetUserClass(class)
}

func preInitialisedThenResolved(shell userClassSetter, login *L, id I) {
	class := "unauthorized"
	class, _ = cli.ResolveLoginClass(login, id)
	shell.SetUserClass(class)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	got := analyzeClassWrites(fset, f, "p")

	type want struct {
		accepted bool
		why      string
	}
	cases := map[string]want{
		"p::shared":      {true, "delegates to the shared resolver and writes its result"},
		"p::inlinedCopy": {false, "inlines a behaviourally identical copy of the policy"},
		"p::decoyCall":   {false, "calls the resolver, DISCARDS it, and writes a literal"},
		"p::methodValue": {false, "writes through a method value the analysis cannot follow"},
		"p::reDerived":   {false, "re-derives the class after the resolver returned"},
		// #6706 review r11. The previous predicate accepted all three of the
		// rows below, because it asked only whether the ARGUMENT IDENTIFIER had
		// ever held the resolver's result. Inserting `class = "super-user"`
		// into applyCLILoginClass — the #6701 defect verbatim — was therefore
		// invisible to this canary, and the LAST row is why the fix is
		// position-aware rather than "any assignment to the name": rejecting a
		// pre-initialisation would have made the predicate reject a perfectly
		// sound shape.
		"p::rebindsAfterResolving": {false,
			"reassigns the bound identifier after the resolver returned"},
		"p::rebindsConditionally": {false,
			"reassigns the bound identifier on one branch after the resolver returned"},
		"p::preInitialisedThenResolved": {true,
			"assigns a placeholder BEFORE resolving, then writes the resolver's result"},
	}
	if len(got) != len(cases) {
		t.Fatalf("analyzer saw %d class writers, want %d: %v", len(got), len(cases), got)
	}
	for key, w := range cases {
		cw, ok := got[key]
		if !ok {
			t.Fatalf("analyzer did not classify %s as a class writer at all", key)
		}
		accepted := cw.resolves && cw.bound && !cw.escapes
		if accepted != w.accepted {
			t.Errorf("%s accepted = %v, want %v — %s (analysis: resolves=%v bound=%v escapes=%v)",
				key, accepted, w.accepted, w.why, cw.resolves, cw.bound, cw.escapes)
		}
	}
}

// pkgRelKeyFor turns a walked path into the package-relative key segment:
// "../daemon/cli_rbac.go" -> "daemon", "../../cmd/cli/main.go" -> "cli".
func pkgRelKeyFor(path string) string {
	return filepath.Base(filepath.Dir(path))
}

// funcKeyFor formats the receiver-aware allowlist key for a FuncDecl.
func funcKeyFor(pkgRel string, fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		if recv := recvTypeNameFor(fn.Recv.List[0].Type); recv != "" {
			return pkgRel + "::" + recv + "." + fn.Name.Name
		}
	}
	return pkgRel + "::" + fn.Name.Name
}

// recvTypeNameFor extracts the receiver type name, stripping a leading '*'.
func recvTypeNameFor(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvTypeNameFor(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvTypeNameFor(t.X)
	case *ast.IndexListExpr:
		return recvTypeNameFor(t.X)
	}
	return ""
}

// TestSetUserClassCanaryDetectsAnUnallowlistedCaller_6701 proves the walker
// above is not vacuous: it runs setUserClassRefs — the very function the walk
// calls, not a copy of it — over a synthetic file that reintroduces the #6701
// default, and requires a hit outside the allowlist.
// ROLE: CHECKER CONTROL, not production coverage — it runs the walker over a SYNTHETIC file, never over this repository
// (#6706 review r11). It proves the PREDICATE discriminates; it cannot
// observe a change to pkg/daemon or cmd/cli. Exactly two tests in this file
// are repository-facing: TestSetUserClassHasOneProductionCaller_6701 and
// TestSetUserClassCallersResolveThroughTheSharedResolver_6701. Counting the
// controls as production coverage overstates this file by a factor of three.
func TestSetUserClassCanaryDetectsAnUnallowlistedCaller_6701(t *testing.T) {
	const src = `package rogue

func boot(shell interface{ SetUserClass(string) }) {
	shell.SetUserClass("super-user")
}

func viaMethodValue(shell interface{ SetUserClass(string) }) {
	setClass := shell.SetUserClass
	setClass("super-user")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var hits []string
	for _, ref := range setUserClassRefs(fset, f, "rogue") {
		if _, allowed := allowedSetUserClassCallers[ref.key]; !allowed {
			hits = append(hits, ref.key)
		}
	}
	sort.Strings(hits)
	want := []string{"rogue::boot", "rogue::viaMethodValue"}
	if len(hits) != len(want) {
		t.Fatalf("synthetic detector found %v, want %v — the canary predicate does not detect "+
			"the defect it claims to guard", hits, want)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Fatalf("synthetic detector found %v, want %v", hits, want)
		}
	}
}

// TestPackageLevelClassWriteIsNotAllowlistedByANeighbour_6701 is the regression
// test for the allowlist BYPASS the #6706 r5 review demonstrated (F3).
//
// The synthetic source is the shape that escaped, reduced: the one allowlisted
// function, followed in the SAME FILE by a package-level method value of
// SetUserClass. With the old running-`enclosing` predicate the var inherited
// `daemon::applyCLILoginClass`, matched the allowlist, and was reported by
// nothing — appended to the real pkg/daemon/cli_rbac.go it gave build rc 0, vet
// rc 0 and both canaries ok.
//
// FAIL-ON-REVERT: key setUserClassRefs on a running `enclosing` variable again
// and this reds — the second reference is attributed to the allowlisted function
// instead of to the package level.
// ROLE: CHECKER CONTROL, not production coverage — it runs the walker over a SYNTHETIC file, never over this repository
// (#6706 review r11). It proves the PREDICATE discriminates; it cannot
// observe a change to pkg/daemon or cmd/cli. Exactly two tests in this file
// are repository-facing: TestSetUserClassHasOneProductionCaller_6701 and
// TestSetUserClassCallersResolveThroughTheSharedResolver_6701. Counting the
// controls as production coverage overstates this file by a factor of three.
func TestPackageLevelClassWriteIsNotAllowlistedByANeighbour_6701(t *testing.T) {
	const src = `package daemon

func applyCLILoginClass(shell userClassSetter, cfg *config.Config, id osident.Identity) {
	class, _ := cli.ResolveLoginClass(cfg.System.Login, id)
	shell.SetUserClass(class)
}

var rogueSetter = rogueShell.SetUserClass

func boot() { rogueSetter("super-user") }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}

	var keys []string
	var unallowlisted []string
	for _, ref := range setUserClassRefs(fset, f, "daemon") {
		keys = append(keys, ref.key)
		if _, allowed := allowedSetUserClassCallers[ref.key]; !allowed {
			unallowlisted = append(unallowlisted, ref.key)
		}
	}
	sort.Strings(keys)

	wantKeys := []string{"daemon::" + packageLevelKey, "daemon::applyCLILoginClass"}
	if len(keys) != len(wantKeys) || keys[0] != wantKeys[0] || keys[1] != wantKeys[1] {
		t.Fatalf("setUserClassRefs attributed %v, want %v — a package-level SetUserClass "+
			"reference must NOT inherit the key of the function declared above it, or the "+
			"allowlist can be bypassed from inside the one file it exists to fence", keys, wantKeys)
	}
	if len(unallowlisted) != 1 || unallowlisted[0] != "daemon::"+packageLevelKey {
		t.Fatalf("unallowlisted references = %v, want exactly [daemon::%s]",
			unallowlisted, packageLevelKey)
	}
}

// productionRoots is the walk root for the #6701 structural canaries: the
// REPOSITORY ROOT, not pkg/ + cmd/.
//
// The previous roots meant a new top-level production package — `internal/`,
// `agent/`, anything a future layout adds — was never scanned, so a
// SetUserClass call there was invisible to both canaries (#6706 MINOR-4). The
// go.mod check makes a wrong relative path a loud failure rather than a silent
// empty walk.
func productionRoots(t *testing.T) []string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %q has no go.mod (%v) — the canary walk root is wrong and "+
			"would scan nothing", root, err)
	}
	return []string{root}
}

// isNestedModuleRoot reports whether path is the root of a NESTED Go module —
// a directory carrying its own go.mod FILE.
//
// `go list ./...` does not descend into these, so a file inside one is not a
// package of the module under test and must not be judged by this canary. The
// walk was widened from pkg/+cmd/ to the module root to close a real gap (a new
// top-level package would otherwise go unscanned), and that widening is what
// made this necessary.
//
// THE !IsDir() TERM IS LOAD-BEARING. cmd/go's own rule (modload/search.go)
// requires a regular file, so a DIRECTORY named `go.mod` is not a module marker
// and `go list ./...` walks straight through it. Without the term,
// `mkdir -p somepkg/go.mod` makes this canary skip a package the toolchain
// genuinely compiles, and a planted violation inside it PASSES (#6706 MINOR-1,
// proven by mutation).
//
// The trigger was NOT an in-tree checkout, as an earlier revision of this
// comment said. `git ls-files | grep go.mod` returns exactly one line, the
// repository root; the nested module is `wt-master/`, an UNTRACKED agent-scratch
// worktree. That is why the skip keys on the go.mod marker rather than a name.
//
// Scope limit: "not in `./...`" is not "does not ship" — a `replace` directive
// would link a nested module into the binary while `go list ./...` still reports
// zero packages for it. Not live today (one tracked go.mod, no replace
// directives), but the reasoning does not extend that far (#6706 MINOR-2).
func isNestedModuleRoot(path string) bool {
	info, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil && !info.IsDir()
}

// walkCanaryFiles is THE traversal rule shared by every #6701 structural
// canary. VERBATIM COPY of pkg/osident's, which is where its reasoning and its
// fixture-tree proof live (TestCanaryWalkRuleMatchesTheToolchain_6706); the two
// packages cannot import each other's test code, and
// TestCanaryTraversalHelpersMatchTheOsidentCopy_6706 below reds if the bodies
// drift apart.
func walkCanaryFiles(root string, visit func(path string)) error {
	// RESOLVE A SYMLINKED ROOT. filepath.WalkDir Lstats its root, so a symlink
	// pointing at the checkout is not a directory to it: the walk visits the
	// link itself, skips it as a non-.go file and reports NOTHING, while
	// `go list ./...` run from that same path reports every package. That is a
	// divergence from cmd/go in the silent direction, which is the one this
	// walk must not have (#6706 review r8 F2). Symlinked SUBdirectories need no
	// such handling: cmd/go does not descend into them either
	// (modload/search.go warns "ignoring symlink" and returns), so
	// filepath.WalkDir's Lstat semantics already match there — verified by
	// planting one and observing `go list ./...` omit it.
	walkRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		walkRoot = resolved
	}
	compiled := map[string]map[string]bool{}
	return filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipCanaryDir(walkRoot, path) {
				return fs.SkipDir
			}
			// Skip NESTED GO MODULES — a directory below the root carrying its
			// own go.mod FILE. See isNestedModuleRoot for why the
			// file-vs-directory distinction is load-bearing rather than
			// pedantic.
			if path != walkRoot && isNestedModuleRoot(path) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if !compiledByGoBuild(compiled, path) {
			return nil
		}
		visit(rebaseCanaryPath(walkRoot, root, path))
		return nil
	})
}

// rebaseCanaryPath re-expresses a path discovered under walkRoot in terms of
// the root the CALLER passed in. VERBATIM COPY of pkg/osident's — see it for
// why a symlinked walk root is a divergence from cmd/go in the silent
// direction (#6706 review r8 F2).
func rebaseCanaryPath(walkRoot, root, path string) string {
	if walkRoot == root {
		return path
	}
	rel, err := filepath.Rel(walkRoot, path)
	if err != nil {
		return path
	}
	return filepath.Join(root, rel)
}

// skipCanaryDir reports directories the canary walks must not descend into,
// modelling cmd/go's own directory rule INCLUDING the part of it that is
// two-phase: `.`/`_`-prefixed and `testdata` directories are skipped before
// they become packages, while a `vendor` directory IS a package and only its
// SUBTREE is pruned (modload/search.go:139-152). VERBATIM COPY of pkg/osident's
// — see it for both escapes this rule has had (an invented `node_modules` skip,
// #6706 review r5 F1; a `vendor` skip that took the directory's own files with
// it, r7 F2).
func skipCanaryDir(root, path string) bool {
	if path == root {
		return false
	}
	name := filepath.Base(path)
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" {
		return true
	}
	parent := filepath.Dir(path)
	return parent != root && filepath.Base(parent) == "vendor"
}

// canaryBuildCtxs are the build contexts a file is offered to; it is scanned if
// EITHER compiles it. VERBATIM COPY of pkg/osident's — see it for why
// build.Default alone answers for the developer's machine rather than for the
// appliance the Makefile builds with CGO_ENABLED=0 (#6706 review r7 F1), why
// the union is preferred to pinning CgoEnabled=false, and which axes remain
// uncovered.
var canaryBuildCtxs = func() [2]build.Context {
	shipped, devel := build.Default, build.Default
	shipped.CgoEnabled = false // Makefile builds xpfd and cli with CGO_ENABLED=0
	devel.CgoEnabled = true
	return [2]build.Context{shipped, devel}
}()

// compiledByGoBuild reports whether the toolchain would compile path into the
// package in its directory, asking go/build ITSELF rather than restating its
// rule, under either of canaryBuildCtxs. VERBATIM COPY of pkg/osident's — see
// it for why the `.go` suffix test alone was not the `./...` rule (#6706 review
// r5 F2), and for why it LOADS the package rather than asking MatchFile, which
// answers a strictly weaker question and scanned a file no configuration
// compiles (r8 F1).
func compiledByGoBuild(cache map[string]map[string]bool, path string) bool {
	dir, name := filepath.Dir(path), filepath.Base(path)
	files, ok := cache[dir]
	if !ok {
		files = compiledFilesInDir(dir)
		cache[dir] = files
	}
	return files[name]
}

// compiledFilesInDir is the per-directory half of compiledByGoBuild. VERBATIM
// COPY of pkg/osident's — see it for why loading the package is not the same
// question as MatchFile, and for the file that MatchFile scanned although no
// toolchain configuration compiles it (#6706 review r8 F1).
func compiledFilesInDir(dir string) map[string]bool {
	out := map[string]bool{}
	for _, ctxt := range canaryBuildCtxs {
		pkg, _ := ctxt.ImportDir(dir, 0)
		if pkg == nil {
			continue
		}
		for _, list := range [][]string{pkg.GoFiles, pkg.CgoFiles, pkg.InvalidGoFiles} {
			for _, name := range list {
				out[name] = true
			}
		}
	}
	return out
}

// relKeyFor renders a walked path relative to root with forward slashes.
func relKeyFor(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	return filepath.ToSlash(rel)
}

// traversalSentinels are repository-relative files both walks MUST have
// scanned: the three #6701 defect sites plus the resolver and its identity
// source. See pkg/osident's copy for why a `filesScanned == 0` floor does not
// bind a PARTIAL traversal defect (#6706 review r5 F8).
//
// The allowlist's own stale-entry check already reds if pkg/daemon goes
// unscanned, since `daemon::applyCLILoginClass` would stop being seen. This is
// the same guarantee for the other three, and it fires with a message that names
// the traversal rather than the allowlist.
var traversalSentinels = []string{
	"pkg/daemon/daemon_run.go",
	"pkg/daemon/cli_rbac.go",
	"pkg/cli/cli.go",
	"pkg/cli/identity.go",
	"cmd/cli/main.go",
}

func requireTraversalSentinels(t *testing.T, scanned map[string]bool, filesScanned int) {
	t.Helper()
	for _, want := range traversalSentinels {
		if !scanned[want] {
			t.Fatalf("the walk never scanned %s (it scanned %d files) — a canary that does not "+
				"reach the #6701 sites reports nothing about them", want, filesScanned)
		}
	}
}
