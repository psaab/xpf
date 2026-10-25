// Package userspace regression canaries for the map-name registry (#1521).
//
// Two canaries enforce the decoupling:
//
//  1. TestNoLiteralMapNamesOutsideRegistry — AST-semantic check that
//     no .Map(<basic string literal>) call inside this package uses a
//     "userspace_" literal outside maps.go. Catches both interpreted
//     and raw string literals. Operator-facing log prose remains free
//     to mention map names by literal (errors.New, fmt.Errorf,
//     comments) because those are not .Map() call arguments.
//
//  2. TestRegistryParityWithLegacyLoader — consistency canary that
//     pins the registry constants against the literal map names
//     used by the retained Rust AF_XDP shim loader at
//     pkg/dataplane/loader_userspace_shim.go. The function name
//     keeps "WithLegacyLoader" suffix only for git-blame continuity
//     with the pre-#1476 era when the canary targeted the (now
//     deleted) loader_ebpf.go.
package userspace

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// TestNoLiteralMapNamesOutsideRegistry enforces that no .Map() call
// in the userspace package uses a string literal that starts with
// "userspace_" — every such name must be a constant defined in
// maps.go (or named in another go file by symbol).
//
// Rationale (#1521 / Codex r1 HIGH-2 / AGY r1):
//   - Uses go/ast so it inspects actual call expressions, not text.
//   - strconv.Unquote handles both `"userspace_x"` and `\`userspace_x\“.
//   - Skips _test.go files (cap test asserts the literal value of the
//     pinned compatibility name; that's a legitimate test-only use).
//   - Hard-fails on any parse or read error rather than silently
//     swallowing them.
func TestNoLiteralMapNamesOutsideRegistry(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/dataplane/userspace: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("no Go packages found in current dir")
	}

	var violations []string
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			base := filepath.Base(path)
			if base == "maps.go" {
				// Registry is allowed to hold the literals.
				continue
			}
			if strings.HasSuffix(base, "_test.go") {
				// Test files may reference literal values for clarity
				// (e.g. maps_sync_cap_test.go's pinned-compat assertion).
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil || sel.Sel.Name != "Map" {
					return true
				}
				if len(call.Args) != 1 {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					// A malformed string literal in production
					// code is a hard failure: the file cannot
					// have parsed cleanly if this path is hit, so
					// record the error explicitly instead of
					// silently swallowing it. Copilot r1 flagged
					// the previous "return true" as a silent
					// bypass risk.
					pos := fset.Position(lit.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d: malformed string literal %s in .Map() call: %v",
						pos.Filename, pos.Line, lit.Value, err))
					return true
				}
				if !strings.HasPrefix(s, "userspace_") {
					return true
				}
				pos := fset.Position(lit.Pos())
				violations = append(violations, fmt.Sprintf(
					"%s:%d: forbidden literal map name %q in .Map() call — "+
						"add a constant to maps.go and reference it instead",
					pos.Filename, pos.Line, s))
				return true
			})
		}
	}
	if len(violations) > 0 {
		t.Fatalf("AST canary violations:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestNoMapNameLiteralAliasesOutsideRegistry closes the
// const-alias / parenthesized-selector / method-alias bypasses
// that the .Map()-only canary above does not catch:
//
//	const stale = "userspace_ctrl"
//	m.bpfShim.Map(stale)            // const alias
//	(m.bpfShim.Map)("userspace_ctrl") // parenthesized selector
//	f := m.bpfShim.Map; f("userspace_ctrl") // method alias
//
// All three patterns hide the literal from the .Map(literal)
// inspector. This canary walks every *ast.BasicLit in the package
// (excluding maps.go and _test.go files) and runs three passes that
// together cover BinaryExpr concat folds, call-arg ident
// resolution against the package-wide const symbol table, and
// trim-padded direct literals.
//
// Prose-exemption rule (current, post-Codex r2 LOW-2): a literal
// is treated as operator-facing prose ONLY if it contains
// whitespace (unicode.IsSpace). The previous `%`-verb exemption was
// dropped because it let programmatic map-name constructions like
// `"userspace_%s"` slip past — those are now flagged. The
// trim-padded check still strips both whitespace and `%` characters
// before comparing against the registry's exact constant values so
// padded-but-otherwise-clean bypasses are still caught.
//
// Rationale: closes Codex code-review r1 MEDIUM-1 and AGY r1 §1
// (const alias / paren selector / method alias).
func TestNoMapNameLiteralAliasesOutsideRegistry(t *testing.T) {
	t.Parallel()

	// Package-level AST parse: build a single symbol table across
	// every production .go file (excluding maps.go and _test.go)
	// so cross-file constant concatenation cannot bypass the
	// canary. AGY r4 §II.2 closed.
	fset := token.NewFileSet()
	parsed, err := parser.ParseDir(fset, ".", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/dataplane/userspace: %v", err)
	}
	var files []*ast.File
	var fileNames []string
	for _, pkg := range parsed {
		// Preserve a deterministic file order so violations
		// reports are stable across runs.
		paths := make([]string, 0, len(pkg.Files))
		for p := range pkg.Files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			base := filepath.Base(p)
			if base == "maps.go" || strings.HasSuffix(base, "_test.go") {
				continue
			}
			// AGY r5 §I.b: skip files containing the standard Go
			// generated-code marker so future codegen output is
			// not subject to the canary. Convention is documented
			// in go/build/{Default,IgnoreGenerated} but go/parser
			// does not surface it directly — walk the file's
			// comment groups instead.
			if astFileIsGenerated(pkg.Files[p]) {
				continue
			}
			files = append(files, pkg.Files[p])
			fileNames = append(fileNames, p)
		}
	}
	hits, err := findForbiddenAliasesInFiles(fset, files, fileNames)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if len(hits) > 0 {
		t.Fatalf("AST alias canary violations:\n  %s", strings.Join(hits, "\n  "))
	}
}

// isKnownNonMapUserspaceLiteral lists "userspace_*" identifiers in
// the package that are NOT BPF map names but operator-facing tokens
// returned from String() helpers or used as JSON field values. They
// pre-date the registry and are intentionally not subject to the
// canary. Extending this list is a conscious decision the reviewer
// should challenge.
func isKnownNonMapUserspaceLiteral(s string) bool {
	switch s {
	case "userspace_compat", // DataplaneMode.String()
		"userspace_strict": // DataplaneMode.String()
		return true
	}
	return false
}

// findForbiddenMapNameAliases is the alias-canary inspector,
// factored out so it can be exercised against synthetic fixtures.
// Returns the set of forbidden literal values discovered in src.
//
// To close the AGY r2 bypass classes:
//
//   - (A) Trailing-space trim bypass (`"userspace_ctrl "` then
//     TrimSpace): inspect the *trimmed* value of every literal, not
//     just the raw value. A literal that, after trimming
//     whitespace/`%` verbs, exactly matches a registered map name is
//     a bypass and reported.
//   - (D) String-concatenation bypass (`"user" + "space_ctrl"`): the
//     compiler folds untyped string + expressions at compile time so
//     neither component basic literal alone starts with "userspace_".
//     We evaluate every *ast.BinaryExpr whose Op is token.ADD and
//     both operands are string constants (recursively) and report
//     the folded value if it starts with "userspace_".
//
// The basic-literal walk is kept as the primary path (covers the
// vast majority of cases), and the two structural walkers above
// catch the residual bypass classes.
// findForbiddenAliasesInFiles is the package-aware multi-file
// inspector. It builds a package-wide symbol table of top-level
// consts only; block-local consts (inside function bodies, switch
// case clauses, etc.) are bound dynamically by scopeWalker at the
// moment the corresponding *ast.DeclStmt is visited, so
// statement-order semantics are preserved (Copilot r5 r5:436).
//
// Pass 1/2/3 over every file run through walkWithScope which
// presents the visitor with the correct effective scope at each
// AST node. This closes AGY r4 §II.1 (local block constants) and
// §II.2 (cross-file concat) which the single-file helper could
// not see, AGY r6 (package-level vs block-local shadow), and
// AGY r7 (switch/case implicit-block shadow).
//
// Returns a slice of "path: hit" violation strings; one entry per
// (file, distinct forbidden literal). Order is deterministic over
// file iteration order — caller passes filenames in a stable order.
func findForbiddenAliasesInFiles(fset *token.FileSet, files []*ast.File, fileNames []string) ([]string, error) {
	if len(files) != len(fileNames) {
		return nil, fmt.Errorf("file/name length mismatch")
	}
	// Build package-wide const symbol table. Top-level first.
	// Run until the table size stabilizes so dependency chains of
	// arbitrary depth converge (AGY r5 §I.a).
	consts := map[string]string{}
	for pass := 0; pass < 32; pass++ {
		prev := len(consts)
		for _, file := range files {
			collectFileConstsInto(file, consts)
		}
		if len(consts) == prev {
			break
		}
	}

	var hits []string
	for i, file := range files {
		path := fileNames[i]
		concatOperand := map[ast.Node]bool{}
		hitSet := map[string]struct{}{}
		report := func(s string) {
			if isKnownNonMapUserspaceLiteral(s) {
				return
			}
			hitSet[s] = struct{}{}
		}

		// Pass 1: BinaryExpr concat fold with scope walker.
		walkWithScope(file, consts, func(n ast.Node, scope map[string]string) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || bin.Op != token.ADD {
				return true
			}
			folded, fok := evalStringExpr(bin, scope)
			if !fok {
				return true
			}
			if isMapNameSuspect(folded) {
				report(folded)
				markBasicLitOperands(bin, concatOperand)
				return true
			}
			trimmed := trimPaddingForBypass(folded)
			if trimmed != folded && isExactRegistryMapName(trimmed) {
				report(trimmed)
				markBasicLitOperands(bin, concatOperand)
			}
			return true
		})

		// Pass 2: CallExpr arg ident-resolution with scope walker.
		walkWithScope(file, consts, func(n ast.Node, scope map[string]string) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, arg := range call.Args {
				if _, isLit := arg.(*ast.BasicLit); isLit {
					continue
				}
				s, ok := evalStringExpr(arg, scope)
				if !ok {
					continue
				}
				if isMapNameSuspect(s) {
					report(s)
					continue
				}
				trimmed := trimPaddingForBypass(s)
				if trimmed != s && isExactRegistryMapName(trimmed) {
					report(trimmed)
				}
			}
			return true
		})

		// Pass 3: direct BasicLit (with trim-padded check) with scope walker.
		walkWithScope(file, consts, func(n ast.Node, scope map[string]string) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if concatOperand[lit] {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if strings.HasPrefix(s, "userspace_") && !containsUnicodeSpace(s) {
				report(s)
				return true
			}
			trimmed := trimPaddingForBypass(s)
			if trimmed != s && isExactRegistryMapName(trimmed) {
				report(s)
			}
			return true
		})

		// Stable sort of this file's hits.
		keys := make([]string, 0, len(hitSet))
		for s := range hitSet {
			keys = append(keys, s)
		}
		sort.Strings(keys)
		for _, h := range keys {
			hits = append(hits, fmt.Sprintf(
				"%s: forbidden map-name literal %q outside maps.go — "+
					"reference a registry constant from maps.go instead",
				path, h))
		}
	}
	return hits, nil
}

// collectFileConstsInto records every const-declared string value
// in file into out. Walks only top-level GenDecls (package scope).
// Skips local block consts to avoid scope shadowing bugs (AGY r6).
//
// Per Go spec §Constant declarations, a parenthesized const block
// may omit a subsequent spec's initializer expression list — in
// that case the spec inherits the most recent preceding non-empty
// expression list (the same iota/inherit rule used by iota chains).
// Track lastValues across specs in the same GenDecl to honor that
// rule; otherwise `const ( A = X; B )` would silently leave B
// unbound and a m.Map(B) call would slip past the canary (AGY
// r-rebase finding).
func collectFileConstsInto(file *ast.File, out map[string]string) {
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		var lastValues []ast.Expr
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if len(vs.Values) > 0 {
				lastValues = vs.Values
			}
			for i, name := range vs.Names {
				if i >= len(lastValues) {
					continue
				}
				if v, ok := evalStringExpr(lastValues[i], out); ok {
					out[name.Name] = v
				}
			}
		}
	}
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// evalGenDeclConsts evaluates every name→value binding from a
// CONST GenDecl's specs against the provided pre-binding scope
// without mutating it. Returns the new bindings as a map so the
// caller can apply them at the correct point in the visitor
// traversal — Copilot r-rebase pos 487 found that applying
// in-place at DeclStmt entry made the just-bound inner name
// visible to its own initializer's child traversal, violating
// Go's "scope begins at end of ConstSpec" rule.
//
// Per Go spec §Constant declarations, a parenthesized const block
// may omit a subsequent spec's initializer expression list — in
// that case the spec inherits the most recent preceding non-empty
// expression list (same rule as iota chains). Track lastValues
// across specs in the same GenDecl to honor that rule; otherwise
// `const ( A = "userspace_ctrl"; B )` would leave B unbound and a
// later m.Map(B) lookup would silently bypass the canary.
func evalGenDeclConsts(gd *ast.GenDecl, scope map[string]string) map[string]string {
	var lastValues []ast.Expr
	// Intermediate within-block scope: a spec later in the same
	// GenDecl CAN reference a constant declared earlier in the
	// same GenDecl (per Go spec — scope begins at end of ConstSpec,
	// and the later spec's ConstSpec comes after the earlier one).
	// So we evaluate against a fold of scope + already-evaluated
	// bindings from this same GenDecl.
	fold := cloneMap(scope)
	out := map[string]string{}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if len(vs.Values) > 0 {
			lastValues = vs.Values
		}
		for i, name := range vs.Names {
			if i >= len(lastValues) {
				continue
			}
			if v, ok := evalStringExpr(lastValues[i], fold); ok {
				fold[name.Name] = v
				out[name.Name] = v
			}
		}
	}
	return out
}

type scopeWalker struct {
	consts []map[string]string
	f      func(ast.Node, map[string]string) bool
}

func (w *scopeWalker) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	var hasNewScope bool
	currentScope := w.consts[len(w.consts)-1]

	switch node.(type) {
	case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
		// Push an EMPTY local frame on top of the current scope
		// stack. Block-local const decls bind into this frame as
		// they are visited in syntactic order — preserving Go's
		// "scope begins at end of ConstSpec" rule. Lookups walk
		// inner→outer so the package-wide table at index 0 is
		// still the default.
		currentScope = cloneMap(currentScope)
		w.consts = append(w.consts, currentScope)
		hasNewScope = true
	}

	// Deferred statement-order binding: when a DeclStmt(CONST) is
	// visited, evaluate its specs against the CURRENT scope (which
	// is the outer scope — the inner names are not yet in scope
	// per Go spec §Declarations and scope: "the scope of an
	// identifier denoting a constant ... declared inside a function
	// begins at the end of the ConstSpec"). Apply the resulting
	// bindings on DeclStmt EXIT (via postVisitor) so:
	//
	//   - Initializer expressions visited during the descent see
	//     the outer scope (Copilot r-rebase pos 487 finding).
	//   - Subsequent statements in the same block see the bindings
	//     because they are applied before the next sibling visit.
	//
	// Pre-evaluating at entry honors the rule that each spec's
	// initializer is evaluated with the scope as of its
	// declaration site — which still has the outer values.
	var pendingBindings map[string]string
	if ds, ok := node.(*ast.DeclStmt); ok {
		if gd, ok := ds.Decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
			pendingBindings = evalGenDeclConsts(gd, currentScope)
		}
	}

	keepDescending := w.f(node, currentScope)

	if !keepDescending {
		if pendingBindings != nil {
			top := w.consts[len(w.consts)-1]
			for k, v := range pendingBindings {
				top[k] = v
			}
		}
		if hasNewScope {
			w.consts = w.consts[:len(w.consts)-1]
		}
		return nil
	}

	return &postVisitor{
		walker:          w,
		hasNewScope:     hasNewScope,
		pendingBindings: pendingBindings,
	}
}

type postVisitor struct {
	walker          *scopeWalker
	hasNewScope     bool
	pendingBindings map[string]string
}

func (pv *postVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		// Apply DeclStmt bindings BEFORE popping any new scope so
		// the bindings land in the same scope frame that was
		// active when the DeclStmt was entered. This makes them
		// visible to siblings later in the same block but not to
		// initializer expressions inside the DeclStmt itself.
		if pv.pendingBindings != nil {
			top := pv.walker.consts[len(pv.walker.consts)-1]
			for k, v := range pv.pendingBindings {
				top[k] = v
			}
		}
		if pv.hasNewScope {
			pv.walker.consts = pv.walker.consts[:len(pv.walker.consts)-1]
		}
		return nil
	}
	return pv.walker.Visit(node)
}

func walkWithScope(node ast.Node, initialScope map[string]string, f func(ast.Node, map[string]string) bool) {
	walker := &scopeWalker{
		consts: []map[string]string{initialScope},
		f:      f,
	}
	ast.Walk(walker, node)
}

func findForbiddenMapNameAliases(src string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	// Single-file const symbol table — top-level consts only.
	// Block-local consts (inside function bodies, case clauses,
	// etc.) are bound dynamically by scopeWalker at the moment the
	// *ast.DeclStmt is visited so statement-order semantics hold
	// (Copilot r5 r5:518). Run until the table stabilizes so deep
	// dependency chains of arbitrary depth converge (AGY r5 §I.a).
	consts := map[string]string{}
	for pass := 0; pass < 32; pass++ {
		prev := len(consts)
		collectFileConstsInto(file, consts)
		if len(consts) == prev {
			break
		}
	}

	// Track which AST nodes have already been reported as part of
	// a folded concat so the basic-literal walk does not double-
	// report.
	concatOperand := map[ast.Node]bool{}

	hitSet := map[string]struct{}{}
	report := func(s string) {
		// Permitted: known non-map operator-facing tokens, and
		// the registry-internal exact strings (those are flagged
		// only when they appear OUTSIDE maps.go; this helper has
		// no visibility into file boundaries, so the file-walker
		// caller already excludes maps.go).
		if isKnownNonMapUserspaceLiteral(s) {
			return
		}
		hitSet[s] = struct{}{}
	}

	// Pass 1: walk every CallExpr / *ast.Ident / BinaryExpr that
	// evaluates to a static string starting with "userspace_" using scope walker.
	// This catches concat folds (AGY r2 §D) and const-ident
	// resolution (AGY r3 §ii).
	walkWithScope(file, consts, func(n ast.Node, scope map[string]string) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		folded, fok := evalStringExpr(bin, scope)
		if !fok {
			return true
		}
		if isMapNameSuspect(folded) {
			report(folded)
			markBasicLitOperands(bin, concatOperand)
		}
		return true
	})

	// Pass 2: walk every CallExpr argument — when the argument
	// resolves (via const-ident, concat, paren) to a static
	// "userspace_*" string, report it using scope walker.
	walkWithScope(file, consts, func(n ast.Node, scope map[string]string) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if _, isLit := arg.(*ast.BasicLit); isLit {
				// Basic literals are covered by Pass 3.
				continue
			}
			s, ok := evalStringExpr(arg, scope)
			if !ok {
				continue
			}
			if isMapNameSuspect(s) {
				report(s)
				continue
			}
			// AGY r3 §iii: const value with non-ASCII whitespace
			// padding. Trim and re-check against the exact
			// registry.
			trimmed := trimPaddingForBypass(s)
			if trimmed != s && isExactRegistryMapName(trimmed) {
				report(trimmed)
			}
		}
		return true
	})

	// Pass 3: basic-literal walk for direct literals (including
	// trim-padded bypasses, AGY r2 §A and AGY r3 §iii) using scope walker.
	walkWithScope(file, consts, func(n ast.Node, scope map[string]string) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if concatOperand[lit] {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		// Standard rule: starts with "userspace_" and contains no
		// whitespace (unicode-aware so `\n`/`\r`/etc are caught).
		if strings.HasPrefix(s, "userspace_") && !containsUnicodeSpace(s) {
			report(s)
			return true
		}
		// Trim-padded rule: a literal padded with whitespace
		// (unicode-aware) or `%` verb characters whose trimmed
		// value exactly equals a registered map name is a bypass.
		trimmed := trimPaddingForBypass(s)
		if trimmed != s && isExactRegistryMapName(trimmed) {
			report(s)
		}
		return true
	})
	hits := make([]string, 0, len(hitSet))
	for s := range hitSet {
		hits = append(hits, s)
	}
	return hits, nil
}

// astFileIsGenerated reports whether the file declares itself as
// "Code generated by" output per Go's standard convention. The
// marker must appear as a top-level comment before the package
// declaration (cmd/go/internal/modindex).
func astFileIsGenerated(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() >= f.Package {
			// Comments after the package clause don't count.
			continue
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "// Code generated") &&
				strings.Contains(c.Text, " DO NOT EDIT.") {
				return true
			}
		}
	}
	return false
}

// isMapNameSuspect returns true when s is a folded string that
// looks like a forbidden map-name alias. It is the entry point for
// the concat/ident passes.
//
// A folded value is suspect if, after stripping leading/trailing
// whitespace AND `%` verb characters, the trimmed value:
//   - starts with "userspace_", and
//   - contains no internal whitespace (real map names are
//     snake_case ASCII; a mid-string space signals prose).
//
// AGY r5 §I.d.2: previous "any whitespace = prose" rule let a NEW
// (not-yet-registered) map name with accidental trailing whitespace
// slip past completely. The trim-first approach catches such names
// even though they aren't in the exact-registry list. Pass 3's
// dedicated trim-padded-equals-registry rule remains as a second
// signal for the bypass-with-padding case on existing names.
func isMapNameSuspect(s string) bool {
	trimmed := trimPaddingForBypass(s)
	if !strings.HasPrefix(trimmed, "userspace_") {
		return false
	}
	// After trim, no further internal whitespace is allowed — real
	// map names are snake_case ASCII. A mid-string space signals
	// prose like "userspace_local_v4 map not loaded".
	for _, r := range trimmed {
		if unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// containsUnicodeSpace returns true if s contains any Unicode
// whitespace rune — including the non-ASCII characters AGY r3 §iii
// flagged as bypass material (e.g. \n, \r, NBSP).
func containsUnicodeSpace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// trimPaddingForBypass strips LEADING and TRAILING whitespace
// (unicode-aware) and LEADING/TRAILING `%` characters from s.
// Internal whitespace and internal `%` characters are deliberately
// preserved so that legitimate operator-facing format strings
// like "update userspace_local_v4 %08x: %w" don't accidentally
// trim down to a registered map name (which would create false
// positives in the trim-padded check). Copilot r-rebase pos 729:
// the comment previously said "any" which incorrectly suggested
// internal stripping.
//
// AGY r3 §iii: must include all whitespace runes, not just
// space/tab, when stripping leading/trailing padding.
func trimPaddingForBypass(s string) string {
	s = strings.TrimFunc(s, unicode.IsSpace)
	s = strings.Trim(s, "%")
	return s
}

// evalStringExpr folds an expression to a static string, walking
// BinaryExpr `+`, ParenExpr, BasicLit, *ast.Ident (resolved against
// the supplied const symbol table), and *ast.CallExpr with a
// single string-typed argument (type conversion like
// `MyType("foo")` or `string("foo")`). Returns the value and true
// on success.
//
// Coverage:
//   - AGY r3 §ii: ident resolution closes the
//     `const x = "a"; const y = "b"; const z = x + y` bypass.
//   - AGY r5 §I.d.1: CallExpr single-arg unwrap closes the typed-
//     conversion bypass `type MapName string; const x =
//     MapName("user") + MapName("space_ctrl")`.
func evalStringExpr(e ast.Expr, consts map[string]string) (string, bool) {
	switch n := e.(type) {
	case *ast.ParenExpr:
		return evalStringExpr(n.X, consts)
	case *ast.BasicLit:
		if n.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(n.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.Ident:
		if consts == nil {
			return "", false
		}
		v, ok := consts[n.Name]
		return v, ok
	case *ast.BinaryExpr:
		if n.Op != token.ADD {
			return "", false
		}
		l, lok := evalStringExpr(n.X, consts)
		if !lok {
			return "", false
		}
		r, rok := evalStringExpr(n.Y, consts)
		if !rok {
			return "", false
		}
		return l + r, true
	case *ast.CallExpr:
		// Single-arg conversions: `MyType("user")` or
		// `string([]byte{...})`. Only fold when the call argument
		// is itself a foldable string expression — byte/rune slice
		// inputs are not handled (AGY r4 §II.3 documented as
		// out-of-scope).
		if len(n.Args) == 1 {
			return evalStringExpr(n.Args[0], consts)
		}
		return "", false
	}
	return "", false
}

// markBasicLitOperands walks an expression and marks every
// BasicLit found as a concat-operand so the standard literal walker
// won't double-report it.
func markBasicLitOperands(e ast.Expr, m map[ast.Node]bool) {
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok {
			m[lit] = true
		}
		return true
	})
}

// isExactRegistryMapName returns true iff s equals one of the
// twelve registered map-name constant values. The check is exact
// (post-trim semantics handled by the caller).
func isExactRegistryMapName(s string) bool {
	switch s {
	case mapNameUserspaceCtrl,
		mapNameUserspaceBindings,
		mapNameUserspaceHeartbeat,
		mapNameUserspaceXSK,
		mapNameUserspaceCPUMap,
		mapNameUserspaceSessions,
		mapNameUserspaceIngressIfaces,
		mapNameUserspaceLocalV4,
		mapNameUserspaceLocalV6,
		mapNameUserspaceInterfaceNATv4,
		mapNameUserspaceInterfaceNATv6,
		mapNameUserspaceProxyNDPv6,
		mapNameUserspaceShimDegradedStats:
		return true
	}
	return false
}

// TestAliasCanaryCatchesBypassPatterns proves the alias-canary
// inspector flags const aliases, parenthesized selectors, method
// aliases, programmatic-name format strings, and concatenation
// fragments. Codex r2 LOW-2 asked for a negative fixture.
func TestAliasCanaryCatchesBypassPatterns(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "const_alias",
			src: `package x
const stale = "userspace_ctrl_alias"
func F(m M) { m.Map(stale) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_ctrl_alias"},
		},
		{
			name: "paren_selector",
			src: `package x
func F(m M) { (m.Map)("userspace_paren_alias") }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_paren_alias"},
		},
		{
			name: "method_alias",
			src: `package x
func F(m M) { f := m.Map; _ = f("userspace_method_alias") }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_method_alias"},
		},
		{
			name: "format_template_construction",
			src: `package x
import "fmt"
func F(m M, x string) { _ = m.Map(fmt.Sprintf("userspace_%s", x)) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_%s"},
		},
		{
			name: "string_concatenation_fragment",
			src: `package x
func F(m M) { _ = m.Map("userspace_" + "session") }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r2 (D): "user" + "space_ctrl" folds to
			// "userspace_ctrl"; the concat walker reports the
			// folded value. "userspace_" + "session" folds to
			// "userspace_session" — caught the same way.
			want: []string{"userspace_session"},
		},
		{
			name: "agy_r2_d_full_split_concat",
			src: `package x
const bypass = "user" + "space_ctrl"
func F(m M) { _ = m.Map(bypass) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r2 (D): exact example. Neither component
			// literal alone starts with "userspace_", but the
			// folded value does. Concat walker reports it.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r2_a_trim_padded_literal",
			src: `package x
const bypass = "userspace_ctrl "
func F(m M) { _ = m.Map(bypass) } // caller would do TrimSpace
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r2 (A): a literal padded with a trailing space.
			// AGY r5 §I.d.2: isMapNameSuspect now trims FIRST so
			// the padded form is reported as the violating literal
			// itself (more useful for the developer than the
			// trimmed clean form). Single dedup'd entry.
			want: []string{"userspace_ctrl "},
		},
		{
			name: "operator_log_prose_allowed",
			src: `package x
import "errors"
func F() error { return errors.New("update userspace_local_v4 %08x: %w") }
`,
			want: nil,
		},
		{
			name: "known_non_map_allowed",
			src: `package x
func S() string { return "userspace_compat" }
`,
			want: nil,
		},
		{
			name: "raw_string_literal_caught",
			src:  "package x\nfunc F(m M) { _ = m.Map(`userspace_raw_alias`) }\ntype M struct{}\nfunc (M) Map(string) any { return nil }\n",
			want: []string{"userspace_raw_alias"},
		},
		{
			name: "agy_r3_ii_const_ident_concat",
			src: `package x
const pfx = "user"
const sfx = "space_ctrl"
const bypass = pfx + sfx
func F(m M) { _ = m.Map(bypass) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r3 §ii: const-ident resolution. Two leaf
			// literals neither of which starts with "userspace_";
			// the folded value does. The const-symbol table closes
			// the bypass; reported on the const decl line.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r3_ii_call_arg_via_ident",
			src: `package x
const bypass = "userspace_ctrl"
func F(m M) { _ = m.Map(bypass) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r3 §ii: call-arg ident resolution. The basic
			// literal in the const decl AND the call-arg via
			// ident both resolve to the same value; dedup is the
			// expected behaviour.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r3_iii_newline_padding",
			src:  "package x\nconst bypass = \"userspace_ctrl\\n\\t\"\nfunc F(m M) { _ = m.Map(bypass) }\ntype M struct{}\nfunc (M) Map(string) any { return nil }\n",
			// AGY r3 §iii: padding with non-space whitespace.
			// AGY r5 §I.d.2: trim-first isMapNameSuspect reports
			// the padded literal as the violating value (more
			// useful diagnostic than the clean form).
			want: []string{"userspace_ctrl\n\t"},
		},
		{
			name: "agy_r3_iii_nbsp_padding",
			src:  "package x\nconst bypass = \"userspace_ctrl\\u00A0\"\nfunc F(m M) { _ = m.Map(bypass) }\ntype M struct{}\nfunc (M) Map(string) any { return nil }\n",
			// AGY r3 §iii: NBSP (U+00A0) is whitespace by Unicode.
			// trimPaddingForBypass uses unicode.IsSpace so NBSP is
			// stripped; trimmed value equals "userspace_ctrl".
			want: []string{"userspace_ctrl "},
		},
		{
			name: "agy_r4_ii_local_block_const_concat",
			src: `package x
func F(m M) {
	const pfx = "user"
	const sfx = "space_ctrl"
	const bypass = pfx + sfx
	m.Map(bypass)
}
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r4 II.1: local block consts. collectFileConstsInto
			// now walks DeclStmt inside function bodies, so the
			// local consts resolve and bypass = pfx + sfx folds to
			// "userspace_ctrl". Pass 1 (BinaryExpr fold) and Pass 2
			// (call-arg ident-resolve) both report; dedup keeps one.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r5_ia_inverted_chain_depth3",
			src: `package x
const chain3 = chain2 + "_stats"
const chain2 = chain1 + "_fallback"
const chain1 = "userspace"
func F(m M) { _ = m.Map(chain3) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r5 I.a: depth-3 dependency chain in inverted decl
			// order. The convergence loop iterates until the consts
			// table stabilizes, resolving chain1, then chain2, then
			// chain3 across three passes. Both the folded final
			// value "userspace_fallback_stats" AND the folded
			// intermediate "userspace_fallback" (chain2) are flagged
			// because each is a forbidden alias at its declaration
			// site — the canary doesn't care that one is "more
			// derived" than the other; both fail.
			want: []string{"userspace_fallback_stats", "userspace_fallback"},
		},
		{
			name: "agy_r5_id1_typed_concat_conversion",
			src: `package x
type MapName string
const TypedBypass = MapName("user") + MapName("space_ctrl")
func F(m M) { _ = m.Map(string(TypedBypass)) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r5 I.d.1: typed-conversion concat. evalStringExpr
			// now unwraps single-arg CallExpr so MapName("user") +
			// MapName("space_ctrl") folds via the BasicLit operands.
			// string(TypedBypass) at the call site also unwraps to
			// the ident-resolved value.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r5_id2_typo_padded_new_name",
			src: `package x
const NewMapWithTypo = "userspace_new_interface_map "
func F(m M) { _ = m.Map(NewMapWithTypo) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r5 I.d.2: a NEW (not-yet-registered) map name with
			// accidental trailing space. The trim-first
			// isMapNameSuspect catches this even though the trimmed
			// value isn't in the exact-registry list yet — the prefix
			// match alone is enough.
			want: []string{"userspace_new_interface_map "},
		},
		{
			name: "agy_r6_block_shadow_chain_bypass",
			src: `package x
const chain3 = chain2 + "_stats"
const chain2 = chain1 + "_fallback"
const chain1 = "userspace"
func F(m M) {
	const chain1 = "innocuous"
	_ = m.Map(chain3)
}
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r6: block-local shadow chain bypass. A block-local constant shadows
			// a package-level constant, which would corrupt a flat symbol table.
			// The scope-aware walker ensures the package-level chain3 still resolves
			// to "userspace_fallback_stats" and is successfully caught.
			want: []string{"userspace_fallback_stats", "userspace_fallback"},
		},
		{
			name: "agy_r7_switch_case_shadow_bypass",
			// Package-level chain (Go permits arbitrary
			// declaration order at package scope, so inverted
			// order is valid). The switch/case bodies are
			// implicit scopes per Go spec; a local shadow in
			// case 1 must NOT leak into the canary's evaluation
			// of m.Map(chain3) in case 2 (which Go binds to the
			// package-level chain3 = "userspace_fallback_stats").
			src: `package x
const chain3 = chain2 + "_stats"
const chain2 = chain1 + "_fallback"
const chain1 = "userspace"
func F(x int, m M) {
	switch x {
	case 1:
		const chain1 = "innocuous"
		_ = chain1
	case 2:
		_ = m.Map(chain3)
	}
}
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_fallback_stats", "userspace_fallback"},
		},
		{
			name: "copilot_r5_statement_order_false_positive",
			// Copilot r5 r5:436 — without statement-order
			// binding, a later-declared block-local const that
			// happens to start with "userspace_" would replace
			// the outer-scope value in the canary's symbol
			// table, causing an INNOCUOUS m.Map(outer) earlier
			// in the same block to be wrongly flagged. With
			// statement-order binding, the call to m.Map(outer)
			// at line 3 sees only the package-level value
			// "innocuous_outer" and is correctly NOT flagged;
			// the inner shadow at line 5 binds afterwards and
			// affects only later expressions in the same block.
			src: `package x
const outer = "innocuous_outer"
func F(m M) {
	_ = m.Map(outer)
	const outer = "userspace_evil"
	_ = outer
}
type M struct{}
func (M) Map(string) any { return nil }
`,
			// The shadow itself IS a forbidden literal at its
			// declaration site (basic-lit walk catches it), so
			// "userspace_evil" appears. But the earlier
			// m.Map(outer) call must resolve to the outer
			// package-level "innocuous_outer" — not to the
			// later shadow.
			want: []string{"userspace_evil"},
		},
		{
			name: "copilot_r5_statement_order_false_negative",
			// Copilot r5 r5:436 — converse case. Outer
			// "userspace_real" is the value at the m.Map(outer)
			// site. A later-declared block-local const shadows
			// outer with an innocuous value. With pre-collect,
			// the canary would have read "innocuous" at the call
			// site and MISSED the violation. Statement-order
			// binding correctly resolves the call to the outer
			// value and flags it.
			src: `package x
const outer = "userspace_real"
func F(m M) {
	_ = m.Map(outer)
	const outer = "innocuous"
	_ = outer
}
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_real"},
		},
		{
			name: "agy_rebase_inherited_initializer_bypass",
			// AGY post-rebase finding: a parenthesized const block
			// where a subsequent spec omits its initializer
			// expression inherits the previous spec's expression list
			// per Go spec §Constant declarations. Without
			// last-values tracking, B would be skipped by the binder
			// and m.Map(B) would silently slip past the canary even
			// though at compile time B == A == "userspace_ctrl".
			src: `package x
const (
	A = "userspace_ctrl"
	B
)
func F(m M) { _ = m.Map(B) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_rebase_inherited_initializer_local_block",
			// Same pattern but in a local block, exercising
			// bindGenDeclConsts via scopeWalker.Visit.
			src: `package x
func F(m M) {
	const (
		A = "userspace_ctrl"
		B
	)
	_ = m.Map(B)
}
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_ctrl"},
		},
		{
			name: "copilot_rebase_shadow_initializer_refs_outer",
			// Copilot r-rebase pos 487 — a block-local const's
			// initializer that references the outer same-name
			// const should resolve via the OUTER scope per Go spec
			// §Declarations and scope ("scope begins at end of
			// ConstSpec"). If the binder applied the inner binding
			// BEFORE the initializer was evaluated by the visitor,
			// Pass 1's later BinaryExpr fold would compute the wrong
			// folded value (double-shadowed). With deferred binding
			// (apply on DeclStmt EXIT), the initializer fold sees
			// only the outer scope.
			src: `package x
const outer = "userspace_outer"
func F(m M) {
	const outer = outer + "_shadow"
	m.Map(outer)
}
type M struct{}
func (M) Map(string) any { return nil }
`,
			// The inner const's compile-time value is
			// "userspace_outer_shadow" (outer at RHS resolves to
			// the package-level outer). m.Map call also sees the
			// inner binding. Both should be flagged with the
			// correct single-shadowed value, not a double-shadowed
			// "userspace_outer_shadow_shadow".
			want: []string{"userspace_outer", "userspace_outer_shadow"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := findForbiddenMapNameAliases(tc.src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !equalStringSets(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(b))
	for _, s := range b {
		m[s]++
	}
	for _, s := range a {
		if m[s] == 0 {
			return false
		}
		m[s]--
	}
	return true
}

// TestRegistryParityWithLegacyLoader asserts that every userspace
// map-name constant matches a literal string still present in the
// retained Rust AF_XDP shim loader at
// pkg/dataplane/loader_userspace_shim.go. The two sides duplicate
// the names; this canary keeps them in lockstep so a rename in
// either file is caught at test time, not at helper bringup.
//
// History (#1476): pre-mechanical-removal this canary pointed at
// pkg/dataplane/loader_ebpf.go, which held both the deleted legacy
// XDP/TC graph AND the retained shim loader. After #1476 the
// retained graph lives in loader_userspace_shim.go and the legacy
// graph is gone; the parity check now policess only the retained
// side. The function name keeps "WithLegacyLoader" suffix only for
// git-blame continuity; rename in a separate PR.
func TestRegistryParityWithLegacyLoader(t *testing.T) {
	t.Parallel()

	loaderPath := filepath.Join("..", "loader_userspace_shim.go")
	body, err := os.ReadFile(loaderPath)
	if err != nil {
		t.Fatalf("read retained shim loader %s: %v", loaderPath, err)
	}

	// Dynamically discover every `mapName...` constant defined in
	// maps.go via AST parse. AGY r3 §v: a hardcoded list goes stale
	// when a new constant is added; using the AST keeps the parity
	// check self-extending.
	entries, err := parseMapsGoRegistry("maps.go")
	if err != nil {
		t.Fatalf("parse maps.go: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("parseMapsGoRegistry returned no constants — maps.go shape changed?")
	}
	for _, e := range entries {
		quoted := []byte(`"` + e.value + `"`)
		if !bytes.Contains(body, quoted) {
			t.Errorf(
				"%s = %q not found as a quoted literal in %s — "+
					"parity broken: rename both sides together or update this canary",
				e.name, e.value, loaderPath)
		}
	}
}

// registryEntry holds one constant from maps.go for parity checks.
type registryEntry struct {
	name  string
	value string
}

// parseMapsGoRegistry parses maps.go and returns every top-level
// `const mapName... = "..."` declaration.
//
// Any mapName* constant whose initializer is not a basic string
// literal — or whose literal fails strconv.Unquote — is a HARD
// FAILURE. Silent-skip would let a future refactor (e.g. building a
// constant from concatenation or from an external identifier) slip
// past the parity check; the test must complain immediately so the
// reviewer is forced to update the canary. (Codex r4 LOW-1.)
func parseMapsGoRegistry(path string) ([]registryEntry, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var out []registryEntry
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "mapName") {
					continue
				}
				if i >= len(vs.Values) {
					return nil, fmt.Errorf(
						"%s: mapName-prefixed const %q has no initializer "+
							"(iota or grouped declaration unsupported)",
						path, name.Name)
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					return nil, fmt.Errorf(
						"%s: mapName-prefixed const %q initializer is %T, "+
							"want *ast.BasicLit (parity canary needs a direct string literal)",
						path, name.Name, vs.Values[i])
				}
				if lit.Kind != token.STRING {
					return nil, fmt.Errorf(
						"%s: mapName-prefixed const %q is a %s literal, want STRING",
						path, name.Name, lit.Kind)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, fmt.Errorf(
						"%s: mapName-prefixed const %q malformed literal %s: %w",
						path, name.Name, lit.Value, err)
				}
				out = append(out, registryEntry{name: name.Name, value: v})
			}
		}
	}
	return out, nil
}

// TestParseMapsGoRegistryRejectsDriftShapes ensures the parity-
// canary helper hard-fails (returns an error) for any `mapName*`
// constant declared in a form it cannot statically reason about,
// instead of silently skipping it and weakening parity coverage.
// Closes Codex r4 LOW-1.
func TestParseMapsGoRegistryRejectsDriftShapes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cases := []struct {
		name        string
		src         string
		wantErrSubs string
	}{
		{
			name: "non_basiclit_initializer",
			src: `package x
const helper = "userspace_ctrl"
const mapNameUserspaceCtrl = helper // ident, not BasicLit
`,
			wantErrSubs: "initializer is *ast.Ident",
		},
		{
			name: "concat_initializer",
			src: `package x
const mapNameUserspaceCtrl = "userspace_" + "ctrl" // BinaryExpr
`,
			wantErrSubs: "initializer is *ast.BinaryExpr",
		},
		{
			name: "non_string_kind",
			src: `package x
const mapNameUserspaceCtrl = 42 // int literal
`,
			wantErrSubs: "INT literal, want STRING",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, tc.name+".go")
			if err := os.WriteFile(path, []byte(tc.src), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := parseMapsGoRegistry(path)
			if err == nil {
				t.Fatalf("expected parseMapsGoRegistry to fail, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrSubs) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrSubs)
			}
		})
	}
}

// TestCrossFileConcatBypassIsCaught proves the multi-file
// inspector resolves package-wide const concatenation that the
// single-file helper cannot see. Closes AGY r4 §II.2.
func TestCrossFileConcatBypassIsCaught(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// File A: declare two innocuous-looking parts.
	if err := os.WriteFile(filepath.Join(dir, "parts.go"), []byte(`package x
const part1 = "user"
const part2 = "space_ctrl"
`), 0o644); err != nil {
		t.Fatalf("write parts.go: %v", err)
	}
	// File B: combine them, lookup via Map().
	if err := os.WriteFile(filepath.Join(dir, "use.go"), []byte(`package x
const MyMap = part1 + part2
type M struct{}
func (M) Map(string) any { return nil }
func F(m M) { _ = m.Map(MyMap) }
`), 0o644); err != nil {
		t.Fatalf("write use.go: %v", err)
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseDir(fset, dir, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse fixture dir: %v", err)
	}
	var files []*ast.File
	var names []string
	for _, pkg := range parsed {
		paths := make([]string, 0, len(pkg.Files))
		for p := range pkg.Files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			files = append(files, pkg.Files[p])
			names = append(names, p)
		}
	}
	hits, err := findForbiddenAliasesInFiles(fset, files, names)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	// At least one hit should reference "userspace_ctrl" — the
	// folded cross-file value.
	found := false
	for _, h := range hits {
		if strings.Contains(h, `"userspace_ctrl"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected hit referencing %q, got: %v", "userspace_ctrl", hits)
	}
}
