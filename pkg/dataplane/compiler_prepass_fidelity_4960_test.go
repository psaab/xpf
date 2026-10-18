package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// prePassShimDivergence records a method the #4960 pre-pass's
// discardingDataPlane answers DIFFERENTLY from the dataplane production
// compiles against, with the reason the divergence is acceptable.
//
// An entry here is a hole in "the pre-pass sees what the real compile sees",
// so each one needs an argument for why it cannot produce a config that clears
// the pre-pass and then fails after compileZones has mutated the host.
var prePassShimDivergence = map[string]string{
	"IsLoaded": "the fake returns true unconditionally; the shim promotes to " +
		"(*Manager).IsLoaded. Stronger than 'harmless': CompileConfig's single " +
		"IsLoaded call is on the REAL dp, above the pre-pass, so the fake's " +
		"answer is never consulted on a path that could half-apply.",
	"GetPersistentNAT": "the fake returns a typed-nil *PersistentNATTable; the " +
		"shim promotes to (*Manager).GetPersistentNAT, which returns the live " +
		"m.PersistentNAT. Every compile-path call site nil-guards, so the " +
		"pre-pass SKIPS the whole persistent-NAT block that production runs. " +
		"No method it would have called can return an error -- asserted " +
		"mechanically by TestPrePassPersistentNATCallsCannotFail_4960 rather " +
		"than by naming them here, because naming them goes stale the moment a " +
		"fourth call is added (#6894 r7 F8).\n\n" +
		"The typed nil is load-bearing in the SAFE direction, which inverts the " +
		"obvious 'improvement'. Teaching the fake to model a real table would " +
		"make the pre-pass CLEAR and REPOPULATE the LIVE persistent-NAT table " +
		"from a compile whose result is then discarded, blanking poolConfigs / " +
		"natIPToPool for any concurrent LookupPool. Under master compileNAT ran " +
		"once against the real dp; under the pre-pass it is skipped and then run " +
		"once by the real pass, so the live table sees an identical sequence. Do " +
		"not 'fix' this by modelling the table.",
}

// #6894 r5 F1: the pre-pass fake must not be MORE PERMISSIVE than the dataplane
// production actually compiles against.
//
// The concern is real in the abstract: discardingDataPlane answers every write
// with nil, so if the production dataplane validated its arguments and returned
// an error, a config could clear the pre-pass, let compileZones mutate the
// host, and then fail in a later phase -- the exact half-applied state #4960
// exists to prevent, produced by the guard meant to close it.
//
// A review round raised it against (*Manager).SetAddressBookEntry
// (maps_policy.go), which does call net.ParseCIDR and does return an error.
// That method belongs to the RETIRED eBPF backend: NewDataPlane and
// NewRuntimeDataPlane both refuse TypeEBPF with ErrEBPFBackendRetired
// (dataplane.go), so no production apply reaches it. What production compiles
// against is userspaceShimCompileDataplane (loader.go), passed by
// CompileUserspaceShim and reached via userspace.Manager.ApplyConfig ->
// .Compile. Its SetAddressBookEntry is a bare `return nil`, so for THAT method
// the fake and production agree exactly and the reported chain does not exist.
//
// This test deliberately does NOT require the fake to validate. Teaching it to
// ParseCIDR would make the PRE-PASS STRICTER than production and reject at
// commit configs the runtime accepts -- an empty address-book `value` is a
// deliberate WARNING, not a reject (compiler_validate_warn.go, #2229), and this
// gate has already swung through over-rejection twice.
//
// SCOPE, and this is the part that was over-read (#6894 r9 F1). "The pre-pass
// is no more permissive than production" is asserted here ONLY about the Go
// DataPlane interface: this test compares discardingDataPlane's method bodies
// against userspaceShimCompileDataplane's. It says nothing about the RUST
// helper, which is the actual enforcement plane and which rejects snapshots the
// Go shim accepted — and does so at publish, after compileZones has mutated the
// host. NPTv6 was a live instance: an unparseable `then` prefix cleared this
// test, cleared the pre-pass, and then failed the apply post-mutation. That
// half is fixed in compileNPTv6 and bound by
// compiler_nptv6_prepass_4960_test.go, NOT here; the residual (overlapping
// prefixes, #2241/#5176) is named in compiler_validate_4960.go. Do not read a
// green result here as "the pre-pass predicts the apply".
//
// WHAT IT DOES CHECK, and why the shape matters. The equivalence is a PROPERTY
// OF THE SHIM, not a law, so:
//
//   - The DataPlane method set is enumerated by REFLECTION, not hardcoded. A
//     hardcoded list silently stops covering methods added later, which is the
//     precise failure this test exists to prevent.
//   - Method bodies are classified by AST, because reflection cannot see them:
//     for an embedded *Manager, Go synthesizes a wrapper on the outer type, so
//     a PROMOTED method is indistinguishable from an overridden one at runtime.
//     That distinction is the whole point -- an un-overridden compile-surface
//     method falls through to the eBPF Manager, which is exactly where the
//     validating implementations live.
//   - Every divergence is allowlisted WITH a reason, and the allowlist is
//     asserted MINIMAL, so it cannot rot into a dumping ground.
func TestPrePassFakeIsNoMorePermissiveThanProduction_4960(t *testing.T) {
	// #6894 r8 F3: scan the whole package, not two named files. Both halves used
	// to read `loader.go` and `compiler_validate_4960.go` by name, so moving
	// `SetFilterRule` into a sibling file WITH A REJECTING BODY left this
	// PASSING — and compileFirewallFilters is a late phase, after compileZones
	// has mutated the host, which is precisely the #4960 shape. The
	// `len(shimDecl) < 40` floor only catches a wholesale move: with 55 methods
	// today, fifteen can migrate before it trips, and a partial split is
	// realistic under the 2000-LOC discipline. The sole-writer canary already
	// scans by directory; these now agree.
	shimDecl, shimNonNoop := declaredMethodsInPackage(t, "userspaceShimCompileDataplane")
	fakeDecl, _ := declaredMethodsInPackage(t, "discardingDataPlane")

	// FLOOR: a rename or file move would empty either scan and pass vacuously.
	if len(shimDecl) < 32 || len(fakeDecl) < 20 {
		t.Fatalf("scan found %d shim and %d fake methods — it is not reaching the "+
			"real types, so a divergence could be introduced without this test "+
			"noticing", len(shimDecl), len(fakeDecl))
	}

	// (1) Every method the production shim DECLARES must be a no-op. A
	//     validating body here is the live version of the reported concern.
	if len(shimNonNoop) > 0 {
		sort.Strings(shimNonNoop)
		t.Errorf("userspaceShimCompileDataplane now has method(s) with a non-no-op "+
			"body: %v\n\nThe #4960 pre-pass compiles against discardingDataPlane, "+
			"whose every method returns nil. While the production shim is also a "+
			"pure no-op the two are equivalent and the pre-pass cannot be more "+
			"permissive than the real compile. A method that can REJECT breaks "+
			"that: a config can pass the pre-pass, let compileZones mutate the "+
			"host, then fail in the real phase — the half-applied apply #4960 "+
			"exists to prevent.\n\nEither give discardingDataPlane the same check "+
			"(accepting that the pre-pass now rejects at commit what the runtime "+
			"would have rejected at apply), or establish the method cannot fail "+
			"for any config that reaches it and add it to prePassShimDivergence "+
			"with that argument.", shimNonNoop)
	}

	// (2) Every method the PRE-PASS CALL SURFACE covers must also be overridden
	//     by the shim — otherwise it promotes to the embedded *Manager, i.e. to
	//     the retired-eBPF implementation, and the fake and production diverge.
	var undocumented []string
	for name := range fakeDecl {
		if shimDecl[name] {
			continue
		}
		// #6894 r7 C2: xpfValidationPass is NOT a DataPlane method at all — it is
		// the unexported marker isValidationPass keys on, defined only on the
		// fake by construction. It never had a production counterpart, so it is
		// not a fake-vs-shim divergence and does not belong in the allowlist on
		// the same footing as the two that are.
		if name == "xpfValidationPass" {
			continue
		}
		if _, ok := prePassShimDivergence[name]; !ok {
			undocumented = append(undocumented, name)
		}
	}
	if len(undocumented) > 0 {
		sort.Strings(undocumented)
		t.Errorf("discardingDataPlane overrides %v, but userspaceShimCompileDataplane "+
			"does NOT — so in production those calls PROMOTE to the embedded "+
			"*Manager, the retired eBPF implementation, while the pre-pass answers "+
			"with the fake's stub. The two are no longer looking at the same "+
			"dataplane on a path the pre-pass claims to model.\n\nEither override "+
			"it on the shim as a no-op, or add it to prePassShimDivergence with an "+
			"argument for why the divergence cannot produce a config that clears "+
			"the pre-pass and fails after compileZones has mutated the host.",
			undocumented)
	}

	// (3) The allowlist must stay MINIMAL, and every entry must correspond to a
	//     REAL, CURRENTLY-DIVERGING method (#6894 r7 C2). The earlier check only
	//     flagged an entry when BOTH types declared it, so a nonexistent name, a
	//     non-interface name, or an empty rationale all passed silently —
	//     measured: an arbitrary bogus exemption left this test green. That
	//     matters because a name can be pre-added, and a later fake stub plus
	//     compile call is then silently excused while production promotes the
	//     fallible Manager implementation.
	//
	//     A legitimate entry is exactly: on the pre-pass CALL SURFACE (the fake
	//     declares it) and NOT overridden by the shim (so it really does
	//     promote).
	var bogus []string
	for name, why := range prePassShimDivergence {
		switch {
		case strings.TrimSpace(why) == "":
			bogus = append(bogus, name+" (empty rationale — an exemption with no "+
				"argument excuses nothing)")
		case !fakeDecl[name]:
			bogus = append(bogus, name+" (not on the pre-pass call surface: "+
				"discardingDataPlane does not declare it, so there is no divergence "+
				"to excuse and the entry can only serve to pre-excuse a future one)")
		case shimDecl[name]:
			bogus = append(bogus, name+" (the shim DOES override it now, so it no "+
				"longer promotes — the exemption is stale)")
		}
	}
	if len(bogus) > 0 {
		sort.Strings(bogus)
		t.Errorf("prePassShimDivergence has entries that do not correspond to a real, "+
			"currently-diverging method:\n  %s\n\nEvery entry is a hole in "+
			"\"the pre-pass sees what the real compile sees\". Remove it, or make it "+
			"describe an actual divergence.", strings.Join(bogus, "\n  "))
	}

	// (4) The reflection half: every DataPlane method must be satisfied, and the
	//     interface is the source of truth for what "the call surface" can grow
	//     into. This is what keeps the scans above from going stale silently.
	iface := reflect.TypeOf((*DataPlane)(nil)).Elem()
	if iface.NumMethod() < 100 {
		t.Fatalf("DataPlane exposes %d methods — the reflection enumeration is not "+
			"seeing the real interface", iface.NumMethod())
	}
	shimType := reflect.TypeOf(userspaceShimCompileDataplane{})
	for i := 0; i < iface.NumMethod(); i++ {
		if _, ok := shimType.MethodByName(iface.Method(i).Name); !ok {
			t.Errorf("userspaceShimCompileDataplane does not satisfy DataPlane.%s",
				iface.Method(i).Name)
		}
	}
}

// declaredMethodsInPackage returns the set of methods DECLARED on recv anywhere
// in the package (promoted ones are absent by construction, which is the
// distinction this test needs), plus the names of those whose body is not a
// bare no-op. Directory-scoped on purpose: a per-file scan is evaded by moving
// a declaration to a sibling (#6894 r8 F3).
func declaredMethodsInPackage(t *testing.T, recv string) (map[string]bool, []string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	decl := map[string]bool{}
	var nonNoop []string
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			if exprTypeName(fn.Recv.List[0].Type) != recv {
				continue
			}
			decl[fn.Name.Name] = true
			if fn.Body == nil || len(fn.Body.List) == 0 {
				continue
			}
			if len(fn.Body.List) == 1 {
				if ret, isRet := fn.Body.List[0].(*ast.ReturnStmt); isRet && returnsOnlyNilOrNothing(ret) {
					continue
				}
			}
			if recv == "userspaceShimCompileDataplane" {
				nonNoop = append(nonNoop, fn.Name.Name)
			}
		}
	}
	if files < 10 {
		t.Fatalf("scanned only %d non-test .go files looking for %s — the scan is "+
			"not reaching the package", files, recv)
	}
	return decl, nonNoop
}

func exprTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

func returnsOnlyNilOrNothing(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return true
	}
	for _, r := range ret.Results {
		id, ok := r.(*ast.Ident)
		if !ok || id.Name != "nil" {
			return false
		}
	}
	return true
}

// TestPrePassPersistentNATCallsCannotFail_4960 discharges the GetPersistentNAT
// exemption's obligation MECHANICALLY (#6894 r7 F8).
//
// The exemption says the pre-pass may skip the persistent-NAT block because
// nothing in it can fail. Stating that in prose under-described it: the
// rationale named ClearPoolConfigs and SetPoolConfig and said "neither returns
// an error" — a two-item word for a set that also contains RegisterNATIP, which
// compileNAT calls twice. The conclusion held, but a reviewer re-checking the
// premise would have verified two of three methods and never looked at the
// third.
//
// Naming three would have the same decay, one call later. So derive the set:
// find every method called on `pnat` inside compileNAT, then assert each of
// those methods is declared with an EMPTY result list. A fourth call is covered
// the moment it is written.
//
// It also discharges an obligation that previously had NO consumer at all. The
// exemption said "if either ever gains an error return this entry must go" —
// but both call sites are bare statements, so adding an error return compiles
// silently at both and nothing observes the transition. This assertion fires on
// the declaration, not on anyone remembering to check a result.
func TestPrePassPersistentNATCallsCannotFail_4960(t *testing.T) {
	fset := token.NewFileSet()
	natFile, err := parser.ParseFile(fset, "compiler_nat.go", nil, 0)
	if err != nil {
		t.Fatalf("parse compiler_nat.go: %v", err)
	}

	// Which identifiers hold the table? Derived, so a rename cannot silently
	// shrink coverage.
	pnatIdents := map[string]bool{}
	for _, d := range natFile.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "compileNAT" && fn.Name.Name != "compileNATWithStaging" && fn.Name.Name != "newNATPersistentStaging") || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range as.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "GetPersistentNAT" || i >= len(as.Lhs) {
					continue
				}
				// #14679: staging assigns s.pnat = dp.GetPersistentNAT()
				// (selector LHS) as well as the legacy local form.
				if id, ok := as.Lhs[i].(*ast.Ident); ok {
					pnatIdents[id.Name] = true
				}
				if lhsSel, ok := as.Lhs[i].(*ast.SelectorExpr); ok {
					pnatIdents[lhsSel.Sel.Name] = true
				}
			}
			return true
		})
	}
	if len(pnatIdents) == 0 {
		t.Fatal("found no `x := dp.GetPersistentNAT()` assignment in compileNAT/staging — " +
			"the derivation is blind, so the exemption is unbacked")
	}

	called := map[string]bool{}
	// #14679: staging holds the table as s.pnat; its commit calls
	// ReplacePoolConfigs. Scan staging methods + wrappers for any
	// PersistentNATTable method call (receiver field or local).
	for _, d := range natFile.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		isStaging := fn.Name.Name == "newNATPersistentStaging" || fn.Name.Name == "compileNATWithStaging" || fn.Name.Name == "compileNAT64WithStaging"
		if fn.Recv != nil {
			for _, f := range fn.Recv.List {
				if star, ok := f.Type.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok && id.Name == "natPersistentStaging" {
						isStaging = true
					}
				}
			}
		}
		if !isStaging {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// s.pnat.Method() or pnat.Method()
			if sel.Sel.Name == "ReplacePoolConfigs" {
				called[sel.Sel.Name] = true
			}
			if recv, ok := sel.X.(*ast.Ident); ok && pnatIdents[recv.Name] {
				called[sel.Sel.Name] = true
			}
			if field, ok := sel.X.(*ast.SelectorExpr); ok && field.Sel.Name == "pnat" {
				called[sel.Sel.Name] = true
			}
			return true
		})
	}

	// FLOOR, EXACT (#6894 r8 F2). A `> 0` floor was evaded by renaming the
	// receiver in one of compileNAT's TWO pnat blocks: coverage dropped 3
	// methods to 1 and the floor still passed, so a genuinely fallible
	// RegisterNATIP would have gone unnoticed. The receiver identifiers are now
	// DERIVED from the `... := dp.GetPersistentNAT()` assignments rather than
	// matched by the literal name `pnat`, and the count is exact — the same
	// discipline the ordering guard uses.
	const wantPnatMethods = 1
	if len(called) != wantPnatMethods {
		t.Fatalf("found %d distinct methods called on the persistent-NAT table in "+
			"compileNAT (%v), expected %d. A DROP means the scan stopped seeing a "+
			"call block and the GetPersistentNAT exemption is silently unbacked for "+
			"whatever it no longer sees; a RISE means a new call whose fallibility "+
			"this assertion has not been told about. Re-derive, then update the "+
			"count deliberately.", len(called), sortedSet(called), wantPnatMethods)
	}

	natTable, err := parser.ParseFile(fset, "persistent_nat.go", nil, 0)
	if err != nil {
		t.Fatalf("parse persistent_nat.go: %v", err)
	}
	// Keyed by RECEIVER+name: persistent_nat.go has one receiver today, but a
	// bare name key is last-declaration-wins the moment a second appears.
	declared := map[string]*ast.FuncDecl{}
	for _, d := range natTable.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if exprTypeName(fn.Recv.List[0].Type) != "PersistentNATTable" {
			continue
		}
		declared[fn.Name.Name] = fn
	}

	var fallible, unresolved []string
	for name := range called {
		fn, ok := declared[name]
		if !ok {
			unresolved = append(unresolved, name)
			continue
		}
		if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
			fallible = append(fallible, name)
		}
	}
	sort.Strings(fallible)
	sort.Strings(unresolved)

	if len(unresolved) > 0 {
		t.Errorf("compileNAT calls pnat.%v, which is not declared in "+
			"persistent_nat.go — this assertion cannot vouch for a method it "+
			"cannot find, so the GetPersistentNAT exemption is unbacked for it",
			unresolved)
	}
	if len(fallible) > 0 {
		t.Errorf("compileNAT calls pnat.%v, which now RETURN something.\n\n"+
			"The GetPersistentNAT exemption in prePassShimDivergence rests on the "+
			"pre-pass being able to skip the whole persistent-NAT block because "+
			"nothing in it can fail. With a result to return, the real pass can "+
			"now reject where the pre-pass silently did nothing — a config clears "+
			"the pre-pass, compileZones mutates the host, and the real compileNAT "+
			"then fails. That is the #4960 shape.\n\nRemove the exemption and make "+
			"discardingDataPlane model the table, or establish that the new result "+
			"cannot be non-nil for any config reaching it.", fallible)
	}
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
