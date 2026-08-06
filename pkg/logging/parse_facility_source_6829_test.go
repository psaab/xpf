package logging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// #6829 review fold (round 3) — the agreement guards, rebuilt behaviourally.
//
// The previous version of this file asserted over an AST walk of ParseFacility's
// SWITCH. That bound the switch, not the function. A short-circuit placed BEFORE
// the switch —
//
//	func ParseFacility(name string) int {
//	    if name == "audit-log" { return FacilityLocal5 }
//	    switch name { ... }
//
// — is invisible to a switch walk, so ParseFacilityChecked("audit-log") kept
// returning (FacilityLocal0, false) while ParseFacility returned FacilityLocal5,
// and all three guards plus the whole package stayed green. That is a live
// over-rejection: a config naming `audit-log` draws a spurious "unmapped
// facility" warning for a facility the runtime does in fact map.
//
// Two things follow.
//
// FIRST, the assertions are now behavioural — they CALL both functions and
// compare results. A structural check can only bind the construct it walks, so
// widening the walk from "the switch" to "every return statement" would buy
// exactly one more mutation shape and stay fragile to the next. Calling the
// function is shape-independent by construction.
//
// SECOND, and this is the part that is easy to get wrong: behavioural
// assertions still need something to ENUMERATE the names to call with, and the
// obvious enumerator is the mapping table. That is not sufficient alone. The
// form "for every table name assert agreement, and for a name absent from the
// table assert ParseFacilityChecked reports not-known" PASSES the mutation
// above, because Checked("audit-log") genuinely IS not-known — the defect is
// that ParseFacility maps it. Verified rather than reasoned: that exact form
// was written, run against the mutation, and came back green.
//
// The missing clause is in TestParseFacilityMappingTableIsComplete_6829 below:
// a name absent from the table must ALSO fall through ParseFacility to the
// default. That converts "the table is complete" from an assumption every
// table-driven test in this package rests on into an assertion one of them
// makes, and it is what reds on the pre-switch return.
//
// The AST walk survives only as a CORPUS CONTRIBUTOR: it supplies names to call
// with, and nothing is asserted about its output. It collects every string
// literal in the whole function BODY rather than case labels, so a name
// special-cased by any construct that mentions it literally is sampled.
//
// NOT BOUND, stated so nobody reads this file as complete — and re-derived in
// round 6 after the corpus widened, because a stale "accepted limit" reads as
// considered-and-kept when it is really just untried.
//
// CLOSED by the package-level widening, listed so the history is legible: a
// `const` identifier hiding a literal, and a package-level `var ... map[string]int`
// consulted before a RETAINED switch. That second one shipped here as "the
// realistic" residual for a round. It was never a property of the approach —
// only of the walk's scope — and both now RED (measured, with a bare-literal
// control to prove the escape had been the identifier rather than the mutation).
//
// STILL OPEN, most to least realistic:
//
//  1. A name special-cased inside ANOTHER FuncDecl in this file, with the
//     literal appearing only in that helper's body. This walk reads
//     ParseFacility's own body plus the file's package-level GenDecls; it does
//     not read sibling function bodies. Widening to every FuncDecl is available
//     and safe (over-inclusion only adds names that agree trivially) — it is
//     not done here because no such helper exists today and the gate scoped
//     round 6 to the GenDecl widening.
//  2. A name assembled by concatenation or derived from another value, so no
//     literal exists anywhere to find. This is the only entry that is genuinely
//     a property of the approach rather than of its scope.
//  3. A name special-cased in a DIFFERENT file of this package: the walk parses
//     syslog.go only.
//
// Escape sequences are NOT in this list: they were, until the extraction
// switched to strconv.Unquote above.
//
// The behavioural assertions are total over the corpus; the corpus is not total
// over the language.
//
// Scale, so the framing is not read as broader than it is: the corpus is ~539
// names, of which only the 14 table entries DISCRIMINATE — for the rest both
// functions return FacilityLocal0 and agreement is trivially satisfied. At HEAD
// the AST contributes zero names the table does not already hold. Its value is
// PROSPECTIVE: it self-samples a mutation that introduces a new literal, which
// is exactly the M1 shape this file exists to catch.

// facilityNameLiterals returns every string literal appearing anywhere in the
// named function's body. It is deliberately over-inclusive: a surplus literal
// merely gets called, and a name the function does not special-case agrees
// trivially. Under-inclusion is the failure that matters, so this walks the
// whole body rather than one construct.
//
// It fails the test on a missing function or an empty extraction rather than
// returning nothing, so a refactor cannot quietly shrink the corpus and leave
// the behavioural assertions running over less than they appear to.
func facilityNameLiterals(t *testing.T, fnName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "syslog.go", nil, 0)
	if err != nil {
		t.Fatalf("parse syslog.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == fnName && fd.Recv == nil {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatalf("%s not found in syslog.go — this builds the corpus the behavioural "+
			"agreement assertions run over; if the function moved, point this at its "+
			"new home rather than deleting it, or those assertions silently cover less", fnName)
	}

	seen := map[string]bool{}
	var out []string
	collect := func(root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			// #6829 F4: UNQUOTE rather than stripping the delimiters. A naive
			// lit.Value[1:len-1] hands back the SOURCE text, so `"audit\x2dlog"` —
			// a bare literal that does appear in the body — enters the corpus as 12
			// characters and never as the 9-character runtime value, escaping a
			// guard whose stated residual says it is sampled.
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				// Not unquotable (should not happen for a STRING literal); fall
				// back to the raw text rather than dropping the name, since an
				// extra corpus entry is harmless and a missing one is not.
				v = lit.Value
			}
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
			return true
		})
	}
	collect(fn.Body)
	// #6829 A1: also walk the file's package-level declarations. The body-only
	// scope let an identifier hide a literal that IS present in syslog.go:
	//
	//	const auditLogFacility = "audit-log"
	//	if name == auditLogFacility { return FacilityLocal5 }
	//
	// slipped, while the identical mutation written with a bare "audit-log"
	// red. So the escape was the IDENTIFIER, not the mutation — measured both
	// ways before this widening was adopted. The same scope choice hid a
	// package-level map consulted before a retained switch, which this file
	// previously shipped as "the realistic" accepted residual. It was not a
	// property of the approach; it was a property of the scope.
	for _, decl := range file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok {
			collect(gd)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: extracted zero string literals — the corpus contribution is empty, "+
			"so the agreement assertions would run over a smaller set than intended", fnName)
	}
	sort.Strings(out)
	return out
}

// facilityCorpus is every name the agreement assertions are evaluated over: the
// mapping table, the string literals of BOTH functions, and the derived
// unmapped corpus from parse_facility_checked_5797_test.go.
func facilityCorpus(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	add := func(names ...string) {
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	for name := range parseFacilityMappingTable {
		add(name)
	}
	add(facilityNameLiterals(t, "ParseFacility")...)
	add(facilityNameLiterals(t, "ParseFacilityChecked")...)
	add(unmappedCorpus()...)
	sort.Strings(out)
	return out
}

// TestParseFacilityCheckedAgreesWithParseFacility_6829 is the total agreement
// property: for ANY name, the code ParseFacilityChecked returns must equal what
// ParseFacility returns. ParseFacilityChecked is a pure VISIBILITY split — it
// adds a bit, it never changes the mapping — so this holds with no exceptions
// and needs no notion of which names are "mapped".
func TestParseFacilityCheckedAgreesWithParseFacility_6829(t *testing.T) {
	for _, name := range facilityCorpus(t) {
		code, _ := ParseFacilityChecked(name)
		if want := ParseFacility(name); code != want {
			t.Errorf("ParseFacilityChecked(%q) code = %d, but ParseFacility(%q) = %d — "+
				"the checked form must never change the mapping, only report whether the "+
				"name had its own case", name, code, name, want)
		}
	}
}

// TestParseFacilityMappingTableIsComplete_6829 is the clause that makes the
// table safe to enumerate over. Every corpus name is in one of two states, and
// both are asserted:
//
//   - in the table: ParseFacility maps it to the recorded value, and
//     ParseFacilityChecked reports it KNOWN;
//   - absent from the table: ParseFacility must FALL THROUGH to FacilityLocal0,
//     and ParseFacilityChecked must report it NOT known.
//
// The first half of the second bullet is what the pre-switch mutation trips: a
// name ParseFacility maps but the table omits returns a non-default code while
// absent, which means the table is incomplete and every test that iterates it
// covers less than it claims.
func TestParseFacilityMappingTableIsComplete_6829(t *testing.T) {
	for _, name := range facilityCorpus(t) {
		want, inTable := parseFacilityMappingTable[name]
		_, known := ParseFacilityChecked(name)

		if inTable {
			if got := ParseFacility(name); got != want {
				t.Errorf("parseFacilityMappingTable[%q] = %d but ParseFacility(%q) = %d; "+
					"the reference table has drifted from the function it mirrors", name, want, name, got)
			}
			if !known {
				t.Errorf("ParseFacilityChecked(%q) reported UNMAPPED, but the table maps it "+
					"— a correct config would emit a spurious substitution warning", name)
			}
			continue
		}

		if got := ParseFacility(name); got != FacilityLocal0 {
			t.Errorf("ParseFacility(%q) = %d, but %q is ABSENT from "+
				"parseFacilityMappingTable, which every table-driven test in this package "+
				"treats as the complete set of specially-mapped names. Either add %q to the "+
				"table or remove whatever special-cases it: a mapping the table does not "+
				"know about is covered by no assertion here, and ParseFacilityChecked "+
				"reports it unmapped — a spurious warning on a config the runtime does map",
				name, got, name, name)
		}
		if known {
			t.Errorf("ParseFacilityChecked(%q) reported KNOWN, but the name has no entry in "+
				"the mapping table — reporting it as mapped re-creates the silent "+
				"substitution this split exists to end", name)
		}
	}
}
