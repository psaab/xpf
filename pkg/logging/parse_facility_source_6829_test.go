package logging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// #6829: the drift guard, in the form that actually drifts.
//
// Before this file there were THREE hand-maintained copies of the same name
// set: ParseFacility's switch, ParseFacilityChecked's case list, and the test's
// parseFacilityMappingTable. The agreement test iterated the TABLE, so a name
// added to ParseFacility alone was never visited by any assertion — the loop
// simply did not reach it. That was demonstrated, not theorised: adding
// `audit-log` to ParseFacility left the whole package green.
//
// A test cannot reflect over a switch statement at run time, so the case labels
// are read from the SOURCE. That turns "the table cannot go stale" from a claim
// into a mechanism: the authority is the function itself, and the two
// hand-written copies are checked against it rather than trusted.
//
// This also completes the over-rejection guard. Over-rejection is
// ParseFacilityChecked reporting `unmapped` for a name ParseFacility maps — and
// the way that arises in practice is exactly a new case landing in ParseFacility
// and not in ParseFacilityChecked. A table-driven test could never see it. This
// one fails on the next build.

// facilityCaseNames extracts the string case labels of the named function's
// top-level switch from the package source. It fails the test rather than
// returning empty on any surprise, so a refactor that moves the mapping out of
// a switch cannot silently turn these guards into no-ops.
func facilityCaseNames(t *testing.T, fnName string) map[string]bool {
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
		t.Fatalf("%s not found in syslog.go — this guard reads the function's case "+
			"labels from source; if the mapping moved, port the guard rather than "+
			"deleting it, or the drift it exists to catch becomes invisible again", fnName)
	}

	names := map[string]bool{}
	var sw *ast.SwitchStmt
	ast.Inspect(fn, func(n ast.Node) bool {
		if s, ok := n.(*ast.SwitchStmt); ok && sw == nil {
			sw = s
		}
		return sw == nil
	})
	if sw == nil {
		t.Fatalf("%s contains no switch statement; this guard reads case labels from "+
			"one. Port the guard to the new shape — do not drop it", fnName)
	}
	for _, stmt := range sw.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok || cc.List == nil { // cc.List == nil is `default:`
			continue
		}
		for _, expr := range cc.List {
			lit, ok := expr.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("%s has a non-string-literal case label %T; this guard assumes "+
					"literal names", fnName, expr)
			}
			names[lit.Value[1:len(lit.Value)-1]] = true
		}
	}
	if len(names) == 0 {
		t.Fatalf("%s: extracted zero case labels — the guard would pass vacuously", fnName)
	}
	return names
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestParseFacilityCheckedCoversEveryParseFacilityCase_6829 is the real
// cannot-drift pin: every name ParseFacility gives its own case MUST be known
// to ParseFacilityChecked, with the same code.
//
// This is the over-rejection direction. A name ParseFacility maps but
// ParseFacilityChecked does not know reports `unmapped`, so a CORRECT config
// emits a substitution warning — which is how operators learn to ignore the
// warning entirely.
func TestParseFacilityCheckedCoversEveryParseFacilityCase_6829(t *testing.T) {
	for _, name := range sortedKeys(facilityCaseNames(t, "ParseFacility")) {
		code, known := ParseFacilityChecked(name)
		if !known {
			t.Errorf("ParseFacility has a case for %q but ParseFacilityChecked reports it "+
				"UNMAPPED — a correct config emits a spurious substitution warning. "+
				"Add %q to ParseFacilityChecked's case list", name, name)
		}
		if want := ParseFacility(name); code != want {
			t.Errorf("ParseFacilityChecked(%q) code = %d, want %d — the checked form must "+
				"agree with ParseFacility exactly", name, code, want)
		}
	}
}

// TestParseFacilityCheckedKnowsNothingExtra_6829 is the other direction: a name
// ParseFacilityChecked claims to know must have its own case in ParseFacility.
// Otherwise `known` would be true for a name that actually falls through to the
// local0 default — the exact conflation ParseFacilityChecked exists to end.
func TestParseFacilityCheckedKnowsNothingExtra_6829(t *testing.T) {
	parseCases := facilityCaseNames(t, "ParseFacility")
	for _, name := range sortedKeys(facilityCaseNames(t, "ParseFacilityChecked")) {
		if !parseCases[name] {
			t.Errorf("ParseFacilityChecked claims to know %q, but ParseFacility has no case "+
				"for it — the name falls through to the local0 DEFAULT, so reporting it "+
				"as mapped re-creates the silent substitution this split removes", name)
		}
	}
}

// TestParseFacilityMappingTableMatchesSource_6829 makes the hand-written
// reference table honest. The agreement tests in
// parse_facility_checked_5797_test.go iterate that table, so any name missing
// from it is a name NO assertion in this package visits. Before this guard, a
// stale table did not fail anything — it just quietly shrank the covered set.
func TestParseFacilityMappingTableMatchesSource_6829(t *testing.T) {
	sourceCases := facilityCaseNames(t, "ParseFacility")

	for _, name := range sortedKeys(sourceCases) {
		if _, ok := parseFacilityMappingTable[name]; !ok {
			t.Errorf("ParseFacility has a case for %q that parseFacilityMappingTable omits. "+
				"The table drives the agreement tests, so %q is currently covered by NO "+
				"assertion in this package — add it to the table", name, name)
		}
	}
	for name := range parseFacilityMappingTable {
		if !sourceCases[name] {
			t.Errorf("parseFacilityMappingTable lists %q, which ParseFacility has no case "+
				"for — the table asserts coverage it does not have", name)
		}
	}
}
