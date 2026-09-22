package refactoraudit

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #6937 canary for the struct-heterogeneity signal.

func repoRoot6937(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestStructFloorsMatchShellConstants6937 pins the Go constants against
// refactoring-audit-lib.sh. Two copies of a threshold drift, and the whole
// reason that lib exists is that the generator and the gate must classify
// identically (#6232/#7253).
func TestStructFloorsMatchShellConstants6937(t *testing.T) {
	root := repoRoot6937(t)
	b, err := os.ReadFile(filepath.Join(root, "scripts", "refactoring-audit-lib.sh"))
	if err != nil {
		t.Fatalf("read lib: %v", err)
	}
	for _, tc := range []struct {
		shellVar string
		goConst  int
	}{
		{"AUDIT_STRUCT_FLOOR", StructWatchFloor},
		{"AUDIT_STRUCT_REFACTOR_FLOOR", StructRefactorFloor},
	} {
		// Anchor to a line start so AUDIT_STRUCT_FLOOR cannot match inside
		// AUDIT_STRUCT_REFACTOR_FLOOR or inside a comment mentioning it.
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(tc.shellVar) + `=(\d+)$`)
		m := re.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s not found as a bare assignment in refactoring-audit-lib.sh", tc.shellVar)
		}
		got, _ := strconv.Atoi(string(m[1]))
		if got != tc.goConst {
			t.Errorf("%s = %d in shell but %d in Go — the generator and the gate would "+
				"classify differently", tc.shellVar, got, tc.goConst)
		}
	}
}

// TestStructMetricIsTypesNotFields6937 is the calibration canary, and it is
// the reason the metric is distinct types rather than field count.
//
// The checked-in tree is deliberately not the fixture: live structs have
// drifted since the historical calibration. These four source literals pin
// the roles, counts, inclusive floor, and aggregate false-positive shape
// without making this package depend on the caller's checkout.
//
// The role mapping is explicit: Over mirrors the live Engine role (27 fields,
// 22 types), Under mirrors CompileResult (32 fields, 21 types), and Aggregate
// mirrors xpfCollector (443 fields, 11 types). Boundary is the independent
// exact-20 pin that the drifted live rows no longer exercise.
func TestStructMetricIsTypesNotFields6937(t *testing.T) {
	dir := t.TempDir()
	fixtures := []struct {
		name   string
		source string
		fields int
		types  int
		tag    string
	}{
		{
			name: "Over",
			source: `package fixture

type Over struct {
	O01 OT01
	O02 OT02
	O03 OT03
	O04 OT04
	O05 OT05
	O06 OT06
	O07 OT07
	O08 OT08
	O09 OT09
	O10 OT10
	O11 OT11
	O12 OT12
	O13 OT13
	O14 OT14
	O15 OT15
	O16 OT16
	O17 OT17
	O18 OT18
	O19 OT19
	O20 OT20
	O21 OT21
	O22a, O22b, O22c, O22d OT01
}
`,
			fields: 25,
			types:  21,
			tag:    "[WATCH]",
		},
		{
			name: "Under",
			source: `package fixture

type Under struct {
	U01 UT01
	U02 UT02
	U03 UT03
	U04 UT04
	U05 UT05
	U06 UT06
	U07 UT07
	U08 UT08
	U09 UT09
	U10 UT10
	U11 UT11
	U12 UT12
	U13 UT13
	U14 UT14
	U15 UT15
	U16 UT16
	U17 UT17
	U18 UT18
	Nested struct {
		A string
		B string
	}
	U19a, U19b, U19c, U19d, U19e, U19f, U19g, U19h, U19i, U19j, U19k, U19l, U19m UT01
}
`,
			fields: 32,
			types:  19,
			tag:    "",
		},
		{
			name: "Boundary",
			source: `package fixture

type Boundary struct {
	B01 BT01
	B02 BT02
	B03 BT03
	B04 BT04
	B05 BT05
	B06 BT06
	B07 BT07
	B08 BT08
	B09 BT09
	B10 BT10
	B11 BT11
	B12 BT12
	B13 BT13
	B14 BT14
	B15 BT15
	B16 BT16
	B17 BT17
	B18 BT18
	B19 BT19
	B20 BT20
	B21a, B21b, B21c, B21d BT01
}
`,
			fields: 24,
			types:  20,
			tag:    "[WATCH]",
		},
		{
			name: "Aggregate",
			source: `package fixture

type Aggregate struct {
	A01 AT01
	A02 AT02
	A03 AT03
	A04 AT04
	A05 AT05
	A06 AT06
	A07 AT07
	A08 AT08
	A09 AT09
	A10 AT10
	A11 AT11
	R001, R002, R003, R004, R005, R006, R007, R008, R009, R010 AT01
	R011, R012, R013, R014, R015, R016, R017, R018, R019, R020 AT01
	R021, R022, R023, R024, R025, R026, R027, R028, R029, R030 AT01
	R031, R032, R033, R034, R035, R036, R037, R038, R039, R040 AT01
	R041, R042, R043, R044, R045, R046, R047, R048, R049, R050 AT01
	R051, R052, R053, R054, R055, R056, R057, R058, R059, R060 AT01
	R061, R062, R063, R064, R065, R066, R067, R068, R069, R070 AT01
	R071, R072, R073, R074, R075, R076, R077, R078, R079, R080 AT01
	R081, R082, R083, R084, R085, R086, R087, R088, R089, R090 AT01
	R091, R092, R093, R094, R095, R096, R097, R098, R099, R100 AT01
	R101, R102, R103, R104, R105, R106, R107, R108, R109 AT01
}
`,
			fields: 120,
			types:  11,
			tag:    "",
		},
	}

	for _, fixture := range fixtures {
		path := filepath.Join(dir, strings.ToLower(fixture.name)+".go")
		if err := os.WriteFile(path, []byte(fixture.source), 0o644); err != nil {
			t.Fatalf("write %s fixture: %v", fixture.name, err)
		}
	}
	rows, err := GoStructs(dir, func(string) bool { return true })
	if err != nil {
		t.Fatalf("GoStructs: %v", err)
	}
	byName := map[string]StructRow{}
	for _, row := range rows {
		byName[row.Name] = row
	}
	if len(byName) != len(fixtures) {
		t.Fatalf("fixture census returned %d named structs, want %d: %+v",
			len(byName), len(fixtures), byName)
	}
	for _, fixture := range fixtures {
		row, ok := byName[fixture.name]
		if !ok {
			t.Fatalf("fixture %s missing from census: %+v", fixture.name, byName)
		}
		if row.Fields != fixture.fields {
			t.Errorf("%s fields = %d, want exactly %d", fixture.name, row.Fields, fixture.fields)
		}
		if row.DistinctTypes != fixture.types {
			t.Errorf("%s distinct types = %d, want exactly %d",
				fixture.name, row.DistinctTypes, fixture.types)
		}
		if got := row.Tag(); got != fixture.tag {
			t.Errorf("%s tag = %q, want %q at floor %d",
				fixture.name, got, fixture.tag, StructWatchFloor)
		}
	}

	over := byName["Over"]
	under := byName["Under"]
	if !(under.Fields > over.Fields && over.DistinctTypes > under.DistinctTypes) {
		t.Errorf("calibration inversion lost: Under %d fields/%d types vs "+
			"Over %d fields/%d types", under.Fields, under.DistinctTypes,
			over.Fields, over.DistinctTypes)
	}
	aggregate := byName["Aggregate"]
	if aggregate.Fields <= over.Fields {
		t.Errorf("aggregate has %d fields, want more than Over's %d-field "+
			"false-positive comparison", aggregate.Fields, over.Fields)
	}
}

// TestRustScannerSeesPubInPathStructs6937 pins the miss that produced NO
// ROW AT ALL for ForwardingState — one of the two god-structs #6937 was
// filed about.
//
// The visibility prefix list was hardcoded and did not include
// `pub(in crate::afxdp)`, so the struct was silently invisible: not a
// wrong count, an absent row, with no error. An unreadable declaration
// must never be indistinguishable from one that does not exist.
func TestRustScannerSeesPubInPathStructs6937(t *testing.T) {
	dir := t.TempDir()
	src := `#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingStateLike {
    pub(in crate::afxdp) local_v4: FastSet<Ipv4Addr>,
    /// a doc comment that must not be counted
    pub(in crate::afxdp) local_v6: FastSet<Ipv6Addr>,
    pub(crate) plain: u32,
    pub other: String,
    bare: bool,
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := RustStructs(dir, func(string) bool { return true })
	if err != nil {
		t.Fatalf("RustStructs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 struct, got %d: %+v — a `pub(in path)` struct that "+
			"produces no row is invisible to the audit, which is how ForwardingState was "+
			"missed entirely", len(rows), rows)
	}
	// 5 fields: the doc comment is not one.
	if rows[0].Fields != 5 {
		t.Errorf("fields = %d, want 5. #6937: `pub(in crate::afxdp)` CONTAINS `::`, so "+
			"splitting the line on its first colon parsed the name as \"pub(in crate\" "+
			"and dropped the field. That reported ForwardingState as 3 fields instead "+
			"of 71 — a wrong number, which is harder to notice than a missing row",
			rows[0].Fields)
	}
	if rows[0].DistinctTypes != 5 {
		t.Errorf("distinct types = %d, want 5 (FastSet<Ipv4Addr>, FastSet<Ipv6Addr>, "+
			"u32, String, bool)", rows[0].DistinctTypes)
	}
}

// TestGoCounterCollapsesAnonymousNestedStructs6937 pins the trap on the Go
// side: printer.Fprint renders a nested `struct { ... }` across multiple
// lines, and counting each rendering as its own type inflated the census
// to "7 structs with >= 100 distinct types" when the truth is 1.
func TestGoCounterCollapsesAnonymousNestedStructs6937(t *testing.T) {
	dir := t.TempDir()
	src := `package x

type Outer struct {
	A int
	Nested struct {
		P string
		Q string
	}
	Other struct {
		R int
	}
	B int
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := GoStructs(dir, func(string) bool { return true })
	if err != nil {
		t.Fatalf("GoStructs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 NAMED struct, got %d: %+v — an ast.Inspect descent "+
			"reports anonymous nested structs as separate structs, which is out of scope",
			len(rows), rows)
	}
	r := rows[0]
	if r.Fields != 4 {
		t.Errorf("fields = %d, want 4 (A, Nested, Other, B) — inner fields are not counted", r.Fields)
	}
	// int, struct{...}, int  -> the two anonymous structs collapse to ONE token.
	if r.DistinctTypes != 2 {
		t.Errorf("distinct types = %d, want 2 (int + a single collapsed struct{...} token). "+
			"Without the collapse each nested struct's multi-line rendering counts as its "+
			"own type and the metric inflates in the alarming direction", r.DistinctTypes)
	}
}
