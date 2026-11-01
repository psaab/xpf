package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unsafe"
)

// #16166 PR-0: completeness of the tolerant-path opt set.
//
// compileOpts carries ~300 lenient*/sanitize* severity-downgrade bools.
// Adding a gate requires the field (link 1) AND `o.field = true` in
// lenientCompileOpts() (link 2). Forgetting link 2 silently makes the
// tolerant load / peer-sync path strict for that gate — the #1960
// brick-the-boot class — and no compiler error catches it, because the
// zero value is a perfectly valid bool. Until now the invariant was
// enforced by reviewer vigilance only.
//
// This test enforces links 1-2 by construction: it reflects recursively
// over compileOpts (including any future embedded or pointer-embedded
// struct, traversed under the nil/cycle policy in
// walkBoolFields16166) and asserts every lenient*/sanitize* bool is
// true in lenientCompileOpts(). The recursion is a defensive arm, not a
// load-bearing one: compileOpts has had no embedded struct since
// #17168 un-embedded the two protocol-scope lenient flags (once the
// formatting-workaround embedded type) into plain fields, but
// a future re-embedding must not silently escape the census. The reverse
// arm (TestLenientCompileOptsHaveReaders17143) enforces link 3 for the
// lenient*/sanitize*/suppress* population: such a field with no selector
// read outside compiler_opts.go is dead — its gate was retired (or never
// wired) and the field must be deleted with it, not certified by the
// links 1-2 arm. It does NOT enforce link 4 (warning/show surface) —
// that is the separately gated registry work, not PR-0.
//
// Scope is deliberately the name prefix, not "every bool": compileOpts
// also carries non-downgrade bools whose lenient value is not uniformly
// true (skipCompactNormalize is a test seam that must stay false so the
// normalizer runs on the tolerant path).
// (#17157: the #4329 node identity used to ride a parallel nodeAware
// bool that needed its own allowlist entry; it now derives from
// opts.nodeID != nil, so no such bool remains.)
// A future non-downgrade bool must not be named lenient*/sanitize*, and
// a future downgrade bool must — the prefix is the contract this test
// polices. The suppress* advisory bools are the one deliberate
// exception already in the tree: they silence commit-time advisories
// (never a hard error) on the tolerant paths, are set true in
// lenientCompileOpts(), and are allowlisted explicitly below so the
// exception is reviewed rather than silent.

// lenientCompletenessAllowlist16166 names every bool field reachable
// from compileOpts that is NOT required to be true in
// lenientCompileOpts(), with the reason. Keys are FULL dotted field
// paths from the compileOpts root (e.g. "skipCompactNormalize" at the
// root, "<embedded>.<field>" inside an embedded struct), never
// bare leaf names: a nested bool that happens to share an allowlisted
// leaf name does NOT inherit the exemption. Any bool neither prefixed
// lenient*/sanitize* (by leaf name) nor keyed here by full path fails
// the census arm of the test, so a new bool forces an explicit
// decision here.
var lenientCompletenessAllowlist16166 = map[string]string{
	// #8690 test seam: production and the tolerant path must run the
	// compact normalizer; only measurement tests set this.
	"skipCompactNormalize": "test seam (#8690); tolerant path must normalize",
	// (no "nodeAware" entry, #17157: node identity derives from
	// opts.nodeID != nil; a parallel bool must never re-enter the
	// allowlist — TestCompileOptsShape17157 fails if one does.)
	// Advisory suppressors: not severity downgrades (the checks warn on
	// every path), but they ARE set true in lenientCompileOpts() today.
	// Listed so the prefix census classifies them deliberately; the
	// truth arm also covers them via the extra check below.
	"suppressClusterNTPAdvisory":         "advisory suppressor (#8357), true in lenientCompileOpts",
	"suppressContestedTrunkZoneAdvisory": "advisory suppressor (#7509), true in lenientCompileOpts",
	"suppressDPDThresholdIKEv2Advisory":  "advisory suppressor (#15025), true in lenientCompileOpts",
	"suppressFabricStampAdvisory":        "advisory suppressor (#10105), true in lenientCompileOpts",
	"suppressSSHUnmanagedAdvisory16737":  "advisory suppressor (#16737), true in lenientCompileOpts",
	"tolerant":                           "tolerant-path mode bit (#17153), true only in lenientCompileOpts",
	"igpIdentityExcused16810":            "compileTree-only exemption for the node-specific IGP identity gate; it is not a lenient downgrade",
	"currentConfigPresent18744":          "active-config presence for the #18744 placeholder gate, supplied only by the strict candidate pipeline; tolerant compiles leave it false, and the gate's own downgrade is lenientClusterAuthKey",
}

// walkBoolFields16166 visits every bool field reachable from v,
// recursing into embedded and nested struct fields AND through
// pointer-to-struct fields (embedded or named). path is the dotted
// field path from the root (e.g. "plantedEmbedded.lenientPlantedEmbedded16166").
//
// Pointer policy (explicit, fail-closed):
//   - nil pointer-to-struct: the pointed-to fields cannot be inspected
//     in this instance, so the walk falls back to the pointed-to TYPE
//     and reports each reachable bool with value false. A nil pointer
//     therefore never hides a lenient* bool: in the completeness test
//     it surfaces as an unregistered (false) downgrade rather than a
//     silent skip. The type fallback terminates via visitedTypes.
//   - non-nil pointer-to-struct: dereferenced and walked by value.
//   - cycles: visitedTypes bounds the type fallback and visitedPtrs
//     (type+pointer identity) bounds live-pointer recursion; revisiting
//     an already-walked pointer reports no fields twice and cannot loop.
func walkBoolFields16166(v reflect.Value, path string, visit func(path string, fv reflect.Value)) {
	walkBoolFieldsRec16166(v, path, visit, map[reflect.Type]bool{}, map[visitPtr16166]bool{})
}

type visitPtr16166 struct {
	typ reflect.Type
	ptr unsafe.Pointer
}

func walkBoolFieldsRec16166(v reflect.Value, path string, visit func(path string, fv reflect.Value), visitedTypes map[reflect.Type]bool, visitedPtrs map[visitPtr16166]bool) {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			walkBoolFieldsByType16166(v.Type().Elem(), path, visit, visitedTypes)
			return
		}
		key := visitPtr16166{typ: v.Type(), ptr: v.UnsafePointer()}
		if visitedPtrs[key] {
			return
		}
		visitedPtrs[key] = true
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := range v.NumField() {
		sf := t.Field(i)
		fv := v.Field(i)
		p := sf.Name
		if path != "" {
			p = path + "." + sf.Name
		}
		switch {
		case fv.Kind() == reflect.Struct:
			walkBoolFieldsRec16166(fv, p, visit, visitedTypes, visitedPtrs)
		case fv.Kind() == reflect.Pointer && fv.Type().Elem().Kind() == reflect.Struct:
			walkBoolFieldsRec16166(fv, p, visit, visitedTypes, visitedPtrs)
		case fv.Kind() == reflect.Bool:
			visit(p, fv)
		}
	}
}

// walkBoolFieldsByType16166 reports every bool reachable from struct
// type t (through struct and pointer-to-struct fields) with a false
// value. Used only for nil pointers, where no live value exists.
// visitedTypes bounds recursion on self-referential types.
func walkBoolFieldsByType16166(t reflect.Type, path string, visit func(path string, fv reflect.Value), visitedTypes map[reflect.Type]bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || visitedTypes[t] {
		return
	}
	visitedTypes[t] = true
	falseVal := reflect.ValueOf(false)
	for i := range t.NumField() {
		sf := t.Field(i)
		p := sf.Name
		if path != "" {
			p = path + "." + sf.Name
		}
		ft := sf.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch {
		case ft.Kind() == reflect.Struct:
			walkBoolFieldsByType16166(ft, p, visit, visitedTypes)
		case sf.Type.Kind() == reflect.Bool:
			visit(p, falseVal)
		}
	}
}

// classifyLenientBool16166 classifies one walked bool field: downgrade
// detection is by LEAF name (a lenient*/sanitize* bool is a downgrade
// wherever it nests); the allowlist exemption is by FULL dotted path,
// so a nested bool sharing an allowlisted leaf name (e.g. a future
// nested "skipCompactNormalize") does NOT inherit the exemption.
// Both the completeness test and the full-path test call this func —
// mutating the allowlist lookup to leaf-name matching must turn the
// full-path test RED.
type lenientBoolClass16166 int

const (
	lenientClassDowngrade16166 lenientBoolClass16166 = iota
	lenientClassAllowlisted16166
	lenientClassUnclassified16166
)

func classifyLenientBool16166(path string) lenientBoolClass16166 {
	leaf := path[strings.LastIndex(path, ".")+1:]
	switch {
	case strings.HasPrefix(leaf, "lenient"), strings.HasPrefix(leaf, "sanitize"):
		return lenientClassDowngrade16166
	case lenientCompletenessAllowlist16166[path] != "":
		return lenientClassAllowlisted16166
	default:
		return lenientClassUnclassified16166
	}
}

func (c lenientBoolClass16166) String() string {
	switch c {
	case lenientClassDowngrade16166:
		return "downgrade"
	case lenientClassAllowlisted16166:
		return "allowlisted"
	default:
		return "unclassified"
	}
}

func TestLenientCompileOptsCompleteness16166(t *testing.T) {
	opts := lenientCompileOpts()
	v := reflect.ValueOf(opts)

	var downgrades, others int
	walkBoolFields16166(v, "", func(path string, fv reflect.Value) {
		leaf := path[strings.LastIndex(path, ".")+1:]
		switch classifyLenientBool16166(path) {
		case lenientClassDowngrade16166:
			downgrades++
			if !fv.Bool() {
				t.Errorf("%s is false in lenientCompileOpts(): the field exists but its "+
					"lenientCompileOpts() entry is missing, so the tolerant load / peer-sync "+
					"path stays STRICT for this gate and a persisted or peer-synced config an "+
					"older binary accepted would fail to boot (#1960). Add `o.%s = true` to "+
					"lenientCompileOpts() in compiler_opts.go", path, leaf)
			}
		case lenientClassAllowlisted16166:
			others++
		default:
			t.Errorf("%s is a bool in compileOpts that is neither a lenient*/sanitize* "+
				"downgrade nor allowlisted by full path in lenientCompletenessAllowlist16166: classify it. "+
				"If it downgrades a gate on the tolerant path, name it lenient*/sanitize* so "+
				"this test requires it true in lenientCompileOpts(); otherwise add its full "+
				"dotted path to the allowlist with the reason its lenient value is not required to be true", path)
		}
	})

	// Census guards: the walk must actually reach the population it
	// claims to police. A walk that silently visits nothing would green
	// while missing exactly the class this test exists to catch, so pin
	// two fields by name and require a plausible census. The floor is
	// deliberately below the current count (330 lenient*/sanitize* bools
	// of 336 total assignments re-measured for #17168) so removing a
	// this test, while a collapsed walk (0) still trips it via the
	// named pins below. Recursion into embedded structs is pinned
	// separately by TestLenientCompletenessWalkRecurses16166, whose
	// planted shape does not depend on the current field population.
	if downgrades < 250 {
		t.Errorf("census: only %d lenient*/sanitize* bools reached by the recursive walk; "+
			"the walk is not reaching the compileOpts population (want ~330)", downgrades)
	}
	if others == 0 {
		t.Error("census: no allowlisted non-downgrade bools reached; the walk is not " +
			"reaching compileOpts fields such as skipCompactNormalize")
	}
	// The two protocol-scope flags are plain compileOpts fields since
	// the #17168 un-embedding; pin them by name.
	if !opts.lenientProtocolInterfaceMembership11310 {
		t.Error("lenientProtocolInterfaceMembership11310 is false in " +
			"lenientCompileOpts(): protocol-scope downgrade not registered")
	}
	if !opts.lenientOSPFAreaInterface11400 {
		t.Error("lenientOSPFAreaInterface11400 is false in " +
			"lenientCompileOpts(): protocol-scope downgrade not registered")
	}
	// The allowlisted suppress* bools are in fact set true today; pin
	// that so the allowlist entry cannot quietly become the place a
	// forgotten registration hides. Removing one from
	// lenientCompileOpts() must fail here, not pass via the allowlist.
	if !opts.suppressClusterNTPAdvisory || !opts.suppressContestedTrunkZoneAdvisory ||
		!opts.suppressDPDThresholdIKEv2Advisory || !opts.suppressFabricStampAdvisory ||
		!opts.suppressSSHUnmanagedAdvisory16737 {
		t.Error("a suppress* advisory bool is false in lenientCompileOpts(): the tolerant " +
			"paths would re-fire commit-time advisories on every boot / peer sync; " +
			"restore its `o.<field> = true` entry in lenientCompileOpts()")
	}
	if !opts.tolerant {
		t.Error("tolerant is false in lenientCompileOpts(): mode queries (#17153) would read strict on the tolerant path; restore its `true` entry")
	}
	if opts.skipCompactNormalize {
		t.Error("skipCompactNormalize is true in lenientCompileOpts(): the tolerant path " +
			"must run the compact normalizer (#8690 seam is test-only)")
	}
	if opts.nodeID != nil {
		t.Error("nodeID is non-nil in lenientCompileOpts(): node identity must come only " +
			"from compileTree's per-call stamp (#4329/#17157)")
	}
}

// TestLenientCompileOptsHaveReaders17143 is the reverse arm (#17143):
// every lenient*/sanitize*/suppress* bool reachable from compileOpts
// must have at least one selector read (X.<field>) in a non-test
// pkg/config/*.go file other than compiler_opts.go (which only declares
// the field and sets it in lenientCompileOpts()). A field with zero
// such readers is dead: its gate was retired or never wired, and the
// links 1-2 arm above would otherwise certify it forever merely for
// being present and true — exactly how lenientLoginClassDeny survived
// the #7172 cut-6 retirement of its gate.
//
// Method follows issue #17143 step 4: collect the field population by
// reflecting over lenientCompileOpts() (so any embedded-struct
// members are included under their leaf names), then
// use go/parser over the production sources to collect every
// SelectorExpr whose Sel is one of those names. Selector collection is
// deliberately name-based, not type-based: a same-named selector on an
// unrelated type would mask a dead field, but no such collision exists
// in this package for this population, and the census floors below
// fail loudly if the parse stops reaching the sources. Composite-
// literal keys in compiler_opts.go (field: true) are KeyValueExpr
// idents, not selectors, so excluding that one file removes both the
// declaration and the registration from the reader set.
func TestLenientCompileOptsHaveReaders17143(t *testing.T) {
	opts := lenientCompileOpts()
	fields := map[string]bool{}
	walkBoolFields16166(reflect.ValueOf(opts), "", func(path string, fv reflect.Value) {
		leaf := path[strings.LastIndex(path, ".")+1:]
		if strings.HasPrefix(leaf, "lenient") || strings.HasPrefix(leaf, "sanitize") ||
			strings.HasPrefix(leaf, "suppress") {
			fields[leaf] = true
		}
	})
	// Census floor: the population must be the ~330 downgrade/advisory
	// bools this arm claims to police. A collapsed walk green here
	// would be worse than no arm.
	if len(fields) < 250 {
		t.Fatalf("census: only %d lenient*/sanitize*/suppress* bools reached; "+
			"the walk is not reaching the compileOpts population", len(fields))
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.): %v", err)
	}
	fset := token.NewFileSet()
	readers := map[string]int{}
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") ||
			name == "compiler_opts.go" {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && fields[sel.Sel.Name] {
				readers[sel.Sel.Name]++
			}
			return true
		})
	}
	if files < 100 {
		t.Fatalf("parsed only %d production files; the reader census is not reaching pkg/config", files)
	}
	if len(readers) < 250 {
		t.Fatalf("only %d of %d lenient*/sanitize*/suppress* fields have any selector read; "+
			"the selector census is mis-parsing the package source", len(readers), len(fields))
	}

	var dead []string
	for name := range fields {
		if readers[name] == 0 {
			dead = append(dead, name)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf("%d lenient*/sanitize*/suppress* compileOpts field(s) have no reader "+
			"outside compiler_opts.go — the field is dead (its gate was retired or "+
			"never wired) and must be deleted with its lenientCompileOpts() entry, "+
			"not left certified by the links 1-2 arm: %s",
			len(dead), strings.Join(dead, ", "))
	}
}

// TestLenientCompletenessWalkRecurses16166 proves the walk itself
// recurses into embedded structs, independent of the current field
// population: a planted lenient bool inside an embedded struct that
// is left false must be reported. compileOpts itself has had no
// embedded struct since #17168, so this planted shape is the only
// thing keeping the walk's recursion honest: without this arm, a
// future refactor that flattened the walk to direct fields — and a
// future re-embedding of lenient flags — would keep the completeness
// test green while missing the embedded pair, the exact failure the
// Codex dissent on #16166 called out.
func TestLenientCompletenessWalkRecurses16166(t *testing.T) {
	type plantedEmbedded struct {
		lenientPlantedEmbedded16166 bool
		lenientPlantedSet16166      bool
	}
	type plantedRoot struct {
		lenientPlantedDirect16166 bool
		plantedEmbedded
	}
	root := plantedRoot{plantedEmbedded: plantedEmbedded{lenientPlantedSet16166: true}}

	var seen []string
	var falseDowngrades []string
	walkBoolFields16166(reflect.ValueOf(root), "", func(path string, fv reflect.Value) {
		seen = append(seen, path)
		name := path[strings.LastIndex(path, ".")+1:]
		if (strings.HasPrefix(name, "lenient") || strings.HasPrefix(name, "sanitize")) && !fv.Bool() {
			falseDowngrades = append(falseDowngrades, path)
		}
	})

	wantSeen := map[string]bool{
		"lenientPlantedDirect16166":                   false,
		"plantedEmbedded.lenientPlantedEmbedded16166": false,
		"plantedEmbedded.lenientPlantedSet16166":      false,
	}
	for _, p := range seen {
		if _, ok := wantSeen[p]; ok {
			wantSeen[p] = true
		} else {
			t.Errorf("walk visited unexpected field %s", p)
		}
	}
	for p, found := range wantSeen {
		if !found {
			t.Errorf("walk did not visit %s; visited %v (recursion into embedded structs is broken)", p, seen)
		}
	}
	if len(falseDowngrades) != 2 {
		t.Errorf("false-downgrade detection = %v, want the unset direct and embedded planted fields", falseDowngrades)
	}
}

// TestLenientCompletenessWalkPointerEmbedded16166 proves the walk
// traverses POINTER-embedded structs — the shape the value-only walker
// silently skipped (scratch-proven false negative on the first head).
// Non-nil: live values are read (a set bool reads true, an unset
// lenient bool is reported false). Nil: the type fallback reports the
// pointed-to bools as false, so a nil pointer can never hide an
// unregistered downgrade. A self-referential pointer cycle must
// terminate without double-visiting.
func TestLenientCompletenessWalkPointerEmbedded16166(t *testing.T) {
	type plantedPtrEmbedded struct {
		lenientPlantedPtrEmbedded16166 bool
		lenientPlantedPtrSet16166      bool
	}
	type plantedPtrRoot struct {
		*plantedPtrEmbedded
	}
	collect := func(root plantedPtrRoot) (seen map[string]bool, falseDown []string) {
		seen = map[string]bool{}
		walkBoolFields16166(reflect.ValueOf(root), "", func(path string, fv reflect.Value) {
			if _, dup := seen[path]; dup {
				t.Errorf("walk visited %s twice", path)
			}
			seen[path] = fv.Bool()
			leaf := path[strings.LastIndex(path, ".")+1:]
			if strings.HasPrefix(leaf, "lenient") && !fv.Bool() {
				falseDown = append(falseDown, path)
			}
		})
		return seen, falseDown
	}

	// Non-nil pointer-embedded: set reads true, unset reported.
	seen, falseDown := collect(plantedPtrRoot{plantedPtrEmbedded: &plantedPtrEmbedded{lenientPlantedPtrSet16166: true}})
	if len(seen) != 2 {
		t.Fatalf("non-nil pointer-embedded: visited %v, want both planted fields", seen)
	}
	if !seen["plantedPtrEmbedded.lenientPlantedPtrSet16166"] {
		t.Errorf("non-nil pointer-embedded: lenientPlantedPtrSet16166 read false, want true (live value not read); visited %v", seen)
	}
	if len(falseDown) != 1 || falseDown[0] != "plantedPtrEmbedded.lenientPlantedPtrEmbedded16166" {
		t.Errorf("non-nil pointer-embedded: false downgrades = %v, want [plantedPtrEmbedded.lenientPlantedPtrEmbedded16166]", falseDown)
	}

	// Nil pointer-embedded: type fallback must still surface both
	// fields as false — never a silent skip.
	seen, falseDown = collect(plantedPtrRoot{})
	if len(seen) != 2 {
		t.Fatalf("nil pointer-embedded: visited %v, want both planted fields via type fallback", seen)
	}
	if len(falseDown) != 2 {
		t.Errorf("nil pointer-embedded: false downgrades = %v, want both planted fields reported false", falseDown)
	}

	// Cycle: a self-referential struct linked to itself must terminate
	// and visit its bool once.
	type plantedCycle struct {
		lenientPlantedCycle16166 bool
		next                     *plantedCycle
	}
	node := &plantedCycle{}
	node.next = node
	visits := 0
	walkBoolFields16166(reflect.ValueOf(node), "", func(path string, fv reflect.Value) {
		visits++
		if path != "lenientPlantedCycle16166" {
			t.Errorf("cycle walk visited unexpected %s", path)
		}
	})
	if visits != 1 {
		t.Errorf("cycle walk visited bool %d times, want 1 (visited-pointer guard)", visits)
	}

	// Nil self-referential type: type fallback must also terminate.
	type plantedNilCycle struct {
		lenientPlantedNilCycle16166 bool
		next                        *plantedNilCycle
	}
	nilPaths := map[string]bool{}
	walkBoolFields16166(reflect.ValueOf(plantedNilCycle{}), "", func(path string, fv reflect.Value) {
		if nilPaths[path] {
			t.Errorf("nil-cycle walk visited %s twice", path)
		}
		nilPaths[path] = true
		if fv.Bool() {
			t.Errorf("nil-cycle walk reported %s true, want live false at root and false type-fallback under next", path)
		}
	})
	// Root bool (live) plus the same bool under the nil `next` pointer
	// (type fallback, distinct path): two distinct paths, each once,
	// and the visited-type guard stops next.next.* expansion.
	if len(nilPaths) != 2 || !nilPaths["lenientPlantedNilCycle16166"] || !nilPaths["next.lenientPlantedNilCycle16166"] {
		t.Errorf("nil-cycle walk visited %v, want root + next.* exactly once each (visited-type guard)", nilPaths)
	}
}

// TestLenientCompletenessAllowlistFullPath16166 proves — through the
// shared classifyLenientBool16166 used by the completeness test, not a
// re-implementation — that classification is by full dotted path: a
// nested bool whose leaf name collides with an allowlisted root field
// ("skipCompactNormalize") must classify unclassified, while the root
// field classifies allowlisted. Mutating classifyLenientBool16166's
// allowlist lookup to leaf-name matching turns this test RED (the
// nested path would classify allowlisted).
func TestLenientCompletenessAllowlistFullPath16166(t *testing.T) {
	type plantedNested struct {
		skipCompactNormalize bool
	}
	type plantedRoot struct {
		plantedNested
	}
	var classified []string
	walkBoolFields16166(reflect.ValueOf(plantedRoot{}), "", func(path string, fv reflect.Value) {
		classified = append(classified, classifyLenientBool16166(path).String()+":"+path)
	})
	want := "unclassified:plantedNested.skipCompactNormalize"
	if len(classified) != 1 || classified[0] != want {
		t.Errorf("nested leaf-name collision classified as %v, want [%s] (full-path allowlist via classifyLenientBool16166)", classified, want)
	}
	// The genuine root field IS allowlisted through the same func.
	if got := classifyLenientBool16166("skipCompactNormalize"); got != lenientClassAllowlisted16166 {
		t.Errorf("classifyLenientBool16166(%q) = %s, want allowlisted", "skipCompactNormalize", got)
	}
	// And a nested lenient* leaf still classifies as a downgrade
	// wherever it nests (leaf detection through the same func).
	if got := classifyLenientBool16166("plantedNested.lenientPlanted16166"); got != lenientClassDowngrade16166 {
		t.Errorf("classifyLenientBool16166(%q) = %s, want downgrade", "plantedNested.lenientPlanted16166", got)
	}
}

// collectPointerToMapFields17157 returns the dotted paths of every
// *map[...] field reachable from struct type t, recursing into
// embedded and named struct fields and through pointer-to-struct
// fields (the walkBoolFieldsRec16166 traversal shape). It is purely
// type-driven, so a nil pointer-to-struct in any instance can never
// hide a nested field. Recursion is bounded per PATH, not per type:
// the same nested type reached under two different field paths is
// walked under both (a *map hidden under either path must red), and
// only a type already on the current path stops the descent, which
// terminates self-referential types (and matches the bool walk's
// distinct-path reporting under a nil self-pointer).
func collectPointerToMapFields17157(t reflect.Type, path string, pathTypes map[reflect.Type]bool, offenders *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || pathTypes[t] {
		return
	}
	pathTypes[t] = true
	defer delete(pathTypes, t)
	for i := range t.NumField() {
		sf := t.Field(i)
		p := sf.Name
		if path != "" {
			p = path + "." + sf.Name
		}
		ft := sf.Type
		if ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Map {
			*offenders = append(*offenders, p+" "+ft.String())
			continue
		}
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			collectPointerToMapFields17157(ft, p, pathTypes, offenders)
		}
	}
}

// pointerToMapFields17157 returns the dotted paths of every
// *map[...] field anywhere in the type graph rooted at t.
func pointerToMapFields17157(t reflect.Type) []string {
	var offenders []string
	collectPointerToMapFields17157(t, "", map[reflect.Type]bool{}, &offenders)
	return offenders
}

// TestCompileOptsShape17157 is the #17157 acceptance guard: compileOpts
// must carry NO pointer-to-map fields (the pre-#17157
// *map[string]struct{} out-parameters that runPreWalkGates wrote
// through while also returning values), and the #16166 allowlist must
// not carry a nodeAware entry (node identity derives from
// opts.nodeID != nil, compileTree's own selector).
//
// The no-*map check recurses through embedded and nested struct
// fields (including pointer-to-struct fields such as
// currentClusterAccepted16858), following the walkBoolFieldsRec16166
// pattern: a *map[...] field hidden inside any nested struct is an
// offender, not just a direct field.
//
// FAIL-ON-REVERT: re-adding `applicationNameCollisions
// *map[string]struct{}` (or any *map[...] field, direct or nested) to
// compileOpts turns this RED, as does re-adding a "nodeAware" key to
// lenientCompletenessAllowlist16166.
func TestCompileOptsShape17157(t *testing.T) {
	// Mutant-proof the recursion itself, independent of the current
	// field population: a planted *map[...] field inside an embedded
	// struct and inside a pointer-to-struct field must both be
	// reported under their dotted paths, while a plain (non-pointer)
	// map field must NOT be reported. A walk flattened to direct
	// fields would report only the direct offender and turn this RED.
	type plantedNested17157 struct {
		plantedPtrMap *map[string]struct{}
	}
	type plantedRoot17157 struct {
		directPtrMap *map[string]int
		plainMap     map[string]bool
		plantedNested17157
		nestedPtr *plantedNested17157
		self      *plantedRoot17157
	}
	got := pointerToMapFields17157(reflect.TypeOf(plantedRoot17157{}))
	sort.Strings(got)
	want := []string{
		"directPtrMap *map[string]int",
		"nestedPtr.plantedPtrMap *map[string]struct {}",
		"plantedNested17157.plantedPtrMap *map[string]struct {}",
	}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("pointerToMapFields17157(plantedRoot17157) = %v, want %v "+
			"(recursion into embedded/nested/pointer-to-struct fields is broken)", got, want)
	}

	if offenders := pointerToMapFields17157(reflect.TypeOf(compileOpts{})); len(offenders) > 0 {
		t.Errorf("compileOpts has pointer-to-map field(s) %s: phase results must return "+
			"as ordinary return values (preWalkResult), never through pointer "+
			"out-parameters on compileOpts (#17157)", strings.Join(offenders, ", "))
	}
	if _, ok := lenientCompletenessAllowlist16166["nodeAware"]; ok {
		t.Error("lenientCompletenessAllowlist16166 still carries \"nodeAware\": node identity " +
			"derives from opts.nodeID != nil (#4329/#17157); the parallel bool must not " +
			"re-enter the allowlist")
	}
	if _, ok := reflect.TypeOf(compileOpts{}).FieldByName("nodeAware"); ok {
		t.Error("compileOpts still has a nodeAware field: node identity derives from " +
			"opts.nodeID != nil (#17157)")
	}
	if _, ok := reflect.TypeOf(compileOpts{}).FieldByName("stampNodeID"); ok {
		t.Error("compileOpts still has a stampNodeID field: node identity derives from " +
			"opts.nodeID != nil (#17157)")
	}
	if _, ok := reflect.TypeOf(compileOpts{}).FieldByName("nodeID"); !ok {
		t.Error("compileOpts has no nodeID field: compileTree must thread its *int " +
			"selector through compileOpts.nodeID (#17157)")
	}
}
