package config

import (
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

// #16166 PR-0: completeness of the tolerant-path opt set.
//
// compileOpts carries ~300 lenient*/sanitize* severity-downgrade bools.
// Adding a gate requires the field (link 1) AND `field: true` in
// lenientCompileOpts() (link 2). Forgetting link 2 silently makes the
// tolerant load / peer-sync path strict for that gate — the #1960
// brick-the-boot class — and no compiler error catches it, because the
// zero value is a perfectly valid bool. Until now the invariant was
// enforced by reviewer vigilance only.
//
// This test enforces links 1-2 by construction: it reflects recursively
// over compileOpts (including the embedded protocolScopeOpts, whose two
// lenient bools a shallow NumField walk over compileOpts would miss,
// and any future pointer-embedded struct, traversed under the
// nil/cycle policy in walkBoolFields16166) and asserts every
// lenient*/sanitize* bool is true in lenientCompileOpts(). It does NOT
// enforce links 3-4 (gate call-site reads the right flag; warning/show
// surface) — that is the separately gated registry work, not PR-0.
//
// Scope is deliberately the name prefix, not "every bool": compileOpts
// also carries non-downgrade bools whose lenient value is not uniformly
// true (skipCompactNormalize is a test seam that must stay false so the
// normalizer runs on the tolerant path; nodeAware is stamped per call
// by the node-aware entry, overwriting whatever the literal held).
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
// root, "protocolScopeOpts.<field>" inside the embedded struct), never
// bare leaf names: a nested bool that happens to share an allowlisted
// leaf name does NOT inherit the exemption. Any bool neither prefixed
// lenient*/sanitize* (by leaf name) nor keyed here by full path fails
// the census arm of the test, so a new bool forces an explicit
// decision here.
var lenientCompletenessAllowlist16166 = map[string]string{
	// #8690 test seam: production and the tolerant path must run the
	// compact normalizer; only measurement tests set this.
	"skipCompactNormalize": "test seam (#8690); tolerant path must normalize",
	// #4329 runtime identity: compileConfigForNodeWithOpts stamps
	// nodeAware/stampNodeID per call after lenientCompileOpts() returns,
	// so the literal's value is never operative.
	"nodeAware": "stamped per call by the node-aware entry (#4329)",
	// Advisory suppressors: not severity downgrades (the checks warn on
	// every path), but they ARE set true in lenientCompileOpts() today.
	// Listed so the prefix census classifies them deliberately; the
	// truth arm also covers them via the extra check below.
	"suppressClusterNTPAdvisory":         "advisory suppressor (#8357), true in lenientCompileOpts",
	"suppressContestedTrunkZoneAdvisory": "advisory suppressor (#7509), true in lenientCompileOpts",
	"suppressDPDThresholdIKEv2Advisory":  "advisory suppressor (#15025), true in lenientCompileOpts",
	"suppressFabricStampAdvisory":        "advisory suppressor (#10105), true in lenientCompileOpts",
}

// walkBoolFields16166 visits every bool field reachable from v,
// recursing into embedded and nested struct fields AND through
// pointer-to-struct fields (embedded or named). path is the dotted
// field path from the root (e.g. "protocolScopeOpts.lenientOSPFAreaInterface11400").
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
					"older binary accepted would fail to boot (#1960). Add `%s: true` to "+
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
	// claims to police. A walk that silently visits nothing (or stops
	// recursing into the embedded protocolScopeOpts) would green while
	// missing exactly the class this test exists to catch, so pin the
	// embedded fields by name and require a plausible census. The floor
	// is deliberately below the current count (re-measured at
	// implementation: 298 lenient*/sanitize* bools, 296 direct in
	// compileOpts plus 2 in the embedded protocolScopeOpts) so removing
	// a retired gate does not flake this test, while a collapsed walk
	// (0, or 296-without-the-embedded-pair shape) still trips it via
	// the named pins below.
	if downgrades < 250 {
		t.Errorf("census: only %d lenient*/sanitize* bools reached by the recursive walk; "+
			"the walk is not reaching the compileOpts population (want ~298)", downgrades)
	}
	if others == 0 {
		t.Error("census: no allowlisted non-downgrade bools reached; the walk is not " +
			"reaching compileOpts fields such as skipCompactNormalize")
	}
	embedded := opts.protocolScopeOpts
	if !embedded.lenientProtocolInterfaceMembership11310 {
		t.Error("protocolScopeOpts.lenientProtocolInterfaceMembership11310 is false in " +
			"lenientCompileOpts(): embedded-struct downgrade not registered (recursion pin)")
	}
	if !embedded.lenientOSPFAreaInterface11400 {
		t.Error("protocolScopeOpts.lenientOSPFAreaInterface11400 is false in " +
			"lenientCompileOpts(): embedded-struct downgrade not registered (recursion pin)")
	}
	// The allowlisted suppress* bools are in fact set true today; pin
	// that so the allowlist entry cannot quietly become the place a
	// forgotten registration hides. Removing one from
	// lenientCompileOpts() must fail here, not pass via the allowlist.
	if !opts.suppressClusterNTPAdvisory || !opts.suppressContestedTrunkZoneAdvisory ||
		!opts.suppressDPDThresholdIKEv2Advisory || !opts.suppressFabricStampAdvisory {
		t.Error("a suppress* advisory bool is false in lenientCompileOpts(): the tolerant " +
			"paths would re-fire commit-time advisories on every boot / peer sync; " +
			"restore its `true` entry in lenientCompileOpts()")
	}
	if opts.skipCompactNormalize {
		t.Error("skipCompactNormalize is true in lenientCompileOpts(): the tolerant path " +
			"must run the compact normalizer (#8690 seam is test-only)")
	}
	if opts.nodeAware {
		t.Error("nodeAware is true in lenientCompileOpts(): node identity must come only " +
			"from the node-aware entry's per-call stamp (#4329)")
	}
}

// TestLenientCompletenessWalkRecurses16166 proves the walk itself
// recurses into embedded structs, independent of the current field
// population: a planted lenient bool inside a protocolScopeOpts-shaped
// embedded struct that is left false must be reported. Without this
// arm, a future refactor that flattened the walk to direct fields
// would keep the completeness test green while missing the embedded
// pair — the exact failure the Codex dissent on #16166 called out.
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
