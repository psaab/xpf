package dataplane

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #7754: every in-package type that embeds discardingDataPlane must DECLARE
// which pass it presents as, with its own xpfValidationPass method.
//
// The defect this closes is silent inheritance. discardingDataPlane carries
// `xpfValidationPass() -> true` — load-bearing, because
// validateBeforeMutateWithResult REJECTS a dataplane without the marker, so the
// pre-pass cannot simply drop it. Go embedding is transitive, so ANY fixture
// embedding the shim to reuse its ~30 no-op methods silently inherits "I am the
// validation pre-pass" as well.
//
// That produced a fixture (recordingDP) that ran the REAL pass while the
// compiler believed it was the discarded one, and there is no symptom: no
// error, no warning, no count discrepancy. It was harmless only because no
// recordingDP test happened to assert on anything isValidationPass gates — and
// isValidationPass gates the compiler's log emission, which is exactly the
// class #6903 is about. The next log-sensitive test written on that fixture
// would have exercised the suppressed side, passed, and proved nothing.
//
// A census rather than a type-system fix because Go offers none: embedding is
// transitive by design, and splitting the marker into its own embeddable type
// would still be inherited through discardingDataPlane. What CAN be enforced is
// that the classification is stated rather than acquired, so a reviewer reading
// a new fixture sees which pass it is without tracing an embedding chain.
func TestEveryDiscardingDataPlaneEmbedderDeclaresItsPass7754(t *testing.T) {
	// The declared classification of each embedder. A new fixture that embeds
	// discardingDataPlane FAILS here until it is added, which is the point: the
	// author has to decide, and the reviewer can see the decision.
	declared := map[string]string{
		"recordingDP":                "real",    // asserts host mutation; must not be the pre-pass
		"failOneDP":                  "prepass", // probes the pre-pass's own phase bodies
		"notAValidationDP":           "real",    // exists to be REJECTED by the marker check
		"natWriteTripwireDP":         "either",  // parameterised by a field, both directions used
		"censusDP6903":               "real",    // #6903 record census needs the real pass
		"quarantineRecordingDP13164": "real",    // captures actual compile-pass behavior
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// A struct whose body embeds discardingDataPlane, in either layout:
	//   type X struct{ discardingDataPlane }
	//   type X struct {
	//           discardingDataPlane
	inline := regexp.MustCompile(`type\s+(\w+)\s+struct\{\s*discardingDataPlane\s*\}`)
	multiline := regexp.MustCompile(`type\s+(\w+)\s+struct\s*\{[^}]*\bdiscardingDataPlane\b`)

	found := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// Strip `//` comments before matching. This census caught its OWN doc
		// comment on the first run — the example `type X struct{
		// discardingDataPlane }` above matched and reported a fixture named
		// "X". A textual census that scans commentary reports the
		// documentation as findings, and the failure is confusing rather than
		// wrong-looking, so it costs a reader real time.
		var sb strings.Builder
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			sb.WriteString(line)
			sb.WriteString("\n")
		}
		src := sb.String()
		for _, re := range []*regexp.Regexp{inline, multiline} {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				found[m[1]] = true
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("census found NO types embedding discardingDataPlane — the " +
			"patterns no longer match the source, so this test is passing " +
			"vacuously and guarding nothing")
	}

	var undeclared, stale []string
	for name := range found {
		if _, ok := declared[name]; !ok {
			undeclared = append(undeclared, name)
		}
	}
	// Fails in BOTH directions: a declaration for a type that no longer exists
	// is stale permission, and leaving it rots the census into a list nobody
	// trusts.
	for name := range declared {
		if !found[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(undeclared)
	sort.Strings(stale)

	if len(undeclared) > 0 {
		t.Errorf("these types embed discardingDataPlane and therefore INHERIT "+
			"`xpfValidationPass() -> true` without saying so: %v\n"+
			"Give each an explicit `func (T) xpfValidationPass() bool` and add "+
			"it to the `declared` map above. A fixture that presents as the "+
			"pre-pass when its author meant the real pass runs a different "+
			"compiler path with NO symptom — see #7754.", undeclared)
	}
	if len(stale) > 0 {
		t.Errorf("declared but no longer present: %v — delete the entries", stale)
	}

	// Every declared embedder must actually carry its own override, not just an
	// entry in the map above. Without this the map is a comment.
	for name, class := range declared {
		if class == "either" {
			continue // parameterised by a field; the method exists, value varies
		}
		want := "func (" + name + ") xpfValidationPass() bool"
		wantPtr := "func (*" + name + ") xpfValidationPass() bool"
		var has bool
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if strings.Contains(string(b), want) || strings.Contains(string(b), wantPtr) {
				has = true
				break
			}
		}
		if !has {
			t.Errorf("%s is declared %q but has no explicit xpfValidationPass "+
				"method — it is inheriting the shim's `true`, which is the "+
				"defect this census exists to prevent", name, class)
		}
	}
}
