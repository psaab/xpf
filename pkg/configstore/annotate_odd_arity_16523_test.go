package configstore

import (
	"strings"
	"testing"
)

// #16523 store-level round-trip: an annotated 3-key address-book leaf
// exports through ShowCandidateSet (FormatSet) as
// `annotate security address-book global address a1 10.0.0.1/32 "..."`.
// Replaying that exact output through LoadSet — and the same annotate
// line through LoadMerge (flat replay) and hierarchical LoadMerge
// (comment attached in braces) — must succeed and land the annotation on
// a1 only. Before the fix AnnotatePath resolved through the
// pair-consuming display walker, which cannot consume the trailing
// 10.0.0.1/32 token, so every one of these loads aborted atomically with
// "path not found". RED on revert of the AnnotatePath fix.

const ann16523 = `annotate security address-book global address a1 10.0.0.1/32 "note-a1"`

func seed16523(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, in := range []string{
		"security address-book global address a1 10.0.0.1/32",
		"security address-book global address a2 10.0.0.2/32",
	} {
		if err := s.SetFromInput(in); err != nil {
			t.Fatalf("SetFromInput(%q): %v", in, err)
		}
	}
	if err := s.Annotate(
		[]string{"security", "address-book", "global", "address", "a1", "10.0.0.1/32"},
		"note-a1",
	); err != nil {
		t.Fatalf("Annotate(full 3-key identity): %v", err)
	}
	return s
}

func TestLoadSetDisplaySetRoundTrip16523(t *testing.T) {
	src := seed16523(t)
	exported := src.ShowCandidateSet()
	if !strings.Contains(exported, ann16523) {
		t.Fatalf("exported display-set missing %q:\n%s", ann16523, exported)
	}

	dst := newTestStore(t)
	if err := dst.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := dst.LoadSet(exported); err != nil {
		t.Fatalf("LoadSet(display set output): %v\n%s", err, exported)
	}
	hier := dst.ShowCandidate()
	if !strings.Contains(hier, "/* note-a1 */") {
		t.Errorf("loaded candidate missing annotation:\n%s", hier)
	}
	// The annotation must be on a1, not a2: re-export and check exactly
	// one annotate line, for a1.
	re := dst.ShowCandidateSet()
	if !strings.Contains(re, ann16523) {
		t.Errorf("re-export missing %q:\n%s", ann16523, re)
	}
	if strings.Contains(re, "address a2 10.0.0.2/32 \"note-a1\"") {
		t.Errorf("annotation landed on a2:\n%s", re)
	}
	if n := strings.Count(re, "annotate "); n != 1 {
		t.Errorf("re-export has %d annotate lines, want 1:\n%s", n, re)
	}
}

func TestLoadMergeAnnotateOddArity16523(t *testing.T) {
	// Flat load merge: set lines plus the annotate line.
	flat := newTestStore(t)
	if err := flat.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	flatBody := "set security address-book global address a1 10.0.0.1/32\n" +
		"set security address-book global address a2 10.0.0.2/32\n" +
		ann16523 + "\n"
	if err := flat.LoadMerge(flatBody); err != nil {
		t.Fatalf("LoadMerge(flat with annotate): %v", err)
	}
	if out := flat.ShowCandidateSet(); !strings.Contains(out, ann16523) {
		t.Errorf("flat LoadMerge lost annotation:\n%s", out)
	}

	// Hierarchical load merge: the comment rides in as /* ... */ before
	// the statement and must survive to a re-exported annotate line.
	hier := newTestStore(t)
	if err := hier.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	hierBody := "security {\n    address-book {\n        global {\n" +
		"            /* note-a1 */\n            address a1 10.0.0.1/32;\n" +
		"            address a2 10.0.0.2/32;\n        }\n    }\n}\n"
	if err := hier.LoadMerge(hierBody); err != nil {
		t.Fatalf("LoadMerge(hierarchical commented): %v", err)
	}
	if out := hier.ShowCandidateSet(); !strings.Contains(out, ann16523) {
		t.Errorf("hierarchical LoadMerge lost annotation:\n%s", out)
	}
}
