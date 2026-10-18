package configstore

import (
	"strings"
	"testing"
)

// #7527: LoadOverride parsed flat set-command input as hierarchical junk and
// then ATOMICALLY REPLACED the candidate with it, returning nil.
//
// The parser treats newlines as whitespace, so a flat script did not fail to
// parse — it collapsed into ONE top-level node whose key path was the entire
// file. Measured before the fix:
//
//	in:  "set system host-name probe-a\nset system domain-name example.net"
//	out: set set system host-name probe-a set system domain-name example.net
//	err: <nil>
//
// The whole candidate became that. Both the CLI and the RPC printed success.
//
// It is reachable through an ordinary workflow, not a contrived one:
// `show configuration | display set > backup.txt` then
// `load override backup.txt`. `load set` accepts only `terminal`, so there was
// no file-based path for flat input at all — and the one an operator would
// naturally reach for destroyed the candidate silently.
func TestLoadOverrideAcceptsFlatSetScript7527(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("set system host-name flat-a\nset system domain-name example.net\n"); err != nil {
		t.Fatalf("LoadOverride(flat set script) = %v, want success", err)
	}
	got := s.ShowCandidateSet()

	// The junk node is the defect's signature: a top-level key literally named
	// `set`, carrying the rest of the file. Assert on the RENDER rather than on
	// an error, because before the fix there was no error to assert on.
	if strings.Contains(got, "set set ") {
		t.Fatalf("the flat script was parsed as hierarchical junk — one top-level "+
			"node named `set` holding the whole file (#7527):\n%s", got)
	}
	for _, want := range []string{
		"set system host-name flat-a",
		"set system domain-name example.net",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("candidate is missing %q after loading a flat script:\n%s", want, got)
		}
	}
}

// OVERRIDE, not merge. The starting tree is the whole distinction between the
// two verbs, and replaying flat lines onto a CLONE of the candidate — the
// obvious way to reuse LoadMerge's body — would silently turn `load override`
// into `load merge`. Every gate above still passes in that world.
func TestLoadOverrideFlatReplacesRatherThanMerges7527(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet("set system host-name old-name\nset system domain-name old.example\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !strings.Contains(s.ShowCandidateSet(), "old.example") {
		t.Fatal("seed did not take; nothing below distinguishes override from merge")
	}

	if err := s.LoadOverride("set system host-name new-name\n"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	got := s.ShowCandidateSet()
	if strings.Contains(got, "old.example") {
		t.Errorf("`old.example` survived an OVERRIDE — the flat replay is merging "+
			"into the existing candidate instead of replacing it, which makes "+
			"`load override` a second spelling of `load merge` (#7527):\n%s", got)
	}
	if !strings.Contains(got, "new-name") {
		t.Errorf("the override's own content is missing:\n%s", got)
	}
}

// The HIERARCHICAL path must be untouched. This is the case that worked, and
// the one every existing caller uses; a classifier that swallowed it would
// break far more than the defect being fixed.
func TestLoadOverrideStillAcceptsHierarchical7527(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	hier := "system {\n    host-name hier-a;\n    domain-name hier.example;\n}\n"
	if err := s.LoadOverride(hier); err != nil {
		t.Fatalf("LoadOverride(hierarchical) = %v, want success", err)
	}
	got := s.ShowCandidateSet()
	for _, want := range []string{"set system host-name hier-a", "set system domain-name hier.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("hierarchical override lost %q:\n%s", want, got)
		}
	}
}

// MISCLASSIFICATION FAILS LOUD. This is what makes accepting flat input the
// bounded choice: if a file were mistaken for flat, the first line without a
// recognized verb is an ERROR, never a silently wrong candidate. Without this
// the fix would trade a silent-junk failure for a different silent-junk
// failure one layer down — ParseSetVerb treats free text as a bare `set` path.
func TestLoadOverrideFlatRejectsAStraySettingLine7527(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet("set system host-name preserved\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := s.ShowCandidateSet()

	err := s.LoadOverride("set system host-name a\nnot-a-set-line\nset system domain-name b\n")
	if err == nil {
		t.Fatal("a flat script containing a line with no verb was ACCEPTED; that line " +
			"materializes a junk top-level node, which is the same class of defect " +
			"one layer down (#7527/#3442 M3)")
	}
	if strings.Contains(err.Error(), "not-a-set-line") {
		t.Errorf("the error echoes the offending line (#14718, coordinates only): %v", err)
	} else if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error does not retain the line coordinate: %v", err)
	}

	// ATOMIC: a rejected override must leave the candidate byte-identical.
	// Replaying onto the tree in place and returning on the first bad line
	// would leave the earlier lines applied while the caller was told it
	// failed — a config nobody authored (#5187, same reason as the merge path).
	if after := s.ShowCandidateSet(); after != before {
		t.Errorf("a REJECTED override mutated the candidate:\nbefore:\n%s\nafter:\n%s",
			before, after)
	}
}

// A comment-and-blank-only flat file is not flat at all (no line carries a
// verb), so it takes the hierarchical path and yields an empty tree. Pinned
// because it is the boundary between the two branches, and because an empty
// override is a legitimate thing to ask for.
func TestLoadOverrideCommentsOnly7527(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet("set system host-name gone\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.LoadOverride("# just a comment\n\n"); err != nil {
		t.Fatalf("LoadOverride(comments only) = %v", err)
	}
	if got := s.ShowCandidateSet(); strings.Contains(got, "gone") {
		t.Errorf("an override with no statements did not replace the candidate:\n%s", got)
	}
}
