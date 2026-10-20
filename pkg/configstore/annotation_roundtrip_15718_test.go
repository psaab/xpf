package configstore

import (
	"strings"
	"testing"
)

// #15718: annotations round-trip through load set / load merge / commit diff.

func TestAnnotationLoadAndCompare15718(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadMerge("set system host-name fw1\nannotate system host-name \"primary fw\"\n"); err != nil {
		t.Fatalf("LoadMerge flat annotate: %v", err)
	}
	cand := s.ShowCandidate()
	if !strings.Contains(cand, "/* primary fw */") {
		t.Fatalf("candidate missing annotation after LoadMerge:\n%s", cand)
	}
	if diff := s.ShowCompare(); !strings.Contains(diff, "primary fw") {
		t.Errorf("ShowCompare hides annotation:\n%s", diff)
	}
	if summary := s.CommitDiffSummary(); summary == "" {
		t.Error("CommitDiffSummary empty for annotation-only change")
	}

	// LoadSet accepts annotate.
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure2: %v", err)
	}
	if _, err := s2.LoadSet("set system host-name fw1\nannotate system host-name \"via load set\"\n"); err != nil {
		t.Fatalf("LoadSet annotate: %v", err)
	}
	if !strings.Contains(s2.ShowCandidate(), "/* via load set */") {
		t.Errorf("LoadSet candidate missing annotation:\n%s", s2.ShowCandidate())
	}

	// Hierarchical LoadMerge with /* comment */ preserves annotation.
	s3 := newTestStore(t)
	if err := s3.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure3: %v", err)
	}
	if err := s3.LoadMerge("system {\n    /* hier note */\n    host-name fw1;\n}\n"); err != nil {
		t.Fatalf("LoadMerge hierarchical: %v", err)
	}
	if !strings.Contains(s3.ShowCandidate(), "/* hier note */") {
		t.Errorf("hierarchical LoadMerge lost annotation:\n%s", s3.ShowCandidate())
	}

	// display set round-trips back through LoadSet.
	setOut := s.ShowCandidateSet()
	s4 := newTestStore(t)
	if err := s4.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure4: %v", err)
	}
	if _, err := s4.LoadSet(setOut); err != nil {
		t.Fatalf("LoadSet(display set): %v\n%s", err, setOut)
	}
	if !strings.Contains(s4.ShowCandidate(), "/* primary fw */") {
		t.Errorf("display-set round-trip lost annotation:\n%s", s4.ShowCandidate())
	}

	// Invalid annotation text in flat load is rejected.
	s5 := newTestStore(t)
	if err := s5.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure5: %v", err)
	}
	if err := s5.LoadMerge("set system host-name fw1\nannotate system host-name \"bad */ inject\"\n"); err == nil {
		t.Error("LoadMerge accepted delimiter annotation")
	}
	// Annotate to missing path is rejected.
	if err := s5.LoadMerge("annotate system host-name \"x\"\n"); err == nil {
		t.Error("LoadMerge annotate missing path accepted")
	}
}
