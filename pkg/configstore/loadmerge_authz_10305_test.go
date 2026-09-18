package configstore

import (
	"strings"
	"testing"
)

// #10305 RED witness: the body that used to bypass the gate is deliberately
// accepted by the store's hierarchical branch, and the denied subtree lands in
// the candidate. The authorization gate must therefore classify the same body
// hierarchically and refuse it before calling LoadMergeAs.
func TestLoadMergeDivergentTriggerRoutesHierarchical10305(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	body := "annotate system host-name \"trigger10305\";\n" +
		"system { root-authentication { plain-text-password hunter2; } }\n"
	if err := s.LoadMerge(body); err != nil {
		t.Fatalf("LoadMerge rejected the hierarchical trigger body: %v", err)
	}
	got := s.ShowCandidateSet()
	if !strings.Contains(got, "set system root-authentication plain-text-password hunter2") {
		t.Fatalf("hierarchical store branch did not materialize the denied subtree:\n%s", got)
	}
}

// `load set` remains a flat-script operation and rejects the hierarchical
// trigger body rather than silently routing it through the merge parser.
func TestLoadSetStillRejectsHierarchicalTrigger10305(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	body := "annotate system host-name \"trigger10305\";\n" +
		"system { host-name allowed10305; }\n"
	if _, err := s.LoadSet(body); err == nil {
		t.Fatal("LoadSet accepted a hierarchical trigger body; load set must stay flat-only")
	}
}
