package configstore

import (
	"strings"
	"testing"
)

// Each operator commit compiles a FRESH *config.Config: no pointer reuse
// across commits, and no shared Warnings backing for a post-commit
// mutation to alias. The #9841 commit-warning sync appends to the
// committed config after the apply; per-commit object/storage ownership
// is what keeps a later commit's sync (or an in-flight response
// projection) from racing an earlier response.
func TestCommitCompilesFreshConfigEachTime9841(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name a"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	c1, err := s.Commit()
	if err != nil {
		t.Fatalf("commit 1: %v", err)
	}
	// Poison c1's warnings the way a post-commit sync would.
	c1.Warnings = append(c1.Warnings, "interface MTU not realized: probe (#9841)")
	if err := s.SetFromInput("system host-name b"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	c2, err := s.Commit()
	if err != nil {
		t.Fatalf("commit 2: %v", err)
	}
	if c1 == c2 {
		t.Fatalf("two commits returned the same *config.Config %p: commits must compile fresh", c1)
	}
	for _, w := range c2.Warnings {
		if strings.Contains(w, "(#9841)") {
			t.Fatalf("commit 2 inherited commit 1's post-commit line %q: Warnings storage is shared", w)
		}
	}
}
