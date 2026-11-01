package configstore

import (
	"strings"
	"testing"
)

// #18719: the #10105 fabric zone-stamp reminder is change-scoped on the
// operator commit path. It prints on the commit that adds or changes the
// fabric, not on later unrelated commits, and `commit check` reports it
// whenever its condition holds.

const fabricZoneStampMarker18719 = "fabric zone stamp (#10105)"

func hasWarning18719(warnings []string, marker string) bool {
	for _, w := range warnings {
		if strings.Contains(w, marker) {
			return true
		}
	}
	return false
}

func set18719(t *testing.T, s *Store, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
}

func commitWarnings18719(t *testing.T, s *Store) []string {
	t.Helper()
	compiled, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return compiled.Warnings
}

func TestCommitScopesFabricZoneStampReminder18719(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	set18719(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
	)
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("the commit that adds the fabric must print the reminder; warnings=%v", w)
	}

	set18719(t, s, "system host-name unrelated-change")
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("an unrelated commit must not repeat the reminder; warnings=%v", w)
	}

	// commit check is not scoped: it reports the reminder while the fabric
	// is unattested, even though nothing about the fabric is staged.
	set18719(t, s, "system host-name another-unrelated-change")
	checked, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	if !hasWarning18719(checked.Warnings, fabricZoneStampMarker18719) {
		t.Fatalf("commit check must report the reminder; warnings=%v", checked.Warnings)
	}
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("the commit after the check is still unrelated; warnings=%v", w)
	}

	set18719(t, s, "chassis cluster fabric-peer-address 10.99.1.2")
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("a commit that changes the fabric must print the reminder; warnings=%v", w)
	}

	set18719(t, s, "chassis cluster fabric-interface-authenticated")
	if w := commitWarnings18719(t, s); hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("an attested fabric must not print the reminder; warnings=%v", w)
	}
	checked, err = s.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	if hasWarning18719(checked.Warnings, fabricZoneStampMarker18719) {
		t.Fatalf("commit check must not report an attested fabric; warnings=%v", checked.Warnings)
	}
}

// The commit-confirmed path compiles at its own site; it is scoped too.
func TestCommitConfirmedScopesFabricZoneStampReminder18719(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	set18719(t, s,
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
	)
	if w := commitWarnings18719(t, s); !hasWarning18719(w, fabricZoneStampMarker18719) {
		t.Fatalf("precondition: the adding commit prints the reminder; warnings=%v", w)
	}
	set18719(t, s, "system host-name unrelated-change")
	compiled, err := s.CommitConfirmed(5)
	if err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	t.Cleanup(func() { _ = s.ConfirmCommit() })
	if hasWarning18719(compiled.Warnings, fabricZoneStampMarker18719) {
		t.Fatalf("an unrelated commit confirmed must not repeat the reminder; warnings=%v", compiled.Warnings)
	}
}
