package cmdtree

import (
	"strings"
	"testing"
)

// TestSessionFilterNATAliasCanonicalizesOnShowAndClear_11831 pins the exact
// `nat` spelling accepted by both local session-filter parsers. Before #11831,
// the tree treated `nat` only as a unique prefix of `nat-only`, rewriting both
// commands to the other spelling instead of declaring the parser's alias.
func TestSessionFilterNATAliasCanonicalizesOnShowAndClear_11831(t *testing.T) {
	for _, command := range []string{
		"show security flow session nat",
		"clear security flow session nat",
	} {
		got, result := Canonicalize(OperationalTree, strings.Fields(command))
		if result != CanonicalOK {
			t.Errorf("Canonicalize(%q) result = %v, want CanonicalOK", command, result)
			continue
		}
		if canonical := strings.Join(got, " "); canonical != command {
			t.Errorf("Canonicalize(%q) = %q, want to preserve the nat alias", command, canonical)
		}
	}
}

// TestClearSessionFilterDoesNotExposeUnparsedLimit_11831 is the scope guard:
// the clear handler has no `limit` case, so its command tree must not advertise
// that token as an accepted option.
func TestClearSessionFilterDoesNotExposeUnparsedLimit_11831(t *testing.T) {
	command := "clear security flow session limit 5"
	if got, result := Canonicalize(OperationalTree, strings.Fields(command)); result == CanonicalOK {
		t.Errorf("Canonicalize(%q) = %q, want unrecognized (clear has no local limit parser case)", command, strings.Join(got, " "))
	}
}
