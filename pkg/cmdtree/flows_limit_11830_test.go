package cmdtree

import (
	"strings"
	"testing"
)

// #11830: the `show chassis cluster data-plane flows` dispatcher accepts three
// dispatcher-legal limit spellings via ParseFlowWorkerMapLimitSpec: `limit N`,
// bare `N`, and `limit=N`. The tree modelled `limit` as a bare leaf, so every
// spelling was CanonicalUnknown and a restricted login class was refused a
// lawful diagnostic outright (evaluateCommandRegex fails closed).
func TestFlowsLimitSpellingsCanonicalize11830(t *testing.T) {
	for _, command := range []string{
		"show chassis cluster data-plane flows limit 10",
		"show chassis cluster data-plane flows 10",
		"show chassis cluster data-plane flows limit=10",
		"show chassis cluster data-plane flows all",
	} {
		got, result := Canonicalize(OperationalTree, strings.Fields(command))
		if result != CanonicalOK {
			t.Errorf("Canonicalize(%q) result = %v, want CanonicalOK", command, result)
			continue
		}
		if canonical := strings.Join(got, " "); canonical != command {
			t.Errorf("Canonicalize(%q) = %q, want unchanged", command, canonical)
		}
	}
}

// The fix must stay narrow: a second word after the limit is not a
// dispatcher-legal selector (ParseFlowWorkerMapLimitSpec rejects 3+ fields),
// so it must still be refused — not absorbed as a sibling or value.
func TestFlowsLimitExtraWordStillRefused11830(t *testing.T) {
	for _, command := range []string{
		"show chassis cluster data-plane flows limit 10 extra",
		"show chassis cluster data-plane flows 10 extra",
		"show chassis cluster data-plane flows limit=10 extra",
	} {
		got, result := Canonicalize(OperationalTree, strings.Fields(command))
		if result != CanonicalUnknown {
			t.Errorf("Canonicalize(%q) = %q, result %v, want CanonicalUnknown", command, strings.Join(got, " "), result)
		}
	}
}
