package cmdtree

import (
	"slices"
	"testing"
)

// Both operator completion positions must include every configured classifier,
// including an entryless inet-precedence classifier (#9899).
func TestCoSClassifierCompletion9899(t *testing.T) {
	cfg := compileCoSSet6858(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service classifiers dscp dscp-9899 forwarding-class best-effort loss-priority low code-points 0",
		"set class-of-service classifiers ieee-802.1 pcp-9899 forwarding-class best-effort loss-priority low code-points 3",
		"set class-of-service classifiers inet-precedence prec-9899 forwarding-class voice loss-priority low code-points 5",
		"set class-of-service classifiers inet-precedence prec-empty-9899",
	)

	want := []string{"dscp-9899", "pcp-9899", "prec-9899", "prec-empty-9899"}
	for _, words := range [][]string{
		{"show", "class-of-service", "classifier"},
		{"show", "class-of-service", "classifier", "name"},
	} {
		got := CompleteFromTree(OperationalTree, words, "", cfg)
		for _, name := range want {
			if !slices.Contains(got, name) {
				t.Errorf("completion after %q omitted configured classifier %q: %q", words, name, got)
			}
		}
	}
}
