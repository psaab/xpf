package cmdtree

import (
	"reflect"
	"testing"
)

// #18664: the remote cli's #16798 gate (cmd/cli validateOperationalLine)
// validates only the words before the first bare `|`, then asks
// ValidateOperationalLine about the words up to and including that `|` to
// learn where the pipe sits. It relies on two properties pinned here:
//
//   - a `|` directly under a keyword-only node is reported as the trailing
//     bad token, with the node's canonical path as the prefix (the gate
//     admits it only for a command whose handler parses pipes);
//   - a `|` after a value slot, a leaf or an AcceptsArgs tail is NOT a
//     keyword-only failure (ok=false), so the gate leaves it to the handler.
//
// If ValidateOperationalLine ever started stripping pipes itself, the first
// property would break and the remote gate would hand `clear security |
// display set` to a help-printing handler that exits 0.
func TestValidateOperationalLinePipePosition18664(t *testing.T) {
	prefix, bad, ambiguous, ok := ValidateOperationalLine([]string{"show", "conf", "|"})
	if !ok || ambiguous || bad != "|" || !reflect.DeepEqual(prefix, []string{"show", "configuration"}) {
		t.Fatalf("pipe under keyword-only `show configuration` = (%v, %q, %v, %v); want ([show configuration], \"|\", false, true)",
			prefix, bad, ambiguous, ok)
	}
	for _, words := range [][]string{
		{"show", "configuration", "security", "|"},    // AcceptsArgs tail
		{"show", "system", "rollback", "1", "|"},      // AcceptsArgs value
		{"show", "chassis", "cluster", "status", "|"}, // leaf
		{"show", "interfaces", "|"},                   // dynamic value slot
	} {
		if prefix, bad, _, ok := ValidateOperationalLine(words); ok {
			t.Fatalf("ValidateOperationalLine(%v) = (%v, %q, ok=true); want ok=false (handler's domain)", words, prefix, bad)
		}
	}
}
