package cmdtree

import (
	"strings"
	"testing"
)

// #15690: Junos inspects VRRP at the top level (`show vrrp`). The tree had
// only `show security vrrp`, so Canonicalize returned CanonicalUnknown for
// the top-level spelling and every regex-restricted login class was
// refused it. Both spellings must canonicalize; the neighbouring
// `show security vrrp` must not regress.
func TestCanonicalizeShowVRRP15690(t *testing.T) {
	for _, line := range []string{"show vrrp", "show security vrrp"} {
		got, res := Canonicalize(OperationalTree, strings.Fields(line))
		if res != CanonicalOK || strings.Join(got, " ") != line {
			t.Errorf("Canonicalize(%q) = %q (%v), want %q CanonicalOK; a regex-restricted "+
				"login class would be refused this lawful command", line, strings.Join(got, " "), res, line)
		}
		if !EveryWordIsAKeyword(OperationalTree, strings.Fields(line)) {
			t.Errorf("%q is not an argument-free keyword path in OperationalTree", line)
		}
	}
	// Abbreviation control: the unique prefix must resolve to the same node.
	got, res := Canonicalize(OperationalTree, []string{"show", "vr"})
	if res != CanonicalOK || strings.Join(got, " ") != "show vrrp" {
		t.Errorf("Canonicalize(show vr) = %q (%v), want \"show vrrp\" CanonicalOK", strings.Join(got, " "), res)
	}
}
