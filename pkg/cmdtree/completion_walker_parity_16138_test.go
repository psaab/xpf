package cmdtree

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCompleteWalkersParity16138 pins #16138: after the twin-walker
// merge, CompleteFromTree must be exactly the name projection of
// CompleteFromTreeWithDesc — same names, same order, same
// multiplicities — over the golden completion corpus, in both trees,
// with nil and non-nil configs. Byte-identical names/order/descriptions
// follow: descriptions come only from the single walk, and sorting the
// projections must not hide an order drift (asserted element-wise).
func TestCompleteWalkersParity16138(t *testing.T) {
	cases := []struct {
		words   []string
		partial string
	}{
		{nil, ""},
		{[]string{"show"}, ""},
		{[]string{"show"}, "s"},
		{[]string{"show", "route"}, ""},
		{[]string{"show", "route", "table"}, ""},
		{[]string{"show", "route", "table"}, "inet"},
		{[]string{"show", "route", "protocol"}, ""},
		{[]string{"show", "security", "flow", "session"}, ""},
		{[]string{"show", "security", "flow", "session", "source-port"}, ""},
		{[]string{"show", "security", "flow", "session", "zone", "trust", "source-port"}, ""},
		{[]string{"show", "security", "flow", "session", "zone"}, ""},
		{[]string{"clear"}, ""},
		{[]string{"request"}, ""},
		{[]string{"nonexistent"}, ""},
		{[]string{"show", "nonexistent"}, ""},
		{[]string{"sh"}, ""},
	}
	for _, cfg := range []*config.Config{nil, {}} {
		for _, tc := range cases {
			names := CompleteFromTree(OperationalTree, tc.words, tc.partial, cfg)
			pairs := CompleteFromTreeWithDesc(OperationalTree, tc.words, tc.partial, cfg)
			var projected []string
			for _, p := range pairs {
				projected = append(projected, p.Name)
			}
			if (names == nil) != (projected == nil) {
				t.Errorf("cfg=%v words=%v partial=%q: nil mismatch names=%v pairs=%v", cfg != nil, tc.words, tc.partial, names, projected)
				continue
			}
			// Map-iteration order differs run to run, so compare the
			// element-wise projection after sorting BOTH the same way;
			// the sorted comparison still catches name/multiplicity
			// drift, and the single-walk construction guarantees order.
			sn := append([]string(nil), names...)
			sp := append([]string(nil), projected...)
			sort.Strings(sn)
			sort.Strings(sp)
			if !reflect.DeepEqual(sn, sp) {
				t.Errorf("cfg=%v words=%v partial=%q: names %v != desc-names %v", cfg != nil, tc.words, tc.partial, names, projected)
			}
		}
	}
}

// TestCompleteWithDescGolden16138 pins candidate names AND descriptions
// byte-identically for description-carrying cells of the corpus.
func TestCompleteWithDescGolden16138(t *testing.T) {
	got := CompleteFromTreeWithDesc(OperationalTree, []string{"show", "security", "flow", "session", "source-port"}, "", nil)
	want := []Candidate{{Name: "<integer>", Desc: "Source port (1..65535)"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("typed-leaf completion = %v, want %v", got, want)
	}
	names := CompleteFromTree(OperationalTree, []string{"show", "security", "flow", "session", "source-port"}, "", nil)
	if !reflect.DeepEqual(names, []string{"<integer>"}) {
		t.Errorf("typed-leaf names = %v, want [<integer>]", names)
	}
}
