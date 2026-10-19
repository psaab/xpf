package cmdtree

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15720: an Options node's valued and flag options live in its Children map
// with nil Children of their own. CompleteFromTree, CompleteFromTreeWithDesc
// and LookupDesc used to return nil/""/a single value's candidates as soon as
// such a leaf was matched, instead of resuming among the remaining options
// the way Canonicalize (#9505) does. The `show security flow session` option
// map is the real-tree probe: typed (source-port), dynamic (zone), two-token
// subtree (sort-by bytes) and flag (nat) leaves must all leave every other
// option completable and describable, and `?` after an option keyword must
// offer that option's values.

func zoneCfg15720() *config.Config {
	return &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{"trust": {}, "untrust": {}},
	}}
}

func sortedStrings15720(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func candidateNames15720(in []Candidate) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, c.Name)
	}
	return out
}

func equalStrings15720(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sessionOptionNames15720 is the full `show security flow session` option map.
var sessionOptionNames15720 = []string{
	"application", "brief", "destination-port", "destination-prefix",
	"interface", "nat", "nat-only", "protocol", "sort-by", "source-nat-pool",
	"source-port", "source-prefix", "summary", "zone",
}

func TestCompleteAfterOptionLeaves15720(t *testing.T) {
	cfg := zoneCfg15720()
	for _, tc := range []struct {
		name  string
		words []string
		want  []string
	}{
		{"typed value consumed", []string{"show", "security", "flow", "session", "source-port", "514"}, sessionOptionNames15720},
		{"dynamic value consumed", []string{"show", "security", "flow", "session", "zone", "trust"}, sessionOptionNames15720},
		{"two-token subtree leaf consumed", []string{"show", "security", "flow", "session", "sort-by", "bytes"}, sessionOptionNames15720},
		{"flag leaf consumed", []string{"show", "security", "flow", "session", "nat"}, sessionOptionNames15720},
		{"placeholder value consumed", []string{"ping", "8.8.8.8", "count", "5"}, []string{"<host>", "count", "routing-instance", "size", "source"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sortedStrings15720(CompleteFromTree(OperationalTree, tc.words, "", cfg)); !equalStrings15720(got, tc.want) {
				t.Errorf("CompleteFromTree(%v) = %v, want %v", tc.words, got, tc.want)
			}
			if got := sortedStrings15720(candidateNames15720(CompleteFromTreeWithDesc(OperationalTree, tc.words, "", cfg))); !equalStrings15720(got, tc.want) {
				t.Errorf("CompleteFromTreeWithDesc(%v) = %v, want %v", tc.words, got, tc.want)
			}
		})
	}
}

func TestCompleteTypedAndDynamicValuesAfterOptionLeaves15720(t *testing.T) {
	cfg := zoneCfg15720()
	// A second option after a consumed first option must still offer its
	// own values: a dynamic option's configured values and a typed option's
	// placeholder.
	for _, words := range [][]string{
		{"show", "security", "flow", "session", "zone", "trust", "zone"},
		{"show", "security", "flow", "session", "source-port", "514", "zone"},
		{"show", "security", "flow", "session", "sort-by", "bytes", "zone"},
		{"show", "security", "flow", "session", "nat", "zone"},
	} {
		if got := sortedStrings15720(CompleteFromTree(OperationalTree, words, "", cfg)); !equalStrings15720(got, []string{"trust", "untrust"}) {
			t.Errorf("CompleteFromTree(%v) = %v, want [trust untrust]", words, got)
		}
		if got := candidateNames15720(CompleteFromTreeWithDesc(OperationalTree, words, "", cfg)); !equalStrings15720(sortedStrings15720(got), []string{"trust", "untrust"}) {
			t.Errorf("CompleteFromTreeWithDesc(%v) = %v, want [trust untrust]", words, got)
		}
	}
	if got := CompleteFromTreeWithDesc(OperationalTree,
		[]string{"show", "security", "flow", "session", "zone", "trust", "source-port"}, "", cfg); len(got) != 1 || got[0].Name != "<integer>" {
		t.Errorf("CompleteFromTreeWithDesc(after zone value, source-port) = %v, want [<integer>]", got)
	}
	// `?` at a typed/dynamic option keyword offers that option's values.
	if got := CompleteFromTreeWithDesc(OperationalTree,
		[]string{"show", "security", "flow", "session", "source-port"}, "", nil); len(got) != 1 || got[0].Name != "<integer>" {
		t.Errorf("CompleteFromTreeWithDesc(source-port) = %v, want [<integer>]", got)
	}
	if got := sortedStrings15720(CompleteFromTree(OperationalTree,
		[]string{"show", "security", "flow", "session", "zone"}, "", cfg)); !equalStrings15720(got, []string{"trust", "untrust"}) {
		t.Errorf("CompleteFromTree(zone) = %v, want [trust untrust]", got)
	}
	// Filtered partials still apply after a consumed option.
	if got := CompleteFromTree(OperationalTree,
		[]string{"show", "security", "flow", "session", "source-port", "514"}, "s", nil); !equalStrings15720(sortedStrings15720(got), []string{"sort-by", "source-nat-pool", "source-port", "source-prefix", "summary"}) {
		t.Errorf("CompleteFromTree(after source-port value, partial s) = %v", got)
	}
}

func TestLookupDescAfterOptionLeaves15720(t *testing.T) {
	for _, tc := range []struct {
		words []string
		name  string
		want  string
	}{
		{[]string{"show", "security", "flow", "session", "source-port", "514"}, "zone", "Filter by security zone"},
		{[]string{"show", "security", "flow", "session", "zone", "trust"}, "source-port", "Filter by source port"},
		{[]string{"show", "security", "flow", "session", "sort-by", "bytes"}, "zone", "Filter by security zone"},
		{[]string{"show", "security", "flow", "session", "nat"}, "zone", "Filter by security zone"},
		{[]string{"show", "security", "flow", "session", "zone"}, "trust", "(configured)"},
		{[]string{"ping", "8.8.8.8", "count", "5"}, "source", "Source address to use"},
	} {
		if got := LookupDesc(tc.words, tc.name, false); got != tc.want {
			t.Errorf("LookupDesc(%v, %q) = %q, want %q", tc.words, tc.name, got, tc.want)
		}
	}
}

// The repair must not widen completion past what Canonicalize accepts: a
// stray word after a consumed option, and abbreviations of option keywords,
// behave exactly as the canonicalizer's one-value rule demands.
func TestCompleteOptionLeavesDoNotWiden15720(t *testing.T) {
	cfg := zoneCfg15720()
	for _, words := range [][]string{
		{"show", "security", "flow", "session", "zone", "trust", "unexpected"},
		{"show", "security", "flow", "session", "source-port", "514", "unexpected"},
		{"show", "security", "flow", "session", "sort-by", "bytes", "unexpected"},
		{"show", "security", "flow", "session", "nat", "unexpected"},
	} {
		if got := CompleteFromTree(OperationalTree, words, "", cfg); len(got) != 0 {
			t.Errorf("CompleteFromTree(%v) = %v, want none", words, got)
		}
		if got := CompleteFromTreeWithDesc(OperationalTree, words, "", cfg); len(got) != 0 {
			t.Errorf("CompleteFromTreeWithDesc(%v) = %v, want none", words, got)
		}
		if _, res := Canonicalize(OperationalTree, words); res == CanonicalOK {
			t.Errorf("Canonicalize(%v) = CanonicalOK; the completion expectation above is unanchored", words)
		}
	}
	abbrev := []string{"show", "security", "flow", "session", "destination-po", "514"}
	if got := sortedStrings15720(CompleteFromTree(OperationalTree, abbrev, "", cfg)); !equalStrings15720(got, sessionOptionNames15720) {
		t.Errorf("CompleteFromTree(%v) = %v, want session options", abbrev, got)
	}
	if got := LookupDesc(abbrev, "zone", false); got != "Filter by security zone" {
		t.Errorf("LookupDesc(%v, zone) = %q, want zone description", abbrev, got)
	}
}

// Options must be honoured by the completion walkers and LookupDesc, not
// only by Canonicalize, or an option-map command's leaves end the walk
// again. AST scope guard in the #8304/#9505 shape, with HasDynamic as the
// positive control that the detector can see reads outside one function.
func TestOptionsHonouredByCompletionWalkers15720(t *testing.T) {
	if control := fieldReadSitesByFunc(t, "HasDynamic"); len(control) < 2 {
		t.Fatalf("positive control failed: HasDynamic reads found in %v", sortedFuncs(control))
	}
	sites := fieldReadSitesByFunc(t, "Options")
	for _, fn := range []string{"CompleteFromTree", "CompleteFromTreeWithDesc", "LookupDesc"} {
		if sites[fn] == 0 {
			t.Errorf("Options is not read in %s(); option-map leaves end that walk (sites %v)", fn, sites)
		}
	}
}

// A second Options command (monitor security packet-drop) exercises the
// same resume through a different option map, and repeating an option
// after its value stays completable, mirroring Canonicalize.
func TestCompleteRepeatedAndOtherOptionMaps15720(t *testing.T) {
	cfg := zoneCfg15720()
	if got := sortedStrings15720(CompleteFromTree(OperationalTree,
		[]string{"monitor", "security", "packet-drop", "from-zone", "trust"}, "", cfg)); len(got) == 0 {
		t.Errorf("CompleteFromTree(after packet-drop from-zone value) = %v, want packet-drop options", got)
	} else {
		for _, want := range []string{"interface", "count", "from-zone"} {
			found := false
			for _, g := range got {
				if g == want {
					found = true
				}
			}
			if !found {
				t.Errorf("CompleteFromTree(after packet-drop from-zone value) = %v, missing %q", got, want)
			}
		}
	}
	if got := LookupDesc([]string{"monitor", "security", "packet-drop", "from-zone", "trust"}, "interface", false); got != "Ingress interface to match" {
		t.Errorf("LookupDesc(after packet-drop from-zone value, interface) = %q", got)
	}
	for _, words := range [][]string{
		{"show", "security", "flow", "session", "zone", "trust", "zone", "untrust"},
		{"show", "security", "flow", "session", "sort-by", "bytes", "sort-by", "packets"},
		{"show", "security", "flow", "session", "zone", "trust", "brief"},
	} {
		if got := CompleteFromTree(OperationalTree, words, "", cfg); len(got) == 0 {
			t.Errorf("CompleteFromTree(%v) = %v, want session options", words, got)
		}
		if _, res := Canonicalize(OperationalTree, words); res != CanonicalOK {
			t.Errorf("Canonicalize(%v) = %v; the completion expectation above is unanchored", words, res)
		}
	}
	// A stray word after a typed option's value is refused too.
	stray := []string{"show", "security", "flow", "session", "source-port", "514", "unexpected"}
	if got := LookupDesc(stray, "zone", false); got != "" {
		t.Errorf("LookupDesc(%v, zone) = %q, want none", stray, got)
	}
}
