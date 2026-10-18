package cmdtree

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14687: Canonicalize returned CanonicalOK when the line ended while a
// value slot was still awaiting its value. The RBAC gate then judged a
// string the dispatcher never ran:
//
//	show firewall filter secret family   RBAC: "show firewall filter secret family"
//	                                     runs: showFirewallFilter("secret","")
//	show firewall filter                 RBAC: "show firewall filter"
//	                                     runs: showFirewallFilters() (all filters)
//	show security screen ids-option      RBAC: "show security screen ids-option"
//	                                     runs: showScreen() (all profiles)
//
// A mandatory value slot is one whose handler has no bare form: a typed
// leaf (IsTypedLeaf), a dynamic node marked RequiresValue, or a
// placeholder that was never filled. Optional dynamic nodes (bare form
// lists all, e.g. `show security zones`, `show interfaces`) stay OK.
func TestCanonicalizeRejectsIncompleteValueSlots14687(t *testing.T) {
	for _, line := range []string{
		// Typed leaf dangling (the anchored bypass in the issue).
		"show firewall filter secret family",
		"show firewall filter f1 family",
		"show firewall filter f1 fam", // abbreviated typed leaf, still dangling
		"ping 1.1.1.1 count",
		"ping 1.1.1.1 cou",
		"traceroute 1.1.1.1 source",
		"show security nat source rule-set",
		"show security flow session destination-port",
		// Mandatory dynamic dangling.
		"show firewall filter",
		"show security screen ids-option",
		"show security screen statistics zone",
		"show security policies from-zone",
		"show security policies from-zone trust to-zone",
		"show security policies from-zone trust to-zone untrust policy",
		"show route table",
		"show route protocol",
		"test security-zone interface",
		// Childless placeholder under a non-root keyword, never filled.
		"show chassis cluster data-plane flows",
	} {
		if got, res := Canonicalize(OperationalTree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("%q canonicalized OK as %q; the line ends with an unfilled mandatory value slot, so a restricted class must fail closed rather than judge a string the dispatcher widens", line, strings.Join(got, " "))
		}
	}
}

// Controls: complete commands and optional-dynamic bare forms must stay OK.
func TestCanonicalizeCompleteAndOptionalBareStayOK14687(t *testing.T) {
	for _, line := range []string{
		"show firewall filter secret family inet",
		"show firewall filter secret family inet effective",
		"show firewall filter secret effective",
		"show firewall filter secret",
		"show firewall",
		"show firewall effective",
		"show security screen",
		"show security screen ids-option prof1",
		"show security screen ids-option prof1 detail",
		"show security screen statistics",
		"show security screen statistics zone trust",
		"show security zones",
		"show security zones detail",
		"show security zones trust",
		"show security zones trust detail",
		"show interfaces",
		"show interfaces ge-0/0/0",
		"show route",
		"show route table inet.0",
		"ping 1.1.1.1",
		"ping 1.1.1.1 count 5",
		"show security policies from-zone trust",
		"show security policies from-zone trust to-zone untrust",
		"show security policies from-zone trust to-zone untrust policy p1",
		"show version",
		// Argument-free RPC/REST command paths: the typed RPC carries the
		// target in a field, so the bare path is a complete charge string.
		"ping",
		"traceroute",
	} {
		got, res := Canonicalize(OperationalTree, strings.Fields(line))
		if res != CanonicalOK {
			t.Errorf("%q: result %v (canon %q), want CanonicalOK; a restricted class would be refused a lawful command", line, res, strings.Join(got, " "))
		}
	}
}

// Synthetic tree: RequiresValue is opt-in. A dynamic node without it may
// end the line; with it, it may not. A typed leaf always requires its value.
func TestCanonicalizeIncompleteSynthetic14687(t *testing.T) {
	dyn := func(*config.Config) []string { return []string{"v1"} }
	tree := map[string]*Node{
		"root": {Desc: "r", Children: map[string]*Node{
			"cmd": {Desc: "c", Children: map[string]*Node{
				"opt":      {Desc: "optional dynamic", DynamicFn: dyn},
				"req":      {Desc: "mandatory dynamic", DynamicFn: dyn, RequiresValue: true},
				"port":     {Desc: "typed", ValueType: ValueInteger},
				"<target>": {Desc: "placeholder"},
			}},
			"bare": {Desc: "b", Children: map[string]*Node{
				"<target>": {Desc: "placeholder"},
			}},
		}},
	}
	for _, tc := range []struct {
		line string
		want CanonicalizeResult
	}{
		{"root cmd opt", CanonicalOK},
		{"root cmd opt v1", CanonicalOK},
		{"root cmd req", CanonicalUnknown},
		{"root cmd req v1", CanonicalOK},
		{"root cmd port", CanonicalUnknown},
		{"root cmd port 22", CanonicalOK},
		{"root cmd", CanonicalUnknown}, // <target> placeholder unfilled
		{"root cmd v1", CanonicalOK},
		{"root bare", CanonicalUnknown},
		{"root bare v1", CanonicalOK},
	} {
		_, res := Canonicalize(tree, strings.Fields(tc.line))
		if res != tc.want {
			t.Errorf("%q: result %v, want %v", tc.line, res, tc.want)
		}
	}
}
