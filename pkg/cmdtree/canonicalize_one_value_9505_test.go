package cmdtree

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9505. Each walker arm is pinned on a purpose-built tree, so the cells do not
// depend on which real commands use which mechanism today. The real-tree table
// below covers the declarations.
func syntheticTree9505() map[string]*Node {
	dyn := func(*config.Config) []string { return []string{"v1"} }
	return map[string]*Node{
		"cmd": {Desc: "first-match command", Children: map[string]*Node{
			"table": {Desc: "dynamic leaf", DynamicFn: dyn},
			"iface": {Desc: "dynamic node with a child", DynamicFn: dyn, Children: map[string]*Node{
				"detail": {Desc: "child"},
			}},
		}},
		"opts": {Desc: "option list", Options: true, Children: map[string]*Node{
			"<target>": {Desc: "placeholder"},
			"zone":     {Desc: "dynamic option", DynamicFn: dyn},
			"port":     {Desc: "typed option", ValueType: ValueInteger},
			"expr":     {Desc: "free-form option", AcceptsArgs: true},
			"flag":     {Desc: "flag option"},
		}},
	}
}

func TestCanonicalizeValueSlotsTakeOneValue9505(t *testing.T) {
	tree := syntheticTree9505()
	for _, tc := range []struct {
		line  string
		want  CanonicalizeResult
		canon string // checked when want == CanonicalOK
	}{
		// Dynamic arm: one value, then only the node's own children.
		{"cmd table v1", CanonicalOK, "cmd table v1"},
		{"cmd tab v1", CanonicalOK, "cmd table v1"},
		{"cmd table v1 x", CanonicalUnknown, ""},
		{"cmd table v1 x y z", CanonicalUnknown, ""},
		{"cmd iface v1 detail", CanonicalOK, "cmd iface v1 detail"},
		{"cmd iface detail", CanonicalOK, "cmd iface detail"},
		{"cmd iface v1 x", CanonicalUnknown, ""},
		// Without Options a sibling does not resume the walk (#8289 extended).
		{"cmd table v1 iface v2", CanonicalUnknown, ""},
		// Placeholder arm: one value.
		{"opts t1", CanonicalOK, "opts t1"},
		{"opts t1 port 22 t2", CanonicalUnknown, ""},
		// Options: any order, every option canonicalized after a value.
		{"opts zone z1 port 22 t1 flag", CanonicalOK, "opts zone z1 port 22 t1 flag"},
		{"opts po 22 zo z1", CanonicalOK, "opts port 22 zone z1"},
		{"opts t1 zone z1 x", CanonicalUnknown, ""},
		// A pending value is a VALUE, even when it abbreviates an option keyword.
		{"opts zone fl t1", CanonicalOK, "opts zone fl t1"},
		{"opts port fl t1", CanonicalOK, "opts port fl t1"},
		// AcceptsArgs inside an option list stops at the next option.
		{"opts expr a b c po 22", CanonicalOK, "opts expr a b c port 22"},
	} {
		got, res := Canonicalize(tree, strings.Fields(tc.line))
		if res != tc.want {
			t.Errorf("%q: result %v, want %v (canon %q)", tc.line, res, tc.want, strings.Join(got, " "))
			continue
		}
		if res == CanonicalOK && strings.Join(got, " ") != tc.canon {
			t.Errorf("%q: canon %q, want %q", tc.line, strings.Join(got, " "), tc.canon)
		}
	}
}

// The real tree: the option lists resolve in any order, which is the
// over-rejection this fix must not cause, and the extra-word shapes are
// refused. Both halves are from the differential run against master recorded in
// docs/log/9505.md.
func TestOperationalTreeOptionListsAndExtraWords9505(t *testing.T) {
	resolve := map[string]string{
		"show security flow session destination-port 22 zone trust":              "",
		"sh sec flow sess zo trust destination-po 22":                            "show security flow session zone trust destination-port 22",
		"ping 1.1.1.1 routing-instance vrf1 count 5 size 1400 source 10.0.0.1":   "",
		"traceroute 1.1.1.1 routing-instance vrf1 source 10.0.0.1":               "",
		"clear security flow session interface ge-0/0/0 zone trust nat-only":     "",
		"monitor traffic interface ge-0/0/0 matching host 1.1.1.1 count 5":       "",
		"monitor security packet-drop from-zone trust interface ge-0/0/0 cou 10": "monitor security packet-drop from-zone trust interface ge-0/0/0 count 10",
		"monitor security flow filter f1 source-port 22 interface ge-0/0/0":      "",
		"monitor security flow file f1 size 100000 files 3 match foo":            "",
		"show security log zone trust protocol tcp action deny 50":               "",
		"show firewall filter f1 family inet effective":                          "",
		"test routing instance vrf1 destination 1.1.1.1":                         "",
		"show interfaces ge-0/0/0 extensive":                                     "",
		"show security policies from-zone trust to-zone untrust policy p1":       "",
		"request chassis cluster failover redundancy-group 1 node 0":             "",
	}
	for line, want := range resolve {
		got, res := Canonicalize(OperationalTree, strings.Fields(line))
		if res != CanonicalOK {
			t.Errorf("%q: %v, want CanonicalOK. A restricted login class is refused this lawful command", line, res)
			continue
		}
		if want == "" {
			want = line
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q: canon %q, want %q", line, strings.Join(got, " "), want)
		}
	}
	for _, line := range []string{
		"show route table secret-vrf bypass",
		"show route table secret-vrf a b c d",
		"show route table secret-vrf protocol bgp",
		"show interfaces ge-0/0/0 bypass",
		"ping 1.1.1.1 junk",
		"ping 1.1.1.1 2.2.2.2",
		"ping 1.1.1.1 count 5 junk",
		"show security flow session zone trust junk",
		"show firewall filter f1 junk",
		// Options belong to `filter`, not `show firewall`: this runs the
		// every-filter listing.
		"show firewall family inet filter f1",
		"test security-zone interface ge-0/0/0 junk",
	} {
		if _, res := Canonicalize(OperationalTree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("%q canonicalized OK; the extra word is not modelled, so an anchored deny on the command without it is bypassed", line)
		}
	}
}

// Options is honoured in Canonicalize and nowhere else, the same scope rule as
// AcceptsArgs (#8304) and for the same reason: the completion walkers answer a
// different question.
func TestOptionsIsHonouredOnlyInCanonicalize9505(t *testing.T) {
	if control := fieldReadSitesByFunc(t, "HasDynamic"); len(control) < 2 {
		t.Fatalf("positive control failed: HasDynamic reads found in %v", sortedFuncs(control))
	}
	sites := fieldReadSitesByFunc(t, "Options")
	if len(sites) == 0 {
		t.Fatal("no production code reads Options, so every declared option list is refused again")
	}
	for _, fn := range sortedFuncs(sites) {
		if fn != "Canonicalize" {
			t.Errorf("Options is read in %s(); it is honoured only in Canonicalize (sites %v)", fn, sites)
		}
	}
}
