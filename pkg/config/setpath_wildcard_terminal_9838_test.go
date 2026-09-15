package config

import (
	"strings"
	"testing"
)

// #9838, merge/replay half: a flat `set` line ending AT a named-instance
// slot rebuilds the EMPTY BRACED CONTAINER it was rendered from (#9126),
// not a bare leaf. Junos `set` creates the container; it never creates a
// leaf at a container position.

func setPathTree9838(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tr := &ConfigTree{}
	for _, cmd := range cmds {
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("%s: parse: %v", cmd, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("%s: SetPath: %v", cmd, err)
		}
	}
	return tr
}

func TestSetPathWildcardTerminalIsContainer9838(t *testing.T) {
	// Container creation is scoped to the #9838 subjects: top-level
	// `interfaces` and `routing-instances`. Every other instance slot
	// keeps the terminal leaf it always built (see
	// TestSetPathNonSubjectTerminalStaysLeaf9838).
	tr := setPathTree9838(t,
		"set interfaces ge-0/0/0",
		"set routing-instances ri1",
		`set interfaces "ge-0/0/5"`,
	)
	ifaces := tr.FindChild("interfaces")
	if ifaces == nil {
		t.Fatal("want an interfaces root")
	}
	for _, name := range []string{"ge-0/0/0", "ge-0/0/5"} {
		n := ifaces.FindChild(name)
		if n == nil {
			t.Errorf("want a %s node", name)
			continue
		}
		if n.IsLeaf {
			t.Errorf("%s: want the empty braced container, got a bare leaf", name)
		}
	}
	ri := tr.FindChild("routing-instances")
	if ri == nil || ri.FindChild("ri1") == nil {
		t.Fatal("want a routing-instances ri1 node")
	}
	if ri.FindChild("ri1").IsLeaf {
		t.Errorf("ri1: want the empty braced container, got a bare leaf")
	}
}

// (groups G moved to TestSetPathNonSubjectTerminalStaysLeaf9838: creation
// is scoped to the #9838 subjects, so groups keeps its terminal leaf.)

func TestSetPathWildcardTerminalReusesContainer9838(t *testing.T) {
	tr := setPathTree9838(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.5/24",
		// The replay of a no-op `ge-0/0/0 { }` merge. Before the fix this
		// appended a leaf twin (terminal replay deduped leaves only) and
		// the #9838 gate refused a spelling nobody wrote.
		"set interfaces ge-0/0/0",
		"set routing-instances ri1 instance-type virtual-router",
		"set routing-instances ri1",
	)
	ifaces := tr.FindChild("interfaces")
	count := 0
	for _, c := range ifaces.Children {
		if len(c.Keys) == 1 && c.Keys[0] == "ge-0/0/0" {
			count++
			if c.IsLeaf {
				t.Errorf("ge-0/0/0: the replay must reuse the container, not append a leaf twin")
			}
			if c.FindChild("unit") == nil {
				t.Errorf("ge-0/0/0: the configured unit went missing from the reused container")
			}
		}
	}
	if count != 1 {
		t.Errorf("ge-0/0/0: want exactly one node after the no-op replay, got %d", count)
	}
	ris := tr.FindChild("routing-instances")
	count = 0
	for _, c := range ris.Children {
		if len(c.Keys) == 1 && c.Keys[0] == "ri1" {
			count++
			if c.IsLeaf {
				t.Errorf("ri1: the replay must reuse the container, not append a leaf twin")
			}
			if c.FindChild("instance-type") == nil {
				t.Errorf("ri1: the configured instance-type went missing from the reused container")
			}
		}
	}
	if count != 1 {
		t.Errorf("ri1: want exactly one node after the no-op replay, got %d", count)
	}
}

// TestSetPathDeclaredTerminalStaysLeaf9838 locks the scope: only a wildcard
// instance slot rebuilds as a container. A DECLARED child with children and
// value args is a value carrier at terminal and stays the leaf it always was.
func TestSetPathDeclaredTerminalStaysLeaf9838(t *testing.T) {
	tr := setPathTree9838(t,
		"set protocols ospf area 0.0.0.0",
		"set routing-options static route 0/0 next-hop 10.0.0.1",
		"set firewall family inet filter F",
		"set interfaces apply-groups foo",
	)
	area := tr.FindChild("protocols").FindChild("ospf").FindChild("area")
	if area == nil || !area.IsLeaf {
		t.Errorf("area 0.0.0.0: want the terminal leaf it always was, got %+v", area)
	}
	// The ECMP value carrier: rebuilding this as a container would strand
	// the gateway the compiler reads from the Keys tail.
	static := tr.FindChild("routing-options").FindChild("static")
	route := static.FindChild("route")
	if route == nil || route.IsLeaf {
		t.Fatalf("route 0/0: want the intermediate container, got %+v", route)
	}
	nh := route.FindChild("next-hop")
	if nh == nil || !nh.IsLeaf {
		t.Errorf("next-hop: want the value leaf, got %+v", nh)
	} else if len(nh.Keys) != 2 || nh.Keys[1] != "10.0.0.1" {
		t.Errorf("next-hop: want Keys [next-hop 10.0.0.1], got %q", nh.Keys)
	}
	filt := tr.FindChild("firewall").FindChild("family").FindChild("filter")
	if filt == nil || !filt.IsLeaf {
		t.Errorf("filter F: want the terminal leaf it always was, got %+v", filt)
	}
	ag := tr.FindChild("interfaces").FindChild("apply-groups")
	if ag == nil || !ag.IsLeaf {
		t.Errorf("apply-groups foo: want the terminal leaf it always was, got %+v", ag)
	}
}

// TestSetPathBareInstanceCompilesLikeBraced9838: the flat terminal spelling
// is what FormatSet renders for `ge-0/0/0 { }` / `ri1 { }`, so it compiles
// as that container — no #9838 refusal, instance present.
func TestSetPathBareInstanceCompilesLikeBraced9838(t *testing.T) {
	tr := setPathTree9838(t,
		"set interfaces ge-0/0/0",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set routing-instances ri1",
	)
	cfg, err := CompileConfig(tr)
	if err != nil {
		t.Fatalf("flat terminals: want a commit, got %v", err)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] == nil {
		t.Errorf("flat `set interfaces ge-0/0/0` compiled no interface; it is the braced spelling in flat form")
	}
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			found = true
		}
	}
	if !found {
		t.Errorf("flat `set routing-instances ri1` compiled no instance; it is the braced spelling in flat form")
	}
	if joined := strings.Join(cfg.Warnings, "\n"); strings.Contains(joined, "#9838") {
		t.Errorf("flat terminals must not warn #9838, got %q", joined)
	}
}

// TestSetPathNonSubjectTerminalStaysLeaf9838: container creation is scoped
// to the #9838 subjects, so every other instance slot keeps the terminal
// leaf it always built — including a group name and an ip-monitoring
// address, whose bodyless leaf is a legitimate, compiling form.
func TestSetPathNonSubjectTerminalStaysLeaf9838(t *testing.T) {
	tr := setPathTree9838(t,
		"set groups G",
		"set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.1.1",
	)
	g := tr.FindChild("groups")
	if g == nil || g.FindChild("G") == nil {
		t.Fatal("want a groups G node")
	}
	if !g.FindChild("G").IsLeaf {
		t.Errorf("groups G: want the terminal leaf it always was, got a container")
	}
	inet := tr.FindChild("chassis").FindChild("cluster").FindChild("redundancy-group").FindChild("ip-monitoring").FindChild("family")
	addr := inet.FindChild("10.0.1.1")
	if addr == nil {
		t.Fatal("want a 10.0.1.1 address node")
	}
	if !addr.IsLeaf {
		t.Errorf("10.0.1.1: want the terminal leaf it always was, got a container")
	}
}

// TestSetPathTerminalReplayPreservesEitherShape9838: a terminal replay that
// names an existing node changes nothing, whichever shape the node has. A
// twin would double-compile (ip-monitoring targets) or false-refuse (group
// definitions) — and for a #9838 subject it would bury the bare leaf whose
// refusal evidence must survive the replay.
func TestSetPathTerminalReplayPreservesEitherShape9838(t *testing.T) {
	countNamed := func(t *testing.T, tr *ConfigTree, nav []string, want string) (leaf, cont int) {
		t.Helper()
		cur := tr.Children
		var parent *Node
		for _, kw := range nav {
			parent = nil
			for _, n := range cur {
				if n.Name() == kw {
					parent = n
					break
				}
			}
			if parent == nil {
				t.Fatalf("navigation %v: no %s node", nav, kw)
			}
			cur = parent.Children
		}
		for _, n := range cur {
			if len(n.Keys) == 1 && n.Keys[0] == want {
				if n.IsLeaf {
					leaf++
				} else {
					cont++
				}
			}
		}
		return leaf, cont
	}
	replay := func(t *testing.T, hier, set string) *ConfigTree {
		t.Helper()
		tr, perrs := NewParser(hier).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs[0])
		}
		p, err := ParseSetCommand(set)
		if err != nil {
			t.Fatalf("%s: parse: %v", set, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("%s: SetPath: %v", set, err)
		}
		return tr
	}

	// Legitimate bodyless leaves: replay is a no-op, the leaf survives alone.
	tr := replay(t, "groups {\n G;\n}\n", "set groups G")
	if l, c := countNamed(t, tr, []string{"groups"}, "G"); l != 1 || c != 0 {
		t.Errorf("groups G leaf + replay: want exactly the leaf, got leaf=%d container=%d", l, c)
	}
	const monLeaf = "chassis {\n cluster {\n redundancy-group 1 {\n ip-monitoring {\n family inet {\n 10.0.1.1;\n }\n }\n }\n }\n}\n"
	tr = replay(t, monLeaf, "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.1.1")
	if l, c := countNamed(t, tr, []string{"chassis", "cluster", "redundancy-group", "ip-monitoring", "family"}, "10.0.1.1"); l != 1 || c != 0 {
		t.Errorf("monitor leaf + replay: want exactly the leaf, got leaf=%d container=%d", l, c)
	}

	// Configured containers: replay is a no-op, the body survives alone.
	tr = replay(t, "groups {\n G {\n system {\n host-name x;\n }\n }\n}\n", "set groups G")
	if l, c := countNamed(t, tr, []string{"groups"}, "G"); l != 0 || c != 1 {
		t.Fatalf("groups container + replay: want exactly the container, got leaf=%d container=%d", l, c)
	}
	if g := tr.FindChild("groups").FindChild("G"); g.FindChild("system") == nil {
		t.Errorf("groups container + replay: the group body went missing")
	}
	const monFull = "chassis {\n cluster {\n redundancy-group 1 {\n ip-monitoring {\n family inet {\n 10.0.1.1 {\n weight 100;\n }\n }\n }\n }\n }\n}\n"
	tr = replay(t, monFull, "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.1.1")
	if l, c := countNamed(t, tr, []string{"chassis", "cluster", "redundancy-group", "ip-monitoring", "family"}, "10.0.1.1"); l != 0 || c != 1 {
		t.Fatalf("monitor container + replay: want exactly the container, got leaf=%d container=%d", l, c)
	}

	// #9838 subjects: the bare leaf survives the replay alone, and still
	// refuses — the replay must not twin it away or convert it.
	tr = replay(t, "interfaces {\n ge-0/0/0;\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n", "set interfaces ge-0/0/0")
	if l, c := countNamed(t, tr, []string{"interfaces"}, "ge-0/0/0"); l != 1 || c != 0 {
		t.Fatalf("iface leaf + replay: want exactly the leaf, got leaf=%d container=%d", l, c)
	}
	if _, err := CompileConfig(tr); err == nil || !strings.Contains(err.Error(), "#9838") {
		t.Errorf("iface leaf + replay: want the #9838 refusal to survive, got %v", err)
	}
	tr = replay(t, "routing-instances {\n ri1;\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n", "set routing-instances ri1")
	if l, c := countNamed(t, tr, []string{"routing-instances"}, "ri1"); l != 1 || c != 0 {
		t.Fatalf("RI leaf + replay: want exactly the leaf, got leaf=%d container=%d", l, c)
	}
	if _, err := CompileConfig(tr); err == nil || !strings.Contains(err.Error(), "#9838") {
		t.Errorf("RI leaf + replay: want the #9838 refusal to survive, got %v", err)
	}
}

// TestSetPathCrossRootTerminalReusesLaterRoot9838: a raw LoadOverride
// retains disjoint top-level stanzas (the parser appends without merging),
// but SetPath descends into the FIRST same-named root. A terminal replay
// naming an instance that lives in a LATER root must resolve there — not
// append an empty twin in root 1 (a #5180 duplicate refusal for
// interfaces, a doubled instance for routing-instances).
func TestSetPathCrossRootTerminalReusesLaterRoot9838(t *testing.T) {
	tr, perrs := NewParser("interfaces {\n ge-0/0/9 { unit 0 { family inet { address 10.9.9.9/24; } } }\n}\ninterfaces {\n ge-0/0/0 { unit 0 { family inet { address 10.0.0.5/24; } } }\n}\n").Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	// Precondition, 5675 pattern: the split-root shape this guards must
	// actually exist, loudly, or a future parser merge would silently
	// pass this test while removing what it protects.
	if got := len(tr.FindChildren("interfaces")); got != 2 {
		t.Fatalf("expected 2 top-level interfaces roots, got %d", got)
	}
	p, err := ParseSetCommand("set interfaces ge-0/0/0")
	if err != nil {
		t.Fatalf("parse set: %v", err)
	}
	if err := tr.SetPath(p); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	count, withUnit := 0, 0
	for _, root := range tr.FindChildren("interfaces") {
		for _, c := range root.Children {
			if len(c.Keys) == 1 && c.Keys[0] == "ge-0/0/0" {
				count++
				if !c.IsLeaf && c.FindChild("unit") != nil {
					withUnit++
				}
			}
		}
	}
	if count != 1 || withUnit != 1 {
		t.Fatalf("want the one configured ge-0/0/0 across both roots, got %d nodes (%d configured)", count, withUnit)
	}

	tr, perrs = NewParser("routing-instances {\n ri9 { instance-type virtual-router; }\n}\nrouting-instances {\n ri1 { instance-type virtual-router; }\n}\n").Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	if got := len(tr.FindChildren("routing-instances")); got != 2 {
		t.Fatalf("expected 2 top-level routing-instances roots, got %d", got)
	}
	p, err = ParseSetCommand("set routing-instances ri1")
	if err != nil {
		t.Fatalf("parse set: %v", err)
	}
	if err := tr.SetPath(p); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	count, withType := 0, 0
	for _, root := range tr.FindChildren("routing-instances") {
		for _, c := range root.Children {
			if len(c.Keys) == 1 && c.Keys[0] == "ri1" {
				count++
				if !c.IsLeaf && c.FindChild("instance-type") != nil {
					withType++
				}
			}
		}
	}
	if count != 1 || withType != 1 {
		t.Fatalf("want the one configured ri1 across both roots, got %d nodes (%d configured)", count, withType)
	}
}
