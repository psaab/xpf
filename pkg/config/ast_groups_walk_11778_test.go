package config

import "testing"

// #11778: group context lookup must union every same-keyed container. A group
// body may be split across repeated blocks, just like the destination tree;
// returning only the first matching block silently drops later inherited
// configuration.
func TestWalkGroupToContextUnionsSplitSameKeyedContainers11778(t *testing.T) {
	groupChildren := []*Node{
		{
			Keys: []string{"system"},
			Children: []*Node{
				{Keys: []string{"host-name", "FROM-FIRST"}, IsLeaf: true},
			},
		},
		{
			Keys: []string{"system"},
			Children: []*Node{
				{Keys: []string{"domain-name", "from-second.example"}, IsLeaf: true},
			},
		},
	}

	got := walkGroupToContext(groupChildren, [][]string{{"system"}})
	host := findNodesByKey(got, "host-name")
	if len(host) != 1 || len(host[0].Keys) < 2 || host[0].Keys[1] != "FROM-FIRST" {
		t.Fatalf("context walk dropped first group body: host-name nodes=%v", host)
	}
	domain := findNodesByKey(got, "domain-name")
	if len(domain) != 1 || len(domain[0].Keys) < 2 || domain[0].Keys[1] != "from-second.example" {
		t.Fatalf("context walk dropped second same-keyed group container: domain-name nodes=%v", domain)
	}
}

// TestNestedApplyGroupsUnionsSplitGroupBody11778 verifies the full expansion
// path: an outer group applies an inner group inside `system`, whose template
// body is split over two same-keyed `system` blocks. Both inherited leaves and
// the inline destination leaf must survive expansion and compilation.
func TestNestedApplyGroupsUnionsSplitGroupBody11778(t *testing.T) {
	const text = `groups {
  inner {
    system { host-name FROM-INNER; }
    system { domain-name inner.example; }
  }
  outer { system { apply-groups inner; } }
}
apply-groups outer;
system { time-zone UTC; }`
	tree, parseErrors := NewParser(text).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("fixture must parse: %v", parseErrors[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("nested group expansion must compile: %v", err)
	}
	if cfg.System.HostName != "FROM-INNER" {
		t.Errorf("first inherited leaf = %q, want FROM-INNER", cfg.System.HostName)
	}
	if cfg.System.DomainName != "inner.example" {
		t.Errorf("nested apply dropped second split group body: DomainName=%q, want inner.example", cfg.System.DomainName)
	}
	if cfg.System.TimeZone != "UTC" {
		t.Errorf("inline destination leaf was lost: TimeZone=%q, want UTC", cfg.System.TimeZone)
	}
}
