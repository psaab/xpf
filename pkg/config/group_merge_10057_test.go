package config

import (
	"strings"
	"testing"
)

// findNode10057 returns the first node whose leading keys match want. The
// fixtures below deliberately inspect the expanded AST rather than compiled
// values: quote and bracket provenance is renderer metadata, not reader input.
func findNode10057(nodes []*Node, want ...string) *Node {
	for _, n := range nodes {
		if len(n.Keys) >= len(want) {
			match := true
			for i, key := range want {
				if n.Keys[i] != key {
					match = false
					break
				}
			}
			if match {
				return n
			}
		}
		if child := findNode10057(n.Children, want...); child != nil {
			return child
		}
	}
	return nil
}

func assertMasksAligned10057(t *testing.T, n *Node) {
	t.Helper()
	if n == nil {
		t.Fatal("node is nil")
	}
	if len(n.KeysQuoted) != 0 && len(n.KeysQuoted) != len(n.Keys) {
		t.Fatalf("quote mask is not aligned: keys=%q quoted=%v", n.Keys, n.KeysQuoted)
	}
	if len(n.KeysBracketed) != 0 && len(n.KeysBracketed) != len(n.Keys) {
		t.Fatalf("bracket mask is not aligned: keys=%q bracketed=%v", n.Keys, n.KeysBracketed)
	}
}

// TestPackedTailProvenance10057 pins both packed-tail synthesis callers. The
// first case is #9855's inline-leaf promotion and checks the display surface;
// the second is #7648's group-side container merge and checks bracket shape.
// Neither compiler reader needs these masks: the cells inspect the merged AST
// and its inheritance renderer, which are the consumers that lost provenance.
func TestPackedTailProvenance10057(t *testing.T) {
	t.Run("9855 promoted quoted match survives inheritance display", func(t *testing.T) {
		text := `groups { G { system { syslog { host 10.0.0.1 port 999; } } } } apply-groups G; ` +
			`system { syslog { host 10.0.0.1 match "a b"; } }`
		tree := parseHierarchical(t, text)
		if err := tree.ExpandGroupsTagged(); err != nil {
			t.Fatalf("ExpandGroupsTagged: %v", err)
		}
		host := findNode10057(tree.Children, "host", "10.0.0.1")
		if host == nil {
			t.Fatal("promoted host node not found")
		}
		assertMasksAligned10057(t, host)
		match := findNode10057(host.Children, "match", "a b")
		if match == nil {
			t.Fatal("promoted match child not found")
		}
		assertMasksAligned10057(t, match)
		if !match.KeyQuoted(1) {
			t.Fatalf("promoted match keys=%q quoted=%v, want authored quote on value", match.Keys, match.KeysQuoted)
		}
		display := tree.FormatInheritance()
		if !strings.Contains(display, `match "a b";`) {
			t.Fatalf("inheritance display lost quoted match value:\n%s", display)
		}
	})

	t.Run("7648 group container preserves bracketed tail", func(t *testing.T) {
		text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { ` +
			`vrrp-group 1 virtual-address [ 10.0.61.1/24 10.0.61.3/24 ]; } } } } } } } apply-groups G; ` +
			`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 { } } } } } }`
		tree := parseHierarchical(t, text)
		if err := tree.ExpandGroupsTagged(); err != nil {
			t.Fatalf("ExpandGroupsTagged: %v", err)
		}
		group := findNode10057(tree.Children, "vrrp-group", "1")
		if group == nil {
			t.Fatal("merged vrrp-group node not found")
		}
		virtual := findNode10057(group.Children, "virtual-address")
		if virtual == nil {
			t.Fatal("synthesized virtual-address child not found")
		}
		assertMasksAligned10057(t, virtual)
		if !virtual.KeyBracketed(1) || !virtual.KeyBracketed(2) {
			t.Fatalf("synthesized virtual-address keys=%q bracketed=%v, want both values bracketed", virtual.Keys, virtual.KeysBracketed)
		}
	})
}
