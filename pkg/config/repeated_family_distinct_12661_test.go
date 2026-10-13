package config

import "testing"

func TestRepeatedFamilyEditorPreservesDistinctAF12661(t *testing.T) {
	tree := hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { address 10.0.0.1/24; filter { input A; } }
            family inet { filter { input B; } }
            family inet6 { address 2001:db8::1/64; filter { input D; } }
        }
    }
}
firewall {
    family inet { filter A { term t { then accept; } } filter B { term t { then accept; } } filter C { term t { then accept; } } }
    family inet6 { filter A { term t { then accept; } } filter B { term t { then accept; } } filter C { term t { then accept; } } filter D { term t { then accept; } } }
}
`)
	if err := tree.SetPath(path12661("inet", "filter", "input", "C")); err != nil {
		t.Fatalf("SetPath inet filter: %v", err)
	}
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "C" {
		t.Fatalf("inet filter = %q, want C", got)
	}
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet6"); got != "D" {
		t.Fatalf("inet6 filter = %q, want D; editing inet crossed family boundary", got)
	}
}
