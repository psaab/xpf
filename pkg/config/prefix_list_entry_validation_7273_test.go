package config

import (
	"strings"
	"testing"
)

// #7273: a malformed entry inside a REFERENCED prefix-list must be rejected at
// commit, because the term's address scope otherwise silently narrows to the
// entries that happen to parse.
//
// The firing input is named deliberately: a list of three prefixes where the
// MIDDLE one is malformed. A fixture whose only entry is malformed would also
// be caught by an implementation that rejects any list it cannot fully parse
// AND by one that rejects a list that resolves to nothing — the partial list is
// what distinguishes "narrowed silently" from "empty".
func TestPrefixListMalformedEntryRejected7273(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list pl1 10.0.0.0/8",
		"set policy-options prefix-list pl1 10.0.0.0/33",
		"set policy-options prefix-list pl1 192.168.0.0/16",
		"set firewall family inet filter f1 term t1 from source-prefix-list pl1",
		"set firewall family inet filter f1 term t1 then discard",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a malformed prefix-list entry committed cleanly. The term's scope " +
			"narrows to the two entries that parse, and neither the #3433 literal gate " +
			"nor the #6463 AddressUnrepresentable marker sees it — both are driven by " +
			"literal from-address tokens, and a prefix-list entry has a different provenance")
	}
	for _, want := range []string{"pl1", "10.0.0.0/33", "f1", "t1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q, so an operator cannot find what to edit: %v", want, err)
		}
	}
}

// The v6 twin, because the two families are separate maps and a fix applied to
// one is a live possibility.
func TestPrefixListMalformedEntryRejectedV6_7273(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list pl6 2001:db8::/32",
		"set policy-options prefix-list pl6 2001:db8::/999",
		"set firewall family inet6 filter f6 term t6 from destination-prefix-list pl6",
		"set firewall family inet6 filter f6 term t6 then accept",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("a malformed IPv6 prefix-list entry committed cleanly")
	}
}

// THE SCOPE BOUNDARY, and the row that distinguishes this implementation from a
// validate-every-prefix-list one.
func TestUnreferencedPrefixListMalformedEntryIsNotAFirewallError7273(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list routing-only 10.0.0.0/33",
		"set firewall family inet filter f1 term t1 from source-address 10.1.0.0/16",
		"set firewall family inet filter f1 term t1 then discard",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a malformed entry in a prefix-list NO firewall filter references "+
			"rejected the commit. This gate is scoped to the firewall family on "+
			"purpose; widening it silently changes behaviour for routing-only "+
			"configurations: %v", err)
	}
}

// The negative control. Without it, "reject every referenced list" passes the
// two positive cells.
func TestWellFormedPrefixListStillCommits7273(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options prefix-list good 10.0.0.0/8",
		"set policy-options prefix-list good 192.168.0.0/16",
		"set firewall family inet filter f1 term t1 from source-prefix-list good",
		"set firewall family inet filter f1 term t1 then discard",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a well-formed referenced prefix-list was rejected: %v", err)
	}
}
