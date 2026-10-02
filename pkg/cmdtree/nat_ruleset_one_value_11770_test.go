package cmdtree

import (
	"strings"
	"testing"
)

// #11770: NAT rule-set nodes take a single rule-set NAME. They were declared
// AcceptsArgs, so `show security nat {source,destination} rule-set <name>
// <junk>` canonicalized OK while the dispatcher ran only <name> — a
// name-anchored deny on the junk-bearing line never matched the command that
// ran (#9022's guard covers only argument-free anchors). Single-value slot:
// exactly one name resolves; trailing junk is refused (fail closed).
func TestNATRuleSetTakesOneValue11770(t *testing.T) {
	for _, line := range []string{
		"show security nat source rule-set rs1",
		"show security nat destination rule-set rs1",
	} {
		got, res := Canonicalize(OperationalTree, strings.Fields(line))
		if res != CanonicalOK {
			t.Errorf("%q: %v, want CanonicalOK. A restricted login class is refused this lawful command", line, res)
			continue
		}
		if strings.Join(got, " ") != line {
			t.Errorf("%q: canon %q, want %q", line, strings.Join(got, " "), line)
		}
	}
	for _, line := range []string{
		"show security nat source rule-set rs1 junk",
		"show security nat source rule-set rs1 a b c",
		"show security nat destination rule-set rs1 junk",
		"show security nat destination rule-set rs1 a b c",
	} {
		if got, res := Canonicalize(OperationalTree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("%q canonicalized OK as %q; the dispatcher runs only the named rule-set, so an anchored deny on this line is evaded", line, strings.Join(got, " "))
		}
	}
}
