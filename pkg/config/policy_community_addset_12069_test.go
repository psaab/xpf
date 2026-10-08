package config

import (
	"strings"
	"testing"
)

// #12069 RED-before: `then community add|set <NAME>` (and the bare
// `then community <NAME>`) must resolve a DEFINED community name to its
// literal members. Base stores the name verbatim and the renderer prints
// `set community CUST`, which bgpd rejects at exec while applying every
// other line — the route is exported without the community.
func TestPolicyThenCommunityAddSetNameResolves12069(t *testing.T) {
	for _, tc := range []struct{ name, clause, field, want string }{
		{"add", "then community add CUST", "add", "65000:100"},
		{"set", "then community set CUST", "community", "65000:100"},
		{"bare", "then community CUST", "community", "65000:100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				"set policy-options community CUST members 65000:100",
				"set policy-options policy-statement P term t1 " + tc.clause,
				"set policy-options policy-statement P term t1 then accept",
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			got := term.Community
			if tc.field == "add" {
				got = term.CommunityAdd
			}
			if got != tc.want {
				t.Fatalf("compiled %s = %q, want resolved literal %q", tc.field, got, tc.want)
			}
		})
	}
}

// #12069 RED-before: use-before-define must still resolve. The definition
// is authored AFTER the policy-statement; resolution runs on the
// fully-compiled config, not inline during clause parsing.
func TestPolicyThenCommunityAddNameResolvesAfterUse12069(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement P term t1 then community add CUST",
		"set policy-options policy-statement P term t1 then accept",
		"set policy-options community CUST members 65000:100",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := cfg.PolicyOptions.PolicyStatements["P"].Terms[0].CommunityAdd; got != "65000:100" {
		t.Fatalf("CommunityAdd = %q, want resolved literal %q", got, "65000:100")
	}
}

func TestPolicyThenCommunityAddResolvesAcrossPolicyOptionsRoots12069(t *testing.T) {
	tree, parseErrs := NewParser(`policy-options {
		policy-statement P {
			term t1 { then { community add CUST; accept; } }
		}
	}
	policy-options {
		community CUST { members 65000:100; }
	}`).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse config: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := cfg.PolicyOptions.PolicyStatements["P"].Terms[0].CommunityAdd; got != "65000:100" {
		t.Fatalf("CommunityAdd = %q, want resolved literal across roots %q", got, "65000:100")
	}
}

func TestPolicyThenCommunityAddRejectsNonLiteral12069(t *testing.T) {
	for _, tc := range []struct {
		name, definition, operand string
	}{
		{"regex member", "65000:*", "BAD"},
		{"invalid literal", "65000:100", "65000:*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				"set policy-options community BAD members " + tc.definition,
				"set policy-options policy-statement P term t1 then community add " + tc.operand,
				"set policy-options policy-statement P term t1 then accept",
			})
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted non-literal community operand %q", tc.operand)
			}
		})
	}
}

func TestPolicyThenCommunityAddExpandsEveryDefinedMember12069(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options community CUST members 65000:100",
		"set policy-options community CUST members no-export",
		"set policy-options policy-statement P term t1 then community add CUST",
		"set policy-options policy-statement P term t1 then accept",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := cfg.PolicyOptions.PolicyStatements["P"].Terms[0].CommunityAdd; got != "65000:100 no-export" {
		t.Fatalf("CommunityAdd = %q, want all resolved members %q", got, "65000:100 no-export")
	}
}

func TestPolicyThenCommunityBracketedNonLiteralRejected12069(t *testing.T) {
	command := "set policy-options policy-statement P term t1 then community [ 65000:1 reject ]"
	path, quoted, grouped, err := ParseSetCommandGrouped(command)
	if err != nil {
		t.Fatalf("ParseSetCommandGrouped: %v", err)
	}
	tree := &ConfigTree{}
	if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
		t.Fatalf("SetPathQuotedGrouped: %v", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted non-literal bracketed community operands")
	}
}

// #12069 RED-before: an UNDEFINED add/set/bare operand must fail
// commit-check, naming the policy, term, and leaf.
func TestPolicyThenCommunityAddSetUndefinedRejected12069(t *testing.T) {
	for _, clause := range []string{
		"then community add NOPE",
		"then community set NOPE",
		"then community NOPE",
	} {
		tree := buildTreeFromSet(t, []string{
			"set policy-options policy-statement EXPORT term t1 " + clause,
			"set policy-options policy-statement EXPORT term t1 then accept",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig ACCEPTED %q with no community NOPE defined; want strict rejection", clause)
		}
		for _, want := range []string{"EXPORT", "t1", "NOPE"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: rejection %q does not name %q", clause, err, want)
			}
		}
	}
}
