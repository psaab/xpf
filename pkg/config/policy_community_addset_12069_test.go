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

// #12069 use-before-definition: the policy action appears before its community
// definition in this flat-set input; compilation still resolves the operand.
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
		name, definition, operand, errorOperand string
	}{
		{"regex member", "65000:*", "BAD", `uses "BAD"`},
		{"invalid literal", "65000:100", "65000:*", `uses "65000:*"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				"set policy-options community BAD members " + tc.definition,
				"set policy-options policy-statement P term t1 then community add " + tc.operand,
				"set policy-options policy-statement P term t1 then accept",
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted non-literal community operand %q", tc.operand)
			}
			if !strings.Contains(err.Error(), tc.errorOperand) {
				t.Fatalf("CompileConfig error %q does not identify rejected operand %s", err, tc.errorOperand)
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
	_, err = CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted non-literal bracketed community operands")
	}
	for _, want := range []string{"65000:1 reject", "FRR community literal"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("CompileConfig error %q does not identify bracketed non-literal %q", err, want)
		}

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
func TestPolicyThenCommunityEmptyDefinitionRejected12069(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options community CUST",
		"set policy-options policy-statement P term t1 then community add CUST",
		"set policy-options policy-statement P term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an empty community definition as a then-community operand")
	}
	for _, want := range []string{"CUST", "members are all literals"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("CompileConfig error %q does not explain empty community definition %q", err, want)
		}
	}
}

// #12069 Astra-R2 fail-open matrix: when a defined name spells a valid
// community literal, failed definition resolution must not fall through to
// literal acceptance. The strict error must identify the authored operand.
func TestPolicyThenCommunityLiteralShapedFailedResolutionRejected12069(t *testing.T) {
	for _, name := range []string{"65000:1", "no-export"} {
		for _, definition := range []string{"empty", "regex", "mixed"} {
			for _, clause := range []string{
				"then community add " + name,
				"then community set " + name,
				"then community " + name,
			} {
				t.Run(name+"/"+definition+"/"+clause, func(t *testing.T) {
					definitionCommands := []string{}
					community := "set policy-options community \"" + name + "\""
					switch definition {
					case "empty":
						definitionCommands = []string{community}
					case "regex":
						definitionCommands = []string{community + ` members "65000:*"`}
					case "mixed":
						definitionCommands = []string{
							community + " members no-export",
							community + ` members "65000:*"`,
						}
					}
					tree := buildTreeFromSet(t, append(definitionCommands,
						"set policy-options policy-statement P term t1 "+clause,
						"set policy-options policy-statement P term t1 then accept",
					))
					_, err := CompileConfig(tree)
					if err == nil {
						t.Fatalf("CompileConfig accepted literal-shaped name %q with %s definition via %q",
							name, definition, clause)
					}
					if !strings.Contains(err.Error(), `uses "`+name+`"`) {
						t.Fatalf("error %q does not name authored operand %q", err, name)
					}
					if strings.ContainsRune(err.Error(), '\x00') {
						t.Fatalf("strict error exposed internal NUL state: %q", err)
					}
					lenient, err := CompileConfigLenient(tree)
					if err != nil {
						t.Fatalf("CompileConfigLenient: %v", err)
					}
					term := lenient.PolicyOptions.PolicyStatements["P"].Terms[0]
					operand := term.Community
					if term.CommunityOp == "add" {
						operand = term.CommunityAdd
					}
					if !term.CommunityResolutionFailed || operand != name {
						t.Fatalf("failed resolution state = (flag %v, operand %q), want (true, authored %q)",
							term.CommunityResolutionFailed, operand, name)
					}
				})
			}
		}
	}
}
