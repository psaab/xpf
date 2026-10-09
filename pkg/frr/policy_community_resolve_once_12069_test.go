package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12069 follow-up (HIGH, Codex/Astra hostile review on PR #12322): compile
// and render add/set/bare policy actions where CUST expands to a community name
// that has a different definition. The authored name must be expanded once.
func TestPolicyCommunityNameResolvedExactlyOnce12069(t *testing.T) {
	for _, tc := range []struct {
		name, clause, want string
	}{
		{"add", "then community add CUST", " set community no-export additive\n"},
		{"set", "then community set CUST", " set community no-export\n"},
		{"bare", "then community CUST", " set community no-export\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileCommunityPolicy12069(t, []string{
				"set policy-options community CUST members no-export",
				"set policy-options community no-export members 65000:999",
				"set policy-options policy-statement P term t1 from protocol bgp",
				"set policy-options policy-statement P term t1 " + tc.clause,
				"set policy-options policy-statement P term t_end then accept",
			})
			got, _ := New().renderPolicyTermSequences(&cfg.PolicyOptions, "P", "P", cfg.PolicyOptions.PolicyStatements["P"], 10)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rendered policy lacks single-resolved community clause %q: %q", tc.want, got)
			}
			if strings.Contains(got, "set community 65000:999") {
				t.Fatalf("renderer re-resolved the compiler's literal as a name: %q", got)
			}
		})
	}
}

// #12069 follow-up (HIGH): a compiled numeric literal can itself spell a
// community name; the renderer must preserve the literal.
func TestPolicyCommunityNumericLiteralNameCollisionResolvedOnce12069(t *testing.T) {
	cfg := compileCommunityPolicy12069(t, []string{
		"set policy-options community CUST members 65000:1",
		`set policy-options community "65000:1" members 65000:999`,
		"set policy-options policy-statement P term t1 from protocol bgp",
		"set policy-options policy-statement P term t1 then community add CUST",
		"set policy-options policy-statement P term t_end then accept",
	})
	got, _ := New().renderPolicyTermSequences(&cfg.PolicyOptions, "P", "P", cfg.PolicyOptions.PolicyStatements["P"], 10)
	if !strings.Contains(got, " set community 65000:1 additive\n") {
		t.Fatalf("renderer did not preserve compiler-resolved numeric literal: %q", got)
	}
	if strings.Contains(got, "set community 65000:999") {
		t.Fatalf("renderer re-resolved the numeric literal as a community name: %q", got)
	}
}

// #12069 follow-up (HIGH): a colliding numeric community name can have a regex
// member. That definition is not a legal set-action operand, but must not
// false-reject the already-resolved literal produced from CUST.
func TestPolicyCommunityRegexNameCollisionDoesNotFalseReject12069(t *testing.T) {
	cfg := compileCommunityPolicy12069(t, []string{
		"set policy-options community CUST members 65000:1",
		`set policy-options community "65000:1" members "65000:.*"`,
		"set policy-options policy-statement P term t1 from protocol bgp",
		"set policy-options policy-statement P term t1 then community add CUST",
		"set policy-options policy-statement P term t_end then accept",
	})
	got, _ := New().renderPolicyTermSequences(&cfg.PolicyOptions, "P", "P", cfg.PolicyOptions.PolicyStatements["P"], 10)
	if !strings.Contains(got, " set community 65000:1 additive\n") {
		t.Fatalf("renderer rejected compiler-resolved literal due to colliding regex definition: %q", got)
	}
}

func compileCommunityPolicy12069(t *testing.T, commands []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}
