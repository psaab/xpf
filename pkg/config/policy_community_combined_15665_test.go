package config

import (
	"strings"
	"testing"
)

// #15665: a term combining `community delete` with `community add`/`set`,
// repeated `community add` statements, or a bracketed value naming several
// defined communities must keep every action. The single-scalar CommunityOp
// overwrote combined actions (delete+add compiled to empty), repeated adds
// kept only the last value, and `add [ c1 c2 ]` with defined names failed
// resolution because the joined string was looked up as one name.

func compile15665(t *testing.T, cmds []string) *Config {
	t.Helper()
	cfg, err := CompileConfig(buildTreeFromSet(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func term15665(t *testing.T, cfg *Config) *PolicyTerm {
	t.Helper()
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 {
		t.Fatalf("policy P terms = %v, want one term", ps)
	}
	return ps.Terms[0]
}

func TestPolicyCommunityDeletePlusAdd15665(t *testing.T) {
	cfg := compile15665(t, []string{
		"set policy-options community C1 members 65000:1",
		"set policy-options community C2 members 65000:2",
		"set policy-options policy-statement P term t1 then community delete C1",
		"set policy-options policy-statement P term t1 then community add C2",
		"set policy-options policy-statement P term t1 then accept",
	})
	term := term15665(t, cfg)
	if len(term.CommunityDelete) != 1 || term.CommunityDelete[0] != "C1" {
		t.Fatalf("CommunityDelete = %v, want [C1]", term.CommunityDelete)
	}
	if term.CommunityAdd != "65000:2" {
		t.Fatalf("CommunityAdd = %q, want %q (delete+add overwrote each other)", term.CommunityAdd, "65000:2")
	}
}

func TestPolicyCommunityDeletePlusSet15665(t *testing.T) {
	cfg := compile15665(t, []string{
		"set policy-options community C1 members 65000:1",
		"set policy-options policy-statement P term t1 then community delete C1",
		"set policy-options policy-statement P term t1 then community set 65000:9",
		"set policy-options policy-statement P term t1 then accept",
	})
	term := term15665(t, cfg)
	if len(term.CommunityDelete) != 1 || term.CommunityDelete[0] != "C1" {
		t.Fatalf("CommunityDelete = %v, want [C1]", term.CommunityDelete)
	}
	if term.CommunityOp != "set" || term.Community != "65000:9" {
		t.Fatalf("CommunityOp/Community = %q/%q, want set/65000:9", term.CommunityOp, term.Community)
	}
}

func TestPolicyCommunityRepeatedAddAccumulates15665(t *testing.T) {
	cfg := compile15665(t, []string{
		"set policy-options policy-statement P term t1 then community add 65000:1",
		"set policy-options policy-statement P term t1 then community add 65000:2",
		"set policy-options policy-statement P term t1 then accept",
	})
	term := term15665(t, cfg)
	if term.CommunityAdd != "65000:1 65000:2" {
		t.Fatalf("CommunityAdd = %q, want %q in order (repeated add dropped)", term.CommunityAdd, "65000:1 65000:2")
	}
}

func TestPolicyCommunityBracketedDefinedNames15665(t *testing.T) {
	cfg := compile15665(t, []string{
		"set policy-options community C1 members 65000:1",
		"set policy-options community C2 members 65000:2",
		"set policy-options policy-statement P term t1 then community add [ C1 C2 ]",
		"set policy-options policy-statement P term t1 then accept",
	})
	term := term15665(t, cfg)
	if term.CommunityAdd != "65000:1 65000:2" {
		t.Fatalf("CommunityAdd = %q, want %q (bracketed defined names not resolved per-token)", term.CommunityAdd, "65000:1 65000:2")
	}
}

func TestPolicyCommunityBracketedUndefinedRejected15665(t *testing.T) {
	_, err := CompileConfig(buildTreeFromSet(t, []string{
		"set policy-options community C1 members 65000:1",
		"set policy-options policy-statement P term t1 then community add [ C1 NOPE ]",
		"set policy-options policy-statement P term t1 then accept",
	}))
	if err == nil {
		t.Fatal("CompileConfig accepted bracketed add with undefined NOPE")
	}
	if !strings.Contains(err.Error(), "NOPE") {
		t.Fatalf("rejection %q does not name NOPE", err)
	}
}
