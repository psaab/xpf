package config

import "testing"

// #12069 follow-up (HIGH, Codex/Astra hostile review on PR #12322): after
// CUST resolves to its literal member `65000:1`, the strict validator must not
// look that literal up as a community name. The colliding named definition has
// a regex member (not a legal set-action value); treating the already-resolved
// literal as a name would falsely reject a valid policy.
func TestPolicyThenCommunityRegexNameCollisionDoesNotFalseReject12069(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options community CUST members 65000:1",
		`set policy-options community "65000:1" members "65000:.*"`,
		"set policy-options policy-statement P term t1 then community add CUST",
		"set policy-options policy-statement P term t1 then accept",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig false-rejected an already-resolved numeric literal because its spelling names a regex community: %v", err)
	}
	if got := cfg.PolicyOptions.PolicyStatements["P"].Terms[0].CommunityAdd; got != "65000:1" {
		t.Fatalf("CommunityAdd = %q, want resolved literal %q", got, "65000:1")
	}
}

// Name resolution intentionally has precedence over literal recognition for
// an authored operand that matches both. Post-compiler consumers use
// ValidCommunityValueLiteral so a resolved result is not looked up again.
func TestResolveCommunityValuePrefersDefinedName12069(t *testing.T) {
	po := &PolicyOptionsConfig{Communities: map[string]*CommunityDef{
		"65000:1": {Name: "65000:1", Members: []string{"65000:999"}},
	}}
	got, ok := ResolveCommunityValue(po, "65000:1")
	if !ok || got != "65000:999" {
		t.Fatalf("ResolveCommunityValue(name/literal collision) = %q, %v; want name-first expansion %q", got, ok, "65000:999")
	}
}
