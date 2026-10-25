package config

import (
	"strings"
	"testing"
)

// #16776 strict gates, post-#16788: any "| " (grouping or atom) and
// description "| " refuse at commit, warn on tolerant load. #16788's
// translator is stricter than the original grouping rewrite — it
// rejects every literal space — so grouped spellings refuse too.

func TestValidCommunityMemberPipe16776(t *testing.T) {
	ok := []string{
		"65000:.*",
		"(65000:1)|(65001:2)",
		"65000:1{2,3}",
	}
	for _, m := range ok {
		if err := ValidCommunityMemberPipe16776(m); err != nil {
			t.Errorf("ValidCommunityMemberPipe16776(%q) = %v, want nil", m, err)
		}
	}
	bad := []string{
		"^((56) | (78)):(.*)$", // grouping in the original #16776 sense; #16788 refuses any literal space
		"65000:1| 666:.*",
		"a| b",
		"| 65000:.*",
		"65000:[| ]", // bracket can match the separator space
	}
	for _, m := range bad {
		if err := ValidCommunityMemberPipe16776(m); err == nil {
			t.Errorf("ValidCommunityMemberPipe16776(%q) = nil, want refusal", m)
		}
	}
}

func TestCommunityPipeStrictAndLenient16776(t *testing.T) {
	atom := []string{
		`set policy-options community BOTH members "65000:1| 666:.*"`,
		"set policy-options policy-statement P term t-reject from community BOTH",
		"set policy-options policy-statement P term t-reject then reject",
	}
	if _, err := CompileConfig(buildTree9007(t, atom...)); err == nil || (!strings.Contains(err.Error(), "16776") && !strings.Contains(err.Error(), "16788")) {
		t.Errorf("strict compile of atom-space member = %v, want pipe refusal (#16776/#16788)", err)
	}
	cfg, err := CompileConfigLenient(buildTree9007(t, atom...))
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "16776") || strings.Contains(w, "community") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient compile gave no warning: %v", cfg.Warnings)
	}

	op := []string{
		`set policy-options community OP members "^((56) | (78)):(.*)$"`,
	}
	if _, err := CompileConfig(buildTree9007(t, op...)); err == nil || !strings.Contains(err.Error(), "16788") && !strings.Contains(err.Error(), "16776") {
		t.Errorf("strict compile of grouped operator regex = %v, want refusal (#16788 translator rejects \"| \"; operator rewrites it without the space)", err)
	}
}

func TestNeighborDescriptionPipeStrictAndLenient16776(t *testing.T) {
	cmds := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		`set protocols bgp group G neighbor 192.0.2.1 description "uplink | primary"`,
	}
	_, err := CompileConfig(buildTree9007(t, cmds...))
	if err == nil || !strings.Contains(err.Error(), "16776") {
		t.Errorf("strict compile of pipe description = %v, want #16776 refusal", err)
	}
	cfg, err := CompileConfigLenient(buildTree9007(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "description") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient compile gave no description warning: %v", cfg.Warnings)
	}
	// Control: plain description commits strict.
	plain := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 192.0.2.1 description plain-peer",
	}
	if _, err := CompileConfig(buildTree9007(t, plain...)); err != nil {
		t.Errorf("strict compile of plain description = %v, want nil", err)
	}
}
