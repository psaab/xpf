package config

import (
	"strings"
	"testing"
)

// #15943 (H15-01): `security user-identification` must be accepted-only
// like `services`: strict SchemaValidate must not closed-world reject it,
// the accepted-only warning must fire, and a bind `password` under
// authentication-source / device-information (wrapped or direct, either
// root) must be redacted, not rendered in cleartext.
func TestSecurityUserIdentificationAcceptedOnly15943(t *testing.T) {
	tree := buildTree(t, []string{
		"set security user-identification authentication-source local-authentication-table auth1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("security user-identification must compile: %v", err)
	}
	if serr := SchemaValidate(tree, cfg); serr != nil {
		t.Fatalf("SchemaValidate rejected security user-identification: %v", serr)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "user-identification") || !strings.Contains(joined, "accepted-only") {
		t.Errorf("security spelling must warn accepted-only, got %v", cfg.Warnings)
	}
}

func TestUserIdentificationPasswordRedacted15943(t *testing.T) {
	const sentinel = "SENTINEL15943"
	for _, lines := range [][]string{
		{"set services authentication-source foo password " + sentinel},
		{"set services device-information password " + sentinel},
		{"set security authentication-source foo password " + sentinel},
		{"set services user-identification authentication-source ad password " + sentinel},
		{"set security user-identification device-information password " + sentinel},
	} {
		tree := buildTree(t, lines)
		if strings.Contains(tree.RedactedClone().Format(), sentinel) {
			t.Errorf("password leaked in cleartext for %v", lines)
		}
	}
}
