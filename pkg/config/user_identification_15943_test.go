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
	if serr := SchemaValidate(tree); serr != nil {
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

func TestServicesUserIdentificationFlatWarns15943(t *testing.T) {
	tree, errs := NewParser("services user-identification authentication-source local-authentication-table auth1;").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{{"strict", CompileConfig}, {"lenient", CompileConfigLenient}} {
		cfg, err := compile.fn(tree)
		if err != nil {
			t.Fatalf("%s compile: %v", compile.name, err)
		}
		joined := strings.Join(cfg.Warnings, "\n")
		if !strings.Contains(joined, "services user-identification authentication-source") || !strings.Contains(joined, "accepted-only") {
			t.Errorf("%s flat services user-identification produced no accepted-only warning: %v", compile.name, cfg.Warnings)
		}
	}
	bare, errs := NewParser("security user-identification;").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse bare: %v", errs)
	}
	cfg, err := CompileConfig(bare)
	if err != nil {
		t.Fatalf("bare security compile: %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "security user-identification") {
		t.Errorf("bare security user-identification did not warn: %v", cfg.Warnings)
	}
}
