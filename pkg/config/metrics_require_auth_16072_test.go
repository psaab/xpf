package config

import (
	"strings"
	"testing"
)

// metrics_require_auth_16072_test.go pins the #16072 config surface:
// `web-management api-auth metrics-require-auth` compiles into
// APIAuthConfig.MetricsRequireAuth, is accepted by the schema, and strict
// commit rejects it without a usable api-auth credential (the runtime
// snapshot would be nil and the gate silently inert).
//
// FAIL-ON-REVERT: dropping the compiler read makes the compiled flag false;
// dropping the strict gate makes the credential-less case commit.

func TestMetricsRequireAuthCompiles16072(t *testing.T) {
	tree := buildTreeFromSets(t,
		"set system services web-management https system-generated-certificate",
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth user admin password correct-horse-battery",
		"set system services web-management api-auth metrics-require-auth",
	)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected metrics-require-auth: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil || wm.APIAuth == nil || !wm.APIAuth.MetricsRequireAuth {
		t.Fatalf("MetricsRequireAuth not compiled: %+v", wm)
	}

	// Absent by default: the loopback posture stays open (#4162).
	tree2 := buildTreeFromSets(t,
		"set system services web-management https system-generated-certificate",
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth user admin password correct-horse-battery",
	)
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig without gate: %v", err)
	}
	if cfg2.System.Services.WebManagement.APIAuth.MetricsRequireAuth {
		t.Fatal("MetricsRequireAuth defaulted on without the leaf")
	}
}

func TestMetricsRequireAuthNeedsCredential16072(t *testing.T) {
	tree := buildTreeFromSets(t,
		"set system services web-management api-auth metrics-require-auth",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit accepted metrics-require-auth with no api-auth credential; " +
			"the runtime snapshot would be nil and the loopback /metrics gate silently inert")
	}
	if !strings.Contains(err.Error(), "#16072") || !strings.Contains(err.Error(), "metrics-require-auth") {
		t.Fatalf("expected a #16072 metrics-require-auth rejection, got: %v", err)
	}

	// The tolerant load path downgrades it to a warning so an already
	// persisted config still boots (#1960 family).
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16072") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient load did not warn about the inert gate: %v", cfg.Warnings)
	}
	if !cfg.System.Services.WebManagement.APIAuth.MetricsRequireAuth {
		t.Fatal("lenient load dropped the compiled gate flag")
	}
}
