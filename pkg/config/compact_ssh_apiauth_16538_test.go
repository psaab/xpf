package config

import (
	"strings"
	"testing"
)

// #16538: brace-elided `ssh no-password-authentication;` /
// `ssh no-passwords;` and `api-auth metrics-require-auth;` passed strict
// commit and compiled to false, because compactNormalizeInScope admitted
// neither (ssh, no-password*) nor (api-auth, metrics-require-auth), so the
// packed tail stayed on the container's Keys and the FindChild readers in
// compiler_system.go saw nothing. The braced spellings set the booleans.
//
// FAIL-ON-REVERT: removing any of the three pairs from
// compactNormalizeInScope makes the elided half of its cell compile false
// (or, for metrics with a credential, makes the gate flag vanish), and
// removing all three makes the flag-only metrics cell commit silently
// instead of taking the #16072 rejection.

func TestCompactSSHAPIAuthFlagsCompile16538(t *testing.T) {
	bracedSSH := `system { services { ssh { no-password-authentication; no-passwords; } } }`
	elidedSSH := `system { services { ssh no-password-authentication; } }`
	elidedSSH2 := `system { services { ssh no-passwords; } }`
	b, e, e2 := compileText(t, bracedSSH), compileText(t, elidedSSH), compileText(t, elidedSSH2)
	if b == nil || e == nil || e2 == nil {
		t.Fatalf("all ssh spellings must compile (braced=%v elided=%v elided2=%v)", b != nil, e != nil, e2 != nil)
	}
	if !b.System.Services.SSH.NoPasswordAuthentication || !b.System.Services.SSH.NoPasswords {
		t.Fatalf("fixture wrong: braced ssh = %+v, want both flags true", b.System.Services.SSH)
	}
	if !e.System.Services.SSH.NoPasswordAuthentication {
		t.Errorf("brace-elided `ssh no-password-authentication;` compiled NoPasswordAuthentication=false; sshd keeps password auth (#16538)")
	}
	if !e2.System.Services.SSH.NoPasswords {
		t.Errorf("brace-elided `ssh no-passwords;` compiled NoPasswords=false; sshd keeps password auth (#16538)")
	}
	// Positive control: with the pass disabled the elided spelling must
	// NOT carry the value, so this cell observes the pass.
	off := compileSeam8690(t, elidedSSH, true)
	if off == nil {
		t.Fatal("pass-disabled elided ssh must compile (to the dropped value)")
	}
	if off.System.Services.SSH.NoPasswordAuthentication {
		t.Error("with the normalizer DISABLED the elided ssh spelling still carried no-password-authentication; this cell is not observing the pass (#16538)")
	}

	// api-auth: credential + expiry present so the #16072/#10826 strict
	// gates pass; only the flag spelling varies.
	bracedAPI := `system { services { web-management { https { system-generated-certificate; } api-auth { expires 2099-01-01; user admin { password "correct-horse-battery"; } metrics-require-auth; } } } }`
	elidedAPI := `system { services { web-management { https { system-generated-certificate; } api-auth { expires 2099-01-01; user admin { password "correct-horse-battery"; } } api-auth metrics-require-auth; } } }`
	ba, ea := compileText(t, bracedAPI), compileText(t, elidedAPI)
	if ba == nil || ea == nil {
		t.Fatalf("both api-auth spellings must compile (braced=%v elided=%v)", ba != nil, ea != nil)
	}
	if !ba.System.Services.WebManagement.APIAuth.MetricsRequireAuth {
		t.Fatalf("fixture wrong: braced api-auth MetricsRequireAuth=false")
	}
	if !ea.System.Services.WebManagement.APIAuth.MetricsRequireAuth {
		t.Errorf("brace-elided `api-auth metrics-require-auth;` compiled MetricsRequireAuth=false; loopback /metrics stays open (#16538)")
	}
	if ea.System.Services.WebManagement.APIAuth.DefaultClass != ba.System.Services.WebManagement.APIAuth.DefaultClass ||
		!ea.System.Services.WebManagement.APIAuth.DefaultExpiresAt.Equal(ba.System.Services.WebManagement.APIAuth.DefaultExpiresAt) ||
		len(ea.System.Services.WebManagement.APIAuth.Users) != len(ba.System.Services.WebManagement.APIAuth.Users) {
		t.Errorf("elided and braced api-auth spellings compile differently: braced=%+v elided=%+v (#16538)", ba.System.Services.WebManagement.APIAuth, ea.System.Services.WebManagement.APIAuth)
	}
}

// The flag-only elided metrics spelling must be refused exactly like its
// braced twin: strict commit rejects it under #16072 for want of a usable
// credential, rather than silently dropping the flag and committing.
func TestCompactMetricsRequireAuthFlagOnlyRefused16538(t *testing.T) {
	elided := `system { services { web-management { api-auth metrics-require-auth; } } }`
	braced := `system { services { web-management { api-auth { metrics-require-auth; } } } }`
	for name, text := range map[string]string{"elided": elided, "braced": braced} {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s parse: %v", name, perrs)
		}
		_, err := CompileConfig(tree)
		if err == nil {
			t.Errorf("%s flag-only metrics-require-auth committed with no credential; want the #16072 refusal its braced twin gets (#16538)", name)
			continue
		}
		if !strings.Contains(err.Error(), "#16072") || !strings.Contains(err.Error(), "metrics-require-auth") {
			t.Errorf("%s: expected a #16072 metrics-require-auth rejection, got: %v", name, err)
		}
	}
	// Tolerant load keeps the flag and warns, as the braced form does
	// (#16072 lenient half).
	tree, perrs := NewParser(elided).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient elided: %v", err)
	}
	if !cfg.System.Services.WebManagement.APIAuth.MetricsRequireAuth {
		t.Error("lenient load dropped the elided metrics-require-auth flag (#16538)")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16072") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient load did not warn about the inert gate: %v", cfg.Warnings)
	}
}
