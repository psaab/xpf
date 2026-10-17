package config

import (
	"strings"
	"testing"
)

// #14447 (DR20-H1): duplicate `root-login` with conflicting values.
// Reader used FindChild (first wins), so `allow; deny;` installed
// RootLogin="allow" -> PermitRootLogin yes, discarding explicit deny.
// Strict must reject both orders; lenient warns + last-wins; identical /
// single unchanged; two ssh blocks pooled; packed spelling covered.

func TestDuplicateRootLoginConflictingStrictReject14447(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"allow then deny", "system { services { ssh { root-login allow; root-login deny; } } }"},
		{"deny then allow", "system { services { ssh { root-login deny; root-login allow; } } }"},
		{"two ssh blocks", "system { services { ssh { root-login allow; } ssh { root-login deny; } } }"},
		{"two services blocks", "system { services { ssh { root-login allow; } } services { ssh { root-login deny; } } }"},
		{"packed", "system { services { ssh root-login allow root-login deny; } }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHierarchical(t, tc.text))
			if err == nil {
				t.Fatalf("strict accepted conflicting duplicate root-login; want reject")
			}
			for _, want := range []string{"root-login", "allow", "deny", "14447"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func TestDuplicateRootLoginLenientLastWins14447(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHierarchical(t, "system { services { ssh { root-login allow; root-login deny; } } }"))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil || cfg.System.Services.SSH.RootLogin != "deny" {
		t.Fatalf("lenient RootLogin=%v want deny (last wins)", cfg.System.Services)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "root-login") && strings.Contains(w, "14447") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient warnings missing root-login/14447: %v", cfg.Warnings)
	}
	// Reverse order lenient -> allow
	cfg2, err := CompileConfigLenient(parseHierarchical(t, "system { services { ssh { root-login deny; root-login allow; } } }"))
	if err != nil {
		t.Fatalf("lenient reverse: %v", err)
	}
	if cfg2.System.Services.SSH.RootLogin != "allow" {
		t.Fatalf("lenient reverse RootLogin=%q want allow", cfg2.System.Services.SSH.RootLogin)
	}
}

func TestDuplicateRootLoginControls14447(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"single deny", "system { services { ssh { root-login deny; } } }", "deny"},
		{"single allow", "system { services { ssh { root-login allow; } } }", "allow"},
		{"identical deny", "system { services { ssh { root-login deny; root-login deny; } } }", "deny"},
		{"identical across blocks", "system { services { ssh { root-login deny; } ssh { root-login deny; } } }", "deny"},
		{"no root-login", "system { services { ssh { protocol-version v2; } } }", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parseHierarchical(t, tc.text))
			if err != nil {
				t.Fatalf("strict control: %v", err)
			}
			got := ""
			if cfg.System.Services != nil && cfg.System.Services.SSH != nil {
				got = cfg.System.Services.SSH.RootLogin
			}
			if got != tc.want {
				t.Fatalf("RootLogin=%q want %q", got, tc.want)
			}
		})
	}
	const grouped = "groups { G1 { system { services { ssh { root-login allow; } } } } G2 { system { services { ssh { root-login deny; } } } } } system { services { ssh { protocol-version v2; } } apply-groups G1; apply-groups G2; }"
	if _, err := CompileConfig(parseHierarchical(t, grouped)); err == nil {
		t.Fatalf("group conflicting duplicate must strict-reject")
	}
	cfg, err := CompileConfigLenient(parseHierarchical(t, grouped))
	if err != nil {
		t.Fatalf("group lenient: %v", err)
	}
	if cfg.System.Services.SSH.RootLogin != "deny" {
		t.Fatalf("group lenient RootLogin=%q want deny (last wins)", cfg.System.Services.SSH.RootLogin)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "root-login") {
			found = true
		}
	}
	if !found {
		t.Fatalf("group lenient missing warning: %v", cfg.Warnings)
	}
	// ForNode parity
	if _, err := CompileConfigForNode(parseHierarchical(t, "system { services { ssh { root-login allow; root-login deny; } } }"), 0); err == nil {
		t.Fatalf("ForNode strict must reject")
	}
	cfgN, err := CompileConfigForNodeLenient(parseHierarchical(t, "system { services { ssh { root-login allow; root-login deny; } } }"), 0)
	if err != nil {
		t.Fatalf("ForNode lenient: %v", err)
	}
	if cfgN.System.Services.SSH.RootLogin != "deny" {
		t.Fatalf("ForNode lenient RootLogin=%q want deny", cfgN.System.Services.SSH.RootLogin)
	}
}
