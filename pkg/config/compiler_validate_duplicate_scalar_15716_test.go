package config

import (
	"strings"
	"testing"
)

// #15716: packed group root-login leaves and header-packed system
// services must reach the #14447 duplicate gate.

func TestDuplicateRootLoginPackedGroups15716(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"packed system groups", "groups { G1 { system services ssh root-login allow; } G2 { system services ssh root-login deny; } } system { services { ssh { protocol-version v2; } } apply-groups G1; apply-groups G2; }"},
		{"packed services groups", "groups { G1 { system { services ssh root-login allow; } } G2 { system { services ssh root-login deny; } } } system { services { ssh { protocol-version v2; } } apply-groups G1; apply-groups G2; }"},
		{"packed ssh groups", "groups { G1 { system { services { ssh root-login allow; } } } G2 { system { services { ssh root-login deny; } } } } system { services { ssh { protocol-version v2; } } apply-groups G1; apply-groups G2; }"},
		{"header-packed system with braced child", "system services ssh root-login deny { services { ssh { root-login allow; } } }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(parseHierarchical(t, tc.text)); err == nil {
				t.Fatalf("strict accepted conflicting duplicate root-login; want reject (#15716)")
			} else {
				for _, want := range []string{"root-login", "allow", "deny", "14447"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q missing %q", err.Error(), want)
					}
				}
			}
		})
	}
}

func TestDuplicateRootLoginPackedGroupsLenient15716(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHierarchical(t, "groups { G1 { system services ssh root-login allow; } G2 { system services ssh root-login deny; } } system { services { ssh { protocol-version v2; } } apply-groups G1; apply-groups G2; }"))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil || cfg.System.Services.SSH.RootLogin != "deny" {
		t.Fatalf("lenient RootLogin=%q want deny (last wins)", cfg.System.Services.SSH.RootLogin)
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
	// Header-packed lenient: header deny is first, braced allow is last.
	cfg2, err := CompileConfigLenient(parseHierarchical(t, "system services ssh root-login deny { services { ssh { root-login allow; } } }"))
	if err != nil {
		t.Fatalf("lenient header: %v", err)
	}
	if cfg2.System.Services.SSH.RootLogin != "allow" {
		t.Fatalf("lenient header RootLogin=%q want allow (last wins)", cfg2.System.Services.SSH.RootLogin)
	}
	found = false
	for _, w := range cfg2.Warnings {
		if strings.Contains(w, "root-login") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient header warnings missing root-login: %v", cfg2.Warnings)
	}
}

func TestDuplicateRootLoginPackedControls15716(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"single packed system group", "groups { G1 { system services ssh root-login deny; } } system { apply-groups G1; }", "deny"},
		{"identical packed groups", "groups { G1 { system services ssh root-login deny; } G2 { system services ssh root-login deny; } } system { services { ssh { protocol-version v2; } } apply-groups G1; apply-groups G2; }", "deny"},
		{"single header-packed", "system services ssh root-login deny;", "deny"},
		{"identical header+braced", "system services ssh root-login deny { services { ssh { root-login deny; } } }", "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parseHierarchical(t, tc.text))
			if err != nil {
				t.Fatalf("strict: %v", err)
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
	// Inline braced deny + single group packed allow: inline peer is not
	// group-adopted, so group is dropped (inline wins) — single effective
	// value, no conflict. This neighbours the adopt-beside gate.
	cfg, err := CompileConfig(parseHierarchical(t, "groups { G1 { system services ssh root-login allow; } } system { services { ssh { root-login deny; } } apply-groups G1; }"))
	if err != nil {
		t.Fatalf("inline-wins control strict: %v", err)
	}
	if cfg.System.Services.SSH.RootLogin != "deny" {
		t.Fatalf("inline-wins RootLogin=%q want deny", cfg.System.Services.SSH.RootLogin)
	}
}
