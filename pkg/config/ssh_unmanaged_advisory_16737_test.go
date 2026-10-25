package config

import (
	"strings"
	"testing"
)

// #16737 (R3-A45-03): with `system-services all` and no `system services
// ssh` stanza, sshd keeps serving under base-image defaults (removing
// the stanza only removes the xpf drop-in), so the commit must carry
// the unmanaged-SSH advisory naming the admitting zone.
// RED pre-fix: no advisory exists, so this fails.
func TestSSHUnmanagedAdvisory16737_AllAdmitsWithoutStanza(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust host-inbound-traffic system-services all",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("system-services all with no ssh stanza must warn that sshd still serves; warnings=%q", cfg.Warnings)
	}
}

// #16737: explicit `ssh`, and the `any-service` full admit, are the
// other two admission shapes that keep tcp/22 reachable unmanaged.
func TestSSHUnmanagedAdvisory16737_ExplicitAndAnyService(t *testing.T) {
	for _, svc := range []string{"ssh", "any-service"} {
		t.Run(svc, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, []string{
				"set security zones security-zone dmz host-inbound-traffic system-services " + svc,
			}))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if !hasSSHUnmanagedAdvisory16737(cfg, "dmz") {
				t.Fatalf("system-services %s with no ssh stanza must warn; warnings=%q", svc, cfg.Warnings)
			}
		})
	}
}

// #16737 control: with the stanza present the service IS managed, so
// no advisory fires (the positive cell is unchanged).
func TestSSHUnmanagedAdvisory16737_SilentWithStanza(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services ssh root-login deny",
		"set security zones security-zone trust host-inbound-traffic system-services all",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("managed ssh stanza must not warn; warnings=%q", cfg.Warnings)
	}
}

// #16737 control: a zone admitting no SSH keeps the advisory silent.
func TestSSHUnmanagedAdvisory16737_SilentWithoutAdmission(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust host-inbound-traffic system-services ping",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Warnings) != 0 && hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("non-SSH zone must not warn; warnings=%q", cfg.Warnings)
	}
}

// #16737: the tolerant path (boot load / peer sync) must stay silent,
// mirroring the #8357 advisory suppression.
func TestSSHUnmanagedAdvisory16737_SilentOnTolerantPath(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set security zones security-zone trust host-inbound-traffic system-services all",
	}))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if hasSSHUnmanagedAdvisory16737(cfg, "trust") {
		t.Fatalf("tolerant path must not repeat the commit advisory; warnings=%q", cfg.Warnings)
	}
}
func hasSSHUnmanagedAdvisory16737(cfg *Config, zone string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no `system services ssh` stanza") && strings.Contains(w, `"`+zone+`"`) {
			return true
		}
	}
	return false
}
